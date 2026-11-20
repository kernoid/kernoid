// SPDX-License-Identifier: AGPL-3.0-or-later
//! IMAP ACL (RFC 4314) on kernoid's grants (RFC 0002, 12.2): `MYRIGHTS`, `GETACL`, `LISTRIGHTS`, `SETACL` and
//! `DELETEACL`. Identifiers are addresses of accounts and `$<group name>` for groups; `SETACL` and `DELETEACL` change
//! the grant on that one mailbox – a grant on the whole store is the administrators' or the owner's, elsewhere.

use kernoid_identity::{IdentityError, role::Principal};
use kernoid_mail::Rights;

use crate::{
    folders::Folder,
    mailboxes::no_permission,
    proto::{
        request::{RightsChange, StoreMode},
        response::{self, Code, Status},
    },
    session::Session,
};

fn identity_error(error: IdentityError) -> Status {
    match error {
        IdentityError::NotFound(what) => Status::no(format!("{what} does not exist")).with_code(Code::NonExistent),
        IdentityError::Refused(reason) => Status::no(reason).with_code(Code::Cannot),
        error => {
            tracing::warn!(%error, "an IMAP ACL command failed");
            Status::unavailable()
        }
    }
}

/// `"name" "identifier"` and what follows, as one untagged response.
fn line(verb: &str, mailbox: &str, utf8: bool, rest: &[(Option<&str>, String)]) -> Vec<u8> {
    let mut out = format!("* {verb} ").into_bytes();
    response::mailbox(&mut out, mailbox, utf8);
    for (identifier, rights) in rest {
        if let Some(identifier) = identifier {
            out.push(b' ');
            response::string(&mut out, identifier.as_bytes(), utf8);
        }
        out.push(b' ');
        if rights.is_empty() {
            out.extend_from_slice(b"\"\"");
        } else {
            out.extend_from_slice(rights.as_bytes());
        }
    }
    out.extend_from_slice(b"\r\n");
    out
}

impl Session {
    /// The mailbox an ACL command names.
    #[allow(clippy::result_large_err, reason = "the error is the response, sent once")]
    async fn acl_folder(&mut self, mailbox: &str) -> Result<Folder, Status> {
        let folders = self.folders().await?;
        folders.find(mailbox).cloned().ok_or_else(|| Status::no("No such mailbox").with_code(Code::NonExistent))
    }

    pub(crate) async fn my_rights(&mut self, mailbox: &str) -> Status {
        match self.acl_folder(mailbox).await {
            Ok(folder) => {
                let out = line("MYRIGHTS", &folder.name, self.utf8, &[(None, folder.rights.letters())]);
                self.write(out);
                Status::done()
            }
            Err(response) => response,
        }
    }

    pub(crate) async fn list_rights(&mut self, mailbox: &str, identifier: &str) -> Status {
        match self.acl_folder(mailbox).await {
            Ok(folder) => {
                // Nothing is granted without asking; each right on its own.
                let mut rights = vec![(Some(identifier), String::new())];
                rights.extend(Rights::ALL.letters().chars().map(|right| (None, right.to_string())));
                let out = line("LISTRIGHTS", &folder.name, self.utf8, &rights);
                self.write(out);
                Status::done()
            }
            Err(response) => response,
        }
    }

    pub(crate) async fn get_acl(&mut self, mailbox: &str) -> Status {
        let folder = match self.acl_folder(mailbox).await {
            Ok(folder) => folder,
            Err(response) => return response,
        };
        // Seeing and changing the access needs `a` (the owner has it).
        if !folder.rights.contains(Rights::ADMIN) {
            return no_permission("see or change the access to this mailbox");
        }
        let identity = &self.inner.identity;
        let grants = match identity.mail_access(folder.owner).await {
            Ok(grants) => grants,
            Err(error) => return identity_error(error),
        };
        let owner_address = match identity.account(folder.owner).await {
            Ok(info) => info.address,
            Err(error) => return identity_error(error),
        };
        let mailbox = folder.info.id;
        let mut permissions = vec![(owner_address, Rights::ALL)];
        // Per grantee: the grant on the whole store together with the one on this mailbox.
        for grant in grants.iter().filter(|grant| grant.mailbox.is_none() || grant.mailbox == Some(mailbox)) {
            let rights = Rights::parse(&grant.rights);
            match permissions.iter_mut().find(|(name, _)| *name == grant.grantee_name) {
                Some((_, held)) => *held |= rights,
                None => permissions.push((grant.grantee_name.clone(), rights)),
            }
        }
        let rest: Vec<(Option<&str>, String)> =
            permissions.iter().map(|(name, rights)| (Some(name.as_str()), rights.letters())).collect();
        let out = line("ACL", &folder.name, self.utf8, &rest);
        self.write(out);
        Status::done()
    }

    /// `SETACL` with a change, `DELETEACL` without: the grant on this one mailbox.
    pub(crate) async fn set_acl(&mut self, mailbox: &str, identifier: &str, change: Option<RightsChange>) -> Status {
        let folder = match self.acl_folder(mailbox).await {
            Ok(folder) => folder,
            Err(response) => return response,
        };
        if !folder.rights.contains(Rights::ADMIN) {
            return no_permission("see or change the access to this mailbox");
        }
        let (owner, mailbox) = (folder.owner, folder.info.id);
        let account = self.account();
        let tenant = self.tenant.expect("only after logging in");
        let identity = &self.inner.identity;
        let grants = match identity.mail_access(owner).await {
            Ok(grants) => grants,
            Err(error) => return identity_error(error),
        };
        let grantee = match identity.mail_grantee(tenant, identifier).await {
            Ok(grantee) => grantee,
            Err(error) => return identity_error(error),
        };
        if grantee == Principal::Account(owner) {
            return Status::no("The owner has every right").with_code(Code::Cannot);
        }
        let current = grants
            .iter()
            .find(|grant| grant.grantee == grantee && grant.mailbox == Some(mailbox))
            .map_or(Rights::NONE, |grant| Rights::parse(&grant.rights));
        let wanted = match change {
            Some(change) => {
                let changed = Rights::parse(&change.letters);
                match change.mode {
                    StoreMode::Replace => changed,
                    StoreMode::Add => current | changed,
                    StoreMode::Remove => Rights::parse(
                        &current.letters().chars().filter(|c| !changed.letters().contains(*c)).collect::<String>(),
                    ),
                }
            }
            None => Rights::NONE,
        };
        let creator = format!("account:{account}");
        let result = if wanted.is_empty() {
            if current.is_empty() {
                Ok(())
            } else {
                identity.remove_mail_access(owner, grantee, Some(mailbox), &creator).await
            }
        } else {
            identity.set_mail_access(owner, grantee, Some(mailbox), &wanted.letters(), false, &creator).await
        };
        match result {
            Ok(()) => Status::done(),
            Err(error) => identity_error(error),
        }
    }
}
