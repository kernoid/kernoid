// SPDX-License-Identifier: AGPL-3.0-or-later
//! IMAP ACL (RFC 4314) on kernoid's grants (RFC 0002, 12.2): `MYRIGHTS`, `GETACL`, `LISTRIGHTS`, `SETACL` and
//! `DELETEACL`. Identifiers are addresses of accounts and `$<group name>` for groups; `SETACL` and `DELETEACL` change
//! the grant on that one mailbox – a grant on the whole store is the administrators' or the owner's, elsewhere.

use kernoid_identity::{IdentityError, role::Principal};
use kernoid_mail::Rights;

use crate::{
    mailboxes::no_permission,
    proto::{
        Command, ResponseCode, StatusResponse,
        protocol::acl::{self, GetAclResponse, ListRightsResponse, ModRightsOp, MyRightsResponse},
    },
    session::Session,
};

/// The proto's rights from letters.
fn proto_rights(rights: Rights) -> Vec<acl::Rights> {
    rights
        .letters()
        .chars()
        .filter_map(|letter| {
            Some(match letter {
                'l' => acl::Rights::Lookup,
                'r' => acl::Rights::Read,
                's' => acl::Rights::Seen,
                'w' => acl::Rights::Write,
                'i' => acl::Rights::Insert,
                'p' => acl::Rights::Post,
                'k' => acl::Rights::CreateMailbox,
                'x' => acl::Rights::DeleteMailbox,
                't' => acl::Rights::DeleteMessages,
                'e' => acl::Rights::Expunge,
                'a' => acl::Rights::Administer,
                _ => return None,
            })
        })
        .collect()
}

fn letters(rights: &[acl::Rights]) -> Rights {
    let letters: String = rights.iter().map(|right| right.to_char() as char).collect();
    Rights::parse(&letters)
}

fn identity_error(error: IdentityError) -> StatusResponse {
    match error {
        IdentityError::NotFound(what) => {
            StatusResponse::no(format!("{what} does not exist")).with_code(ResponseCode::NonExistent)
        }
        IdentityError::Refused(reason) => StatusResponse::no(reason).with_code(ResponseCode::Cannot),
        error => {
            tracing::warn!(%error, "an IMAP ACL command failed");
            StatusResponse::database_failure()
        }
    }
}

impl Session {
    pub(crate) async fn acl(&mut self, command: Command, arguments: acl::Arguments) -> StatusResponse {
        let folders = match self.folders().await {
            Ok(folders) => folders,
            Err(response) => return response,
        };
        let Some(folder) = folders.find(&arguments.mailbox_name) else {
            return StatusResponse::no("No such mailbox").with_code(ResponseCode::NonExistent);
        };
        let (owner, mailbox, rights, name) = (folder.owner, folder.info.id, folder.rights, folder.name.clone());
        let account = self.account();
        let is_utf8 = self.is_utf8;
        match command {
            Command::MyRights => {
                self.write(MyRightsResponse { mailbox_name: name, rights: proto_rights(rights) }.into_bytes(is_utf8));
                return StatusResponse::completed(command);
            }
            Command::ListRights => {
                let identifier = arguments.identifier.unwrap_or_default();
                let response = ListRightsResponse {
                    mailbox_name: name,
                    identifier,
                    // Nothing is granted without asking; each right on its own.
                    permissions: std::iter::once(Vec::new())
                        .chain(Rights::ALL.letters().chars().map(|c| proto_rights(Rights::parse(&c.to_string()))))
                        .collect(),
                };
                self.write(response.into_bytes(is_utf8));
                return StatusResponse::completed(command);
            }
            _ => {}
        }
        // Seeing and changing the access needs `a` (the owner has it).
        if !rights.contains(Rights::ADMIN) {
            return no_permission("see or change the access to this mailbox");
        }
        let identity = &self.inner.identity;
        let grants = match identity.mail_access(owner).await {
            Ok(grants) => grants,
            Err(error) => return identity_error(error),
        };
        match command {
            Command::GetAcl => {
                let owner_address = match identity.account(owner).await {
                    Ok(info) => info.address,
                    Err(error) => return identity_error(error),
                };
                let mut permissions = vec![(owner_address, proto_rights(Rights::ALL))];
                // Per grantee: the grant on the whole store together with the one on this mailbox.
                let mut names: Vec<&str> = Vec::new();
                for grant in grants.iter().filter(|grant| grant.mailbox.is_none() || grant.mailbox == Some(mailbox)) {
                    if !names.contains(&grant.grantee_name.as_str()) {
                        names.push(&grant.grantee_name);
                    }
                }
                for name in names {
                    let rights = grants
                        .iter()
                        .filter(|grant| grant.grantee_name == name)
                        .filter(|grant| grant.mailbox.is_none() || grant.mailbox == Some(mailbox))
                        .fold(Rights::NONE, |rights, grant| rights | Rights::parse(&grant.rights));
                    permissions.push((name.to_owned(), proto_rights(rights)));
                }
                self.write(GetAclResponse { mailbox_name: name, permissions }.into_bytes(is_utf8));
                StatusResponse::completed(command)
            }
            Command::SetAcl | Command::DeleteAcl => {
                let tenant = self.tenant.expect("only after logging in");
                let identifier = arguments.identifier.unwrap_or_default();
                let grantee = match identity.mail_grantee(tenant, &identifier).await {
                    Ok(grantee) => grantee,
                    Err(error) => return identity_error(error),
                };
                if grantee == Principal::Account(owner) {
                    return StatusResponse::no("The owner has every right").with_code(ResponseCode::Cannot);
                }
                let current = grants
                    .iter()
                    .find(|grant| grant.grantee == grantee && grant.mailbox == Some(mailbox))
                    .map_or(Rights::NONE, |grant| Rights::parse(&grant.rights));
                let wanted = match (command, arguments.mod_rights) {
                    (Command::SetAcl, Some(change)) => {
                        let changed = letters(&change.rights);
                        match change.op {
                            ModRightsOp::Replace => changed,
                            ModRightsOp::Add => current | changed,
                            ModRightsOp::Remove => Rights::parse(
                                &current
                                    .letters()
                                    .chars()
                                    .filter(|c| !changed.letters().contains(*c))
                                    .collect::<String>(),
                            ),
                        }
                    }
                    _ => Rights::NONE,
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
                    Ok(()) => StatusResponse::completed(command),
                    Err(error) => identity_error(error),
                }
            }
            _ => StatusResponse::bad("Not an ACL command"),
        }
    }
}
