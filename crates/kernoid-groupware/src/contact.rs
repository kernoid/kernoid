// SPDX-License-Identifier: AGPL-3.0-or-later
//! Contacts (RFC 0004, 5): one vCard per resource, sealed, with its index.

use kernoid_mail::StoreChange;
use uuid::Uuid;

use crate::{
    Expect, Groupware, GroupwareError, Result,
    changes::{self, Change, Entry, ObjectType},
    check_resource_name, contact_path,
    ical::{self, ParsedContact},
    resource_name,
};

/// A contact as listed: everything but its content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactInfo {
    pub id: Uuid,
    pub account: Uuid,
    pub addressbook: Uuid,
    pub resource_name: String,
    pub uid: String,
    pub kind: String,
    pub emails: Vec<String>,
    pub size: i64,
    /// The modification sequence of its last change: its ETag.
    pub modseq: i64,
}

struct Row {
    id: Uuid,
    addressbook_id: Uuid,
    resource_name: String,
    uid: String,
    kind: String,
    emails: Vec<String>,
    size: i64,
    modseq: i64,
}

impl Row {
    fn info(self, account: Uuid) -> ContactInfo {
        ContactInfo {
            id: self.id,
            account,
            addressbook: self.addressbook_id,
            resource_name: self.resource_name,
            uid: self.uid,
            kind: self.kind,
            emails: self.emails,
            size: self.size,
            modseq: self.modseq,
        }
    }
}

impl Groupware {
    /// The contacts of an address book, or of all of the account's.
    pub async fn contacts(&self, account: Uuid, addressbook: Option<Uuid>) -> Result<Vec<ContactInfo>> {
        let mut read = self.read(account).await?;
        let rows = sqlx::query_as!(
            Row,
            "SELECT id, addressbook_id, resource_name, uid, kind, emails, size, modseq
             FROM contacts WHERE account_id = $1 AND ($2::uuid IS NULL OR addressbook_id = $2) ORDER BY resource_name",
            account,
            addressbook,
        )
        .fetch_all(read.connection())
        .await?;
        read.finish().await?;
        Ok(rows.into_iter().map(|row| row.info(account)).collect())
    }

    /// The account's contacts with this address (lower case).
    pub async fn contacts_by_email(&self, account: Uuid, email: &str) -> Result<Vec<ContactInfo>> {
        let mut read = self.read(account).await?;
        let rows = sqlx::query_as!(
            Row,
            "SELECT id, addressbook_id, resource_name, uid, kind, emails, size, modseq
             FROM contacts WHERE account_id = $1 AND emails @> ARRAY[$2::text] ORDER BY id",
            account,
            email.to_lowercase(),
        )
        .fetch_all(read.connection())
        .await?;
        read.finish().await?;
        Ok(rows.into_iter().map(|row| row.info(account)).collect())
    }

    pub async fn contact(&self, account: Uuid, id: Uuid) -> Result<ContactInfo> {
        let mut read = self.read(account).await?;
        let row = sqlx::query_as!(
            Row,
            "SELECT id, addressbook_id, resource_name, uid, kind, emails, size, modseq
             FROM contacts WHERE account_id = $1 AND id = $2",
            account,
            id,
        )
        .fetch_optional(read.connection())
        .await?;
        read.finish().await?;
        row.map(|row| row.info(account)).ok_or(GroupwareError::NotFound("the contact"))
    }

    pub async fn contact_by_name(&self, account: Uuid, addressbook: Uuid, name: &str) -> Result<Option<ContactInfo>> {
        let mut read = self.read(account).await?;
        let row = sqlx::query_as!(
            Row,
            "SELECT id, addressbook_id, resource_name, uid, kind, emails, size, modseq
             FROM contacts WHERE account_id = $1 AND addressbook_id = $2 AND resource_name = $3",
            account,
            addressbook,
            name,
        )
        .fetch_optional(read.connection())
        .await?;
        read.finish().await?;
        Ok(row.map(|row| row.info(account)))
    }

    /// The vCards of contacts, opened; ids that are not the account's are left out.
    pub async fn contact_data(&self, account: Uuid, ids: &[Uuid]) -> Result<Vec<(ContactInfo, String)>> {
        let mut read = self.read(account).await?;
        let tenant = read.tenant();
        let rows = sqlx::query!(
            "SELECT id, addressbook_id, resource_name, uid, kind, emails, size, modseq, data
             FROM contacts WHERE account_id = $1 AND id = ANY($2)",
            account,
            ids,
        )
        .fetch_all(read.connection())
        .await?;
        read.finish().await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let text = self.open(tenant, &contact_path(tenant, account, row.id), &row.data).await?;
            let info = Row {
                id: row.id,
                addressbook_id: row.addressbook_id,
                resource_name: row.resource_name,
                uid: row.uid,
                kind: row.kind,
                emails: row.emails,
                size: row.size,
                modseq: row.modseq,
            }
            .info(account);
            out.push((info, text));
        }
        Ok(out)
    }

    /// Stores a vCard under `name` in an address book (CardDAV `PUT`): creates the resource or replaces it; whether
    /// it was created.
    pub async fn put_contact(
        &self,
        account: Uuid,
        addressbook: Uuid,
        name: &str,
        text: &str,
        expect: Expect,
    ) -> Result<(ContactInfo, bool)> {
        check_resource_name(name)?;
        let parsed = ical::parse_contact(text)?;
        let mut change = self.change(account).await?;
        let known = sqlx::query_scalar!(
            "SELECT 1 AS \"one!\" FROM addressbooks WHERE id = $1 AND account_id = $2",
            addressbook,
            account
        )
        .fetch_optional(change.connection())
        .await?;
        if known.is_none() {
            return Err(GroupwareError::NotFound("the address book"));
        }
        let existing = sqlx::query!(
            "SELECT id, modseq, size, uid FROM contacts WHERE addressbook_id = $1 AND resource_name = $2 FOR UPDATE",
            addressbook,
            name,
        )
        .fetch_optional(change.connection())
        .await?;
        match (expect, &existing) {
            (Expect::New, Some(_)) => return Err(GroupwareError::PreconditionFailed),
            (Expect::Version(version), Some(row)) if row.modseq != version => {
                return Err(GroupwareError::PreconditionFailed);
            }
            (Expect::Version(_), None) => return Err(GroupwareError::PreconditionFailed),
            _ => {}
        }
        let conflict = sqlx::query_scalar!(
            "SELECT resource_name FROM contacts WHERE addressbook_id = $1 AND uid = $2 AND resource_name <> $3",
            addressbook,
            parsed.uid,
            name,
        )
        .fetch_optional(change.connection())
        .await?;
        if let Some(other) = conflict {
            return Err(GroupwareError::UidConflict(other));
        }
        if let Some(row) = &existing
            && row.uid != parsed.uid
        {
            return Err(GroupwareError::UidConflict(name.to_owned()));
        }
        let id = existing.as_ref().map_or_else(Uuid::now_v7, |row| row.id);
        let created = existing.is_none();
        let info =
            self.write_contact(&mut change, addressbook, id, name, text, &parsed, existing.map(|row| row.size)).await?;
        change.commit().await?;
        Ok((info, created))
    }

    /// Creates a contact from a vCard (JMAP `ContactCard/set`): its resource name comes from its UID.
    pub async fn create_contact(&self, account: Uuid, addressbook: Uuid, text: &str) -> Result<ContactInfo> {
        let parsed = ical::parse_contact(text)?;
        let mut change = self.change(account).await?;
        let known = sqlx::query_scalar!(
            "SELECT 1 AS \"one!\" FROM addressbooks WHERE id = $1 AND account_id = $2",
            addressbook,
            account
        )
        .fetch_optional(change.connection())
        .await?;
        if known.is_none() {
            return Err(GroupwareError::NotFound("the address book"));
        }
        let taken = sqlx::query_scalar!(
            "SELECT resource_name FROM contacts WHERE addressbook_id = $1 AND uid = $2",
            addressbook,
            parsed.uid,
        )
        .fetch_optional(change.connection())
        .await?;
        if let Some(other) = taken {
            return Err(GroupwareError::UidConflict(other));
        }
        let id = Uuid::now_v7();
        let mut name = resource_name(&parsed.uid, id, "vcf");
        let name_taken = sqlx::query_scalar!(
            "SELECT 1 AS \"one!\" FROM contacts WHERE addressbook_id = $1 AND resource_name = $2",
            addressbook,
            name,
        )
        .fetch_optional(change.connection())
        .await?;
        if name_taken.is_some() {
            name = format!("{id}.vcf");
        }
        let info = self.write_contact(&mut change, addressbook, id, &name, text, &parsed, None).await?;
        change.commit().await?;
        Ok(info)
    }

    /// Replaces the content of a contact, keeping where it is (JMAP update). The UID must stay.
    pub async fn replace_contact(&self, account: Uuid, id: Uuid, text: &str) -> Result<ContactInfo> {
        let parsed = ical::parse_contact(text)?;
        let mut change = self.change(account).await?;
        let row = sqlx::query!(
            "SELECT addressbook_id, resource_name, uid, size FROM contacts WHERE id = $1 AND account_id = $2 FOR UPDATE",
            id,
            account,
        )
        .fetch_optional(change.connection())
        .await?
        .ok_or(GroupwareError::NotFound("the contact"))?;
        if parsed.uid != row.uid {
            return Err(GroupwareError::Invalid("a contact keeps its UID".into()));
        }
        let info = self
            .write_contact(&mut change, row.addressbook_id, id, &row.resource_name, text, &parsed, Some(row.size))
            .await?;
        change.commit().await?;
        Ok(info)
    }

    #[allow(clippy::too_many_arguments)]
    async fn write_contact(
        &self,
        change: &mut StoreChange,
        addressbook: Uuid,
        id: Uuid,
        name: &str,
        text: &str,
        parsed: &ParsedContact,
        old_size: Option<i64>,
    ) -> Result<ContactInfo> {
        let account = change.account();
        let tenant = change.tenant();
        crate::sealed::refuse_plain(change.connection(), addressbook).await?;
        let size = text.len() as i64;
        change.charge(size - old_size.unwrap_or(0)).await?;
        let modseq = change.next_modseq().await?;
        let sealed = self.seal(tenant, &contact_path(tenant, account, id), text).await?;
        let row = sqlx::query_as!(
            Row,
            "INSERT INTO contacts (id, account_id, addressbook_id, resource_name, uid, kind, emails, data, size, modseq)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
             ON CONFLICT (id) DO UPDATE SET kind = excluded.kind, emails = excluded.emails, data = excluded.data,
                 size = excluded.size, modseq = excluded.modseq
             RETURNING id, addressbook_id, resource_name, uid, kind, emails, size, modseq",
            id,
            account,
            addressbook,
            name,
            parsed.uid,
            parsed.kind,
            &parsed.emails,
            sealed,
            size,
            modseq,
        )
        .fetch_one(change.connection())
        .await?;
        let entry = Entry {
            object_type: ObjectType::Contact,
            id,
            collection: Some(addressbook),
            resource_name: Some(name),
            change: if old_size.is_none() { Change::Created } else { Change::Updated },
        };
        changes::record(change.connection(), account, modseq, entry).await?;
        Ok(row.info(account))
    }

    /// Destroys a contact (CardDAV `DELETE`, JMAP destroy).
    pub async fn destroy_contact(&self, account: Uuid, id: Uuid, expect: Expect) -> Result<ContactInfo> {
        let mut change = self.change(account).await?;
        let row = sqlx::query_as!(
            Row,
            "DELETE FROM contacts WHERE id = $1 AND account_id = $2
             RETURNING id, addressbook_id, resource_name, uid, kind, emails, size, modseq",
            id,
            account,
        )
        .fetch_optional(change.connection())
        .await?
        .ok_or(GroupwareError::NotFound("the contact"))?;
        if let Expect::Version(version) = expect
            && version != row.modseq
        {
            return Err(GroupwareError::PreconditionFailed);
        }
        let modseq = change.next_modseq().await?;
        let entry = Entry {
            object_type: ObjectType::Contact,
            id,
            collection: Some(row.addressbook_id),
            resource_name: Some(&row.resource_name),
            change: Change::Destroyed,
        };
        changes::record(change.connection(), account, modseq, entry).await?;
        change.charge(-row.size).await?;
        change.commit().await?;
        Ok(row.info(account))
    }

    /// Moves a contact to another address book of the account, under `name` there (CardDAV `MOVE`, JMAP
    /// `addressBookIds`).
    pub async fn move_contact(&self, account: Uuid, id: Uuid, to: Uuid, name: Option<&str>) -> Result<ContactInfo> {
        if let Some(name) = name {
            check_resource_name(name)?;
        }
        let mut change = self.change(account).await?;
        let row = sqlx::query!(
            "SELECT addressbook_id, resource_name, uid FROM contacts WHERE id = $1 AND account_id = $2 FOR UPDATE",
            id,
            account
        )
        .fetch_optional(change.connection())
        .await?
        .ok_or(GroupwareError::NotFound("the contact"))?;
        let target = sqlx::query_scalar!(
            "SELECT 1 AS \"one!\" FROM addressbooks WHERE id = $1 AND account_id = $2",
            to,
            account
        )
        .fetch_optional(change.connection())
        .await?;
        if target.is_none() {
            return Err(GroupwareError::NotFound("the address book"));
        }
        let name = name.unwrap_or(&row.resource_name).to_owned();
        let clash = sqlx::query_scalar!(
            "SELECT id FROM contacts WHERE addressbook_id = $1 AND (resource_name = $2 OR uid = $3) AND id <> $4",
            to,
            name,
            row.uid,
            id,
        )
        .fetch_optional(change.connection())
        .await?;
        if clash.is_some() {
            return Err(GroupwareError::PreconditionFailed);
        }
        let left = change.next_modseq().await?;
        let gone = Entry {
            object_type: ObjectType::Contact,
            id,
            collection: Some(row.addressbook_id),
            resource_name: Some(&row.resource_name),
            change: Change::Destroyed,
        };
        changes::record(change.connection(), account, left, gone).await?;
        let modseq = change.next_modseq().await?;
        let moved = sqlx::query_as!(
            Row,
            "UPDATE contacts SET addressbook_id = $3, resource_name = $4, modseq = $5 WHERE id = $1 AND account_id = $2
             RETURNING id, addressbook_id, resource_name, uid, kind, emails, size, modseq",
            id,
            account,
            to,
            name,
            modseq,
        )
        .fetch_one(change.connection())
        .await?;
        let arrived = Entry {
            object_type: ObjectType::Contact,
            id,
            collection: Some(to),
            resource_name: Some(&name),
            change: Change::Created,
        };
        changes::record(change.connection(), account, modseq, arrived).await?;
        change.commit().await?;
        Ok(moved.info(account))
    }
}
