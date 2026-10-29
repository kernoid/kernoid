<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# RFC 0005 – Files

- **Status:** draft, 2026-10-28; implemented: all sections (`kernoid-files`, migration 0032; `kernoid-jmap`;
  `kernoid-server`'s `webdav`); links (11.3, migration 0038) since 0.2.
- **Scope:** how files and directories are stored (sections 1–7), how programs reach them (JMAP: 8, WebDAV: 9, the
  web app: 10), how they are counted (13), shared (11) and kept by the tenant rather than a person (drives, 12).

The whitepaper leaves the sync protocol open: kernoid's own, or an open one that is good enough. This RFC takes the
open one: **JMAP for files**, the IETF's
[JMAP File Storage extension](https://datatracker.ietf.org/doc/draft-ietf-jmap-filenode/) (`FileNode`) – a draft,
revision 19 on 2026-10-28 – in the same JMAP that serves mail, calendars and contacts (RFC 0002, 11.1; RFC 0004,
8.2). Its authors state its aim as replacing WebDAV for remote file systems, as JMAP Calendars and Contacts replace
CalDAV and CardDAV. kernoid's own apps (MIT, apart from the server) speak only this protocol; anybody may write
others against it. The draft still changes: kernoid follows the revision named here and records deviations below.

## 1. Data, not events

Files are **data**, like mail (RFC 0002, 1) and calendars (RFC 0004, 2): tables in PostgreSQL changed in ordinary
transactions, the content in object storage. What an administrator or an owner decides – the quota, sharing, drives
– is events.

## 2. The file store of an account

- **Who has one:** every account with the service `files` (RFC 0003, 4) – with or without a mailbox – and every
  drive (section 12). Shared mailboxes and groups have none (a drive takes the place of the "group as owner of shared
  folders" of RFC 0001, 7.4).
- It is its own store, not the mail store: `file_accounts` holds its tenant, its **modification sequence**
  (`modseq`), the oldest state its journal can bring up to date (`changes_floor`) and the bytes used. Every change
  takes this row first (`FOR UPDATE`), so changes to one account's files are one after another. The first use
  creates it with the default directories (section 4).
- **Why not the mail store:** an account may have files without mail (RFC 0003), and files are counted against a
  quota of their own (section 13). The JMAP states of `FileNode` are the file store's `modseq`; those of mail,
  calendars and contacts stay the mail store's.
- Every change notifies the PostgreSQL channel `kernoid_mail` with the account's id, as mail does, so that JMAP push
  (RFC 0002, 11.1) tells clients.

## 3. Nodes

A **node** is a directory or a file (the draft's `@type` `Directory`, `File`). One table, `file_nodes`:

| Field | Notes |
|---|---|
| `id` | UUIDv7, the JMAP id |
| `parent_id` | a directory of the same account, or none (top level) |
| `node_type` | `directory` or `file`; never changes |
| `name` | see below; unique among siblings |
| `role` | directories only: `trash`, or none (section 4) |
| `content_id`, `size`, `media_type`, `executable` | files only: the current content (section 5), its size in bytes, its media type (`application/octet-stream` if not given), the executable flag |
| `created`, `modified`, `accessed` | set by the client, defaulting to now; kernoid changes `modified` itself only on a direct write (8) |
| `changed` | set by kernoid on every change of the node |
| `is_subscribed` | the owner's display setting |

- **Names:** 1–255 bytes of UTF-8, without the characters `/ < > : " \ | ? *` and control characters, not `.` or
  `..` – the draft's advice for clients on all common systems (its section 9.3). Names are compared exactly; JMAP
  clients may ask for a case-insensitive check (`compareCaseInsensitively`). **OPEN:** refusing Windows' reserved
  names (`CON`, …) and trailing dots and spaces – clients deal with them for now, as the draft expects.
- **Depth:** at most 64 levels (`maxFileNodeDepth`). Moving a directory below itself is refused.
- **Symbolic links** (`SymLink`) are not supported for now (**OPEN**); neither are extended attributes (the draft's
  `xattr`).

## 4. Default directories

The first use of an account's store creates one top-level directory **Trash** with the role `trash`; a drive has
none – what is destroyed there is gone, as on a network drive. A directory with a role cannot be
renamed, moved or destroyed (draft, section 5). What goes into the trash is the clients' choice: kernoid's apps move
files there, and destroying a node is final. **OPEN:** emptying the trash after a time per tenant, as for mail
(RFC 0002, 13.2); default names in the tenant's language; further roles (`documents`, `pictures`, …).

## 5. Content and garbage

A file's content is stored **in parts** of 8 MiB in object storage (`kernoid_store::parts`): a stream is cut into
parts as it arrives, each part sealed with the tenant's key on its own (RFC 0001, 6), bound to its own path
`<prefix>/<n>` – so no part can stand in for another – and written; only one part is in memory at a time. PostgreSQL
keeps each content in `file_contents`: its prefix, the number of parts, the size, the SHA-256 of the whole and the
media type. A part missing or cut off fails to open.

- **Uploads** (JMAP, WebDAV, direct writes) stream the same way, uploads below `upload/<account>/<id>`. A file that
  takes an upload takes its parts as they are – no copy –, and a file that takes another file's content shares its
  parts (`FileNode/set` with its `blobId`, WebDAV's COPY). Several contents may thus name one prefix; its parts go
  with the last of them. Content that is an email or one of its parts is copied in.
- **Garbage** follows mail (RFC 0002, 7): each part is named in `blob_garbage` before it is written – an upload's
  due when the upload expires, a file's within an hour –; the transaction that gives the content to a file takes
  the names back; a content that goes hands parts no other content names to the garbage at once.
- **Size:** at most `files.max_file_size` bytes (default 10 GiB). Reading takes ranges (`Range`), part by part.
- **OPEN:** uploads that resume after a broken connection (a single request carries a file today; JMAP's blob
  extension, [RFC 9404](https://www.rfc-editor.org/rfc/rfc9404), could join uploaded pieces).

## 6. Versions

A file that gets new content keeps the content it had as a **version**: the row in `file_contents` stays, with the
file's modification time of then. The newest `files.versions_kept` (default 10) are kept, the older go. Versions count
towards the quota. Restoring a version makes it the file's content again and the content it had a version.
**OPEN:** keeping versions by time per tenant; versions of what was destroyed.

## 7. Changes and states

Every change takes the store's next `modseq` and writes one row per changed node to `file_changes`:
`(account, modseq, node, created/updated/destroyed)`. `FileNode/changes` reads it like mail's journal (RFC 0002, 6),
and rows age out with it (`mail.changes_kept_days`); a state older than the floor gets `cannotCalculateChanges`.

### 7.1 Limits of a change

Destroying a directory with all it holds (`onDestroyRemoveChildren`) destroys at most 10 000 nodes at once; a larger
subtree is refused (the draft's section 10.3 asks for such a limit), and the client destroys it in parts.

## 8. Access: JMAP

The capability `urn:ietf:params:jmap:filenode` is in the session for every store the caller reaches – its own, those
shared with it (`isPersonal` false), the tenant's drives it has rights on (`kernoid:drive` true) – with
`maxFileNodeDepth` 64, `maxSizeFileNodeName` 255, `forbiddenNameChars` as in section 3, `supportedNodeTypes`
`Directory` and `File`, `caseInsensitiveNames` false, `mayCreateTopLevelFileNode` as the rights say (section 11), and
no web URLs yet.

JMAP itself is no longer only for mail: an account with `files` and without `mail` logs in to JMAP and sees only
files; mail, calendar and contact methods answer `accountNotSupportedByMethod`, and no mail store is made for it.
Logging in is as for mail programs (RFC 0002, 11): a kernoid session, or HTTP Basic with a login name and an app
password – or the password, if the account needs no second factor. Over HTTP the request names the instance, so the
login name is found as at the login page: an address, or a username or verified contact address where the tenant
allows them (RFC 0003, 2) – accounts without a native address log in too. **OPEN:** OAuth for programs. Uploads (RFC 8620,
6.1) go to an account whose files the caller may add to or write, and may be as large as the larger of
`mail.max_message_size` and `files.max_file_size`.

- **Methods:** `FileNode/get` (with `fetchParents`), `/changes`, `/set` (with `onDestroyRemoveChildren`, `onExists`
  `replace` and `rename`, `compareCaseInsensitively`, and `shareWith`), `/query` (with `depth`), `/queryChanges`
  (answers `cannotCalculateChanges`); JMAP Sharing's `Principal/get` and `Principal/query`
  ([RFC 9670](https://www.rfc-editor.org/rfc/rfc9670); `urn:ietf:params:jmap:principals`): the people and groups of
  the caller's tenant, so that a program finds whom to share with.
- **Rights and what shows** follow the draft's section 5: `myRights` on directories, nodes the user can discover but
  not read with their other properties null, `FileNode/changes` reporting as destroyed what the user no longer sees,
  and a change of sharing as a change of everything it covers.
- **Queries** support the filters `isTopLevel`, `parentId`, `ancestorId`, `descendantId`, `nodeType`, `role`,
  `hasAnyRole`, `blobId`, `isExecutable`, `created…`, `modified…`, `accessed…`, `minSize`, `maxSize`, `name`,
  `nameMatch`, `mediaType`, `mediaTypeMatch` and `text` (on name and media type), and sorting by `name`, `size`,
  `mediaType`, `created`, `modified`, `nodeType` and `tree`. **OPEN:** `body` – searching inside files (it needs
  text extraction).
- **Blobs:** a file's content – current or a version – has the blob id `f-<content id>`; it is downloaded like any
  blob (RFC 8620, 6.2), also in ranges (`Range`, 206). A `FileNode/set` may name any blob the caller may read there –
  an upload, another file, an email or one of its parts (section 5).
- **Versions** (section 6) are kernoid's own extension, `https://kernoid.dev/jmap/file-versions`: `FileVersion/get`
  with a `nodeId` lists a file's contents (`id`, `blobId`, `size`, `mediaType`, `modified`, `created`,
  `isCurrent`), newest first; `FileNode/set` giving a file the `blobId` of one of its versions restores it.
- **Direct writes** (draft, section 4): `PUT /jmap/files/<account>/<node>` streams a file's new content, with the
  media type from `Content-Type`; it answers `blobId`, `size`, `mediaType` and `digest:sha-256`. **OPEN:** `PATCH`
  (needs the blob extension's patch formats); checking `Repr-Digest`.
- **Sets** are done in the order destroy, create, update, each node in its own transaction, so that a client can
  destroy a node and create one of the same name in one call, as the draft requires. **OPEN:** two nodes swapping
  their names in one `FileNode/set` is refused (`alreadyExists`).
- **OPEN:** `FileNode/copy` between accounts; `isSubscribed` of others than the owner (it is accepted, not kept);
  `accessed` is set only by clients; locks (section 9) are WebDAV's only.

## 9. Access: WebDAV

For the file managers of operating systems and other programs that speak WebDAV
([RFC 4918](https://www.rfc-editor.org/rfc/rfc4918), classes 1 and 2), at `/webdav/` of every instance host – what
the draft means to replace, but what many programs speak today. Logging in is as for JMAP (section 8).

- `/webdav/` lists the stores the caller reaches as collections: its own by its login name, others by their names
  (an owner's address, a drive's name). Below a store, paths are the nodes' names.
- **Methods:** `OPTIONS`, `PROPFIND` (depth 0 and 1; `infinity` answers like 1), `GET` and `HEAD` (with ranges),
  `PUT` (streaming; an existing file gets new content, the old becomes a version), `DELETE`, `MKCOL`, `COPY`, `MOVE`
  (within a store; between stores **OPEN**), `PROPPATCH` (accepted, not kept – Windows sets times and attributes),
  `LOCK` and `UNLOCK`.
- **Properties:** `displayname`, `resourcetype`, `getcontentlength`, `getcontenttype`, `getetag` (the content id;
  for a directory its last change), `getlastmodified`, `creationdate`, `supportedlock`, `lockdiscovery`, and for a
  store `quota-used-bytes` and `quota-available-bytes` ([RFC 4331](https://www.rfc-editor.org/rfc/rfc4331)).
- **Locks** (`file_locks`): write locks, exclusive or shared, on a node or a directory with all below it, for at most
  an hour unless refreshed. A change to what a lock holds needs its token in the `If` header (423 otherwise). A lock
  on a free name makes an empty file there. Only WebDAV honours locks.
- The XML is Stalwart's dav-proto, as for CalDAV (RFC 0004, 8.1); media types of files sent without one are
  guessed from the name.

## 10. The web app

The web app (`web/app`) has a view **Files**: the stores the user reaches on the side (their own, drives, what others
share), browsing, uploading with progress (a file of the same name gets new content and the old becomes a version),
downloading, new folders, renaming, the trash, sharing folders with people and groups (at three levels: view; edit;
edit and share) and a file's versions with restoring. It speaks only JMAP, like the rest of the app, and shows only
what the rights allow.

## 11. Sharing

### 11.1 Rights

The draft's rights (section 5): `mayRead`, `mayAddChildren`, `mayRename`, `mayDelete`, `mayModifyContent`,
`mayShare` – stored as letters `r`, `a`, `n`, `d`, `w`, `s`. A **grant** gives an account or a group of the tenant
rights on one directory and all below it, or on a whole store. A user's rights on a node are the union of the grants
to them and their groups on the store, the node and its ancestors – inherited rights are a floor. The owner has all;
a drive has no owner. Files carry no grants of their own: they have their directory's rights.

- A node is **discoverable** if the user may read it, or if it or one below it is granted to them; discoverable
  nodes above what is granted show their name only (the way there).
- Creating at the top of a store needs `mayAddChildren` on the whole store (`mayCreateTopLevelFileNode`). Moving
  needs `mayRename` and `mayAddChildren` where it goes; destroying a directory with what it holds needs `mayDelete`
  and `mayRead` on it.

### 11.2 Who grants

Grants are administration: events on the owning account (`account.file_access_set`, `account.file_access_removed`),
projected into `file_access`, like mail's and calendars' (RFC 0002, 12.2; RFC 0004, 9).

- **Owners and those with `mayShare`** share directories through JMAP's `shareWith` (a map of principal ids to
  rights; `shareWith/<id>` changes one) – never more rights than they have.
- **Administrators** (`accounts.manage`) grant on any account's files of the tenant, directories or whole stores:
  REST `GET`/`PUT`/`DELETE /v1/accounts/{id}/files/access`, GraphQL `fileAccess`, `setFileAccess`,
  `removeFileAccess`, CLI `kernoid files access|grant|revoke`.
- **OPEN:** a change of a group's members changes what its members see without a journal entry; clients see it at
  their next full sync.

### 11.3 Links

A **link** opens one file, or one directory with all below it, for reading to anyone who has it – without an
account.

- **Who:** whoever has `mayShare` on the node – the owner, or those it was shared with on – makes and removes links,
  through kernoid's JMAP extension `https://kernoid.dev/jmap/file-links`: `FileLink/get` (all, those of a `nodeId`,
  or `ids`) and `FileLink/set` (create with `nodeId`, `expires` and `password`, each optional but the first; destroy).
  There is no update: a changed link is a new one. The session's capability names where links open
  (`urlTemplate`, `https://<instance>/app/link.html#{token}`).
- **Events:** making and removing a link are administration, `account.file_link_added` (link id, node, expiry,
  whether it has a password) and `account.file_link_removed` on the owning account, so they appear in its audit log.
  The **token** (256 random bits) is shown once, in the answer to `FileLink/set`; `file_links` keeps its SHA-256 and
  the password's Argon2id hash – written in the transaction of the event, never in it (RFC 0001, 8).
- **Opening:** `GET /v1/links/{token}` names what the link opens, `…/nodes` lists a directory within it, and
  `…/download/{node}` sends a file (ranges, and the sandbox of every download). Everything outside the linked node is
  unknown. A link with a password answers 401 until `POST /v1/links/{token}/unlock` with the password, whose access
  token (12 hours, `file_link_access`) the other requests carry as `access`. Anonymous callers cause no events: wrong
  passwords are counted per link (`file_link_failures`; ten in 15 minutes close the link for the rest of them).
- A link ends when it expires, is removed, or its node is destroyed; it does not work while the owner or the tenant is
  deactivated.
- The web app opens links on its page `link.html`: the token stays in the URL's fragment, which browsers do not send
  to the server or in `Referer`.
- **OPEN:** links that let people add files ("file drop"); links that reveal their token again later (they would
  need it sealed instead of hashed); limits on downloads per link.

## 12. Drives

A **drive** is a file store that belongs to the tenant, not to a person – for what a team or an organisation keeps
together, such as the files of a company's partners, none of whom owns them (as SharePoint's document libraries).

- A drive is an account of the kind `drive` (`account.drive_added`): a name, the service `files` always, no address,
  no login of any kind, no mailbox, no trash. Its files count against its own quota (section 13).
- People reach it only through grants (section 11) – usually on the whole store, e.g. `randws` for every member.
- Administrators create drives (`accounts.manage`): REST `GET`/`POST /v1/drives`, GraphQL `drives` and `addDrive`,
  CLI `kernoid files drives|add-drive`; they rename, deactivate and set quotas as for any account.
- **OPEN:** removing a drive with its files (RFC 0003, 7); drives that tenant members create themselves.

## 13. Quotas

- An account's file quota is administration: `account.files_quota_set` (bytes, or none for the tenant's default),
  kept in `accounts.files_quota`; a tenant's default `tenant.default_files_quota_set`
  (`tenants.default_files_quota`). Without either there is no limit.
- It is separate from the mail quota (RFC 0002, 8): the services are granted separately (RFC 0003, 4), and a
  mailbox that fills up should not stop work on files, nor the other way round. **OPEN:** one quota over both, if
  operators ask for it.
- What counts is the size of the files' contents, versions included. A change that would go over the quota is refused
  (JMAP `overQuota`, WebDAV 507). Content added to a shared store or a drive counts against its owner's quota.
- **Administration API and CLI:** an account's use and quota, setting it, and the tenant's default – with
  `accounts.manage` (quota of one account) and `tenant.manage` (default), as for mail (RFC 0002, 12.3).
  `kernoid account files-quota` and `kernoid tenant files-quota` for operators.
- **OPEN:** JMAP Quotas ([RFC 9425](https://www.rfc-editor.org/rfc/rfc9425)) with `FileNode` in `types`.

## 14. Open

- Removing an account's files with the account (RFC 0003, 7).
- Import and export of a whole file store (e.g. as a ZIP or tar archive, the draft's section 7).
- End-to-end encryption of files – after 1.0 (whitepaper).
- Office documents in the browser (WOPI) – a module of 1.0.
