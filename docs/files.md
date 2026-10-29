---
title: Files
nav_order: 5.85
permalink: /files/
---

# Files

Every account with the service `files` has a file store of its own: directories and files, with a **Trash** from the
first use. An account does not need a mailbox for it. Folders are shared with people and groups of the tenant, and
**drives** hold files that belong to the tenant rather than to a person. Programs reach files over JMAP and WebDAV;
the [web app]({{ '/app/' | relative_url }}) has them too. The design is
[RFC 0005](https://github.com/kernoid/kernoid/blob/main/rfcs/0005-files.md).

## Turning files on

The service `files` is off unless an administrator grants it (`kernoid account grant-service <ACCOUNT> files`, or
`PUT /v1/accounts/{id}/services/files`), or the tenant's rules give it to new accounts (`kernoid tenant
service-policy`). See [Accounts and logins]({{ '/login/#accounts-and-logins' | relative_url }}). Someone without the
service still reaches what is shared with them and the drives they have rights on.

## Drives

A drive is a file store of the tenant – for what a team or an organisation keeps together, as SharePoint's document
libraries: nobody owns it, members have rights on it. A drive has a name, no address and no login; its files count
against its own quota.

```sh
kernoid files add-drive <TENANT> --name "Partners"         # prints the drive's id
kernoid files grant <DRIVE> partner1@example.org randws    # every right on the whole drive
kernoid files grant <DRIVE> partner2@example.org randws
kernoid files grant <DRIVE> '$Staff' r --node <DIRECTORY>  # a group may read one folder
kernoid files access <DRIVE>
```

The same through the administration API: `POST /v1/drives`, `GET /v1/drives`, and
`PUT /v1/accounts/{drive}/files/access` with `grantee_kind`, `grantee_id`, `rights` and, for one folder, `node`
(`accounts.manage`).

## Sharing

Rights are letters: `r` read, `a` add, `n` rename and move, `d` delete, `w` change content, `s` share on. A grant is on
a folder and all below it, or – leaving out the folder – on a whole store; it goes to an account or a group of the
tenant. Rights add up down the tree: what is granted on a folder holds for everything in it.

- **Owners share their own folders** in the web app (Share: view; edit; edit and share) or with JMAP's `shareWith`.
  Whoever has the right to share may share on, never more than they have.
- **Administrators** grant on any account's files and on drives: `kernoid files grant|revoke|access`,
  `GET`/`PUT`/`DELETE /v1/accounts/{id}/files/access`, GraphQL `fileAccess`, `setFileAccess`, `removeFileAccess`.
- What is shared with someone appears in their session as another account (JMAP), in `/webdav/` as another folder,
  and in the web app on the side.

## Links

A **link** opens a file, or a folder with all below it, to anyone who has it – to view and download, without an
account. Whoever may share something may make links to it: in the web app (Link), or with kernoid's JMAP extension
`https://kernoid.dev/jmap/file-links` (`FileLink/get`, `FileLink/set` with `nodeId`, `expires` and `password`).

- A link may expire and may have a **password**. The address is shown once, when the link is made – kernoid keeps
  only a hash of it –, and goes to `https://<instance domain>/app/link.html#<token>` (the session's
  `urlTemplate`); the token is in the part of the address browsers do not send.
- The page asks `GET /v1/links/<token>`, `…/nodes` and `…/download/<node>`; a password is given at
  `POST /v1/links/<token>/unlock`, whose access token opens the link for twelve hours. Ten wrong passwords in a quarter
  of an hour close the link for the rest of it.
- Removing the link, or the file or folder, ends it at once; so does deactivating the owner or the tenant.
- Every link is in the audit log of its owner (`account.file_link_added`, `account.file_link_removed`).

## Versions

A file that gets new content keeps what it had as a version – the newest `files.versions_kept` (10 unless
configured). The web app lists them (Versions) for downloading and restoring; JMAP programs use kernoid's extension
`https://kernoid.dev/jmap/file-versions` (`FileVersion/get`) and restore by giving the file a version's `blobId`.
Versions count towards the quota.

## JMAP

Programs reach files through JMAP with the IETF draft
[JMAP File Storage](https://datatracker.ietf.org/doc/draft-ietf-jmap-filenode/) (`urn:ietf:params:jmap:filenode`),
revision 19 – a draft, which may still change – and JMAP Sharing's principals
([RFC 9670](https://www.rfc-editor.org/rfc/rfc9670)) to find people and groups.

- `FileNode/get` (with `fetchParents`), `FileNode/changes`, `FileNode/set` (with `onExists` `replace` or `rename`,
  `onDestroyRemoveChildren`, `compareCaseInsensitively`, `shareWith`) and `FileNode/query`; `Principal/get` and
  `Principal/query`.
- Content is uploaded as a blob (`/jmap/upload/<account>/`, streamed) and given to a file with its `blobId`; any blob
  the account may read will do – an attachment of an email, too. Downloads take ranges.
- `PUT /jmap/files/<account>/<node>` replaces a file's content directly; the `Content-Type` becomes its type.
- Names: up to 255 bytes, none of `/ < > : " \ | ? *` or control characters, not `.` or `..`; unique in their folder.
  At most 64 levels.

Logging in: the web app's login (a session), or HTTP Basic with the account's address and an app password – or its
password if it needs no second factor.

## WebDAV

File managers connect to `https://<instance host>/webdav/` with the account's login name – its address, or its
username or contact address where the tenant allows them – and an app password (or its password without a second
factor):

| Program | What to do |
|---|---|
| macOS Finder | Go → Connect to Server, `https://login.example.org/webdav/` |
| Windows Explorer | Map network drive, `https://login.example.org/webdav/` |
| GNOME Files, Dolphin | `davs://login.example.org/webdav/` |

The web app shows these settings, per system, under "Connect a file manager" in Files and on the account page.

`/webdav/` holds one folder per store: the account's own (by its address), each drive (by its name) and what others
share. Downloads – over JMAP and WebDAV, mail attachments too – carry `X-Content-Type-Options: nosniff` and a
sandboxing Content-Security-Policy, so an HTML or SVG file opened in the browser cannot run scripts on the instance's
origin (PDFs only may be framed by the web app, for its viewer). Uploads and downloads stream, locks keep two programs
from writing the same file, and a file written again keeps its earlier content as a version.

## Limits and quota

- **Size:** a file takes at most `files.max_file_size` bytes (10 GiB unless configured); content is stored in parts
  of 8 MiB and never held in memory as a whole.
- **Quota:** files have a quota of their own, apart from mail: `kernoid account files-quota <ACCOUNT> <BYTES>`
  (`none` for the tenant's default) and `kernoid tenant files-quota <TENANT> <BYTES>` (`none` for no limit), or
  `PUT /v1/accounts/{id}/files/quota` and `PUT /v1/tenant/files-quota`. `GET /v1/accounts/{id}/files` shows what an
  account or a drive uses. Versions count; what someone adds to a shared folder counts against the folder's owner.
- **Content** is encrypted with the tenant's key before it goes to object storage.

{: .note }
OPEN: links that let people add files, uploads that resume after a broken connection, searching inside files, symbolic links, moving
between stores over WebDAV, emptying the trash after a time.
