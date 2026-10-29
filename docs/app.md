---
title: Web app
nav_order: 5.9
permalink: /app/
---

# Web app

kernoid brings its own web app for mail, calendar, contacts and files, served at `https://<instance domain>/app/` – the
instance's address itself (`/`) leads there. It uses the instance's login: whoever is logged in at `/login` is logged
in here, and someone who is not is sent to the login and back (`/login/account?next=/app/`).

| Part | What it does |
|---|---|
| Mail | mailboxes, the emails of each with search, reading – HTML emails as cleaned rich text, or in their original layout in a sandbox; either way without scripts, forms or remote images (no tracking) –, writing with attachments, replying, forwarding, flagging, moving, deleting, downloading attachments; new mail appears without reloading – and, if switched on in the account, as a notification of the browser while the app is open in the background |
| Calendar | the account's calendars and those shared with it, a month, a week or a day at a time; events with time or all day, repeating, a place, a video meeting, a description and participants – who are invited by email, and whose answers show; one event of a series changed or deleted on its own, or the whole series; invitations are answered here |
| Contacts | the address books' contacts with search; name, email, phone, organization and a note |
| Files | the account's own files, the tenant's drives and what others share, on the side; uploading with progress (also by dragging files onto the page – a file of the same name gets new content, the old one stays as a version), downloading, new folders, renaming, copying and moving to another store (own files, team folders, what others share), the trash, sharing folders with people and groups, links for people without an account (with expiry and password; the page they open shows, plays and downloads), a file's versions with restoring; images, audio, video, PDFs and text shown in place (other files are downloaded); how to connect a file manager over WebDAV; an account with files and no mail sees only this |
| Administration | for administrators only, as their permissions allow (kernoid checks them on every request): the tenant's settings (name, second factor, logins, registration, services, quotas, retention), domains with the DNS records mail needs, accounts (people, external accounts, shared mailboxes – with addresses, logins, password, second factors, services, quotas, access to mail and files, Sieve filters, sessions, applications, linked providers), groups, team folders and who may use them, roles, projects and applications, identity providers, SCIM tokens; for instance administrators also the instance, its tenants (and working on any of them), instance roles, signing keys and the mail queue. Creating instances, the main key and ACME stay with the operator's [CLI]({{ '/cli/' | relative_url }}) |
| Account | name, appearance (light, dark or as the system – also for the login), the vacation response, notifications of new mail, password, second factors, recovery codes, app passwords and the settings for mail programs, calendars and file managers, applications, sessions (see [Login]({{ '/login/' | relative_url }})) |

The app talks to kernoid only through JMAP ([Mail]({{ '/mail/' | relative_url }}),
[Calendars and contacts]({{ '/calendars/' | relative_url }}), [Files]({{ '/files/' | relative_url }})), in German or English as the browser prefers. It is
free software under the MIT licence (`web/app`), built with [Solid](https://www.solidjs.com) and TypeScript, and can be
installed as an app from the browser.

{: .note }
OPEN: notifications while the app is closed (Web Push), previews of office documents (an
office suite is planned as a module); in the administration import and export.
