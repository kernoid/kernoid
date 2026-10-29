---
title: Mail
nav_order: 5.7
permalink: /mail/
---

# Mail

Every account has a mail store: mailboxes, emails and threads. kernoid receives mail for its tenants' domains as
their MX, sends their mail, and serves it to mail programs over JMAP, IMAP and POP3. The design is
[RFC 0002](https://github.com/kernoid/kernoid/blob/main/rfcs/0002-mail-data-model.md).

## Receiving mail

1. Configure `[smtp]` with `hostname` – the name the MX records will point to – and run a process with the role `smtp`
   (part of `all`). It listens on `smtp.listen`, port 25 by default.
2. Give kernoid certificates (`mail.tls`, `http.tls` or `http.acme`): they then serve `STARTTLS`. Without them, mail
   arrives unencrypted, and kernoid says so in its log.
3. For each verified domain of a tenant, publish an MX record pointing to that host name:

   ```
   firma.example.  3600  IN  MX  10 mail.example.org.
   ```

kernoid accepts mail only for addresses it knows and refuses the rest at `RCPT TO`, so that nobody gets a bounce
later; it relays nothing. A message is stored for every recipient before kernoid answers – there is no queue for
incoming mail.

| Address | Delivered to |
|---|---|
| an account's address or alias | the account |
| the same with a subaddress, `alice+news@…` | the account |
| a group's address | every active member of the group, each once |

Groups get addresses with `PUT /v1/groups/{id}/addresses/{address}` (needs `groups.manage`); an address belongs to one
account or one group in the whole installation. With `PUT /v1/groups/{id}/send-as` (`{"enabled": true}`, or the switch
under Administration → Groups) the members may also **send as the group**: its addresses appear among their identities
in JMAP and submission accepts them – mail programs set them as the sender themselves.

The client's address must reach kernoid unchanged – every check depends on it. Behind a TCP load balancer that hides
it, kernoid cannot check SPF or iprev (the PROXY protocol is not supported yet).

## Checks and spam

kernoid checks iprev, SPF (for `HELO` and `MAIL FROM`), DKIM, ARC and DMARC, and writes the results into an
`Authentication-Results` header. `Authentication-Results` headers that claim kernoid's host name are removed from
incoming mail first.

- A message failing DMARC from a domain with `p=reject` is refused; with `p=quarantine` it goes to Junk.
- A basic filter adds up a score and files mail at `smtp.junk_score` (5) or above in Junk. Every test that counted is
  named in the `X-Spam-Status` header:

| Test | Score |
|---|---|
| `SPF_FAIL` / `SPF_SOFTFAIL` | 3 / 1.5 |
| `SPF_HELO_FAIL` (bounces, which have no sender to check) | 2 |
| `DKIM_FAIL` (a signature fails and none passes) | 1 |
| `DMARC_FAIL` (policy `none`) | 2 |
| `IPREV_FAIL` | 1 |
| `MISSING_MESSAGE_ID`, `MISSING_DATE` | 1 each |
| `MISSING_FROM` | 2 |
| `FROM_LOCAL_UNAUTHENTICATED`: the sender claims a domain kernoid serves, and neither DMARC nor an aligned DKIM signature or SPF result backs it | 5 |

A message whose `Message-ID` the account received in the last seven days is skipped as a duplicate. That also makes
it safe for the sending server to retry: when a recipient cannot be stored for now (quota, a database error), kernoid
answers `451`/`452` for the whole message.

## Sieve

An account's active [Sieve](https://www.rfc-editor.org/rfc/rfc5228) script decides where its mail goes. kernoid
carries out `keep`, `fileinto` (also `:create`, with `/` between the names of nested mailboxes), `discard` and flags;
`redirect` and `vacation` go out through the queue – a redirect with the account as the envelope sender, a vacation
reply at most once per sender within its `:days`. `reject` and `notify` are skipped, and the message is kept.

```sh
kernoid mail sieve put <ACCOUNT> lists lists.sieve --activate
```

```sieve
require ["fileinto", "mailbox"];
if header :contains "List-ID" "dev.lists.example" {
    fileinto :create "Lists/dev";
}
```

Users will manage their scripts themselves with ManageSieve and JMAP; for now it is the CLI.

## Quotas

`kernoid account mail-quota <ACCOUNT> <BYTES>` limits how much an account's mail takes; `none` hands it back to the
tenant's default, which `kernoid tenant mail-quota <TENANT> <BYTES>` sets (`none` there for no limit). Mail for an
account at its limit is answered with `452`, so the sending server tries again later. The administration API does
the same (`PUT /v1/accounts/{id}/mail/quota`, `PUT /v1/tenant/mail-quota`).

## Sending mail

Mail programs send through **submission**: port 587 with `STARTTLS`, or port 465 with TLS from the start
(`smtp.submission_listen`, `smtp.submissions_listen`). kernoid offers it only when it has certificates, and lets
programs log in only over TLS (`AUTH PLAIN` or `LOGIN`).

- **App passwords:** a mail program logs in with the account's address and an app password – made in the account
  settings (`POST /v1/account/app-passwords`) or by the operator (`kernoid account app-password add`), shown once.
  The account's own password works too, but only for accounts that need no second factor. Resetting an account's
  second factors removes its app passwords.
- An account sends as its own addresses only: `MAIL FROM` and `From` must be one of them.
- Local recipients get the message at once. Everything else waits in the **queue** in PostgreSQL: a worker delivers
  it to the MX hosts of each domain, tries again after 2, 5, 15 and 30 minutes, then hourly, then every four hours,
  for `smtp.queue_days` (5), and then sends the sender a bounce. `kernoid mail queue` shows what waits.
- **DKIM:** every verified domain gets an RSA key (selector `kernoid1`), and mail is signed with the key of its
  `From` domain as it leaves the queue.
- **TLS on the way out:** kernoid uses `STARTTLS` whenever the other server offers it. A domain with signed TLSA
  records (DANE) or an MTA-STS policy in `enforce` mode gets its mail only over TLS with a certificate that matches.
- **A relay:** where port 25 cannot go out, `[smtp.relay]` hands all mail for other servers to a relay, over TLS
  and with a login.

## DNS records

`kernoid tenant mail-dns <TENANT>` (or `GET /v1/tenant/mail-dns`) lists, for each verified domain, what to publish
and whether it is published:

| Record | Where | What |
|---|---|---|
| MX | the domain | `smtp.hostname` |
| SPF | TXT on the domain | `v=spf1 mx -all`, or `smtp.spf` (for a relay, its SPF include) |
| DKIM | TXT at `kernoid1._domainkey.<domain>` | the key kernoid made, `v=DKIM1; k=rsa; p=…` |
| DMARC | TXT at `_dmarc.<domain>` | any policy; kernoid suggests `v=DMARC1; p=quarantine` |

## JMAP

Mail programs and web apps reach an account's mail over [JMAP](https://jmap.io) (RFC 8620, RFC 8621) at
`https://<instance host>/.well-known/jmap`. They log in with HTTP Basic – the address and an app password, or the
password of an account without a second factor – or with a kernoid session.

- Mailboxes, emails (read, written, imported, parsed, queried), threads, identities (the account's addresses) and
  sending (`EmailSubmission`, through the queue with the same checks as submission).
- Blobs: an email's raw message and each of its parts can be downloaded; uploads are kept a day.
- **Push:** `/jmap/eventsource` sends a `StateChange` as soon as the account's mail changes.
- Searching message text (`body`, `text`) uses the full-text index; search snippets mark the words found.
- Not yet: the `header` filter, `VacationResponse` (use Sieve), WebSocket and push subscriptions.

## IMAP and POP3

Configure `[imap]` and give kernoid certificates (`mail.tls`, `http.tls` or `http.acme`); a process with the role `imap` (part of
`all`) then listens for IMAP on port 143 (`STARTTLS`) and 993 (TLS). POP3 is off unless `imap.pop3_listen` (110) or
`imap.pop3_tls_listen` (995) is set. Clients log in with the address and an app password – or the password of an
account without a second factor – and only over TLS.

- **IMAP4rev2 and IMAP4rev1** with `IDLE`, `MOVE`, `UIDPLUS`, `CONDSTORE`/`QRESYNC`, `SPECIAL-USE`, `LIST-STATUS`,
  `ESEARCH` and more; the folders are the account's mailboxes, separated by `/`, and the inbox is `INBOX`.
- Flags are the JMAP keywords, so a message read or flagged in one program is read or flagged in all. `\Deleted`
  takes effect with `EXPUNGE`.
- **POP3** sees the inbox only; deleted messages leave it when the client quits.
- Not yet: `SORT`, `THREAD`, quotas over IMAP, renaming `INBOX`.

Mail programs that support Mozilla's autoconfiguration (Thunderbird and others) find these settings by themselves at
`https://<domain>/.well-known/autoconfig/mail/config-v1.1.xml` – served by kernoid at the instance's host, and at
`/mail/config-v1.1.xml` for an `autoconfig.<domain>` name pointed at it. It names `smtp.hostname` and the usual ports
(993 and 143, 465 and 587): kernoid cannot know which ports a container setup publishes.

## Shared mailboxes and access

A **shared mailbox** – `info@`, `support@` – is an account nobody logs in as: it receives mail, has a quota and Sieve
scripts, and people use it through access granted to them.

```sh
kernoid account add-shared <TENANT> info@firma.example --name "Info"
kernoid mail grant <SHARED MAILBOX> '$Support' --rights lrswite --send-as   # every member of the group Support
kernoid mail grant <ACCOUNT> bob@firma.example --rights lr --mailbox inbox  # one mailbox, read only
kernoid mail access <ACCOUNT>
```

- **Rights** are IMAP's (RFC 4314): `l` see the mailbox, `r` read, `s` keep read/unread, `w` other flags, `i` add
  messages, `k` create mailboxes, `x` delete or rename, `t` delete messages, `e` expunge, `a` change the access.
  `lrs` reads, `lrswite` works in a mailbox. A grant is for the whole store or for one mailbox; **send as** (whole
  store only) lets the grantee send from the owner's addresses.
- A grant to a **group** holds for its members while they are members.
- **Mail programs** see shared mail at once: IMAP in `Shared/<address>/…` (with `ACL`: `MYRIGHTS`, `GETACL`,
  `SETACL`), JMAP as further accounts in the session. Submission accepts the owner's addresses with send as.
- **People share their own mail** with colleagues: IMAP `SETACL` on their own mailboxes, or the API
  (`PUT /v1/account/mail/access`). Only administrators grant send as and access to shared mailboxes.
- Not yet: per-user subscriptions to shared folders, JMAP Sharing (RFC 9670).

## Search

Message text is found through PostgreSQL's full-text search: each email's text parts and attachment names are
indexed when it arrives. A search matches whole words and word beginnings – `brau` finds *Brauhaus* – and every
word of the query must occur; it is the same for every language (no stemming). Subject and addresses are searched
in what PostgreSQL keeps of each email. Emails stored before the index came get theirs from the worker, in
rounds of up to five minutes every ten minutes.

## Retention

A tenant can have Trash and Junk emptied automatically:

```sh
kernoid tenant mail-retention <TENANT> --trash-days 30 --junk-days 14   # `none` keeps them
```

The days count from when an email entered the folder; the worker removes what is older every ten minutes. The API
has `PUT /v1/tenant/mail-retention` (`tenant.manage`).

## Import and export

Mailboxes move as **mbox** files, with read, flagged and answered states and other keywords (in the `Status`,
`X-Status` and `X-Keywords` headers mail programs know):

```sh
kernoid mail export <ACCOUNT> ./alice              # every mailbox, one .mbox file each
kernoid mail import-mbox <ACCOUNT> Archive.mbox --mailbox archive
```

The API does the same per mailbox: `GET` and `POST /v1/accounts/{id}/mail/mailboxes/{mailbox}/mbox` (by id or
role; imports up to 2 MiB – larger files with the CLI). Moving whole accounts from another provider comes with the
migration module.

