<!-- SPDX-License-Identifier: MIT -->
# kernoid-mime

Internet mail for [kernoid](https://kernoid.dev) – its own library, written from the RFCs, the one the server stores,
searches and answers IMAP and JMAP with, and the apps read decrypted messages with:

- **Messages** (`message`; RFC 5322, RFC 2045–2049): every part with the byte ranges of its header and body in the raw
  message, so that IMAP sections and JMAP blobs are exactly what was received; nested messages (`message/rfc822`,
  `message/global`, the parts of a digest). Real mail is read as far as it goes: multiparts without their closing
  delimiter, bare line feeds, junk lines in a header, 8-bit header fields, nesting cut at `MAX_DEPTH`.
- **Header fields** (`header`, `address`, `date`, `words`): unstructured text with encoded words (RFC 2047, adjacent
  words joined, characters split across words put back together), addresses and groups (RFC 5322, 3.4, obsolete forms,
  UTF-8 of RFC 6532), dates in every form mail programs write, message ids, URLs, lists.
- **MIME** (`params`, `transfer`, `charset`): content types and dispositions with RFC 2231's continuations and
  charsets, base64 and quoted-printable read leniently, the charsets of the WHATWG Encoding Standard (ISO-8859-x,
  Windows-125x, KOI8, Shift_JIS, ISO-2022-JP, EUC-JP, GB18030, Big5, EUC-KR …) and UTF-7; text that is valid UTF-8 is
  read as UTF-8 whatever its label says.
- **Reading** (`body`, `subject`): text, HTML and attachment parts as RFC 8621, 4.1.4 chooses them, HTML as text,
  previews, base subjects (RFC 5256, with reply and forward markers of other languages).
- **Writing** (`build`): header fields folded at 78 characters, encoded words and RFC 2231 where text is not ASCII,
  multiparts (`alternative`, `related`, `mixed`, any other), attachments and inline parts, bodies in 7bit,
  quoted-printable or base64 as their content needs, `Date` and `Message-ID` where they are missing.

```rust
let message = kernoid_mime::Message::parse(raw).ok_or("not a message")?;
let root = message.root();
let subject = root.subject();
for part in root.attachments() {
    println!("{:?} {} bytes at {}", part.attachment_name(), part.decoded_len(), part.offset_body());
}
let reply = kernoid_mime::MessageBuilder::new()
    .from(("Alice", "alice@example.org"))
    .to(["bob@example.org"])
    .subject("Re: Hello")
    .text_body("Hi Bob")
    .write();
```

Part numbers – the order `MessageRef::parts` gives: the top part, then every part in document order, a nested message
counted as one part – are part of what kernoid stores and answers (JMAP part blob ids); they do not change.

Its only dependency is [encoding_rs](https://crates.io/crates/encoding_rs). uuencode and `format=flowed` (RFC 3676) are
not decoded: no part of kernoid needs them so far (`OPEN`).

MIT – see [LICENSE](LICENSE).
