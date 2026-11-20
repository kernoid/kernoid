// SPDX-License-Identifier: MIT
//! Messages in the shapes the common mail programs write (written for these tests after the RFCs' rules and what
//! those programs are known to produce), random damage that must never panic, and the byte ranges of every part.

use kernoid_mime::{Kind, Message, MessageBuilder, PartRef, html_to_text};

/// Outlook: `multipart/mixed` around `multipart/related` around `multipart/alternative`, Windows-1252 in
/// quoted-printable, an attachment name as an encoded word inside quotes.
const OUTLOOK: &[u8] = b"Received: from EX01.corp.example (10.0.0.1) by EX02.corp.example\r\n\
\x20with Microsoft SMTP Server; Tue, 3 Nov 2026 09:12:44 +0100\r\n\
From: =?iso-8859-1?Q?M=FCller=2C_J=FCrgen?= <j.mueller@corp.example>\r\n\
To: \"Schmidt, Anna\" <a.schmidt@corp.example>\r\n\
Subject: AW: WG: =?iso-8859-1?Q?Angebot_f=FCr_M=E4rz?=\r\n\
Thread-Topic: =?iso-8859-1?Q?Angebot_f=FCr_M=E4rz?=\r\n\
Date: Tue, 3 Nov 2026 08:12:43 +0000\r\n\
Message-ID: <AM0PR01MB1234ABCD@AM0PR01MB1234.eurprd01.prod.outlook.com>\r\n\
References: <a1@corp.example>\r\n <AM0PR01MB0000@eurprd01.prod.outlook.com>\r\n\
In-Reply-To: <AM0PR01MB0000@eurprd01.prod.outlook.com>\r\n\
Content-Language: de-DE\r\n\
Content-Type: multipart/mixed;\r\n\
\tboundary=\"_004_AM0PR01MB1234_\"\r\n\
MIME-Version: 1.0\r\n\
\r\n\
--_004_AM0PR01MB1234_\r\n\
Content-Type: multipart/related;\r\n\
\tboundary=\"_003_AM0PR01MB1234_\";\r\n\
\ttype=\"multipart/alternative\"\r\n\
\r\n\
--_003_AM0PR01MB1234_\r\n\
Content-Type: multipart/alternative;\r\n\
\tboundary=\"_000_AM0PR01MB1234_\"\r\n\
\r\n\
--_000_AM0PR01MB1234_\r\n\
Content-Type: text/plain; charset=\"iso-8859-1\"\r\n\
Content-Transfer-Encoding: quoted-printable\r\n\
\r\n\
Hallo Anna,=0D=0A=0D=0Aanbei das Angebot f=FCr M=E4rz.=0D=0A=0D=0AGr=FC=DFe=\r\n\
\x20J=FCrgen\r\n\
\r\n\
--_000_AM0PR01MB1234_\r\n\
Content-Type: text/html; charset=\"iso-8859-1\"\r\n\
Content-Transfer-Encoding: quoted-printable\r\n\
\r\n\
<html><head><meta http-equiv=3D\"Content-Type\" content=3D\"text/html; charset=3D=\r\n\
iso-8859-1\"><style>p{margin:0}</style></head><body><p>Hallo Anna,</p><p>anbei=\r\n\
\x20das Angebot f=FCr M=E4rz.</p><img src=3D\"cid:image001.png@01DB0000.00000000\"=\r\n\
></body></html>\r\n\
\r\n\
--_000_AM0PR01MB1234_--\r\n\
\r\n\
--_003_AM0PR01MB1234_\r\n\
Content-Type: image/png; name=\"image001.png\"\r\n\
Content-Description: image001.png\r\n\
Content-Disposition: inline; filename=\"image001.png\"; size=8;\r\n\
\tcreation-date=\"Tue, 03 Nov 2026 08:12:43 GMT\"\r\n\
Content-ID: <image001.png@01DB0000.00000000>\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
iVBORw0KGgo=\r\n\
\r\n\
--_003_AM0PR01MB1234_--\r\n\
\r\n\
--_004_AM0PR01MB1234_\r\n\
Content-Type: application/pdf; name=\"=?iso-8859-1?Q?Angebot_M=E4rz.pdf?=\"\r\n\
Content-Description: =?iso-8859-1?Q?Angebot_M=E4rz.pdf?=\r\n\
Content-Disposition: attachment;\r\n\
\tfilename=\"=?iso-8859-1?Q?Angebot_M=E4rz.pdf?=\"; size=9\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
JVBERi0xLjQK\r\n\
\r\n\
--_004_AM0PR01MB1234_--\r\n";

/// Gmail: `multipart/alternative` with UTF-8 text in quoted-printable and HTML in base64, an attachment with
/// `X-Attachment-Id`.
const GMAIL: &[u8] = b"MIME-Version: 1.0\r\n\
Date: Wed, 4 Nov 2026 18:03:21 +0100\r\n\
Message-ID: <CAF=abc+def@mail.gmail.com>\r\n\
Subject: =?UTF-8?B?VHJlZmZlbiBhbSBNb250YWcg8J+Ygg==?=\r\n\
From: Bob Example <bob.example@gmail.com>\r\n\
To: alice@firma.example, carol@firma.example\r\n\
Cc: Team: dave@firma.example;\r\n\
Content-Type: multipart/mixed; boundary=\"0000000000001a2b3c05f1e2d3c4\"\r\n\
\r\n\
--0000000000001a2b3c05f1e2d3c4\r\n\
Content-Type: multipart/alternative; boundary=\"0000000000001a2b3a05f1e2d3c2\"\r\n\
\r\n\
--0000000000001a2b3a05f1e2d3c2\r\n\
Content-Type: text/plain; charset=\"UTF-8\"\r\n\
Content-Transfer-Encoding: quoted-printable\r\n\
\r\n\
Hi Alice,\r\n\
\r\n\
see you on Monday =F0=9F=98=82\r\n\
\r\n\
--0000000000001a2b3a05f1e2d3c2\r\n\
Content-Type: text/html; charset=\"UTF-8\"\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
PGRpdiBkaXI9Imx0ciI+SGkgQWxpY2UsPGRpdj48YnI+PC9kaXY+PGRpdj5zZWUgeW91IG9uIE1v\r\n\
bmRheSDwn5iCPC9kaXY+PC9kaXY+\r\n\
--0000000000001a2b3a05f1e2d3c2--\r\n\
--0000000000001a2b3c05f1e2d3c4\r\n\
Content-Type: text/csv; charset=\"US-ASCII\"; name=\"plan.csv\"\r\n\
Content-Disposition: attachment; filename=\"plan.csv\"\r\n\
Content-Transfer-Encoding: base64\r\n\
Content-ID: <f_lp1a2b3c0>\r\n\
X-Attachment-Id: f_lp1a2b3c0\r\n\
\r\n\
YSxiCjEsMgo=\r\n\
--0000000000001a2b3c05f1e2d3c4--\r\n";

/// Apple Mail: a boundary with `=`, 7bit US-ASCII text, an attachment named after RFC 2231, an inline image without
/// `Content-ID`.
const APPLE: &[u8] = b"Content-Type: multipart/mixed;\r\n\
\tboundary=\"Apple-Mail=_5B1C4E7A-1234-4C2D-9F00-ABCDEF012345\"\r\n\
Mime-Version: 1.0 (Mac OS X Mail 16.0 \\(3774.600.62\\))\r\n\
Subject: Fotos\r\n\
From: Carol <carol@icloud.example>\r\n\
Date: Thu, 5 Nov 2026 07:45:00 +0100\r\n\
Message-Id: <4F2E2B0C-9A00-4E6B-8D11-0123456789AB@icloud.example>\r\n\
To: Alice <alice@firma.example>\r\n\
\r\n\
\r\n\
--Apple-Mail=_5B1C4E7A-1234-4C2D-9F00-ABCDEF012345\r\n\
Content-Transfer-Encoding: 7bit\r\n\
Content-Type: text/plain;\r\n\
\tcharset=us-ascii\r\n\
\r\n\
Here they are.\r\n\
\r\n\
--Apple-Mail=_5B1C4E7A-1234-4C2D-9F00-ABCDEF012345\r\n\
Content-Disposition: inline;\r\n\
\tfilename*=utf-8''Stra%C3%9Fe.jpg\r\n\
Content-Type: image/jpeg;\r\n\
\tx-unix-mode=0644;\r\n\
\tname=\"=?utf-8?Q?Stra=C3=9Fe=2Ejpg?=\"\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
/9j/4AAQ\r\n\
--Apple-Mail=_5B1C4E7A-1234-4C2D-9F00-ABCDEF012345--\r\n";

/// Thunderbird: a preamble, `format=flowed`, a file name in RFC 2231 continuations, a forwarded message.
const THUNDERBIRD: &[u8] = b"Message-ID: <0a1b2c3d-4e5f@firma.example>\r\n\
Date: Fri, 6 Nov 2026 10:00:00 +0100\r\n\
MIME-Version: 1.0\r\n\
User-Agent: Mozilla Thunderbird\r\n\
Content-Language: en-US, de-DE\r\n\
To: bob@firma.example\r\n\
From: Dave <dave@firma.example>\r\n\
Subject: Fwd: Lunch\r\n\
Content-Type: multipart/mixed;\r\n\
\x20boundary=\"------------Xy12Ab34Cd56Ef78Gh90Ij12\"\r\n\
\r\n\
This is a multi-part message in MIME format.\r\n\
--------------Xy12Ab34Cd56Ef78Gh90Ij12\r\n\
Content-Type: text/plain; charset=UTF-8; format=flowed\r\n\
Content-Transfer-Encoding: 8bit\r\n\
\r\n\
F\xc3\xbcr dich. \r\n\
Bis dann.\r\n\
\r\n\
--------------Xy12Ab34Cd56Ef78Gh90Ij12\r\n\
Content-Type: application/vnd.oasis.opendocument.text;\r\n\
\x20name*0*=UTF-8''Ein%20sehr%20langer%20Dateiname%20f%C3%BCr%20den%20Test%20;\r\n\
\x20name*1*=%E2%80%93%20Teil%202.odt\r\n\
Content-Disposition: attachment;\r\n\
\x20filename*0*=UTF-8''Ein%20sehr%20langer%20Dateiname%20f%C3%BCr%20den%20Test%20;\r\n\
\x20filename*1*=%E2%80%93%20Teil%202.odt\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
UEsDBA==\r\n\
--------------Xy12Ab34Cd56Ef78Gh90Ij12\r\n\
Content-Type: message/rfc822; name=\"Lunch.eml\"\r\n\
Content-Disposition: attachment; filename=\"Lunch.eml\"\r\n\
\r\n\
From: Eve <eve@firma.example>\r\n\
Subject: Lunch\r\n\
Content-Type: text/plain; charset=ISO-2022-JP\r\n\
\r\n\
\x1b$B$3$s$K$A$O\x1b(B\r\n\
\r\n\
--------------Xy12Ab34Cd56Ef78Gh90Ij12--\r\n";

/// A bounce (RFC 3464) as mail servers send them.
const BOUNCE: &[u8] = b"From: Mail Delivery System <MAILER-DAEMON@mx.example>\r\n\
To: alice@firma.example\r\n\
Subject: Undelivered Mail Returned to Sender\r\n\
Auto-Submitted: auto-replied\r\n\
Content-Type: multipart/report; report-type=delivery-status;\r\n\
\tboundary=\"ABC123.1700000000/mx.example\"\r\n\
\r\n\
--ABC123.1700000000/mx.example\r\n\
Content-Description: Notification\r\n\
Content-Type: text/plain; charset=us-ascii\r\n\
\r\n\
Your message could not be delivered.\r\n\
\r\n\
--ABC123.1700000000/mx.example\r\n\
Content-Description: Delivery report\r\n\
Content-Type: message/delivery-status\r\n\
\r\n\
Reporting-MTA: dns; mx.example\r\n\
\r\n\
Final-Recipient: rfc822; bob@remote.example\r\n\
Action: failed\r\n\
Status: 5.1.1\r\n\
\r\n\
--ABC123.1700000000/mx.example\r\n\
Content-Description: Undelivered Message Headers\r\n\
Content-Type: text/rfc822-headers\r\n\
\r\n\
From: alice@firma.example\r\n\
Subject: Hello\r\n\
\r\n\
--ABC123.1700000000/mx.example--\r\n";

fn names(parts: &[PartRef<'_>]) -> Vec<String> {
    parts.iter().map(|part| part.attachment_name().unwrap_or("-").to_owned()).collect()
}

/// Every part's ranges lie in the message, in order, inside their container, and its slices are those ranges.
fn check_ranges(message: &Message<'_>) {
    let raw = message.raw();
    for part in message.all_parts() {
        assert!(part.offset_header() <= part.offset_body() && part.offset_body() <= part.offset_end());
        assert!(part.offset_end() <= raw.len());
        assert_eq!(part.raw_headers(), &raw[part.offset_header()..part.offset_body()]);
        assert_eq!(part.raw_body(), &raw[part.offset_body()..part.offset_end()]);
        for child in part.children() {
            assert!(child.offset_header() >= part.offset_body() && child.offset_end() <= part.offset_end());
        }
        if let Some(nested) = part.nested() {
            let root = nested.root_part();
            assert_eq!((root.offset_header(), root.offset_end()), (part.offset_body(), part.offset_end()));
        }
    }
    let ids: Vec<usize> = message.root().parts().map(|part| part.id()).collect();
    assert!(ids.windows(2).all(|pair| pair[0] < pair[1]), "parts in document order");
}

#[test]
fn outlook() {
    let message = Message::parse(OUTLOOK).unwrap();
    check_ranges(&message);
    let root = message.root();
    assert_eq!(root.subject().as_deref(), Some("AW: WG: Angebot für März"));
    assert_eq!(root.base_subject(), "Angebot für März");
    let from = root.from().unwrap();
    assert_eq!(from.first().unwrap().name(), Some("Müller, Jürgen"));
    assert_eq!(root.to().unwrap().first().unwrap().name(), Some("Schmidt, Anna"));
    assert_eq!(root.references(), ["a1@corp.example", "AM0PR01MB0000@eurprd01.prod.outlook.com"]);
    assert_eq!(root.date().unwrap().to_timestamp(), 1_793_693_563);
    let text = root.body_text(0).unwrap();
    assert!(text.starts_with("Hallo Anna,\r\n\r\nanbei das Angebot für März.\r\n\r\nGrüße Jürgen"), "{text:?}");
    let html = root.body_html(0).unwrap();
    assert!(html.contains("<p>anbei das Angebot für März.</p><img src=\"cid:image001.png@01DB0000.00000000\">"));
    assert_eq!(html_to_text(&html), "Hallo Anna,\nanbei das Angebot für März.\n");
    let attachments = root.attachments();
    assert_eq!(names(&attachments), ["image001.png", "Angebot März.pdf"]);
    assert_eq!(attachments[0].content_id().as_deref(), Some("image001.png@01DB0000.00000000"));
    assert_eq!(attachments[1].decoded().as_ref(), b"%PDF-1.4\n");
    assert_eq!(attachments[1].content_description().as_deref(), Some("Angebot März.pdf"));
    assert_eq!(root.root_part().content_language(), ["de-DE"]);
}

#[test]
fn gmail() {
    let message = Message::parse(GMAIL).unwrap();
    check_ranges(&message);
    let root = message.root();
    assert_eq!(root.subject().as_deref(), Some("Treffen am Montag 😂"));
    assert_eq!(root.message_id().as_deref(), Some("CAF=abc+def@mail.gmail.com"));
    assert_eq!(root.to().unwrap().mailboxes().count(), 2);
    let cc = root.cc().unwrap();
    assert_eq!(cc.groups()[0].0, Some("Team"));
    assert_eq!(root.body_text(0).as_deref(), Some("Hi Alice,\r\n\r\nsee you on Monday 😂\r\n"));
    assert_eq!(
        root.body_html(0).as_deref(),
        Some("<div dir=\"ltr\">Hi Alice,<div><br></div><div>see you on Monday 😂</div></div>")
    );
    let csv = root.attachments();
    assert_eq!(names(&csv), ["plan.csv"]);
    assert_eq!(csv[0].kind(), Kind::Text);
    assert_eq!(csv[0].text().as_deref(), Some("a,b\n1,2\n"));
    assert_eq!(root.body_preview(9).as_deref(), Some("Hi Alice,"));
}

#[test]
fn apple_mail() {
    let message = Message::parse(APPLE).unwrap();
    check_ranges(&message);
    let root = message.root();
    assert_eq!(root.message_id().as_deref(), Some("4F2E2B0C-9A00-4E6B-8D11-0123456789AB@icloud.example"));
    assert_eq!(root.body_text(0).as_deref(), Some("Here they are.\r\n"));
    let parts: Vec<PartRef<'_>> = root.parts().collect();
    assert_eq!(parts.len(), 3);
    assert_eq!(parts[2].attachment_name(), Some("Straße.jpg"));
    assert_eq!(parts[2].content_type().unwrap().attribute("name"), Some("Straße.jpg"));
    assert_eq!(parts[2].kind(), Kind::InlineBinary);
    // An inline image after text in multipart/mixed is shown in both bodies, not listed (RFC 8621, 4.1.4).
    assert_eq!(root.text_body().len(), 2);
    assert_eq!(root.html_body().len(), 2);
    assert!(root.attachments().is_empty());
}

#[test]
fn thunderbird() {
    let message = Message::parse(THUNDERBIRD).unwrap();
    check_ranges(&message);
    let root = message.root();
    assert_eq!(root.root_part().content_language(), ["en-US", "de-DE"]);
    assert_eq!(root.body_text(0).as_deref(), Some("Für dich. \r\nBis dann.\r\n"));
    let attachments = root.attachments();
    assert_eq!(names(&attachments), ["Ein sehr langer Dateiname für den Test – Teil 2.odt", "Lunch.eml"]);
    let forwarded = attachments[1].nested().unwrap();
    assert_eq!(forwarded.subject().as_deref(), Some("Lunch"));
    assert_eq!(forwarded.body_text(0).as_deref(), Some("こんにちは\r\n"));
    assert_eq!(forwarded.container().unwrap().id(), attachments[1].id());
    // The forwarded message's parts are its own.
    assert_eq!(root.parts().count(), 4);
    assert_eq!(forwarded.parts().count(), 1);
}

#[test]
fn bounces() {
    let message = Message::parse(BOUNCE).unwrap();
    check_ranges(&message);
    let root = message.root();
    let parts: Vec<PartRef<'_>> = root.parts().collect();
    assert_eq!(parts.len(), 4);
    assert_eq!(parts[2].media_type(), "message/delivery-status");
    assert!(!parts[2].is_message());
    assert_eq!(parts[3].text().as_deref(), Some("From: alice@firma.example\r\nSubject: Hello\r\n"));
    assert_eq!(root.body_text(0).as_deref(), Some("Your message could not be delivered.\r\n"));
}

#[test]
fn bare_line_feeds_and_eight_bit_headers() {
    let raw = b"From: J\xfcrgen <j@x.example>\nSubject: Gr\xc3\xbc\xc3\x9fe\nContent-Type: multipart/alternative; boundary=b\n\n\
--b\nContent-Type: text/plain\n\nplain \xfc\n--b\nContent-Type: text/html; charset=utf-8\n\n<b>bold</b>\n--b--\n";
    let message = Message::parse(raw).unwrap();
    check_ranges(&message);
    let root = message.root();
    assert_eq!(root.from().unwrap().first().unwrap().name(), Some("Jürgen"));
    assert_eq!(root.subject().as_deref(), Some("Grüße"));
    assert_eq!(root.body_text(0).as_deref(), Some("plain ü"));
    assert_eq!(root.body_html(0).as_deref(), Some("<b>bold</b>"));
}

#[test]
fn built_messages_read_back() {
    let raw = MessageBuilder::new()
        .from(("Ünïcødé Name", "u@x.example"))
        .to(["a@x.example"])
        .subject("日本語の件名 and ASCII")
        .text_body("Zeile 1\nZeile 2 – ü\n")
        .attachment("text/plain", "ä.txt", "inhalt".as_bytes().to_vec())
        .write();
    let message = Message::parse(&raw).unwrap();
    check_ranges(&message);
    let root = message.root();
    assert_eq!(root.subject().as_deref(), Some("日本語の件名 and ASCII"));
    assert_eq!(root.from().unwrap().first().unwrap().name(), Some("Ünïcødé Name"));
    assert_eq!(root.body_text(0).as_deref(), Some("Zeile 1\r\nZeile 2 – ü\r\n"));
    assert_eq!(names(&root.attachments()), ["ä.txt"]);
    assert_eq!(root.attachments()[0].text().as_deref(), Some("inhalt"));
}

/// Damage of every kind never panics, and the ranges stay right.
#[test]
fn random_damage() {
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut random = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let alphabet = b"\r\n\r\n-:;\"=?()<>@,[]\\ \tabBqQ0\x80\xff\x1b=?utf-8?q?";
    for sample in [OUTLOOK, GMAIL, APPLE, THUNDERBIRD, BOUNCE] {
        for round in 0..400 {
            let mut bytes = sample.to_vec();
            for _ in 0..(random() % 24) {
                if bytes.is_empty() {
                    break;
                }
                let position = (random() as usize) % bytes.len();
                match random() % 4 {
                    0 => bytes[position] = alphabet[(random() as usize) % alphabet.len()],
                    1 => {
                        bytes.remove(position);
                    }
                    2 => bytes.insert(position, alphabet[(random() as usize) % alphabet.len()]),
                    _ => bytes.truncate(position.max(1)),
                }
            }
            if round % 50 == 0 {
                bytes = (0..(random() % 600)).map(|_| random() as u8).collect();
            }
            exercise(&bytes);
        }
    }
}

fn exercise(bytes: &[u8]) {
    let Some(message) = Message::parse(bytes) else { return };
    check_ranges(&message);
    for part in message.all_parts() {
        let _ = (part.text_checked(), part.decoded_len(), part.attachment_name(), part.content_id());
        let _ = (part.content_language(), part.content_location(), part.content_description(), part.kind());
        for header in part.headers().iter() {
            let _ = (header.text(), header.addresses(), header.date(), header.message_ids(), header.urls());
            let _ = header.list();
        }
        if let Some(nested) = part.nested() {
            let _ = (nested.subject(), nested.bodies());
        }
    }
    let root = message.root();
    let _ = (root.bodies(), root.body_preview(256), root.base_subject(), root.body_html(0));
    if let Some(text) = root.body_text(0) {
        let _ = html_to_text(&text);
    }
    let _ = Message::parse_headers(bytes);
}

#[test]
fn random_text_through_every_reader() {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut random = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let pieces = [
        "=?", "?=", "?q?", "?B?", "utf-8", "<", ">", "\"", "(", ")", ":", ";", ",", "@", " ", "\r\n ", "&#", "&amp",
        "<p>", "</", "Re:", "[", "]", "ü", "日", "*0*=", "''", "%", "+0200", "Feb", "29", "1969", "23:59:60", "\\",
    ];
    for _ in 0..3000 {
        let text: String = (0..(random() % 20)).map(|_| pieces[(random() as usize) % pieces.len()]).collect();
        let _ = kernoid_mime::words::decode(&text);
        let _ = kernoid_mime::words::encode(&text);
        let _ = kernoid_mime::address::parse(&text);
        let _ = kernoid_mime::date::parse(&text);
        let _ = kernoid_mime::params::parse(&text, true);
        let _ = kernoid_mime::base_subject(&text);
        let _ = html_to_text(&text);
        let _ = kernoid_mime::header::message_ids(&text);
        let _ = kernoid_mime::transfer::qp_decode(text.as_bytes());
        let _ = kernoid_mime::charset::decode(Some("utf-7"), text.as_bytes());
        let raw = format!("Subject: {text}\r\nContent-Type: {text}\r\nContent-Disposition: {text}\r\n\r\n{text}");
        exercise(raw.as_bytes());
    }
}
