// SPDX-License-Identifier: MIT
//! What a reader shows of a message: the text, HTML and attachment parts as RFC 8621, 4.1.4 chooses them, and HTML
//! as plain text for previews, search and Sieve.

use crate::message::{MessageRef, PartRef};

fn is_inline_media(media_type: &str) -> bool {
    media_type.starts_with("image/") || media_type.starts_with("audio/") || media_type.starts_with("video/")
}

struct Walk<'m> {
    message: MessageRef<'m>,
    attachments: Vec<usize>,
}

impl<'m> Walk<'m> {
    fn part(&self, index: usize) -> PartRef<'m> {
        self.message.message().part(index).expect("a part of the message")
    }

    /// `parseStructure` of RFC 8621, 4.1.4.
    fn structure(
        &mut self,
        parts: &[usize],
        multipart_type: &str,
        in_alternative: bool,
        mut html: Option<&mut Vec<usize>>,
        mut text: Option<&mut Vec<usize>>,
    ) {
        let text_length = text.as_ref().map(|list| list.len());
        let html_length = html.as_ref().map(|list| list.len());
        for (i, &index) in parts.iter().enumerate() {
            let part = self.part(index);
            let media_type = part.media_type();
            let disposition_attachment =
                part.content_disposition().is_some_and(|d| d.ctype().eq_ignore_ascii_case("attachment"));
            let is_inline = !disposition_attachment
                && (media_type == "text/plain" || media_type == "text/html" || is_inline_media(media_type))
                && (i == 0
                    || (multipart_type != "related"
                        && (is_inline_media(media_type) || part.attachment_name().is_none())));
            if part.is_multipart() {
                let sub_type = media_type.split_once('/').map_or("", |(_, sub)| sub).to_owned();
                let children: Vec<usize> = part.children().map(|child| child.id()).collect();
                self.structure(
                    &children,
                    &sub_type,
                    in_alternative || sub_type == "alternative",
                    html.as_deref_mut(),
                    text.as_deref_mut(),
                );
            } else if is_inline {
                if multipart_type == "alternative" {
                    match media_type {
                        "text/plain" => {
                            if let Some(list) = text.as_deref_mut() {
                                list.push(index);
                            }
                        }
                        "text/html" => {
                            if let Some(list) = html.as_deref_mut() {
                                list.push(index);
                            }
                        }
                        _ => self.attachments.push(index),
                    }
                    continue;
                } else if in_alternative {
                    if media_type == "text/plain" {
                        html = None;
                    }
                    if media_type == "text/html" {
                        text = None;
                    }
                }
                if let Some(list) = text.as_deref_mut() {
                    list.push(index);
                }
                if let Some(list) = html.as_deref_mut() {
                    list.push(index);
                }
                if (text.is_none() || html.is_none()) && is_inline_media(media_type) {
                    self.attachments.push(index);
                }
            } else {
                self.attachments.push(index);
            }
        }
        if multipart_type == "alternative"
            && let (Some(text), Some(html)) = (text, html)
        {
            let (text_length, html_length) = (text_length.unwrap_or(0), html_length.unwrap_or(0));
            if text_length == text.len() && html_length != html.len() {
                text.extend_from_slice(&html[html_length..]);
            }
            if html_length == html.len() && text_length != text.len() {
                html.extend_from_slice(&text[text_length..]);
            }
        }
    }
}

/// The text body, HTML body and attachments of a message, as part ids.
pub(crate) fn structure(message: MessageRef<'_>) -> (Vec<usize>, Vec<usize>, Vec<usize>) {
    let (mut text, mut html) = (Vec::new(), Vec::new());
    let mut walk = Walk { message, attachments: Vec::new() };
    walk.structure(&[message.root_index()], "mixed", false, Some(&mut html), Some(&mut text));
    (text, html, walk.attachments)
}

/// Named character references mail uses most; others stay as written.
fn entity(name: &str) -> Option<char> {
    if let Some(number) = name.strip_prefix('#') {
        let code = match number.strip_prefix(['x', 'X']) {
            Some(hex) => u32::from_str_radix(hex, 16).ok()?,
            None => number.parse().ok()?,
        };
        return char::from_u32(code).filter(|c| *c != '\0');
    }
    Some(match name {
        "amp" => '&',
        "lt" => '<',
        "gt" => '>',
        "quot" => '"',
        "apos" => '\'',
        "nbsp" => '\u{a0}',
        "shy" => '\u{ad}',
        "copy" => '©',
        "reg" => '®',
        "trade" => '™',
        "euro" => '€',
        "pound" => '£',
        "yen" => '¥',
        "cent" => '¢',
        "sect" => '§',
        "deg" => '°',
        "plusmn" => '±',
        "times" => '×',
        "divide" => '÷',
        "middot" => '·',
        "bull" => '•',
        "hellip" => '…',
        "ndash" => '–',
        "mdash" => '—',
        "lsquo" => '‘',
        "rsquo" => '’',
        "sbquo" => '‚',
        "ldquo" => '“',
        "rdquo" => '”',
        "bdquo" => '„',
        "laquo" => '«',
        "raquo" => '»',
        "auml" => 'ä',
        "ouml" => 'ö',
        "uuml" => 'ü',
        "Auml" => 'Ä',
        "Ouml" => 'Ö',
        "Uuml" => 'Ü',
        "szlig" => 'ß',
        "eacute" => 'é',
        "egrave" => 'è',
        "ecirc" => 'ê',
        "aacute" => 'á',
        "agrave" => 'à',
        "acirc" => 'â',
        "iacute" => 'í',
        "oacute" => 'ó',
        "uacute" => 'ú',
        "ccedil" => 'ç',
        "ntilde" => 'ñ',
        "Eacute" => 'É',
        "zwnj" => '\u{200c}',
        "zwj" => '\u{200d}',
        _ => return None,
    })
}

const BLOCKS: [&str; 30] = [
    "p",
    "div",
    "br",
    "li",
    "tr",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "blockquote",
    "table",
    "ul",
    "ol",
    "hr",
    "pre",
    "section",
    "article",
    "header",
    "footer",
    "dl",
    "dt",
    "dd",
    "address",
    "figure",
    "form",
    "nav",
    "main",
    "title",
];

/// HTML as plain text: tags out (block elements become line breaks), scripts, styles and comments out, character
/// references decoded, white space collapsed outside `pre`.
pub fn html_to_text(html: &str) -> String {
    let mut out = String::with_capacity(html.len() / 2);
    let mut rest = html;
    let mut pre = 0usize;
    let mut space = false;
    let newline = |out: &mut String| {
        while out.ends_with(' ') {
            out.pop();
        }
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
    };
    while !rest.is_empty() {
        if let Some(comment) = rest.strip_prefix("<!--") {
            rest = comment.find("-->").map_or("", |end| &comment[end + 3..]);
            continue;
        }
        if rest.starts_with('<') {
            let close = rest.find('>').unwrap_or(rest.len());
            let tag = &rest[1..close];
            rest = rest.get(close + 1..).unwrap_or_default();
            let closing = tag.starts_with('/');
            let name: String = tag
                .trim_start_matches('/')
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric())
                .collect::<String>()
                .to_ascii_lowercase();
            if !closing && matches!(name.as_str(), "script" | "style" | "head") {
                // Skip to the closing tag.
                let lower = rest.to_ascii_lowercase();
                let close = format!("</{name}");
                rest = match lower.find(&close) {
                    Some(at) => rest[at..].find('>').map_or("", |end| &rest[at + end + 1..]),
                    None => "",
                };
                continue;
            }
            if name == "pre" {
                pre = if closing { pre.saturating_sub(1) } else { pre + 1 };
            }
            if name == "br" {
                while out.ends_with(' ') {
                    out.pop();
                }
                out.push('\n');
                space = false;
            } else if BLOCKS.contains(&name.as_str()) {
                newline(&mut out);
                space = false;
            } else if name == "td" || name == "th" {
                space = true;
            }
            continue;
        }
        let next = rest.find('<').unwrap_or(rest.len());
        let (text, after) = rest.split_at(next);
        rest = after;
        let mut chars = text.char_indices().peekable();
        while let Some((at, c)) = chars.next() {
            let c = if c == '&' {
                let tail = &text[at + 1..];
                match tail.find(';').filter(|end| *end <= 10).and_then(|end| Some((end, entity(&tail[..end])?))) {
                    Some((end, decoded)) => {
                        for _ in 0..=end {
                            chars.next();
                        }
                        decoded
                    }
                    None => '&',
                }
            } else {
                c
            };
            if pre > 0 {
                out.push(c);
            } else if c.is_whitespace() && c != '\u{a0}' {
                space = true;
            } else {
                if space && !out.is_empty() && !out.ends_with('\n') && !out.ends_with(' ') {
                    out.push(' ');
                }
                space = false;
                out.push(if c == '\u{a0}' { ' ' } else { c });
            }
        }
    }
    while out.ends_with(' ') {
        out.pop();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Message;

    fn types(parts: Vec<PartRef<'_>>) -> Vec<String> {
        parts.iter().map(|part| part.media_type().to_owned()).collect()
    }

    #[test]
    fn html_as_text() {
        assert_eq!(html_to_text("<p>Hello <b>you</b></p>"), "Hello you\n");
        assert_eq!(
            html_to_text(
                "<html><head><title>T</title><style>p{}</style></head><body><p>Gr&uuml;&szlig;e,&nbsp;Welt</p>\n<div>A &amp; B &#8211; &#x2014; &bogus;</div><br>x<!-- hidden --><script>alert(1)</script></body></html>"
            ),
            "Grüße, Welt\nA & B – — &bogus;\n\nx"
        );
        assert_eq!(html_to_text("<pre>  two\n  lines</pre>after"), "  two\n  lines\nafter");
        assert_eq!(html_to_text("a<"), "a");
        assert_eq!(html_to_text("&"), "&");
    }

    #[test]
    fn bodies_of_rfc_8621() {
        // The example of RFC 8621, 4.1.4, its parts named by their content.
        let raw = "Subject: x\r\nContent-Type: multipart/mixed; boundary=1\r\n\r\n\
--1\r\nContent-Type: text/plain\r\n\r\nA\r\n\
--1\r\nContent-Type: multipart/mixed; boundary=2\r\n\r\n\
--2\r\nContent-Type: multipart/alternative; boundary=3\r\n\r\n\
--3\r\nContent-Type: multipart/mixed; boundary=4\r\n\r\n\
--4\r\nContent-Type: text/plain\r\n\r\nB\r\n\
--4\r\nContent-Type: image/jpeg\r\nContent-Disposition: inline\r\n\r\nC\r\n\
--4\r\nContent-Type: text/plain\r\n\r\nD\r\n--4--\r\n\
--3\r\nContent-Type: multipart/related; boundary=5\r\n\r\n\
--5\r\nContent-Type: text/html\r\n\r\nE\r\n\
--5\r\nContent-Type: image/jpeg\r\n\r\nF\r\n--5--\r\n--3--\r\n\
--2\r\nContent-Type: image/jpeg\r\nContent-Disposition: attachment\r\n\r\nG\r\n\
--2\r\nContent-Type: application/x-excel\r\n\r\nH\r\n\
--2\r\nContent-Type: message/rfc822\r\n\r\nSubject: J\r\n\r\nJ\r\n--2--\r\n\
--1\r\nContent-Type: text/plain\r\n\r\nK\r\n--1--\r\n";
        let message = Message::parse(raw.as_bytes()).unwrap();
        let names = |parts: Vec<PartRef<'_>>| -> String {
            parts.iter().map(|part| String::from_utf8_lossy(&part.raw_body()[..1]).into_owned()).collect()
        };
        let root = message.root();
        assert_eq!(names(root.text_body()), "ABCDK");
        assert_eq!(names(root.html_body()), "AEK");
        assert_eq!(names(root.attachments()), "CFGHS");
        assert!(root.has_attachments());
    }

    #[test]
    fn bodies_of_simple_messages() {
        let plain = Message::parse(b"Subject: x\r\n\r\nHello\r\n").unwrap();
        assert_eq!(types(plain.root().text_body()), ["text/plain"]);
        assert_eq!(types(plain.root().html_body()), ["text/plain"]);
        assert!(!plain.root().has_attachments());
        assert_eq!(plain.root().body_html(0), None);
        assert_eq!(plain.root().body_preview(3).as_deref(), Some("Hel"));
        let html = Message::parse(b"Content-Type: text/html\r\n\r\n<p>Hi <i>there</i></p>").unwrap();
        assert_eq!(html.root().body_text(0).as_deref(), Some("Hi there\n"));
        assert_eq!(html.root().body_html(0).as_deref(), Some("<p>Hi <i>there</i></p>"));
        let pdf = Message::parse(b"Content-Type: application/pdf\r\n\r\n%PDF").unwrap();
        assert!(pdf.root().text_body().is_empty());
        assert_eq!(types(pdf.root().attachments()), ["application/pdf"]);
    }
}
