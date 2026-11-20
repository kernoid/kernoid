// SPDX-License-Identifier: MIT
//! HTML as plain text – kernoid's own, written from the HTML standard's syntax (tokenization, raw text elements,
//! character references), for showing and quoting mail: block elements become lines, paragraphs, headings, lists,
//! quotations and preformatted text keep their shape, links become `text <url>`, images their alternative text, and
//! nothing of scripts, styles or the head is shown. Nothing is run or loaded.
//!
//! The work is linear in the input whatever it holds: an unterminated tag, comment or raw text ends the scan instead of
//! being searched for again, a closing tag pops what it closes at most once, and only the first [`MAX_LEVELS`] levels
//! of quotation and lists are drawn.

/// Levels of quotations and lists drawn in a line's prefix; deeper ones are read but not indented further.
pub const MAX_LEVELS: usize = 16;

/// The narrowest a line's text gets, however deep its prefix.
const MIN_TEXT: usize = 10;

/// HTML as plain text, lines wrapped at `width` columns (counted in characters; at least 20).
pub fn to_text(html: &str, width: usize) -> String {
    let mut writer = Writer::new(width.max(20));
    let mut tokens = Tokens { html, at: 0 };
    while let Some(token) = tokens.next_token() {
        match token {
            Token::Text(text) => writer.text(&decode(text)),
            Token::Start { name, attributes, closed } => {
                if let Some(end) = RAW.iter().find(|raw| **raw == name) {
                    // Raw text: up to the closing tag, never markup, never shown.
                    if !closed {
                        tokens.skip_raw(end);
                    }
                    continue;
                }
                writer.start(&name, attributes, closed);
            }
            Token::End(name) => writer.end(&name),
        }
    }
    writer.finish()
}

/// Elements whose content is raw text, none of it shown.
const RAW: [&str; 8] = ["script", "style", "title", "textarea", "xmp", "iframe", "noembed", "noframes"];

/// Elements whose content is not shown (it is markup, not raw text).
const HIDDEN: [&str; 5] = ["head", "template", "svg", "math", "object"];

#[derive(Debug, PartialEq, Eq)]
enum Token<'a> {
    Text(&'a str),
    Start { name: String, attributes: &'a str, closed: bool },
    End(String),
}

/// The tokens of a document: text, start tags (with their attributes unparsed) and end tags; comments, doctypes and
/// processing instructions are passed over.
struct Tokens<'a> {
    html: &'a str,
    at: usize,
}

impl<'a> Tokens<'a> {
    fn next_token(&mut self) -> Option<Token<'a>> {
        loop {
            let rest = self.html.get(self.at..)?;
            if rest.is_empty() {
                return None;
            }
            let Some(lt) = rest.find('<') else {
                self.at = self.html.len();
                return Some(Token::Text(rest));
            };
            if lt > 0 {
                self.at += lt;
                return Some(Token::Text(&rest[..lt]));
            }
            let after = &rest[1..];
            if let Some(comment) = after.strip_prefix("!--") {
                // A comment: up to `-->`, or the end.
                self.at += match comment.find("-->") {
                    Some(end) => 4 + end + 3,
                    None => rest.len(),
                };
                continue;
            }
            let first = after.chars().next();
            let end_tag = first == Some('/');
            let name_start = if end_tag { &after[1..] } else { after };
            match name_start.chars().next() {
                Some(c) if c.is_ascii_alphabetic() => {}
                Some('!' | '?') if !end_tag => {
                    // A doctype, a CDATA section or a processing instruction: up to `>`.
                    self.at += rest.find('>').map_or(rest.len(), |end| end + 1);
                    continue;
                }
                _ => {
                    // Not a tag: the `<` is text.
                    self.at += 1;
                    return Some(Token::Text("<"));
                }
            }
            let Some(gt) = tag_end(rest) else {
                // An unterminated tag ends the document (as the standard's end of file in a tag does).
                self.at = self.html.len();
                return None;
            };
            self.at += gt + 1;
            let inside = &rest[1..gt];
            let inside = if end_tag { &inside[1..] } else { inside };
            let name_len = inside.find(|c: char| c.is_ascii_whitespace() || c == '/').unwrap_or(inside.len());
            let name = inside[..name_len].to_ascii_lowercase();
            if end_tag {
                return Some(Token::End(name));
            }
            let attributes = &inside[name_len..];
            let closed = attributes.trim_end().ends_with('/');
            return Some(Token::Start { name, attributes, closed });
        }
    }

    /// Passes over raw text up to the closing tag of `name` (any case), or to the end.
    fn skip_raw(&mut self, name: &str) {
        let rest = &self.html.as_bytes()[self.at..];
        let mut from = 0;
        while let Some(found) = rest[from..].windows(2).position(|pair| pair == b"</") {
            let start = from + found + 2;
            let candidate = &rest[start..];
            if candidate.len() >= name.len()
                && candidate[..name.len()].eq_ignore_ascii_case(name.as_bytes())
                && candidate.get(name.len()).is_none_or(|c| c.is_ascii_whitespace() || *c == b'>' || *c == b'/')
            {
                let gt = candidate.iter().position(|c| *c == b'>').map_or(candidate.len(), |end| end + 1);
                self.at += start + gt;
                return;
            }
            from = start;
        }
        self.at = self.html.len();
    }
}

/// Where the tag at the start of `text` ends: its `>` outside quoted attribute values.
fn tag_end(text: &str) -> Option<usize> {
    let mut quote = None;
    for (i, c) in text.char_indices().skip(1) {
        match (quote, c) {
            (None, '"' | '\'') => {
                // Only a quote after `=` opens a value; elsewhere it is part of a name.
                if text[..i].trim_end().ends_with('=') {
                    quote = Some(c);
                }
            }
            (None, '>') => return Some(i),
            (Some(q), c) if c == q => quote = None,
            _ => {}
        }
    }
    None
}

/// The value of attribute `wanted` among `attributes`, its character references decoded.
fn attribute(attributes: &str, wanted: &str) -> Option<String> {
    let mut rest = attributes;
    loop {
        rest = rest.trim_start_matches(|c: char| c.is_ascii_whitespace() || c == '/');
        if rest.is_empty() {
            return None;
        }
        let name_len = rest.find(|c: char| c.is_ascii_whitespace() || c == '=' || c == '/').unwrap_or(rest.len());
        let name = &rest[..name_len];
        rest = rest[name_len..].trim_start();
        let value = if let Some(after) = rest.strip_prefix('=') {
            let after = after.trim_start();
            let (value, next) = match after.chars().next() {
                Some(q @ ('"' | '\'')) => {
                    let body = &after[1..];
                    let end = body.find(q).unwrap_or(body.len());
                    (&body[..end], body.get(end + 1..).unwrap_or(""))
                }
                _ => {
                    let end = after.find(|c: char| c.is_ascii_whitespace()).unwrap_or(after.len());
                    (&after[..end], &after[end..])
                }
            };
            rest = next;
            Some(value)
        } else {
            if name_len == 0 {
                // A stray character: skip it.
                rest = rest.get(1..).unwrap_or("");
            }
            None
        };
        if name.eq_ignore_ascii_case(wanted) {
            return Some(decode(value.unwrap_or("")));
        }
    }
}

/// Text with its character references decoded: named ones (the common ones of mail), decimal and hexadecimal.
pub fn decode(text: &str) -> String {
    if !text.contains('&') {
        return text.to_owned();
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        rest = &rest[amp..];
        match reference(rest) {
            Some((decoded, len)) => {
                out.push_str(decoded.as_ref());
                rest = &rest[len..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// The character reference at the start of `text` (which starts with `&`) and its length.
fn reference(text: &str) -> Option<(std::borrow::Cow<'static, str>, usize)> {
    let body = &text[1..];
    if let Some(number) = body.strip_prefix('#') {
        let (digits, radix, skip) = match number.strip_prefix(['x', 'X']) {
            Some(hex) => (hex, 16, 2),
            None => (number, 10, 1),
        };
        let len = digits.find(|c: char| !c.is_digit(radix)).unwrap_or(digits.len());
        if len == 0 {
            return None;
        }
        // Too many digits is out of range, whatever they say.
        let value = if len > 8 { u32::MAX } else { u32::from_str_radix(&digits[..len], radix).ok()? };
        let c = match value {
            0 => '\u{FFFD}',
            // Windows-1252's characters, as the standard reads them in 0x80–0x9F.
            0x80..=0x9F => WINDOWS_1252[(value - 0x80) as usize],
            _ => char::from_u32(value).unwrap_or('\u{FFFD}'),
        };
        let semicolon = usize::from(digits[len..].starts_with(';'));
        return Some((c.to_string().into(), 1 + skip + len + semicolon));
    }
    let len = body.find(|c: char| !c.is_ascii_alphanumeric()).unwrap_or(body.len());
    if len == 0 || len > 32 {
        return None;
    }
    let name = &body[..len];
    let value = NAMED.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)?;
    let semicolon = usize::from(body[len..].starts_with(';'));
    Some((value.into(), 1 + len + semicolon))
}

const WINDOWS_1252: [char; 32] = [
    '€', '\u{81}', '‚', 'ƒ', '„', '…', '†', '‡', 'ˆ', '‰', 'Š', '‹', 'Œ', '\u{8D}', 'Ž', '\u{8F}', '\u{90}', '‘', '’',
    '“', '”', '•', '–', '—', '˜', '™', 'š', '›', 'œ', '\u{9D}', 'ž', 'Ÿ',
];

/// The named character references mail uses most; others stay as written.
const NAMED: &[(&str, &str)] = &[
    ("amp", "&"),
    ("AMP", "&"),
    ("lt", "<"),
    ("LT", "<"),
    ("gt", ">"),
    ("GT", ">"),
    ("quot", "\""),
    ("QUOT", "\""),
    ("apos", "'"),
    ("nbsp", "\u{A0}"),
    ("ensp", "\u{2002}"),
    ("emsp", "\u{2003}"),
    ("thinsp", "\u{2009}"),
    ("zwnj", "\u{200C}"),
    ("zwj", "\u{200D}"),
    ("shy", "\u{AD}"),
    ("copy", "©"),
    ("COPY", "©"),
    ("reg", "®"),
    ("REG", "®"),
    ("trade", "™"),
    ("hellip", "…"),
    ("mdash", "—"),
    ("ndash", "–"),
    ("lsquo", "‘"),
    ("rsquo", "’"),
    ("sbquo", "‚"),
    ("ldquo", "“"),
    ("rdquo", "”"),
    ("bdquo", "„"),
    ("laquo", "«"),
    ("raquo", "»"),
    ("lsaquo", "‹"),
    ("rsaquo", "›"),
    ("bull", "•"),
    ("middot", "·"),
    ("dagger", "†"),
    ("Dagger", "‡"),
    ("permil", "‰"),
    ("prime", "′"),
    ("euro", "€"),
    ("cent", "¢"),
    ("pound", "£"),
    ("yen", "¥"),
    ("curren", "¤"),
    ("sect", "§"),
    ("para", "¶"),
    ("deg", "°"),
    ("plusmn", "±"),
    ("times", "×"),
    ("divide", "÷"),
    ("minus", "−"),
    ("micro", "µ"),
    ("frac12", "½"),
    ("frac14", "¼"),
    ("frac34", "¾"),
    ("sup1", "¹"),
    ("sup2", "²"),
    ("sup3", "³"),
    ("iexcl", "¡"),
    ("iquest", "¿"),
    ("ordf", "ª"),
    ("ordm", "º"),
    ("not", "¬"),
    ("macr", "¯"),
    ("acute", "´"),
    ("cedil", "¸"),
    ("uml", "¨"),
    ("larr", "←"),
    ("rarr", "→"),
    ("uarr", "↑"),
    ("darr", "↓"),
    ("harr", "↔"),
    ("check", "✓"),
    ("Auml", "Ä"),
    ("Ouml", "Ö"),
    ("Uuml", "Ü"),
    ("auml", "ä"),
    ("ouml", "ö"),
    ("uuml", "ü"),
    ("szlig", "ß"),
    ("Agrave", "À"),
    ("Aacute", "Á"),
    ("Acirc", "Â"),
    ("Atilde", "Ã"),
    ("Aring", "Å"),
    ("AElig", "Æ"),
    ("Ccedil", "Ç"),
    ("Egrave", "È"),
    ("Eacute", "É"),
    ("Ecirc", "Ê"),
    ("Euml", "Ë"),
    ("Igrave", "Ì"),
    ("Iacute", "Í"),
    ("Icirc", "Î"),
    ("Iuml", "Ï"),
    ("Ntilde", "Ñ"),
    ("Ograve", "Ò"),
    ("Oacute", "Ó"),
    ("Ocirc", "Ô"),
    ("Otilde", "Õ"),
    ("Oslash", "Ø"),
    ("Ugrave", "Ù"),
    ("Uacute", "Ú"),
    ("Ucirc", "Û"),
    ("Yacute", "Ý"),
    ("agrave", "à"),
    ("aacute", "á"),
    ("acirc", "â"),
    ("atilde", "ã"),
    ("aring", "å"),
    ("aelig", "æ"),
    ("ccedil", "ç"),
    ("egrave", "è"),
    ("eacute", "é"),
    ("ecirc", "ê"),
    ("euml", "ë"),
    ("igrave", "ì"),
    ("iacute", "í"),
    ("icirc", "î"),
    ("iuml", "ï"),
    ("ntilde", "ñ"),
    ("ograve", "ò"),
    ("oacute", "ó"),
    ("ocirc", "ô"),
    ("otilde", "õ"),
    ("oslash", "ø"),
    ("ugrave", "ù"),
    ("uacute", "ú"),
    ("ucirc", "û"),
    ("yacute", "ý"),
    ("yuml", "ÿ"),
    ("OElig", "Œ"),
    ("oelig", "œ"),
    ("Scaron", "Š"),
    ("scaron", "š"),
];

/// What a line's prefix is made of, outside in.
#[derive(Debug)]
enum Level {
    Quote,
    List {
        ordered: bool,
        next: i64,
    },
    /// An item of a list: its marker (`* `, `3. `), drawn on its first line, spaces of its width on the others.
    Item {
        marker: String,
        drawn: bool,
    },
}

/// Builds the text: paragraphs of inline text, wrapped when a block ends.
struct Writer {
    width: usize,
    out: String,
    levels: Vec<Level>,
    quotes: usize,
    lists: usize,
    items: usize,
    /// The paragraph so far: words with single spaces, `\n` for a line break.
    paragraph: String,
    space: bool,
    /// A blank line before the next line, if anything came before – drawn with the quotation's depth when it was asked
    /// for.
    blank: Option<usize>,
    /// The last line written was blank.
    was_blank: bool,
    pre: usize,
    /// The first newline right after `<pre>` is not content.
    pre_start: bool,
    hidden: Vec<&'static str>,
    /// Open links: their target and where their text started in the paragraph (with the paragraph's number then).
    links: Vec<(Option<String>, usize, usize)>,
    paragraphs: usize,
}

impl Writer {
    fn new(width: usize) -> Self {
        Writer {
            width,
            out: String::new(),
            levels: Vec::new(),
            quotes: 0,
            lists: 0,
            items: 0,
            paragraph: String::new(),
            space: false,
            blank: None,
            was_blank: false,
            pre: 0,
            pre_start: false,
            hidden: Vec::new(),
            links: Vec::new(),
            paragraphs: 0,
        }
    }

    fn text(&mut self, text: &str) {
        if !self.hidden.is_empty() {
            return;
        }
        if self.pre > 0 {
            let text = if std::mem::take(&mut self.pre_start) {
                text.strip_prefix("\r\n").or_else(|| text.strip_prefix('\n')).unwrap_or(text)
            } else {
                text
            };
            self.paragraph.extend(text.chars().filter(|c| *c != '\r'));
            return;
        }
        for c in text.chars() {
            if c.is_ascii_whitespace() {
                self.space = true;
            } else if c != '\u{AD}' {
                if self.space && !self.paragraph.is_empty() && !self.paragraph.ends_with('\n') {
                    self.paragraph.push(' ');
                }
                self.space = false;
                self.paragraph.push(c);
            }
        }
    }

    fn start(&mut self, name: &str, attributes: &str, closed: bool) {
        if let Some(hidden) = HIDDEN.iter().find(|h| **h == name) {
            if !closed {
                self.hidden.push(hidden);
            }
            return;
        }
        if name == "body" {
            // A head left open ends here.
            self.hidden.clear();
            return;
        }
        if !self.hidden.is_empty() {
            return;
        }
        match name {
            "br" => {
                self.paragraph.push('\n');
                self.space = false;
            }
            "p" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6" | "dl" | "table" | "figure" | "address" | "fieldset"
            | "details" => self.paragraph_break(),
            "div" | "section" | "article" | "header" | "footer" | "nav" | "main" | "aside" | "center" | "tr" | "dt"
            | "dd" | "caption" | "figcaption" | "summary" | "legend" | "tbody" | "thead" | "tfoot" => self.line_break(),
            "td" | "th" => self.space = true,
            "hr" => {
                self.paragraph_break();
                let rule = "-".repeat(self.text_width().min(40));
                self.line(&rule);
                self.ask_blank();
            }
            "pre" => {
                self.paragraph_break();
                self.pre += 1;
                self.pre_start = true;
            }
            "blockquote" => {
                self.paragraph_break();
                self.levels.push(Level::Quote);
                self.quotes += 1;
            }
            "ul" | "ol" | "menu" => {
                if self.in_item() {
                    self.line_break();
                } else {
                    self.paragraph_break();
                }
                let next = attribute(attributes, "start").and_then(|s| s.trim().parse().ok()).unwrap_or(1);
                self.levels.push(Level::List { ordered: name == "ol", next });
                self.lists += 1;
            }
            "li" => {
                self.line_break();
                if matches!(self.levels.last(), Some(Level::Item { .. })) {
                    self.levels.pop();
                    self.items -= 1;
                }
                let marker = match self.levels.last_mut() {
                    Some(Level::List { ordered: true, next }) => {
                        let marker = format!("{next}. ");
                        *next = next.saturating_add(1);
                        marker
                    }
                    _ => "* ".to_owned(),
                };
                self.levels.push(Level::Item { marker, drawn: false });
                self.items += 1;
            }
            "a" => {
                let href = attribute(attributes, "href").map(|h| h.trim().to_owned());
                self.links.push((href, self.paragraph.len(), self.paragraphs));
            }
            "img" => {
                if let Some(alt) = attribute(attributes, "alt").filter(|alt| !alt.trim().is_empty()) {
                    self.text(&alt);
                }
            }
            _ => {}
        }
    }

    fn end(&mut self, name: &str) {
        if let Some(open) = self.hidden.last() {
            if *open == name {
                self.hidden.pop();
            }
            return;
        }
        match name {
            "p" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6" | "dl" | "table" | "figure" | "address" | "fieldset"
            | "details" => self.paragraph_break(),
            "div" | "section" | "article" | "header" | "footer" | "nav" | "main" | "aside" | "center" | "tr" | "dt"
            | "dd" | "caption" | "figcaption" | "summary" | "legend" => self.line_break(),
            "pre" if self.pre > 0 => {
                self.paragraph_break();
                self.pre -= 1;
            }
            "blockquote" if self.quotes > 0 => {
                self.paragraph_break();
                while let Some(level) = self.levels.pop() {
                    self.forget(&level);
                    if matches!(level, Level::Quote) {
                        break;
                    }
                }
                self.ask_blank();
            }
            "ul" | "ol" | "menu" if self.lists > 0 => {
                self.line_break();
                while let Some(level) = self.levels.pop() {
                    self.forget(&level);
                    if matches!(level, Level::List { .. }) {
                        break;
                    }
                }
                if !self.in_item() {
                    self.ask_blank();
                }
            }
            "li" => {
                self.line_break();
                if matches!(self.levels.last(), Some(Level::Item { .. })) {
                    self.levels.pop();
                    self.items -= 1;
                }
            }
            "a" => {
                let Some((Some(href), start, paragraph)) = self.links.pop() else { return };
                if href.is_empty() || href.starts_with('#') || href.to_ascii_lowercase().starts_with("javascript:") {
                    return;
                }
                let text = if paragraph == self.paragraphs { self.paragraph.get(start..).unwrap_or("") } else { "" };
                let text = text.trim();
                let bare = href.strip_prefix("mailto:").unwrap_or(&href);
                if text == href || text == bare {
                    return;
                }
                if text.is_empty() {
                    self.text(&href);
                } else {
                    self.text(&format!(" <{href}>"));
                }
            }
            _ => {}
        }
    }

    fn forget(&mut self, level: &Level) {
        match level {
            Level::Quote => self.quotes -= 1,
            Level::List { .. } => self.lists -= 1,
            Level::Item { .. } => self.items -= 1,
        }
    }

    fn in_item(&self) -> bool {
        self.items > 0
    }

    /// The width left for text after the prefix.
    fn text_width(&self) -> usize {
        let prefix: usize = self
            .levels
            .iter()
            .take(MAX_LEVELS)
            .map(|level| match level {
                Level::Quote => 2,
                Level::List { .. } => 0,
                Level::Item { marker, .. } => marker.chars().count(),
            })
            .sum();
        self.width.saturating_sub(prefix).max(MIN_TEXT)
    }

    /// Ends the paragraph: its lines written.
    fn line_break(&mut self) {
        self.space = false;
        if self.paragraph.is_empty() {
            return;
        }
        let paragraph = std::mem::take(&mut self.paragraph);
        self.paragraphs += 1;
        let width = self.text_width();
        for line in paragraph.split('\n') {
            if self.pre > 0 {
                self.line(line);
                continue;
            }
            let mut current = String::new();
            let mut length = 0;
            for word in line.split(' ').filter(|w| !w.is_empty()) {
                let len = word.chars().count();
                if length > 0 && length + 1 + len > width {
                    self.line(&current);
                    current.clear();
                    length = 0;
                }
                if length > 0 {
                    current.push(' ');
                    length += 1;
                }
                current.push_str(word);
                length += len;
            }
            self.line(&current);
        }
    }

    fn paragraph_break(&mut self) {
        self.line_break();
        self.ask_blank();
    }

    fn ask_blank(&mut self) {
        let depth = self.quotes.min(MAX_LEVELS);
        self.blank = Some(self.blank.map_or(depth, |asked| asked.min(depth)));
    }

    /// Writes one line with its prefix.
    fn line(&mut self, text: &str) {
        let text = text.replace('\u{A0}', " ");
        let text = text.trim_end();
        if text.is_empty() && self.in_item_unmarked() {
            // An empty line before an item's first text would draw its marker alone.
            return;
        }
        if let Some(depth) = self.blank.take()
            && !self.out.is_empty()
            && !self.was_blank
        {
            let quotes = ">".repeat(depth.min(self.quotes.min(MAX_LEVELS)));
            self.out.push_str(&quotes);
            self.out.push('\n');
            self.was_blank = true;
        }
        if text.is_empty() && (self.was_blank || self.out.is_empty()) {
            return;
        }
        let mut prefix = String::new();
        for level in self.levels.iter_mut().take(MAX_LEVELS) {
            match level {
                Level::Quote => prefix.push_str("> "),
                Level::List { .. } => {}
                Level::Item { marker, drawn } => {
                    if *drawn {
                        prefix.extend(std::iter::repeat_n(' ', marker.chars().count()));
                    } else {
                        prefix.push_str(marker);
                        *drawn = true;
                    }
                }
            }
        }
        let line = format!("{prefix}{text}");
        self.out.push_str(line.trim_end());
        self.out.push('\n');
        self.was_blank = text.is_empty();
    }

    fn in_item_unmarked(&self) -> bool {
        self.levels.iter().take(MAX_LEVELS).any(|level| matches!(level, Level::Item { drawn: false, .. }))
    }

    fn finish(mut self) -> String {
        self.line_break();
        // Blank lines at the end, quoted or not, are not content.
        while let Some(last) = self.out.trim_end_matches('\n').rsplit('\n').next()
            && !self.out.trim_end_matches('\n').is_empty()
            && last.chars().all(|c| c == '>')
        {
            let end = self.out.trim_end_matches('\n').len() - last.len();
            self.out.truncate(end);
        }
        let end = self.out.trim_end_matches('\n').len();
        self.out.truncate(end);
        self.out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paragraphs_and_line_breaks() {
        assert_eq!(to_text("<p>Hello <b>you</b>,</p><p>second\n  paragraph</p>", 80), "Hello you,\n\nsecond paragraph");
        assert_eq!(to_text("one<br>two<br><br><br>three", 80), "one\ntwo\n\nthree");
        assert_eq!(to_text("<div>a</div><div>b</div>", 80), "a\nb");
        assert_eq!(to_text("<h1>Title</h1>Text", 80), "Title\n\nText");
    }

    #[test]
    fn scripts_styles_and_the_head_are_not_shown() {
        let html = "<html><head><title>T</title><style>p{color:red}</style></head><body><p>Shown</p>\
                    <script>alert('</p>')</script><SCRIPT type=x>document.write(1)</SCRIPT ><p>Too</p></body></html>";
        assert_eq!(to_text(html, 80), "Shown\n\nToo");
        assert_eq!(to_text("<!-- hidden <p>x</p> -->seen<!DOCTYPE html>", 80), "seen");
        assert_eq!(to_text("<head><meta charset=utf-8><body>Body", 80), "Body");
    }

    #[test]
    fn links_show_their_target() {
        assert_eq!(
            to_text(r#"See <a href="https://x.example/a?b=1&amp;c=2">the page</a>."#, 80),
            "See the page <https://x.example/a?b=1&c=2>."
        );
        assert_eq!(to_text("<a href='https://x.example'>https://x.example</a>", 80), "https://x.example");
        assert_eq!(to_text("<a href=mailto:a@x.example>a@x.example</a>", 80), "a@x.example");
        assert_eq!(to_text("<a href=\"#top\">Top</a> <a href=\"javascript:x()\">Run</a>", 80), "Top Run");
        assert_eq!(to_text("<a href=\"https://x.example\"><img src=logo.png></a>", 80), "https://x.example");
        assert_eq!(
            to_text("<a href=\"https://x.example\"><img src=l.png alt=\"Logo\"></a>", 80),
            "Logo <https://x.example>"
        );
    }

    #[test]
    fn lists_are_marked_and_indented() {
        let html =
            "<p>Before</p><ul><li>one<li>two is long enough to wrap here<ol start=3><li>three<li>four</ol></ul>After";
        assert_eq!(
            to_text(html, 20),
            "Before\n\n* one\n* two is long enough\n  to wrap here\n  3. three\n  4. four\n\nAfter"
        );
    }

    #[test]
    fn quotations_are_quoted() {
        let html = "<p>Yes.</p><blockquote><p>Will you come?</p><p>Bring <i>cake</i>.</p>\
                    <blockquote>Earlier</blockquote></blockquote><p>Bye</p>";
        assert_eq!(to_text(html, 80), "Yes.\n\n> Will you come?\n>\n> Bring cake.\n>\n> > Earlier\n\nBye");
    }

    #[test]
    fn preformatted_text_keeps_its_shape() {
        assert_eq!(to_text("<pre>\n  a  b\n\n c</pre>after", 80), "  a  b\n\n c\n\nafter");
    }

    #[test]
    fn character_references() {
        assert_eq!(
            decode("&lt;a&gt; &amp;amp; &quot;&#39;&#x41;&#65&nbsp;&euro;&unknown; & &#0; &#x110000; &#150;"),
            "<a> &amp; \"'AA\u{A0}€&unknown; & \u{FFFD} \u{FFFD} –"
        );
        assert_eq!(to_text("Gr&uuml;&szlig;e,&nbsp;&nbsp;Jana", 80), "Grüße,  Jana");
    }

    #[test]
    fn long_lines_wrap_and_long_words_stay_whole() {
        assert_eq!(to_text("aaa bbb ccc ddd eee fff ggg", 20), "aaa bbb ccc ddd eee\nfff ggg");
        let word = "x".repeat(30);
        assert_eq!(to_text(&format!("a {word} b"), 20), format!("a\n{word}\nb"));
    }

    #[test]
    fn tables_and_rules() {
        assert_eq!(to_text("<table><tr><td>a</td><td>b</td></tr><tr><td>c</td></tr></table>x", 80), "a b\nc\n\nx");
        assert_eq!(
            to_text("a<hr>b", 30),
            "a\n\n----------------------------------------\n\nb".replace(&"-".repeat(40), &"-".repeat(30))
        );
    }

    #[test]
    fn broken_markup_is_read_as_far_as_it_goes() {
        assert_eq!(to_text("a < b and c<d", 80), "a < b and c");
        assert_eq!(to_text("x <p title='>'>y", 80), "x\n\ny");
        assert_eq!(to_text("x<!-- never closed", 80), "x");
        assert_eq!(to_text("x<script>never closed", 80), "x");
        assert_eq!(to_text("</blockquote></ul></li></pre>text", 80), "text");
        assert_eq!(to_text("", 80), "");
    }

    #[test]
    fn hostile_input_takes_linear_work() {
        // Each of these took quadratic time in a naive scan; at this size that would be seconds.
        let n = 200_000;
        let started = std::time::Instant::now();
        for html in [
            "<a".repeat(n),
            "<".repeat(n),
            "<blockquote><ul><li>".repeat(n / 10) + "x",
            "<li>".repeat(n) + &"</blockquote>".repeat(n),
            "<ul>".repeat(n) + &"</ul>".repeat(n),
            "<!--".repeat(n),
            "<script>".to_owned() + &"</scrip".repeat(n),
            "&".repeat(n) + &"&#".repeat(n),
            "<p a='".to_owned() + &"x".repeat(n),
        ] {
            let text = to_text(&html, 80);
            assert!(text.len() <= html.len() * 4);
        }
        assert!(started.elapsed() < std::time::Duration::from_secs(10), "{:?}", started.elapsed());
    }
}
