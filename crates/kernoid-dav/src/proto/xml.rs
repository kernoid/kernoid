// SPDX-License-Identifier: AGPL-3.0-or-later
//! XML of WebDAV bodies. A request is read whole into a small tree – the bodies are small and their elements may come
//! in any order – with quick-xml's namespace resolution; a response is written by [`Writer`].
//!
//! Reading refuses what XML could be abused with: a document type declaration (and with it every entity of one's own),
//! entity references other than the five predefined, bodies over [`MAX_BODY`], more than [`MAX_DEPTH`] levels and more
//! than [`MAX_ELEMENTS`] elements. Comments and processing instructions are skipped. A prefix that is not declared
//! leaves its element without a namespace rather than failing the request: some clients send such bodies, and the
//! element is then simply unknown.

use std::fmt::Write as _;

use quick_xml::{
    NsReader, XmlVersion,
    escape::escape,
    events::{BytesStart, Event},
    name::ResolveResult,
};

use super::{Error, schema::Namespace};

/// The largest body read.
pub const MAX_BODY: usize = 4 * 1024 * 1024;
/// The deepest nesting of elements.
pub const MAX_DEPTH: usize = 64;
/// The most elements in one body.
pub const MAX_ELEMENTS: usize = 100_000;

/// An element: its namespace (empty for none), local name, attributes and content.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Element {
    pub ns: String,
    pub name: String,
    pub attrs: Vec<Attribute>,
    pub children: Vec<Content>,
}

/// An attribute: its namespace (empty for none – the usual case), local name and value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    pub ns: String,
    pub name: String,
    pub value: String,
}

/// What an element holds: elements and text, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Content {
    Element(Element),
    Text(String),
}

impl Element {
    /// Whether the element is `name` in `ns`.
    pub fn is(&self, ns: Namespace, name: &str) -> bool {
        self.ns == ns.uri() && self.name == name
    }

    /// The elements below this one.
    pub fn elements(&self) -> impl Iterator<Item = &Element> {
        self.children.iter().filter_map(|child| match child {
            Content::Element(element) => Some(element),
            Content::Text(_) => None,
        })
    }

    /// The first element below this one that is `name` in `ns`.
    pub fn child(&self, ns: Namespace, name: &str) -> Option<&Element> {
        self.elements().find(|element| element.is(ns, name))
    }

    /// The elements below this one that are `name` in `ns`.
    pub fn children_named<'a>(&'a self, ns: Namespace, name: &'a str) -> impl Iterator<Item = &'a Element> {
        self.elements().filter(move |element| element.is(ns, name))
    }

    /// The value of the attribute `name` without a namespace.
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs.iter().find(|attr| attr.ns.is_empty() && attr.name == name).map(|attr| attr.value.as_str())
    }

    /// All text in the element and below it.
    pub fn text(&self) -> String {
        let mut out = String::new();
        self.collect_text(&mut out);
        out
    }

    fn collect_text(&self, out: &mut String) {
        for child in &self.children {
            match child {
                Content::Text(text) => out.push_str(text),
                Content::Element(element) => element.collect_text(out),
            }
        }
    }

    /// What the element holds, written as XML that stands on its own: every element declares the default namespace
    /// it needs, so the text can be put into any other document (dead properties, a lock's owner).
    pub fn inner_xml(&self) -> String {
        let mut out = String::new();
        for child in &self.children {
            write_content(&mut out, child, "");
        }
        out
    }
}

fn write_content(out: &mut String, content: &Content, default_ns: &str) {
    match content {
        Content::Text(text) => out.push_str(&escape(text.as_str())),
        Content::Element(element) => {
            let _ = write!(out, "<{}", element.name);
            if element.ns != default_ns {
                let _ = write!(out, " xmlns=\"{}\"", escape(element.ns.as_str()));
            }
            for (number, attr) in element.attrs.iter().enumerate() {
                if attr.ns.is_empty() {
                    let _ = write!(out, " {}=\"{}\"", attr.name, escape(attr.value.as_str()));
                } else {
                    let _ = write!(
                        out,
                        " xmlns:a{number}=\"{}\" a{number}:{}=\"{}\"",
                        escape(attr.ns.as_str()),
                        attr.name,
                        escape(attr.value.as_str())
                    );
                }
            }
            if element.children.is_empty() {
                out.push_str("/>");
            } else {
                out.push('>');
                for child in &element.children {
                    write_content(out, child, &element.ns);
                }
                let _ = write!(out, "</{}>", element.name);
            }
        }
    }
}

fn malformed(error: impl std::fmt::Display) -> Error {
    Error::Malformed(error.to_string())
}

/// Reads a body into its root element.
pub fn parse(body: &[u8]) -> Result<Element, Error> {
    if body.len() > MAX_BODY {
        return Err(Error::TooLarge);
    }
    let text = std::str::from_utf8(body).map_err(|_| Error::NotUtf8)?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut reader = NsReader::from_str(text);
    let mut stack: Vec<Element> = Vec::new();
    let mut root: Option<Element> = None;
    let mut elements = 0usize;
    loop {
        let (ns, event) = reader.read_resolved_event().map_err(malformed)?;
        let ns = match ns {
            ResolveResult::Bound(ns) => String::from_utf8_lossy(ns.as_ref()).into_owned(),
            ResolveResult::Unbound | ResolveResult::Unknown(_) => String::new(),
        };
        match event {
            Event::DocType(_) => return Err(Error::Dtd),
            Event::Start(_) | Event::Empty(_) if root.is_some() => {
                return Err(Error::Malformed("more than one root element".into()));
            }
            Event::Start(start) => {
                elements += 1;
                if elements > MAX_ELEMENTS || stack.len() >= MAX_DEPTH {
                    return Err(Error::TooComplex);
                }
                let element = element(&reader, ns, &start)?;
                stack.push(element);
            }
            Event::Empty(start) => {
                elements += 1;
                if elements > MAX_ELEMENTS || stack.len() >= MAX_DEPTH {
                    return Err(Error::TooComplex);
                }
                let element = element(&reader, ns, &start)?;
                match stack.last_mut() {
                    Some(parent) => parent.children.push(Content::Element(element)),
                    None => root = Some(element),
                }
            }
            Event::End(_) => {
                let element = stack.pop().ok_or_else(|| Error::Malformed("unexpected end tag".into()))?;
                match stack.last_mut() {
                    Some(parent) => parent.children.push(Content::Element(element)),
                    None => root = Some(element),
                }
            }
            Event::Text(text) => {
                let text = text.xml10_content().map_err(malformed)?;
                push_text(&mut stack, &text)?;
            }
            Event::CData(data) => {
                let text = data.decode().map_err(malformed)?;
                push_text(&mut stack, &text)?;
            }
            Event::GeneralRef(reference) => {
                let character = if reference.is_char_ref() {
                    reference.resolve_char_ref().map_err(malformed)?.ok_or(Error::Entity)?
                } else {
                    match &reference[..] {
                        b"amp" => '&',
                        b"lt" => '<',
                        b"gt" => '>',
                        b"apos" => '\'',
                        b"quot" => '"',
                        _ => return Err(Error::Entity),
                    }
                };
                push_text(&mut stack, character.encode_utf8(&mut [0; 4]))?;
            }
            Event::Comment(_) | Event::PI(_) | Event::Decl(_) => {}
            Event::Eof => break,
        }
    }
    if !stack.is_empty() {
        return Err(Error::Malformed("unclosed element".into()));
    }
    root.ok_or_else(|| Error::Malformed("no root element".into()))
}

/// Adds text to the open element, joined with text right before it; outside the root only white space may stand.
fn push_text(stack: &mut [Element], text: &str) -> Result<(), Error> {
    let Some(parent) = stack.last_mut() else {
        return match text.trim().is_empty() {
            true => Ok(()),
            false => Err(Error::Malformed("text outside the root element".into())),
        };
    };
    match parent.children.last_mut() {
        Some(Content::Text(before)) => before.push_str(text),
        _ => parent.children.push(Content::Text(text.to_owned())),
    }
    Ok(())
}

fn element(reader: &NsReader<&[u8]>, ns: String, start: &BytesStart<'_>) -> Result<Element, Error> {
    let name = String::from_utf8_lossy(start.local_name().as_ref()).into_owned();
    let mut attrs = Vec::new();
    for attr in start.attributes() {
        let attr = attr.map_err(malformed)?;
        if attr.key.as_namespace_binding().is_some() {
            continue;
        }
        let (attr_ns, local) = reader.resolver().resolve_attribute(attr.key);
        let attr_ns = match attr_ns {
            ResolveResult::Bound(ns) => String::from_utf8_lossy(ns.as_ref()).into_owned(),
            _ => String::new(),
        };
        let value = attr.normalized_value(XmlVersion::Implicit1_0).map_err(|_| Error::Entity)?;
        attrs.push(Attribute {
            ns: attr_ns,
            name: String::from_utf8_lossy(local.as_ref()).into_owned(),
            value: value.into_owned(),
        });
    }
    Ok(Element { ns, name, attrs, children: Vec::new() })
}

/// A response document. The root declares all of kernoid's prefixes ([`Namespace::ALL`]); elements of other namespaces
/// – dead properties – declare their own.
#[derive(Debug)]
pub struct Writer {
    out: String,
    root: bool,
}

impl Default for Writer {
    fn default() -> Self {
        Self::new()
    }
}

impl Writer {
    pub fn new() -> Self {
        Self { out: String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"), root: true }
    }

    fn name(&mut self, ns: Namespace, name: &str) {
        let _ = write!(self.out, "{}:{name}", ns.prefix());
        if std::mem::take(&mut self.root) {
            for ns in Namespace::ALL {
                let _ = write!(self.out, " xmlns:{}=\"{}\"", ns.prefix(), ns.uri());
            }
        }
    }

    /// `<ns:name` – attributes may follow; [`Self::end_start`] or [`Self::end_empty`] close the tag.
    pub fn start_tag(&mut self, ns: Namespace, name: &str) -> &mut Self {
        self.out.push('<');
        self.name(ns, name);
        self
    }

    pub fn attr(&mut self, name: &str, value: &str) -> &mut Self {
        let _ = write!(self.out, " {name}=\"{}\"", escape(value));
        self
    }

    pub fn end_start(&mut self) {
        self.out.push('>');
    }

    pub fn end_empty(&mut self) {
        self.out.push_str("/>");
    }

    pub fn open(&mut self, ns: Namespace, name: &str) {
        self.start_tag(ns, name).end_start();
    }

    pub fn close(&mut self, ns: Namespace, name: &str) {
        let _ = write!(self.out, "</{}:{name}>", ns.prefix());
    }

    pub fn empty(&mut self, ns: Namespace, name: &str) {
        self.start_tag(ns, name).end_empty();
    }

    /// `<ns:name>text</ns:name>`.
    pub fn text_element(&mut self, ns: Namespace, name: &str, text: &str) {
        self.open(ns, name);
        self.text(text);
        self.close(ns, name);
    }

    /// Text, escaped; a carriage return as `&#13;`, which an XML parser keeps – iCalendar and vCard data in
    /// `calendar-data` and `address-data` end their lines with CRLF, and a bare CR would become LF on reading.
    pub fn text(&mut self, text: &str) {
        self.out.push_str(&escape(text).replace('\r', "&#13;"));
    }

    /// XML written by [`Element::inner_xml`], as it is.
    pub fn raw(&mut self, xml: &str) {
        self.out.push_str(xml);
    }

    /// An element of any namespace, with `content` written by `inner` – for properties kernoid does not know.
    pub fn foreign(&mut self, ns: &str, name: &str, inner: Option<&str>) {
        match Namespace::from_uri(ns) {
            Some(known) => {
                self.start_tag(known, name);
            }
            None if ns.is_empty() => {
                let _ = write!(self.out, "<{name}");
            }
            None => {
                let _ = write!(self.out, "<x:{name} xmlns:x=\"{}\"", escape(ns));
            }
        }
        match inner {
            Some(inner) if !inner.is_empty() => {
                self.out.push('>');
                self.out.push_str(inner);
                match Namespace::from_uri(ns) {
                    Some(known) => self.close(known, name),
                    None if ns.is_empty() => {
                        let _ = write!(self.out, "</{name}>");
                    }
                    None => {
                        let _ = write!(self.out, "</x:{name}>");
                    }
                }
            }
            _ => self.out.push_str("/>"),
        }
    }

    pub fn finish(self) -> String {
        self.out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carriage_returns_survive() {
        let mut writer = Writer::new();
        writer.text("BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n");
        assert!(writer.finish().contains("BEGIN:VCALENDAR&#13;\nEND:VCALENDAR&#13;\n"));
    }

    #[test]
    fn namespaces_resolve_and_text_joins_with_references() {
        let root = parse(
            br#"<?xml version="1.0" encoding="utf-8"?>
            <D:propfind xmlns:D="DAV:" xmlns="urn:x"><D:prop><thing a="1 &amp; 2">x &lt; y &#65;<![CDATA[<z>]]></thing></D:prop></D:propfind>"#,
        )
        .unwrap();
        assert!(root.is(Namespace::Dav, "propfind"));
        let thing = root.child(Namespace::Dav, "prop").unwrap().elements().next().unwrap();
        assert_eq!((thing.ns.as_str(), thing.name.as_str()), ("urn:x", "thing"));
        assert_eq!(thing.attr("a"), Some("1 & 2"));
        assert_eq!(thing.text(), "x < y A<z>");
    }

    #[test]
    fn doctypes_entities_and_size_are_refused() {
        let billion = br#"<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">]><lolz>&lol;</lolz>"#;
        assert_eq!(parse(billion), Err(Error::Dtd));
        assert_eq!(parse(b"<a>&lol;</a>"), Err(Error::Entity));
        assert_eq!(parse(&vec![b' '; MAX_BODY + 1]), Err(Error::TooLarge));
        let deep = "<a>".repeat(MAX_DEPTH + 1) + &"</a>".repeat(MAX_DEPTH + 1);
        assert_eq!(parse(deep.as_bytes()), Err(Error::TooComplex));
        assert!(matches!(parse(b"<a><b></a>"), Err(Error::Malformed(_))));
        assert!(matches!(parse(b"<a/><b/>"), Err(Error::Malformed(_))));
        assert!(matches!(parse(b""), Err(Error::Malformed(_))));
        assert_eq!(parse(&[0xff, 0xfe]), Err(Error::NotUtf8));
    }

    #[test]
    fn inner_xml_stands_on_its_own() {
        let root =
            parse(br#"<p:prop xmlns:p="urn:p" xmlns:q="urn:q"><q:a q:x="1" y="2"><b>t &amp; u</b></q:a>text</p:prop>"#)
                .unwrap();
        let inner = root.inner_xml();
        assert_eq!(inner, r#"<a xmlns="urn:q" xmlns:a0="urn:q" a0:x="1" y="2"><b xmlns="">t &amp; u</b></a>text"#);
        // Read back inside another document, it is the same.
        let again = parse(format!("<w>{inner}</w>").as_bytes()).unwrap();
        assert_eq!(again.children, root.children);
    }

    #[test]
    fn the_writer_declares_once() {
        let mut writer = Writer::new();
        writer.open(Namespace::Dav, "multistatus");
        writer.text_element(Namespace::Dav, "href", "/a&b");
        writer.foreign("urn:other", "thing", Some("1"));
        writer.foreign("", "plain", None);
        writer.close(Namespace::Dav, "multistatus");
        let out = writer.finish();
        assert_eq!(out.matches("<?xml").count(), 1);
        assert!(out.starts_with("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:multistatus xmlns:D=\"DAV:\""));
        assert!(out.contains("<D:href>/a&amp;b</D:href><x:thing xmlns:x=\"urn:other\">1</x:thing><plain/>"), "{out}");
        parse(out.as_bytes()).unwrap();
    }
}
