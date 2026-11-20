// SPDX-License-Identifier: AGPL-3.0-or-later
//! The tree of a SAML message: kernoid's own small DOM on quick-xml, holding exactly what Exclusive XML
//! Canonicalization needs and what kernoid reads – elements with their namespace declarations, attributes and text.
//!
//! The profile is strict: a document type declaration, processing instructions, entity references other than the five
//! predefined ones, characters XML 1.0 does not allow, undeclared prefixes, relative namespace URIs, duplicate
//! attributes (also by expanded name) and two elements with the same `ID` are all refused. Input, depth, nodes and
//! attributes are bounded. Comments are dropped (canonicalization without comments ignores them) and text on both
//! sides of one is joined, so that what kernoid reads is what a signature covers: `a<!---->b` is the text `ab`.
//! CDATA sections become text; line ends are normalized as XML 1.0 says (2.11), attribute values as it says for CDATA
//! attributes (3.3.3).

use std::collections::{BTreeMap, HashMap};

use quick_xml::{
    Reader, XmlVersion,
    events::{BytesStart, Event},
};

use super::SamlError;

/// The largest document parsed.
pub const MAX_INPUT: usize = 512 * 1024;
/// The deepest nesting of elements.
pub const MAX_DEPTH: usize = 64;
/// The most nodes (elements and text) in one document.
pub const MAX_NODES: usize = 50_000;
/// The most attributes and namespace declarations on one element.
pub const MAX_ATTRIBUTES: usize = 64;

const XML_NAMESPACE: &str = "http://www.w3.org/XML/1998/namespace";
const XMLNS_NAMESPACE: &str = "http://www.w3.org/2000/xmlns/";

pub type NodeId = usize;

#[derive(Debug, Clone)]
pub(crate) enum Node {
    Element(Element),
    Text(String),
}

/// An element as written: its prefix (empty for none), local name and namespace (empty for none), the namespaces it
/// declares itself (`""` the default namespace; an empty URI undeclares it), its attributes and children.
#[derive(Debug, Clone)]
pub struct Element {
    pub prefix: String,
    pub local: String,
    pub namespace: String,
    pub declarations: Vec<(String, String)>,
    pub attributes: Vec<Attribute>,
    pub(crate) children: Vec<NodeId>,
    pub(crate) parent: Option<NodeId>,
    /// Bytes of the source: from `<` to the end of the end tag.
    pub span: (usize, usize),
    /// The byte after the start tag's `>`.
    pub content_start: usize,
}

impl Element {
    /// The name as written, `prefix:local` or `local`.
    pub fn qualified(&self) -> String {
        if self.prefix.is_empty() { self.local.clone() } else { format!("{}:{}", self.prefix, self.local) }
    }
}

/// An attribute (not a namespace declaration): prefix, local name, namespace (empty for none) and normalized value.
#[derive(Debug, Clone)]
pub struct Attribute {
    pub prefix: String,
    pub local: String,
    pub namespace: String,
    pub value: String,
}

impl Attribute {
    pub fn qualified(&self) -> String {
        if self.prefix.is_empty() { self.local.clone() } else { format!("{}:{}", self.prefix, self.local) }
    }
}

/// A parsed document.
#[derive(Debug, Clone)]
pub struct Document {
    nodes: Vec<Node>,
    root: NodeId,
    ids: HashMap<String, NodeId>,
}

fn fail<T>(message: impl Into<String>) -> Result<T, SamlError> {
    Err(SamlError(message.into()))
}

fn malformed<T>(what: impl std::fmt::Display) -> Result<T, SamlError> {
    fail(format!("the message is not well-formed XML: {what}"))
}

/// Whether `c` is a character XML 1.0 allows (production 2, Char).
fn is_xml_char(c: char) -> bool {
    matches!(c, '\u{9}' | '\u{A}' | '\u{D}' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}')
}

fn check_chars(text: &str) -> Result<(), SamlError> {
    match text.chars().all(is_xml_char) {
        true => Ok(()),
        false => malformed("a character XML does not allow"),
    }
}

/// Line ends as XML 1.0 normalizes them: `\r\n` and a lone `\r` become `\n`.
fn normalize_line_ends(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\r', "\n")
}

/// A name without a colon in it, as XML Namespaces 1.0 requires of prefixes and local names.
fn check_ncname(name: &str) -> Result<(), SamlError> {
    let mut chars = name.chars();
    let first_ok = chars.next().is_some_and(|c| c.is_alphabetic() || c == '_');
    if !first_ok || !chars.all(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '.' | '\u{B7}')) {
        return malformed(format!("{name:?} is not a name"));
    }
    Ok(())
}

/// Splits `prefix:local`.
fn split_name(name: &[u8]) -> Result<(String, String), SamlError> {
    let name = std::str::from_utf8(name).map_err(|_| SamlError("a name is not UTF-8".into()))?;
    let (prefix, local) = match name.split_once(':') {
        Some((prefix, local)) => (prefix, local),
        None => ("", name),
    };
    if !prefix.is_empty() {
        check_ncname(prefix)?;
    }
    check_ncname(local)?;
    Ok((prefix.to_owned(), local.to_owned()))
}

/// What the parser keeps of an open element.
struct Open {
    id: NodeId,
    scope: BTreeMap<String, String>,
}

impl Document {
    /// Parses `xml` (UTF-8) into its tree, refusing everything outside the profile.
    pub fn parse(xml: &str) -> Result<Self, SamlError> {
        if xml.len() > MAX_INPUT {
            return fail("the message is too large");
        }
        // A DTD is refused before anything else is looked at.
        if xml.to_ascii_uppercase().contains("<!DOCTYPE") {
            return fail("the message contains a DTD");
        }
        let offset = if xml.starts_with('\u{feff}') { '\u{feff}'.len_utf8() } else { 0 };
        let mut reader = Reader::from_str(&xml[offset..]);
        let config = reader.config_mut();
        config.check_comments = true;
        config.check_end_names = true;
        config.expand_empty_elements = false;
        config.allow_dangling_amp = false;
        config.allow_unmatched_ends = false;
        config.trim_text_start = false;
        config.trim_text_end = false;

        let mut nodes: Vec<Node> = Vec::new();
        let mut stack: Vec<Open> = Vec::new();
        let mut root: Option<NodeId> = None;
        let mut ids: HashMap<String, NodeId> = HashMap::new();
        let mut seen_anything = false;
        loop {
            let start = offset + usize::try_from(reader.buffer_position()).unwrap_or(usize::MAX);
            let event = match reader.read_event() {
                Ok(event) => event,
                Err(e) => return malformed(e),
            };
            let end = offset + usize::try_from(reader.buffer_position()).unwrap_or(usize::MAX);
            match event {
                Event::DocType(_) => return fail("the message contains a DTD"),
                Event::PI(_) => return fail("the message contains a processing instruction"),
                Event::Decl(decl) => {
                    if seen_anything {
                        return malformed("the XML declaration is not at the start");
                    }
                    let version = decl.version().map_err(|e| SamlError(format!("bad XML declaration: {e}")))?;
                    if version.as_ref() != b"1.0" {
                        return fail("only XML 1.0 is accepted");
                    }
                    if let Some(encoding) = decl.encoding() {
                        let encoding = encoding.map_err(|e| SamlError(format!("bad XML declaration: {e}")))?;
                        if !encoding.eq_ignore_ascii_case(b"utf-8") {
                            return fail("only UTF-8 is accepted");
                        }
                    }
                }
                Event::Start(_) | Event::Empty(_) if root.is_some() && stack.is_empty() => {
                    return malformed("more than one root element");
                }
                Event::Start(ref tag) | Event::Empty(ref tag) => {
                    if stack.len() >= MAX_DEPTH {
                        return fail("the message is nested too deeply");
                    }
                    if nodes.len() >= MAX_NODES {
                        return fail("the message has too many nodes");
                    }
                    let parent = stack.last();
                    let (element, scope) = element(tag, parent.map(|open| &open.scope), parent.map(|open| open.id))?;
                    let id = nodes.len();
                    if let Some(value) = element.attributes.iter().find(|a| a.namespace.is_empty() && a.local == "ID")
                        && ids.insert(value.value.clone(), id).is_some()
                    {
                        return fail("two elements of the message have the same ID");
                    }
                    nodes.push(Node::Element(Element { span: (start, end), content_start: end, ..element }));
                    match stack.last() {
                        Some(open) => push_child(&mut nodes, open.id, id),
                        None => root = Some(id),
                    }
                    if matches!(event, Event::Start(_)) {
                        stack.push(Open { id, scope });
                    }
                }
                Event::End(_) => {
                    let open = stack.pop().ok_or_else(|| SamlError("unexpected end tag".into()))?;
                    if let Node::Element(element) = &mut nodes[open.id] {
                        element.span.1 = end;
                    }
                }
                Event::Text(text) => {
                    let raw = text.decode().map_err(|e| SamlError(format!("the message is not UTF-8: {e}")))?;
                    if raw.contains("]]>") {
                        return malformed("]]> in text");
                    }
                    let text = normalize_line_ends(&raw);
                    check_chars(&text)?;
                    push_text(&mut nodes, &stack, &text)?;
                }
                Event::CData(data) => {
                    let raw = data.decode().map_err(|e| SamlError(format!("the message is not UTF-8: {e}")))?;
                    let text = normalize_line_ends(&raw);
                    check_chars(&text)?;
                    if stack.is_empty() {
                        return malformed("character data outside the root element");
                    }
                    push_text(&mut nodes, &stack, &text)?;
                }
                Event::GeneralRef(reference) => {
                    let character = if reference.is_char_ref() {
                        match reference.resolve_char_ref() {
                            Ok(Some(c)) if is_xml_char(c) => c,
                            _ => return malformed("a character reference XML does not allow"),
                        }
                    } else {
                        match &reference[..] {
                            b"amp" => '&',
                            b"lt" => '<',
                            b"gt" => '>',
                            b"apos" => '\'',
                            b"quot" => '"',
                            _ => return fail("the message refers to an entity other than the predefined ones"),
                        }
                    };
                    if stack.is_empty() {
                        return malformed("a reference outside the root element");
                    }
                    push_text(&mut nodes, &stack, character.encode_utf8(&mut [0; 4]))?;
                }
                Event::Comment(_) => {}
                Event::Eof => break,
            }
            seen_anything = true;
        }
        if !stack.is_empty() {
            return malformed("an element is not closed");
        }
        let root = root.ok_or_else(|| SamlError("the message is empty".into()))?;
        Ok(Self { nodes, root, ids })
    }

    /// The document element.
    pub fn root(&self) -> NodeId {
        self.root
    }

    pub fn element(&self, id: NodeId) -> Option<&Element> {
        match self.nodes.get(id) {
            Some(Node::Element(element)) => Some(element),
            _ => None,
        }
    }

    pub(crate) fn node(&self, id: NodeId) -> &Node {
        &self.nodes[id]
    }

    /// Whether `id` is the element `local` in `namespace`.
    pub fn is(&self, id: NodeId, namespace: &str, local: &str) -> bool {
        self.element(id).is_some_and(|element| element.namespace == namespace && element.local == local)
    }

    /// The value of the attribute `name` without a namespace.
    pub fn attribute(&self, id: NodeId, name: &str) -> Option<&str> {
        self.element(id)?
            .attributes
            .iter()
            .find(|attribute| attribute.namespace.is_empty() && attribute.local == name)
            .map(|attribute| attribute.value.as_str())
    }

    /// The child nodes, elements and text.
    pub fn children(&self, id: NodeId) -> &[NodeId] {
        self.element(id).map(|element| element.children.as_slice()).unwrap_or_default()
    }

    /// The child elements.
    pub fn child_elements(&self, id: NodeId) -> impl Iterator<Item = NodeId> + '_ {
        self.children(id).iter().copied().filter(|child| self.element(*child).is_some())
    }

    /// The child elements that are `local` in `namespace`.
    pub fn children_named<'d>(
        &'d self,
        id: NodeId,
        namespace: &'d str,
        local: &'d str,
    ) -> impl Iterator<Item = NodeId> + 'd {
        self.child_elements(id).filter(move |child| self.is(*child, namespace, local))
    }

    /// Whether all text directly in the element is white space.
    pub fn has_only_space_text(&self, id: NodeId) -> bool {
        self.children(id).iter().all(|child| match &self.nodes[*child] {
            Node::Text(text) => text.chars().all(|c| matches!(c, ' ' | '\t' | '\n' | '\r')),
            Node::Element(_) => true,
        })
    }

    /// All text in the element and below it, in order.
    pub fn text(&self, id: NodeId) -> String {
        let mut out = String::new();
        self.collect_text(id, &mut out);
        out
    }

    fn collect_text(&self, id: NodeId, out: &mut String) {
        for child in self.children(id) {
            match &self.nodes[*child] {
                Node::Text(text) => out.push_str(text),
                Node::Element(_) => self.collect_text(*child, out),
            }
        }
    }

    /// The element whose `ID` attribute is `value`.
    pub fn by_id(&self, value: &str) -> Option<NodeId> {
        self.ids.get(value).copied()
    }

    /// Every `ID` value in the document.
    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.ids.keys().map(String::as_str)
    }

    /// The parent element.
    pub fn parent(&self, id: NodeId) -> Option<NodeId> {
        self.element(id)?.parent
    }

    /// The namespaces in scope on an element: prefix (`""` the default namespace) → URI. The default namespace is
    /// left out where it is undeclared; `xml` is never listed.
    pub fn in_scope(&self, id: NodeId) -> BTreeMap<String, String> {
        let mut chain = Vec::new();
        let mut current = Some(id);
        while let Some(node) = current {
            chain.push(node);
            current = self.parent(node);
        }
        let mut scope = BTreeMap::new();
        for node in chain.into_iter().rev() {
            if let Some(element) = self.element(node) {
                for (prefix, uri) in &element.declarations {
                    scope.insert(prefix.clone(), uri.clone());
                }
            }
        }
        scope.retain(|prefix, uri| !(prefix.is_empty() && uri.is_empty()));
        scope
    }
}

fn push_child(nodes: &mut [Node], parent: NodeId, child: NodeId) {
    if let Node::Element(element) = &mut nodes[parent] {
        element.children.push(child);
    }
}

/// Adds text to the open element, joined with text right before it; outside the root only white space may stand.
fn push_text(nodes: &mut Vec<Node>, stack: &[Open], text: &str) -> Result<(), SamlError> {
    let Some(open) = stack.last() else {
        return match text.chars().all(|c| matches!(c, ' ' | '\t' | '\n' | '\r')) {
            true => Ok(()),
            false => malformed("text outside the root element"),
        };
    };
    let last = match &nodes[open.id] {
        Node::Element(element) => element.children.last().copied(),
        Node::Text(_) => None,
    };
    if let Some(last) = last
        && let Node::Text(before) = &mut nodes[last]
    {
        before.push_str(text);
        return Ok(());
    }
    if nodes.len() >= MAX_NODES {
        return fail("the message has too many nodes");
    }
    let id = nodes.len();
    nodes.push(Node::Text(text.to_owned()));
    push_child(nodes, open.id, id);
    Ok(())
}

/// An element from its start tag, with the namespaces in scope on it.
fn element(
    tag: &BytesStart<'_>,
    scope: Option<&BTreeMap<String, String>>,
    parent: Option<NodeId>,
) -> Result<(Element, BTreeMap<String, String>), SamlError> {
    let (prefix, local) = split_name(tag.name().as_ref())?;
    let mut declarations: Vec<(String, String)> = Vec::new();
    let mut raw_attributes: Vec<(String, String, String)> = Vec::new();
    for attribute in tag.attributes() {
        let attribute = attribute.or_else(malformed)?;
        if attribute.value.contains(&b'<') {
            return malformed("< in an attribute value");
        }
        let value = attribute.normalized_value(XmlVersion::Implicit1_0).or_else(|e| {
            fail(format!("an attribute value refers to an entity other than the predefined ones or is malformed: {e}"))
        })?;
        check_chars(&value)?;
        let key = std::str::from_utf8(attribute.key.as_ref()).map_err(|_| SamlError("a name is not UTF-8".into()))?;
        if key == "xmlns" {
            if value == XML_NAMESPACE || value == XMLNS_NAMESPACE {
                return fail("a reserved namespace is declared as the default namespace");
            }
            declarations.push((String::new(), value.into_owned()));
        } else if let Some(declared) = key.strip_prefix("xmlns:") {
            check_ncname(declared)?;
            match declared {
                "xmlns" => return fail("the prefix xmlns is declared"),
                "xml" if value != XML_NAMESPACE => return fail("the prefix xml is bound to another namespace"),
                _ if declared != "xml" && (value == XML_NAMESPACE || value == XMLNS_NAMESPACE) => {
                    return fail("a reserved namespace is bound to another prefix");
                }
                _ if value.is_empty() => return fail("a prefix is undeclared"),
                _ => {}
            }
            declarations.push((declared.to_owned(), value.into_owned()));
        } else {
            let (attribute_prefix, attribute_local) = split_name(key.as_bytes())?;
            raw_attributes.push((attribute_prefix, attribute_local, value.into_owned()));
        }
        if declarations.len() + raw_attributes.len() > MAX_ATTRIBUTES {
            return fail("an element has too many attributes");
        }
    }
    for (_, uri) in &declarations {
        // C14N refuses relative namespace URIs; SAML has none.
        if !uri.is_empty() && !uri.contains(':') {
            return fail("a namespace URI is relative");
        }
    }
    let mut scope = scope.cloned().unwrap_or_default();
    for (declared, uri) in &declarations {
        scope.insert(declared.clone(), uri.clone());
    }
    let resolve = |prefix: &str| -> Result<String, SamlError> {
        match prefix {
            "xml" => Ok(XML_NAMESPACE.to_owned()),
            "xmlns" => fail("the prefix xmlns is used on a name"),
            _ => match scope.get(prefix) {
                Some(uri) => Ok(uri.clone()),
                None if prefix.is_empty() => Ok(String::new()),
                None => fail(format!("the prefix {prefix} is not declared")),
            },
        }
    };
    let namespace = resolve(&prefix)?;
    let mut attributes = Vec::with_capacity(raw_attributes.len());
    for (attribute_prefix, attribute_local, value) in raw_attributes {
        // Unprefixed attributes are in no namespace.
        let attribute_namespace = if attribute_prefix.is_empty() { String::new() } else { resolve(&attribute_prefix)? };
        if attributes
            .iter()
            .any(|other: &Attribute| other.namespace == attribute_namespace && other.local == attribute_local)
        {
            return malformed("an attribute appears twice");
        }
        attributes.push(Attribute {
            prefix: attribute_prefix,
            local: attribute_local,
            namespace: attribute_namespace,
            value,
        });
    }
    let element = Element {
        prefix,
        local,
        namespace,
        declarations,
        attributes,
        children: Vec::new(),
        parent,
        span: (0, 0),
        content_start: 0,
    };
    Ok((element, scope))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comments_are_dropped_and_text_joined() {
        let doc = Document::parse("<a>user@a<!---->.com<!-- x --></a>").unwrap();
        assert_eq!(doc.text(doc.root()), "user@a.com");
        assert_eq!(doc.children(doc.root()).len(), 1);
    }

    #[test]
    fn attribute_values_are_normalized() {
        let doc = Document::parse("<a b=\"x\ty\r\nz&#xA;&#9;&amp;\"/>").unwrap();
        assert_eq!(doc.attribute(doc.root(), "b"), Some("x y z\n\t&"));
    }

    #[test]
    fn line_ends_in_text_are_normalized() {
        let doc = Document::parse("<a>1\r\n2\r3&#xD;</a>").unwrap();
        assert_eq!(doc.text(doc.root()), "1\n2\n3\r");
    }

    #[test]
    fn what_is_outside_the_profile_is_refused() {
        for (xml, why) in [
            ("<!DOCTYPE a [<!ENTITY e \"x\">]><a>&e;</a>", "DTD"),
            ("<!doctype a><a/>", "DTD"),
            ("<a>&e;</a>", "entity"),
            ("<a b=\"&e;\"/>", "entity"),
            ("<?pi x?><a/>", "processing instruction"),
            ("<a><?pi x?></a>", "processing instruction"),
            ("<p:a/>", "not declared"),
            ("<a xmlns:p=\"urn:x\"><p:b/><q:c/></a>", "not declared"),
            ("<a xmlns:p=\"\"/>", "undeclared"),
            ("<a xmlns=\"relative\"/>", "relative"),
            ("<a b=\"1\" b=\"2\"/>", "duplicated"),
            ("<a xmlns:p=\"urn:x\" xmlns:q=\"urn:x\" p:b=\"1\" q:b=\"2\"/>", "twice"),
            ("<a><b ID=\"x\"/><c ID=\"x\"/></a>", "same ID"),
            ("<a/><b/>", "more than one root"),
            ("<a>&#0;</a>", "character"),
            ("<a>&#x1;</a>", "character"),
            ("<a>\u{1}</a>", "character"),
            ("<a><b></a>", "well-formed"),
            ("<a>", "not closed"),
            ("", "empty"),
            ("<?xml version=\"1.1\"?><a/>", "XML 1.0"),
            ("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><a/>", "UTF-8"),
            ("<a b=\"<\"/>", "<"),
        ] {
            let error = Document::parse(xml).unwrap_err().to_string();
            assert!(error.contains(why), "{xml}: {error}");
        }
    }

    #[test]
    fn size_and_depth_are_bounded() {
        let deep = format!("{}{}", "<a>".repeat(MAX_DEPTH + 1), "</a>".repeat(MAX_DEPTH + 1));
        assert!(Document::parse(&deep).unwrap_err().to_string().contains("deeply"));
        let wide = format!("<a>{}</a>", "<b/>".repeat(MAX_NODES));
        assert!(Document::parse(&wide).unwrap_err().to_string().contains("too many nodes"));
        let large = format!("<a>{}</a>", "x".repeat(MAX_INPUT));
        assert!(Document::parse(&large).unwrap_err().to_string().contains("too large"));
        let attributes: String = (0..=MAX_ATTRIBUTES).map(|n| format!(" a{n}=\"\"")).collect();
        assert!(Document::parse(&format!("<a{attributes}/>")).unwrap_err().to_string().contains("too many attributes"));
    }

    #[test]
    fn spans_point_into_the_source() {
        let xml = "<?xml version=\"1.0\"?>\n<a xmlns=\"urn:a\"><b x=\"1\">t</b><c/></a>";
        let doc = Document::parse(xml).unwrap();
        let b = doc.child_elements(doc.root()).next().unwrap();
        let element = doc.element(b).unwrap();
        assert_eq!(&xml[element.span.0..element.span.1], "<b x=\"1\">t</b>");
        assert_eq!(&xml[element.content_start..element.span.1], "t</b>");
        assert_eq!(element.namespace, "urn:a");
        let c = doc.child_elements(doc.root()).nth(1).unwrap();
        let element = doc.element(c).unwrap();
        assert_eq!(&xml[element.span.0..element.span.1], "<c/>");
    }
}
