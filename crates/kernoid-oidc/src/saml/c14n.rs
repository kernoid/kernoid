// SPDX-License-Identifier: AGPL-3.0-or-later
//! Exclusive XML Canonicalization 1.0 without comments (<http://www.w3.org/2001/10/xml-exc-c14n#>), written from the
//! W3C Recommendation and Canonical XML 1.0, for what an XML signature in SAML references: the subtree of one element,
//! optionally without one descendant (the enveloped signature), with an InclusiveNamespaces PrefixList.
//!
//! - Elements are written `<name`, namespace declarations, attributes, `>`, content, `</name>` – empty ones too.
//! - A namespace declaration is written on an element if the element visibly uses its prefix (its own prefix, or one
//!   of its attributes'; an unprefixed element uses the default namespace) – or the prefix is in the PrefixList and
//!   in scope – and the nearest output ancestor did not write the same prefix with the same URI. `xmlns=""` is written
//!   where the default namespace is used, empty, and an output ancestor wrote a non-empty one. The prefix `xml` is
//!   never declared. Declarations are sorted by prefix (the default first), attributes by namespace URI (none first),
//!   then local name.
//! - Text escapes `&`, `<`, `>` and carriage return; attribute values `&`, `<`, `"`, tab, line feed and carriage
//!   return. Comments are not part of the tree ([`super::dom`] drops them), nor are processing instructions (refused).

use std::collections::BTreeMap;

use super::dom::{Document, Node, NodeId};

/// The canonical form of the element `apex` and everything below it, leaving out `exclude` and its subtree.
pub fn canonicalize(doc: &Document, apex: NodeId, exclude: Option<NodeId>, inclusive: &[String]) -> Vec<u8> {
    let mut out = String::new();
    let rendered = BTreeMap::new();
    write_element(doc, apex, exclude, inclusive, &rendered, &mut out);
    out.into_bytes()
}

fn write_element(
    doc: &Document,
    id: NodeId,
    exclude: Option<NodeId>,
    inclusive: &[String],
    rendered: &BTreeMap<String, String>,
    out: &mut String,
) {
    let Some(element) = doc.element(id) else { return };
    let scope = doc.in_scope(id);

    // The prefixes this element needs declared: those it uses visibly, and those of the PrefixList in scope.
    let mut wanted: Vec<String> = vec![element.prefix.clone()];
    for attribute in &element.attributes {
        if !attribute.prefix.is_empty() {
            wanted.push(attribute.prefix.clone());
        }
    }
    for prefix in inclusive {
        let prefix = if prefix == "#default" { String::new() } else { prefix.clone() };
        if prefix.is_empty() || scope.contains_key(&prefix) {
            wanted.push(prefix);
        }
    }
    wanted.sort();
    wanted.dedup();

    let mut mine = rendered.clone();
    let mut declarations: Vec<(String, String)> = Vec::new();
    for prefix in wanted {
        if prefix == "xml" {
            continue;
        }
        if prefix.is_empty() {
            let value = scope.get("").map(String::as_str).unwrap_or("");
            let before = rendered.get("").map(String::as_str).unwrap_or("");
            if value != before {
                declarations.push((String::new(), value.to_owned()));
                mine.insert(String::new(), value.to_owned());
            }
            continue;
        }
        let Some(value) = scope.get(&prefix) else { continue };
        if rendered.get(&prefix) != Some(value) {
            declarations.push((prefix.clone(), value.clone()));
            mine.insert(prefix, value.clone());
        }
    }

    let name = element.qualified();
    out.push('<');
    out.push_str(&name);
    // `wanted` was sorted, so the declarations are too, the default namespace first.
    for (prefix, uri) in &declarations {
        if prefix.is_empty() {
            out.push_str(" xmlns=\"");
        } else {
            out.push_str(" xmlns:");
            out.push_str(prefix);
            out.push_str("=\"");
        }
        escape_attribute(uri, out);
        out.push('"');
    }
    let mut attributes: Vec<_> = element.attributes.iter().collect();
    attributes.sort_by(|a, b| (a.namespace.as_str(), a.local.as_str()).cmp(&(b.namespace.as_str(), b.local.as_str())));
    for attribute in attributes {
        out.push(' ');
        out.push_str(&attribute.qualified());
        out.push_str("=\"");
        escape_attribute(&attribute.value, out);
        out.push('"');
    }
    out.push('>');
    for child in doc.children(id) {
        if Some(*child) == exclude {
            continue;
        }
        match doc.node(*child) {
            Node::Text(text) => escape_text(text, out),
            Node::Element(_) => write_element(doc, *child, exclude, inclusive, &mine, out),
        }
    }
    out.push_str("</");
    out.push_str(&name);
    out.push('>');
}

fn escape_text(text: &str, out: &mut String) {
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
}

fn escape_attribute(value: &str, out: &mut String) {
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
}

/// The prefixes of an InclusiveNamespaces PrefixList (white space separated; `#default` for the default namespace).
pub fn prefix_list(value: &str) -> Vec<String> {
    value.split([' ', '\t', '\n', '\r']).filter(|token| !token.is_empty()).map(str::to_owned).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c14n(xml: &str) -> String {
        let doc = Document::parse(xml).unwrap();
        String::from_utf8(canonicalize(&doc, doc.root(), None, &[])).unwrap()
    }

    fn c14n_of(xml: &str, id: &str, inclusive: &[&str]) -> String {
        let doc = Document::parse(xml).unwrap();
        let apex = doc.by_id(id).unwrap();
        let inclusive: Vec<String> = inclusive.iter().map(|p| (*p).to_owned()).collect();
        String::from_utf8(canonicalize(&doc, apex, None, &inclusive)).unwrap()
    }

    /// Canonical XML 1.0, 3.2: white space in content is kept.
    #[test]
    fn whitespace_in_document_content() {
        let xml = "<doc>\n   <clean>   </clean>\n   <dirty>   A   B   </dirty>\n   <mixed>\n      A\n      <clean>   </clean>\n      B\n      <dirty>   A   B   </dirty>\n      C\n   </mixed>\n</doc>";
        assert_eq!(c14n(xml), xml);
    }

    /// Canonical XML 1.0, 3.3 (without its DTD): start and end tags, attribute and namespace order, empty elements,
    /// default namespace undeclarations – with the exclusive rules: only visibly used namespaces are written.
    #[test]
    fn start_and_end_tags() {
        let xml = concat!(
            "<doc>\n   <e1   />\n   <e2   ></e2>\n   <e3   name = \"elem3\"   id=\"elem3\"   />\n",
            "   <e4   name=\"elem4\"   id=\"elem4\"   ></e4>\n",
            "   <e5 a:attr=\"out\" b:attr=\"sorted\" attr2=\"all\" attr=\"I'm\"\n",
            "      xmlns:b=\"http://www.ietf.org\"\n      xmlns:a=\"http://www.w3.org\"\n",
            "      xmlns=\"http://example.org\"/>\n",
            "   <e6 xmlns=\"\" xmlns:a=\"http://www.w3.org\">\n      <e7 xmlns=\"http://www.ietf.org\">\n",
            "         <e8 xmlns=\"\" xmlns:a=\"http://www.w3.org\">\n            <e9 xmlns=\"\" xmlns:a=\"http://www.ietf.org\"/>\n",
            "         </e8>\n      </e7>\n   </e6>\n</doc>"
        );
        let expected = concat!(
            "<doc>\n   <e1></e1>\n   <e2></e2>\n   <e3 id=\"elem3\" name=\"elem3\"></e3>\n",
            "   <e4 id=\"elem4\" name=\"elem4\"></e4>\n",
            "   <e5 xmlns=\"http://example.org\" xmlns:a=\"http://www.w3.org\" xmlns:b=\"http://www.ietf.org\" ",
            "attr=\"I'm\" attr2=\"all\" b:attr=\"sorted\" a:attr=\"out\"></e5>\n",
            "   <e6>\n      <e7 xmlns=\"http://www.ietf.org\">\n         <e8 xmlns=\"\">\n            <e9></e9>\n",
            "         </e8>\n      </e7>\n   </e6>\n</doc>"
        );
        assert_eq!(c14n(xml), expected);
    }

    /// Canonical XML 1.0, 3.4 (without its DTD): character modifications and character references.
    #[test]
    fn character_modifications_and_references() {
        let xml = concat!(
            "<doc>\n   <text>First line&#x0d;&#10;Second line</text>\n   <value>&#x32;</value>\n",
            "   <compute><![CDATA[value>\"0\" && value<\"10\" ?\"valid\":\"error\"]]></compute>\n",
            "   <compute expr='value>\"0\" &amp;&amp; value&lt;\"10\" ?\"valid\":\"error\"'>valid</compute>\n",
            "   <norm attr=' &apos;   &#x20;&#13;&#xa;&#9;   &apos; '/>\n</doc>"
        );
        let expected = concat!(
            "<doc>\n   <text>First line&#xD;\nSecond line</text>\n   <value>2</value>\n",
            "   <compute>value&gt;\"0\" &amp;&amp; value&lt;\"10\" ?\"valid\":\"error\"</compute>\n",
            "   <compute expr=\"value>&quot;0&quot; &amp;&amp; value&lt;&quot;10&quot; ?&quot;valid&quot;:&quot;error&quot;\">valid</compute>\n",
            "   <norm attr=\" '    &#xD;&#xA;&#x9;   ' \"></norm>\n</doc>"
        );
        assert_eq!(c14n(xml), expected);
    }

    /// Canonical XML 1.0, 3.1 (the parts without DTD and processing instructions): comments go, the XML declaration
    /// and white space outside the document element are not part of an element's subtree.
    #[test]
    fn comments_and_declaration() {
        let xml = "<?xml version=\"1.0\"?>\n<!-- Comment 1 -->\n<doc>Hello, world!<!-- Comment 2 --></doc>\n<!-- Comment 3 -->";
        assert_eq!(c14n(xml), "<doc>Hello, world!</doc>");
    }

    /// Exclusive XML Canonicalization 1.0, 2.2: the namespaces of an apex's ancestors are not written unless used.
    #[test]
    fn exclusive_example_of_the_recommendation() {
        let xml = concat!(
            "<n0:local xmlns:n0=\"foo:bar\" xmlns:n3=\"ftp://example.org\">",
            "<n1:elem2 xmlns:n1=\"http://example.net\" xml:lang=\"en\" ID=\"e2\">",
            "<n3:stuff xmlns:n3=\"ftp://example.org\"/></n1:elem2></n0:local>"
        );
        assert_eq!(
            c14n_of(xml, "e2", &[]),
            concat!(
                "<n1:elem2 xmlns:n1=\"http://example.net\" ID=\"e2\" xml:lang=\"en\">",
                "<n3:stuff xmlns:n3=\"ftp://example.org\"></n3:stuff></n1:elem2>"
            )
        );
        // The same subtree in a context without n3 on the ancestor canonicalizes the same – exclusively.
        let alone = concat!(
            "<n2:pdu xmlns:n1=\"http://example.com\" xmlns:n2=\"http://foo.example\" xml:lang=\"fr\" xml:space=\"retain\">",
            "<n1:elem2 xmlns:n1=\"http://example.net\" xml:lang=\"en\" ID=\"e2\">",
            "<n3:stuff xmlns:n3=\"ftp://example.org\"/></n1:elem2></n2:pdu>"
        );
        assert_eq!(c14n_of(alone, "e2", &[]), c14n_of(xml, "e2", &[]));
    }

    #[test]
    fn inclusive_prefixes_are_written_where_in_scope() {
        let xml = concat!(
            "<r xmlns=\"urn:d\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">",
            "<v ID=\"v\" xsi:type=\"xs:string\">x</v></r>"
        );
        assert_eq!(
            c14n_of(xml, "v", &[]),
            "<v xmlns=\"urn:d\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" ID=\"v\" xsi:type=\"xs:string\">x</v>"
        );
        assert_eq!(
            c14n_of(xml, "v", &["xs"]),
            concat!(
                "<v xmlns=\"urn:d\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" ",
                "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" ID=\"v\" xsi:type=\"xs:string\">x</v>"
            )
        );
        // A listed prefix not in scope is not written.
        assert!(!c14n_of(xml, "v", &["nope"]).contains("nope"));
    }

    #[test]
    fn default_namespace_undeclarations() {
        let xml = "<a xmlns=\"urn:a\" ID=\"a\"><b xmlns=\"\"><c/></b><p:d xmlns:p=\"urn:p\" xmlns=\"\"/></a>";
        assert_eq!(
            c14n_of(xml, "a", &[]),
            "<a xmlns=\"urn:a\" ID=\"a\"><b xmlns=\"\"><c></c></b><p:d xmlns:p=\"urn:p\"></p:d></a>"
        );
        // An unprefixed apex without a default namespace writes no declaration at all.
        let xml = "<p:a xmlns:p=\"urn:p\"><b ID=\"b\"/></p:a>";
        assert_eq!(c14n_of(xml, "b", &[]), "<b ID=\"b\"></b>");
    }

    #[test]
    fn a_descendant_can_be_left_out() {
        let xml = "<a ID=\"a\"><x/> <s><t/></s> <y/></a>";
        let doc = Document::parse(xml).unwrap();
        let s = doc.child_elements(doc.root()).nth(1).unwrap();
        assert_eq!(
            String::from_utf8(canonicalize(&doc, doc.root(), Some(s), &[])).unwrap(),
            "<a ID=\"a\"><x></x>  <y></y></a>"
        );
    }

    #[test]
    fn the_prefix_list_is_split_on_white_space() {
        assert_eq!(prefix_list(" xs  #default\nsaml "), ["xs", "#default", "saml"]);
    }
}
