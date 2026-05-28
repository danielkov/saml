//! Minimal serializer for `Document` / `Element` trees, plus a builder
//! API for constructing documents programmatically (used by metadata and
//! protocol emission paths).
//!
//! This module is *not* a canonicalizer. Canonicalization (Exclusive /
//! Inclusive C14N) is a separate transform performed by `dsig::c14n`. The
//! output of `emit_document` is well-formed XML suitable for the wire,
//! but its byte representation is not guaranteed to be canonical — that
//! guarantee is provided by c14n applied on top of the same parsed tree.
//!
//! Design choices:
//!
//! - Hand-emitted strings (no `quick_xml::Writer`) so that namespace
//!   declarations are written *exactly as recorded on each element*
//!   (`namespaces_declared_here`) and attribute order is preserved verbatim.
//! - Character data is XML-escaped per the well-formedness rules:
//!   `& < >` in text, `& < " \r` in attribute values. (Newlines and tabs in
//!   attribute values are also numeric-escaped because XML 1.0 §3.3.3
//!   normalizes them to spaces on parse, so a round-trip requires escape on
//!   emit. c14n applies its own stricter escaping rules.)
//! - Prefix selection: when an element or attribute has a namespace URI, we
//!   walk the in-scope namespace stack (computed during the emit traversal)
//!   and pick the most recently declared prefix bound to that URI. This makes
//!   round-tripping deterministic for any document where each namespace URI
//!   is consistently declared with the same prefix (the SAML common case).

use std::collections::HashMap;

use crate::error::Error;

use super::parse::{
    Attribute, Document, Element, ElementId, ElementPath, Node, QName, XML_NS,
};

// =============================================================================
// Constructor API: build documents programmatically for outbound XML.
// =============================================================================

impl Document {
    /// Wrap a freshly-built [`Element`] tree into a [`Document`], assigning
    /// fresh [`ElementId`]s in document order and populating the `ID` /
    /// `xml:id` index.
    ///
    /// Returns `Error::XmlParse("duplicate ID")` if the freshly-built tree
    /// contains conflicting `ID` attribute values, mirroring the parse-time
    /// rule (RFC-002 §1.1) so programmatic emit cannot smuggle in an
    /// XSW-prone document either.
    pub(crate) fn new(root: Element) -> Result<Self, Error> {
        let mut paths: Vec<ElementPath> = Vec::new();
        let mut id_index: HashMap<String, ElementId> = HashMap::new();
        let mut root = root;
        let mut current_path: ElementPath = Vec::new();
        renumber(&mut root, &mut current_path, &mut paths, &mut id_index)?;
        Ok(Document {
            root,
            id_index,
            paths,
        })
    }
}

fn renumber(
    element: &mut Element,
    current_path: &mut ElementPath,
    paths: &mut Vec<ElementPath>,
    id_index: &mut HashMap<String, ElementId>,
) -> Result<(), Error> {
    let new_id = ElementId(
        u32::try_from(paths.len())
            .map_err(|_err| Error::XmlEmit("element id exceeds u32::MAX".to_string()))?,
    );
    element.id = new_id;
    paths.push(current_path.clone());

    for attr in &element.attributes {
        let is_id_attr = (attr.qname.namespace.is_none() && attr.qname.local == "ID")
            || (attr.qname.namespace.as_deref() == Some(XML_NS) && attr.qname.local == "id");
        if is_id_attr {
            if id_index.contains_key(&attr.value) {
                return Err(Error::XmlParse("duplicate ID".to_string()));
            }
            id_index.insert(attr.value.clone(), new_id);
        }
    }

    // Recurse into element children in document order, threading the path
    // through so each descendant gets a unique ElementId in DFS pre-order.
    for (child_idx, child) in element.children.iter_mut().enumerate() {
        if let Node::Element(child_elem) = child {
            let idx = u32::try_from(child_idx)
                .map_err(|_err| Error::XmlEmit("child index exceeds u32::MAX".to_string()))?;
            current_path.push(idx);
            renumber(child_elem, current_path, paths, id_index)?;
            current_path.pop();
        }
    }

    Ok(())
}

impl Element {
    /// Start building an [`Element`] with the given expanded name.
    pub(crate) fn build(qname: QName) -> ElementBuilder {
        ElementBuilder {
            qname,
            namespaces: Vec::new(),
            attributes: Vec::new(),
            children: Vec::new(),
        }
    }
}

/// Fluent builder for an [`Element`] subtree. Returned from
/// [`Element::build`]. The resulting [`Element`] has placeholder
/// `ElementId(0)`; once the whole tree is wrapped in
/// [`Document::new`] every element receives its real document-order ID.
pub(crate) struct ElementBuilder {
    qname: QName,
    namespaces: Vec<(Option<String>, String)>,
    attributes: Vec<Attribute>,
    children: Vec<Node>,
}

impl ElementBuilder {
    /// Add an attribute with no recorded source prefix. Programmatic emission
    /// has no signer-original prefix to preserve, so c14n falls back to
    /// whichever in-scope binding resolves the URI.
    pub(crate) fn with_attribute(mut self, name: QName, value: impl Into<String>) -> Self {
        self.attributes.push(Attribute {
            qname: name,
            source_prefix: None,
            value: value.into(),
        });
        self
    }

    pub(crate) fn with_namespace(
        mut self,
        prefix: Option<String>,
        uri: impl Into<String>,
    ) -> Self {
        self.namespaces.push((prefix, uri.into()));
        self
    }

    pub(crate) fn with_child(mut self, node: Node) -> Self {
        self.children.push(node);
        self
    }

    pub(crate) fn with_text(mut self, text: impl Into<String>) -> Self {
        self.children.push(Node::Text(text.into()));
        self
    }

    pub(crate) fn finish(self) -> Element {
        Element {
            qname: self.qname,
            source_prefix: None,
            namespaces_declared_here: self.namespaces,
            attributes: self.attributes,
            children: self.children,
            id: ElementId(0), // placeholder; reassigned by `Document::new`
        }
    }
}

// =============================================================================
// Serialization
// =============================================================================

/// Serialize an entire document. The output starts at the root element; no
/// `<?xml ?>` declaration is emitted (callers that need one can prepend it).
pub(crate) fn emit_document(doc: &Document) -> Result<String, Error> {
    emit_element(doc.root())
}

/// Serialize a single element (and its subtree) in document order.
pub(crate) fn emit_element(element: &Element) -> Result<String, Error> {
    let mut out = String::new();
    let mut ns_stack: Vec<Vec<(Option<String>, String)>> = Vec::new();
    emit_element_inner(element, &mut out, &mut ns_stack)?;
    Ok(out)
}

fn emit_element_inner(
    element: &Element,
    out: &mut String,
    ns_stack: &mut Vec<Vec<(Option<String>, String)>>,
) -> Result<(), Error> {
    // Push this element's namespace declarations onto the in-scope stack so
    // they're visible when resolving the element's own QName + attribute
    // QNames during this serialization pass.
    ns_stack.push(element.namespaces_declared_here.clone());

    // Open tag.
    out.push('<');
    let elem_prefix: Option<String> =
        resolve_prefix_for_emit(element.qname.namespace.as_deref(), ns_stack)?.map(str::to_owned);
    write_qualified_name(out, elem_prefix.as_deref(), &element.qname.local);

    // Namespace declarations, in the order they were recorded.
    for (prefix, uri) in &element.namespaces_declared_here {
        out.push(' ');
        match prefix {
            None => out.push_str("xmlns"),
            Some(p) => {
                out.push_str("xmlns:");
                out.push_str(p);
            }
        }
        out.push_str("=\"");
        push_attr_escaped(out, uri);
        out.push('"');
    }

    // Attributes, in recorded order.
    for attr in &element.attributes {
        out.push(' ');
        let attr_prefix: Option<String> =
            resolve_prefix_for_attribute(attr.qname.namespace.as_deref(), ns_stack)?
                .map(str::to_owned);
        write_qualified_name(out, attr_prefix.as_deref(), &attr.qname.local);
        out.push_str("=\"");
        push_attr_escaped(out, &attr.value);
        out.push('"');
    }

    if element.children.is_empty() {
        out.push_str("/>");
    } else {
        out.push('>');
        for child in &element.children {
            match child {
                Node::Element(e) => emit_element_inner(e, out, ns_stack)?,
                Node::Text(t) => push_text_escaped(out, t),
                Node::Comment(c) => {
                    if c.contains("--") || c.ends_with('-') {
                        return Err(Error::XmlEmit(
                            "comment content forms invalid XML comment".to_string(),
                        ));
                    }
                    out.push_str("<!--");
                    out.push_str(c);
                    out.push_str("-->");
                }
            }
        }
        out.push_str("</");
        write_qualified_name(out, elem_prefix.as_deref(), &element.qname.local);
        out.push('>');
    }

    ns_stack.pop();
    Ok(())
}

/// Find the prefix bound to `uri` in the in-scope namespace stack.
/// Returns `None` for the default namespace (no prefix).
///
/// For *element* names: `None` for `uri` means "no namespace"; if that's
/// matched by the default declaration (`xmlns=""` or no declaration), we
/// return `Ok(None)` (unprefixed). For named namespaces, the most recent
/// matching binding wins.
fn resolve_prefix_for_emit<'a>(
    uri: Option<&str>,
    ns_stack: &'a [Vec<(Option<String>, String)>],
) -> Result<Option<&'a str>, Error> {
    let Some(uri) = uri else {
        return Ok(None);
    };
    if uri == XML_NS {
        return Ok(Some("xml"));
    }
    // Walk inward-to-outward (most recent declarations first).
    for layer in ns_stack.iter().rev() {
        for (prefix, declared_uri) in layer.iter().rev() {
            if declared_uri == uri {
                return Ok(prefix.as_deref());
            }
        }
    }
    Err(Error::XmlEmit(format!(
        "no namespace prefix in scope for URI {uri}"
    )))
}

/// Attribute-specific variant of [`resolve_prefix_for_emit`]: an unprefixed
/// attribute name is *never* in the default namespace (XML Namespaces 1.0
/// §6.2), so a namespaced attribute must use a non-default prefix.
fn resolve_prefix_for_attribute<'a>(
    uri: Option<&str>,
    ns_stack: &'a [Vec<(Option<String>, String)>],
) -> Result<Option<&'a str>, Error> {
    let Some(uri) = uri else {
        return Ok(None);
    };
    if uri == XML_NS {
        return Ok(Some("xml"));
    }
    for layer in ns_stack.iter().rev() {
        for (prefix, declared_uri) in layer.iter().rev() {
            if declared_uri == uri && prefix.is_some() {
                return Ok(prefix.as_deref());
            }
        }
    }
    Err(Error::XmlEmit(format!(
        "no non-default namespace prefix in scope for attribute URI {uri}"
    )))
}

fn write_qualified_name(out: &mut String, prefix: Option<&str>, local: &str) {
    if let Some(p) = prefix {
        out.push_str(p);
        out.push(':');
    }
    out.push_str(local);
}

/// Escape text content per XML 1.0 §2.4.
fn push_text_escaped(out: &mut String, text: &str) {
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            // Carriage returns must be escaped so that XML 1.0 line-ending
            // normalization (CR/CRLF -> LF) doesn't change the value on
            // re-parse.
            '\r' => out.push_str("&#13;"),
            c => out.push(c),
        }
    }
}

/// Escape an attribute value per XML 1.0 §3.3.3 / well-formedness rules.
fn push_attr_escaped(out: &mut String, value: &str) {
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            // Tab, newline, carriage return inside attribute values are
            // normalized to space on re-parse unless escaped numerically.
            '\t' => out.push_str("&#9;"),
            '\n' => out.push_str("&#10;"),
            '\r' => out.push_str("&#13;"),
            c => out.push(c),
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(xml: &str) -> Document {
        Document::parse(xml.as_bytes()).expect("parse")
    }

    #[test]
    fn emit_round_trip_simple() {
        let xml = r"<root><child>hello</child></root>";
        let doc = parse(xml);
        let out = emit_document(&doc).unwrap();
        // Re-parse and compare structurally.
        let doc2 = Document::parse(out.as_bytes()).unwrap();
        assert_eq!(doc2.root().qname().local(), "root");
        let child = doc2.root().child_element(None, "child").unwrap();
        assert_eq!(child.text_content(), "hello");
    }

    #[test]
    fn emit_preserves_namespaces() {
        let xml = r#"<a:root xmlns:a="urn:a" xmlns="urn:default" a:k="v"><inner/></a:root>"#;
        let doc = parse(xml);
        let out = emit_document(&doc).unwrap();
        assert!(out.contains(r#"xmlns:a="urn:a""#));
        assert!(out.contains(r#"xmlns="urn:default""#));
        assert!(out.contains(r#"a:k="v""#));
        // Round-trip stability of namespace bindings.
        let doc2 = Document::parse(out.as_bytes()).unwrap();
        assert_eq!(doc2.root().qname().namespace(), Some("urn:a"));
        assert_eq!(doc2.root().attribute(Some("urn:a"), "k"), Some("v"));
    }

    #[test]
    fn emit_escapes_text_and_attributes() {
        // Build programmatically so we can exercise the escapes directly.
        let root = Element::build(QName::new(None, "root"))
            .with_attribute(QName::new(None, "k"), "a\"<&\nb")
            .with_text("<&>")
            .finish();
        let doc = Document::new(root).unwrap();
        let out = emit_document(&doc).unwrap();
        assert!(out.contains(r#"k="a&quot;&lt;&amp;&#10;b""#), "got: {out}");
        assert!(out.contains("&lt;&amp;&gt;"), "got: {out}");
    }

    #[test]
    fn emit_self_closing_for_empty_element() {
        let root = Element::build(QName::new(None, "x")).finish();
        let doc = Document::new(root).unwrap();
        let out = emit_document(&doc).unwrap();
        assert_eq!(out, "<x/>");
    }

    #[test]
    fn emit_preserves_comments() {
        let xml = r"<root><!-- keep --><x/></root>";
        let doc = parse(xml);
        let out = emit_document(&doc).unwrap();
        assert!(out.contains("<!-- keep -->"));
    }

    #[test]
    fn builder_id_index_populates() {
        let inner = Element::build(QName::new(None, "Assertion"))
            .with_attribute(QName::new(None, "ID"), "xyz")
            .finish();
        let outer = Element::build(QName::new(None, "Response"))
            .with_attribute(QName::new(None, "ID"), "abc")
            .with_child(Node::Element(inner))
            .finish();
        let doc = Document::new(outer).unwrap();
        let abc = doc.element_by_id_attr("abc").unwrap();
        let xyz = doc.element_by_id_attr("xyz").unwrap();
        assert_eq!(doc.element(abc).unwrap().qname().local(), "Response");
        assert_eq!(doc.element(xyz).unwrap().qname().local(), "Assertion");
    }

    #[test]
    fn builder_rejects_duplicate_id() {
        let a = Element::build(QName::new(None, "a"))
            .with_attribute(QName::new(None, "ID"), "dup")
            .finish();
        let b = Element::build(QName::new(None, "b"))
            .with_attribute(QName::new(None, "ID"), "dup")
            .finish();
        let root = Element::build(QName::new(None, "root"))
            .with_child(Node::Element(a))
            .with_child(Node::Element(b))
            .finish();
        let err = Document::new(root).unwrap_err();
        match err {
            Error::XmlParse(msg) => assert!(msg.contains("duplicate ID")),
            _ => panic!("expected XmlParse"),
        }
    }

    #[test]
    fn programmatic_namespaced_emit() {
        // Build <a:root xmlns:a="urn:a"><a:child a:k="v"/></a:root>.
        let child = Element::build(QName::new(Some("urn:a".to_owned()), "child"))
            .with_attribute(QName::new(Some("urn:a".to_owned()), "k"), "v")
            .finish();
        let root = Element::build(QName::new(Some("urn:a".to_owned()), "root"))
            .with_namespace(Some("a".to_owned()), "urn:a")
            .with_child(Node::Element(child))
            .finish();
        let doc = Document::new(root).unwrap();
        let out = emit_document(&doc).unwrap();
        assert!(out.contains("<a:root"), "got: {out}");
        assert!(out.contains("xmlns:a=\"urn:a\""), "got: {out}");
        assert!(out.contains("<a:child"), "got: {out}");
        assert!(out.contains("a:k=\"v\""), "got: {out}");

        // Re-parse and structurally check.
        let doc2 = Document::parse(out.as_bytes()).unwrap();
        assert_eq!(doc2.root().qname().namespace(), Some("urn:a"));
        let child2 = doc2
            .root()
            .child_element(Some("urn:a"), "child")
            .unwrap();
        assert_eq!(child2.attribute(Some("urn:a"), "k"), Some("v"));
    }

    #[test]
    fn emit_single_element_requires_in_scope_declarations() {
        // emit_element walks only the element's own + descendant namespace
        // declarations; it does not synthesize declarations from ancestor
        // context. This is fine for the canonicalize-and-sign pipeline because
        // canonicalization handles inclusive-namespace surfacing separately.
        // Documenting the behavior so future callers don't expect otherwise.
        let xml = r#"<root xmlns="urn:n"><a><b>x</b></a></root>"#;
        let doc = parse(xml);
        let a = doc.root().child_element(Some("urn:n"), "a").unwrap();
        emit_element(a).unwrap_err();

        // Emitting the root itself, which carries the declaration, works.
        let out = emit_element(doc.root()).unwrap();
        assert!(out.contains("xmlns=\"urn:n\""));
        assert!(out.contains("<a>"));
        assert!(out.contains("<b>x</b>"));
    }
}
