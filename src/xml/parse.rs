//! DOM-ish XML parser per `docs/rfcs/RFC-002-xml-crypto-core.md` §1.
//!
//! Implementation notes
//! --------------------
//! - Parser is built directly on `quick_xml::Reader<&[u8]>` event stream. We
//!   maintain our own namespace stack rather than using `NsReader` because c14n
//!   needs to see *exactly which namespace declarations are recorded on which
//!   element*, not just the resolved bindings.
//! - Each `Element` owns its children inline (`Vec<Node>` where `Node` may be
//!   `Element`, `Text`, or `Comment`). The `Document` additionally stores a
//!   per-element *path* (a sequence of child indices from the root) keyed by
//!   [`ElementId`], so the opaque handle issued at parse time resolves to a
//!   borrow without any unsafe pointer aliasing.
//! - DTDs, processing instructions, and duplicate ID attributes are rejected
//!   at parse time per RFC-002 §1.1.

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;

use quick_xml::Reader;
use quick_xml::events::Event;
use quick_xml::events::attributes::Attribute as QxAttribute;
use quick_xml::name::{PrefixDeclaration, QName as QxQName};

use crate::error::Error;

// =============================================================================
// QName
// =============================================================================

/// An expanded XML qualified name: namespace URI + local name.
///
/// Equality and hashing are based on the namespace URI and local name only;
/// the *prefix* used in the source document is recorded separately on each
/// `Element` under `namespaces_declared_here` (so canonicalization can
/// reconstruct the exact in-scope namespace declarations).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct QName {
    pub namespace: Option<String>,
    pub local: String,
}

impl QName {
    pub fn new(ns: impl Into<Option<String>>, local: impl Into<String>) -> Self {
        Self {
            namespace: ns.into(),
            local: local.into(),
        }
    }

    pub fn local(&self) -> &str {
        &self.local
    }

    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }
}

impl fmt::Display for QName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.namespace {
            Some(ns) => write!(f, "{{{}}}{}", ns, self.local),
            None => f.write_str(&self.local),
        }
    }
}

// =============================================================================
// Limits
// =============================================================================

/// Parse-time resource limits. Defaults match RFC-002 §1.1.
#[derive(Debug, Clone, Copy)]
pub struct XmlLimits {
    pub max_depth: usize,
    pub max_total_nodes: usize,
    pub max_attribute_count: usize,
    pub max_text_length: usize,
}

impl Default for XmlLimits {
    fn default() -> Self {
        Self {
            max_depth: 100,
            max_total_nodes: 100_000,
            max_attribute_count: 100,
            max_text_length: 1_048_576,
        }
    }
}

// =============================================================================
// Element / Node / ElementId
// =============================================================================

/// Opaque, stable handle to an `Element` within a `Document`.
///
/// Issued by `Document::parse` (or `Document::new` for documents built
/// programmatically); remains valid for the lifetime of the owning document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ElementId(pub(crate) u32);

/// A single XML element with its inline child list.
///
/// The fields mirror RFC-002 §1: `namespaces_declared_here` is the set of
/// `xmlns(:prefix)?="..."` declarations *literally written on this element*
/// (not the in-scope set inherited from ancestors). `attributes` is preserved
/// in document order, after XML 1.0 attribute-value normalization performed by
/// `quick-xml`.
///
/// `source_prefix` is the literal prefix the source document used to qualify
/// this element's name (or `None` for elements written without a prefix,
/// including those bound through the default namespace). Both `Exclusive` and
/// `Inclusive` XML-C14N require canonicalization to emit the prefix the signer
/// actually wrote: when a Keycloak-style assertion declares both `xmlns="…"`
/// and `xmlns:saml="…"` resolving to the same URI on the same element, picking
/// either prefix yields a well-formed document but produces a *different* byte
/// sequence — and therefore a different digest — than the one the signer
/// committed to. Preserving this hint lets c14n reproduce the original prefix
/// choice on canonical emit. For programmatically-built elements the field is
/// `None`; c14n then falls back to whichever in-scope binding resolves the URI.
#[derive(Debug, Clone)]
pub(crate) struct Element {
    pub(crate) qname: QName,
    pub(crate) source_prefix: Option<String>,
    pub(crate) namespaces_declared_here: Vec<(Option<String>, String)>,
    pub(crate) attributes: Vec<Attribute>,
    pub(crate) children: Vec<Node>,
    pub(crate) id: ElementId,
}

/// A single XML attribute on an [`Element`], preserving the source prefix
/// for c14n prefix selection. See the [`Element::source_prefix`] field
/// documentation for why this matters.
#[derive(Debug, Clone)]
pub(crate) struct Attribute {
    pub(crate) qname: QName,
    pub(crate) source_prefix: Option<String>,
    pub(crate) value: String,
}

#[derive(Debug, Clone)]
pub(crate) enum Node {
    Element(Element),
    Text(String),
    Comment(String),
}

impl Element {
    pub(crate) fn qname(&self) -> &QName {
        &self.qname
    }

    pub(crate) fn id(&self) -> ElementId {
        self.id
    }

    pub(crate) fn attribute(&self, namespace: Option<&str>, local: &str) -> Option<&str> {
        for attr in &self.attributes {
            if attr.qname.local == local && attr.qname.namespace.as_deref() == namespace {
                return Some(attr.value.as_str());
            }
        }
        None
    }

    /// Iterate attributes along with the prefix the source document used to
    /// qualify each one. Returns `(qname, source_prefix, value)` per
    /// attribute. The `source_prefix` is the literal prefix string written
    /// in the source XML (for example `"saml"` for `saml:foo="..."`), or
    /// `None` for unprefixed attributes (which per XML Namespaces 1.0 §6.2
    /// have no namespace). c14n uses this to reproduce the signer's prefix
    /// choice when multiple in-scope prefixes resolve to the same URI.
    pub(crate) fn attributes_with_source_prefix(
        &self,
    ) -> impl Iterator<Item = (&QName, Option<&str>, &str)> {
        self.attributes.iter().map(|attr| {
            (
                &attr.qname,
                attr.source_prefix.as_deref(),
                attr.value.as_str(),
            )
        })
    }

    pub(crate) fn children(&self) -> impl Iterator<Item = &Node> {
        self.children.iter()
    }

    pub(crate) fn child_elements(&self) -> impl Iterator<Item = &Element> {
        self.children.iter().filter_map(|child| match child {
            Node::Element(e) => Some(e),
            _ => None,
        })
    }

    pub(crate) fn child_element<'a>(
        &'a self,
        namespace: Option<&str>,
        local: &str,
    ) -> Option<&'a Element> {
        self.child_elements().find(|child| {
            child.qname.local == local && child.qname.namespace.as_deref() == namespace
        })
    }

    pub(crate) fn all_child_elements<'a>(
        &'a self,
        namespace: Option<&str>,
        local: &str,
    ) -> impl Iterator<Item = &'a Element> {
        let ns_owned = namespace.map(str::to_owned);
        let local_owned = local.to_owned();
        self.child_elements().filter(move |child| {
            child.qname.local == local_owned && child.qname.namespace == ns_owned
        })
    }

    /// Concatenation of all *direct* text children, preserving internal
    /// whitespace exactly. Comments and child elements are not traversed.
    pub(crate) fn text_content(&self) -> String {
        let mut out = String::new();
        for child in &self.children {
            if let Node::Text(t) = child {
                out.push_str(t);
            }
        }
        out
    }

    /// Insert `node` into this element's children at `index`. Panics if
    /// `index > self.children.len()` (matches `Vec::insert`).
    ///
    /// This is the single mutable accessor used by outbound signing
    /// (`dsig::sign::sign_element`) to splice a freshly-built `<ds:Signature>`
    /// element into the schema-required `signaturePosition` slot inside a
    /// SAML protocol element. Document ID indices and element paths remain
    /// stale until the element is re-wrapped in `Document::new`, which
    /// renumbers every `ElementId` in document order.
    pub(crate) fn insert_child(&mut self, index: usize, node: Node) {
        self.children.insert(index, node);
    }
}

// =============================================================================
// Document
// =============================================================================

/// Path from the root to an element, as a sequence of `children` indices.
/// A path of `[]` denotes the root itself.
pub(crate) type ElementPath = Vec<u32>;

/// Parsed XML document.
///
/// Owns a single [`Element`] tree (`root`) plus two side indices:
///
/// - `paths`: maps each `ElementId(u32)` (the index) to the sequence of child
///   positions to walk from `root` to reach that element. This lets the opaque
///   handle resolve to a borrow without `unsafe` aliasing.
/// - `id_index`: maps each `ID`/`xml:id` attribute *value* found at parse time
///   to the corresponding `ElementId`. Populated during parse, used for
///   `Reference URI` resolution. Duplicate ID values cause parse failure, so
///   this index is unique by construction (RFC-002 §1.1).
#[derive(Debug, Clone)]
pub(crate) struct Document {
    pub(crate) root: Element,
    pub(crate) id_index: HashMap<String, ElementId>,
    pub(crate) paths: Vec<ElementPath>,
}

impl Document {
    /// Parse XML with default [`XmlLimits`].
    pub(crate) fn parse(xml: &[u8]) -> Result<Document, Error> {
        Self::parse_with_limits(xml, XmlLimits::default())
    }

    /// Parse XML with caller-supplied limits.
    pub(crate) fn parse_with_limits(xml: &[u8], limits: XmlLimits) -> Result<Document, Error> {
        parse_inner(xml, &limits)
    }

    pub(crate) fn root(&self) -> &Element {
        &self.root
    }

    /// Resolve an [`ElementId`] back to its element.
    pub(crate) fn element(&self, id: ElementId) -> Option<&Element> {
        let path = self.paths.get(id.0 as usize)?;
        let mut current: &Element = &self.root;
        for &idx in path {
            let node = current.children.get(idx as usize)?;
            match node {
                Node::Element(child) => current = child,
                _ => return None,
            }
        }
        Some(current)
    }

    /// Look up an element by its parse-time-registered `ID` / `xml:id`
    /// attribute value. Returns `None` if no element declared that value.
    pub(crate) fn element_by_id_attr(&self, id_attr: &str) -> Option<ElementId> {
        self.id_index.get(id_attr).copied()
    }

    /// First element in document order with the given expanded name, anywhere
    /// in the subtree (including the root).
    #[cfg(any(test, feature = "slo"))]
    pub(crate) fn find_first<'a>(
        &'a self,
        namespace: Option<&str>,
        local: &str,
    ) -> Option<&'a Element> {
        find_first_in(&self.root, namespace, local)
    }
}

#[cfg(any(test, feature = "slo"))]
fn find_first_in<'a>(
    element: &'a Element,
    namespace: Option<&str>,
    local: &str,
) -> Option<&'a Element> {
    if element.qname.local == local && element.qname.namespace.as_deref() == namespace {
        return Some(element);
    }
    for child in element.child_elements() {
        if let Some(found) = find_first_in(child, namespace, local) {
            return Some(found);
        }
    }
    None
}

// =============================================================================
// Parser implementation
// =============================================================================

/// The XML namespace URI per XML 1.0 §5. Bound to the `xml:` prefix at all
/// times without an explicit declaration.
pub(crate) const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";

/// Frame on the parser's element-construction stack. Each entry is a
/// partially-built [`Element`] plus the path from the document root needed to
/// register its `ElementId` in the arena.
struct StackFrame {
    element: Element,
    path: ElementPath,
}

/// One layer of the in-scope namespace mapping during parsing. Walked
/// outward-to-inward to resolve `prefix -> URI`.
#[derive(Default)]
struct NsLayer {
    /// `None` key = default namespace declaration.
    bindings: Vec<(Option<Vec<u8>>, String)>,
}

fn resolve_prefix<'a>(stack: &'a [NsLayer], prefix: Option<&[u8]>) -> Option<&'a str> {
    // The implicit `xml:` prefix is always bound.
    if let Some(p) = prefix
        && p == b"xml"
    {
        return Some(XML_NS);
    }
    for layer in stack.iter().rev() {
        for (decl_prefix, uri) in layer.bindings.iter().rev() {
            if decl_prefix.as_deref() == prefix {
                return if uri.is_empty() {
                    None
                } else {
                    Some(uri.as_str())
                };
            }
        }
    }
    None
}

/// Apply XML 1.0 §2.11 end-of-line normalization to the raw input bytes:
/// translate every two-byte `#xD #xA` sequence and every standalone `#xD` to
/// a single `#xA`. Returns a borrowed slice when the input has no `#xD` bytes
/// (the common LF-terminated case) so the fast path is zero-copy.
fn normalize_line_endings(xml: &[u8]) -> Cow<'_, [u8]> {
    if !xml.contains(&b'\r') {
        return Cow::Borrowed(xml);
    }
    let mut out: Vec<u8> = Vec::with_capacity(xml.len());
    // Single-pass scan with a peekable iterator so we can collapse `\r\n`
    // without indexing into the slice (which would trip `clippy::indexing_slicing`).
    let mut iter = xml.iter().peekable();
    while let Some(&b) = iter.next() {
        if b == b'\r' {
            out.push(b'\n');
            // `\r\n` collapses to a single `\n`; standalone `\r` also becomes `\n`.
            if iter.peek().copied().copied() == Some(b'\n') {
                iter.next();
            }
        } else {
            out.push(b);
        }
    }
    Cow::Owned(out)
}

fn parse_inner(xml: &[u8], limits: &XmlLimits) -> Result<Document, Error> {
    // XML 1.0 §2.11 line-end normalization: translate every `#xD #xA` two-byte
    // sequence and every standalone `#xD` to a single `#xA` before parsing.
    // This is the spec's first-pass behavior ("the XML processor must behave as
    // if it normalized all line breaks ... on input, before parsing") and is
    // essential for c14n correctness — without it, text content from CRLF
    // sources contains literal `\r` bytes that c14n escapes as `&#xD;`, and
    // signatures over those texts fail to verify against the signer's
    // canonical bytes (which were computed from a normalized infoset).
    //
    // We use `Cow` so that the common LF-only case stays zero-copy.
    let normalized = normalize_line_endings(xml);
    let mut reader = Reader::from_reader(normalized.as_ref());
    {
        let cfg = reader.config_mut();
        // Distinguish `<x/>` (Empty) from `<x></x>` (Start+End). We use this
        // to avoid pushing a namespace layer for self-closing elements.
        cfg.expand_empty_elements = false;
        // Preserve whitespace exactly; c14n needs faithful text content.
        cfg.trim_text_start = false;
        cfg.trim_text_end = false;
        cfg.check_end_names = true;
    }

    let mut stack: Vec<StackFrame> = Vec::new();
    let mut ns_stack: Vec<NsLayer> = Vec::new();
    let mut paths: Vec<ElementPath> = Vec::new();
    let mut id_index: HashMap<String, ElementId> = HashMap::new();
    let mut completed_root: Option<Element> = None;
    let mut total_nodes: usize = 0;

    loop {
        let event = reader
            .read_event()
            .map_err(|e| Error::XmlParse(format!("quick-xml: {e}")))?;

        match event {
            Event::Eof => break,
            Event::Decl(_) => {
                // XML declaration: skipped. We don't preserve `<?xml ...?>`.
            }
            Event::DocType(_) => {
                return Err(Error::XmlParse("DTDs not allowed".to_string()));
            }
            Event::PI(_) => {
                return Err(Error::XmlParse(
                    "processing instructions not allowed".to_string(),
                ));
            }
            Event::Start(start) => {
                total_nodes = total_nodes
                    .checked_add(1)
                    .ok_or_else(|| Error::XmlParse("max nodes exceeded".to_string()))?;
                if total_nodes > limits.max_total_nodes {
                    return Err(Error::XmlParse("max nodes exceeded".to_string()));
                }
                let (element, path) = open_element(
                    &start,
                    /* self_closing */ false,
                    &stack,
                    &mut ns_stack,
                    &mut paths,
                    &mut id_index,
                    limits,
                )?;
                stack.push(StackFrame { element, path });
                if stack.len() > limits.max_depth {
                    return Err(Error::XmlParse("max depth exceeded".to_string()));
                }
            }
            Event::Empty(start) => {
                total_nodes = total_nodes
                    .checked_add(1)
                    .ok_or_else(|| Error::XmlParse("max nodes exceeded".to_string()))?;
                if total_nodes > limits.max_total_nodes {
                    return Err(Error::XmlParse("max nodes exceeded".to_string()));
                }
                let (element, _path) = open_element(
                    &start,
                    /* self_closing */ true,
                    &stack,
                    &mut ns_stack,
                    &mut paths,
                    &mut id_index,
                    limits,
                )?;
                close_element(element, &mut stack, &mut completed_root)?;
            }
            Event::End(end) => {
                let frame = stack
                    .pop()
                    .ok_or_else(|| Error::XmlParse("unmatched end tag".to_string()))?;
                ns_stack.pop();
                let expected_local = &frame.element.qname.local;
                let actual = end.name();
                let actual_local_name = actual.local_name();
                let actual_local = std::str::from_utf8(actual_local_name.as_ref())
                    .map_err(|err| Error::XmlParse(format!("non-UTF-8 element name: {err}")))?;
                if actual_local != expected_local.as_str() {
                    return Err(Error::XmlParse(format!(
                        "end tag mismatch: expected </{expected_local}>, got </{actual_local}>"
                    )));
                }
                close_element(frame.element, &mut stack, &mut completed_root)?;
            }
            Event::Text(text) => {
                let value = text
                    .unescape()
                    .map_err(|e| Error::XmlParse(format!("text decode: {e}")))?
                    .into_owned();
                if value.len() > limits.max_text_length {
                    return Err(Error::XmlParse("max text length exceeded".to_string()));
                }
                if value.is_empty() {
                    continue;
                }
                push_text(&mut stack, value, &mut total_nodes, limits)?;
            }
            Event::CData(cdata) => {
                let bytes = cdata.into_inner();
                let value = std::str::from_utf8(&bytes)
                    .map_err(|err| Error::XmlParse(format!("non-UTF-8 CDATA: {err}")))?
                    .to_owned();
                if value.len() > limits.max_text_length {
                    return Err(Error::XmlParse("max text length exceeded".to_string()));
                }
                if value.is_empty() {
                    continue;
                }
                push_text(&mut stack, value, &mut total_nodes, limits)?;
            }
            Event::Comment(comment) => {
                let bytes = comment.into_inner();
                let value = std::str::from_utf8(&bytes)
                    .map_err(|err| Error::XmlParse(format!("non-UTF-8 comment: {err}")))?
                    .to_owned();
                if value.len() > limits.max_text_length {
                    return Err(Error::XmlParse("max text length exceeded".to_string()));
                }
                total_nodes = total_nodes
                    .checked_add(1)
                    .ok_or_else(|| Error::XmlParse("max nodes exceeded".to_string()))?;
                if total_nodes > limits.max_total_nodes {
                    return Err(Error::XmlParse("max nodes exceeded".to_string()));
                }
                // Comments outside the root element (e.g. before the document
                // element) are silently dropped — they have nowhere to live in
                // our tree, and SAML never relies on them.
                if let Some(frame) = stack.last_mut() {
                    frame.element.children.push(Node::Comment(value));
                }
            }
        }
    }

    if !stack.is_empty() {
        return Err(Error::XmlParse("unclosed element at EOF".to_string()));
    }

    let root = completed_root.ok_or_else(|| Error::XmlParse("empty document".to_string()))?;
    Ok(Document {
        root,
        id_index,
        paths,
    })
}

fn push_text(
    stack: &mut [StackFrame],
    value: String,
    total_nodes: &mut usize,
    limits: &XmlLimits,
) -> Result<(), Error> {
    let Some(frame) = stack.last_mut() else {
        // Whitespace / text outside the root is silently dropped by quick-xml's
        // event stream behavior; non-whitespace before the root would surface
        // as a parse error before reaching here.
        return Ok(());
    };
    *total_nodes = total_nodes
        .checked_add(1)
        .ok_or_else(|| Error::XmlParse("max nodes exceeded".to_string()))?;
    if *total_nodes > limits.max_total_nodes {
        return Err(Error::XmlParse("max nodes exceeded".to_string()));
    }
    frame.element.children.push(Node::Text(value));
    Ok(())
}

/// Build an [`Element`] from a `<Start>` or `<Empty>` event.
///
/// Side effects:
/// - Pushes the element's `namespaces_declared_here` onto `ns_stack` so that
///   the element's own name/attribute prefix resolution sees its declarations.
/// - If `self_closing`, pops that layer back off (the element has no
///   descendants, so the layer must not leak).
/// - Registers the element's path in `paths` and assigns its `ElementId`.
/// - Inserts an `(id_value -> ElementId)` mapping into `id_index` for any
///   `ID` or `xml:id` attribute; duplicate values fail with `Error::XmlParse`.
fn open_element(
    start: &quick_xml::events::BytesStart<'_>,
    self_closing: bool,
    stack: &[StackFrame],
    ns_stack: &mut Vec<NsLayer>,
    paths: &mut Vec<ElementPath>,
    id_index: &mut HashMap<String, ElementId>,
    limits: &XmlLimits,
) -> Result<(Element, ElementPath), Error> {
    // -------- Pass 1: collect namespace declarations from raw attributes ----
    let mut new_layer = NsLayer::default();
    let mut declared: Vec<(Option<String>, String)> = Vec::new();
    // Raw attributes carry their original key bytes verbatim so that a
    // following resolution pass can both expand the QName *and* record the
    // literal source prefix used to qualify them (needed for c14n prefix
    // selection — see `Element::source_prefix` docs).
    let mut raw_attrs: Vec<(Vec<u8>, String)> = Vec::new();
    let mut attribute_count: usize = 0;

    for attr_result in start.attributes() {
        let attr: QxAttribute<'_> =
            attr_result.map_err(|e| Error::XmlParse(format!("attribute: {e}")))?;

        attribute_count = attribute_count
            .checked_add(1)
            .ok_or_else(|| Error::XmlParse("max attributes per element exceeded".to_string()))?;
        if attribute_count > limits.max_attribute_count {
            return Err(Error::XmlParse(
                "max attributes per element exceeded".to_string(),
            ));
        }

        let key_bytes = attr.key.into_inner().to_vec();
        let value = attr
            .unescape_value()
            .map_err(|e| Error::XmlParse(format!("attribute value decode: {e}")))?
            .into_owned();

        match QxQName(&key_bytes).as_namespace_binding() {
            Some(PrefixDeclaration::Default) => {
                declared.push((None, value.clone()));
                new_layer.bindings.push((None, value));
            }
            Some(PrefixDeclaration::Named(prefix_bytes)) => {
                let prefix_str = std::str::from_utf8(prefix_bytes)
                    .map_err(|err| Error::XmlParse(format!("non-UTF-8 namespace prefix: {err}")))?
                    .to_owned();
                declared.push((Some(prefix_str), value.clone()));
                new_layer
                    .bindings
                    .push((Some(prefix_bytes.to_vec()), value));
            }
            None => {
                raw_attrs.push((key_bytes, value));
            }
        }
    }

    // Make `new_layer` visible for *this* element's own name/attribute
    // resolution. For a Start event the layer will remain on the stack for
    // descendants; for an Empty (self-closing) event we will pop it before
    // returning.
    ns_stack.push(new_layer);

    // -------- Resolve this element's QName ---------------------------------
    let raw_name = start.name();
    let raw_name_bytes = raw_name.into_inner();
    let elem_qname = resolve_qname(raw_name_bytes, ns_stack, /* is_attribute */ false)?;
    let elem_source_prefix = extract_source_prefix(raw_name_bytes)?;

    // -------- Resolve non-namespace attribute QNames -----------------------
    let mut resolved_attrs: Vec<Attribute> = Vec::with_capacity(raw_attrs.len());
    for (key_bytes, value) in raw_attrs {
        let qn = resolve_qname(&key_bytes, ns_stack, /* is_attribute */ true)?;
        let source_prefix = extract_source_prefix(&key_bytes)?;
        resolved_attrs.push(Attribute {
            qname: qn,
            source_prefix,
            value,
        });
    }

    // -------- Compute path + assign ElementId ------------------------------
    let path: ElementPath = if let Some(parent) = stack.last() {
        let mut p = parent.path.clone();
        let child_index = u32::try_from(parent.element.children.len())
            .map_err(|_err| Error::XmlParse("element index exceeds u32::MAX".to_string()))?;
        p.push(child_index);
        p
    } else {
        Vec::new()
    };
    let id_value = ElementId(
        u32::try_from(paths.len())
            .map_err(|_err| Error::XmlParse("element id exceeds u32::MAX".to_string()))?,
    );
    paths.push(path.clone());

    // -------- Register `ID` / `xml:id` attribute in id_index ---------------
    // Rule per RFC-002 §1.1: any attribute whose local name is exactly `ID`
    // (with no namespace), or `xml:id` (local `id` in the XML namespace).
    for attr in &resolved_attrs {
        let is_id_attr = (attr.qname.namespace.is_none() && attr.qname.local == "ID")
            || (attr.qname.namespace.as_deref() == Some(XML_NS) && attr.qname.local == "id");
        if is_id_attr {
            if id_index.contains_key(&attr.value) {
                return Err(Error::XmlParse("duplicate ID".to_string()));
            }
            id_index.insert(attr.value.clone(), id_value);
        }
    }

    let element = Element {
        qname: elem_qname,
        source_prefix: elem_source_prefix,
        namespaces_declared_here: declared,
        attributes: resolved_attrs,
        children: Vec::new(),
        id: id_value,
    };

    if self_closing {
        ns_stack.pop();
    }

    Ok((element, path))
}

fn close_element(
    element: Element,
    stack: &mut [StackFrame],
    completed_root: &mut Option<Element>,
) -> Result<(), Error> {
    if let Some(parent) = stack.last_mut() {
        parent.element.children.push(Node::Element(element));
        Ok(())
    } else if completed_root.is_some() {
        Err(Error::XmlParse(
            "multiple root elements not allowed".to_string(),
        ))
    } else {
        *completed_root = Some(element);
        Ok(())
    }
}

/// Extract the literal prefix substring (if any) from a raw QName byte slice.
/// Returns `Ok(Some("saml"))` for `b"saml:Assertion"`, `Ok(None)` for
/// `b"Assertion"`. Used to thread the source document's prefix choice through
/// to canonicalization so the c14n output matches what the signer hashed.
fn extract_source_prefix(name: &[u8]) -> Result<Option<String>, Error> {
    let q = QxQName(name);
    let (_local, prefix) = q.decompose();
    match prefix {
        Some(p) => {
            let s = std::str::from_utf8(p.as_ref())
                .map_err(|err| Error::XmlParse(format!("non-UTF-8 namespace prefix: {err}")))?;
            Ok(Some(s.to_owned()))
        }
        None => Ok(None),
    }
}

/// Resolve `name` (raw bytes from the source) into an expanded [`QName`].
///
/// For *element* names, an unprefixed name binds to the default namespace
/// (if any). For *attribute* names, an unprefixed name has no namespace
/// regardless of the default declaration (XML Namespaces 1.0 §6.2).
fn resolve_qname(name: &[u8], ns_stack: &[NsLayer], is_attribute: bool) -> Result<QName, Error> {
    let q = QxQName(name);
    let (local, prefix) = q.decompose();
    let local_str = std::str::from_utf8(local.as_ref())
        .map_err(|err| Error::XmlParse(format!("non-UTF-8 local name: {err}")))?
        .to_owned();

    let namespace = match prefix {
        Some(p) => {
            let prefix_bytes = p.as_ref();
            match resolve_prefix(ns_stack, Some(prefix_bytes)) {
                Some(uri) => Some(uri.to_owned()),
                None => {
                    return Err(Error::XmlParse(format!(
                        "unbound namespace prefix: {}",
                        std::str::from_utf8(prefix_bytes).unwrap_or("<invalid utf-8>")
                    )));
                }
            }
        }
        None => {
            if is_attribute {
                None
            } else {
                resolve_prefix(ns_stack, None).map(str::to_owned)
            }
        }
    };

    Ok(QName {
        namespace,
        local: local_str,
    })
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::*;

    fn parse(xml: &str) -> Document {
        Document::parse(xml.as_bytes()).expect("parse should succeed")
    }

    #[test]
    fn parses_simple_document() {
        let doc = parse(r"<root><child>hello</child></root>");
        assert_eq!(doc.root().qname().local(), "root");
        assert_eq!(doc.root().qname().namespace(), None);
        let child = doc.root().child_element(None, "child").unwrap();
        assert_eq!(child.text_content(), "hello");
    }

    #[test]
    fn round_trip_attributes_and_namespaces() {
        let xml = r#"<a:root xmlns:a="urn:a" xmlns="urn:default" a:k="v" plain="p">
            <inner/>
        </a:root>"#;
        let doc = parse(xml);
        assert_eq!(doc.root().qname().namespace(), Some("urn:a"));
        assert_eq!(doc.root().qname().local(), "root");
        assert_eq!(doc.root().attribute(Some("urn:a"), "k"), Some("v"));
        // Unprefixed attribute has no namespace regardless of default xmlns.
        assert_eq!(doc.root().attribute(None, "plain"), Some("p"));

        let inner = doc
            .root()
            .child_element(Some("urn:default"), "inner")
            .unwrap();
        assert_eq!(inner.qname().namespace(), Some("urn:default"));

        let declared = doc.root().namespaces_declared_here.clone();
        assert!(declared.contains(&(Some("a".to_owned()), "urn:a".to_owned())));
        assert!(declared.contains(&(None, "urn:default".to_owned())));
    }

    #[test]
    fn id_attribute_lookup_and_resolution() {
        let xml = r#"<Response xmlns="urn:p" ID="abc"><Assertion ID="xyz"/></Response>"#;
        let doc = parse(xml);
        let response_id = doc.element_by_id_attr("abc").unwrap();
        let assertion_id = doc.element_by_id_attr("xyz").unwrap();
        assert_ne!(response_id, assertion_id);

        let response = doc.element(response_id).unwrap();
        assert_eq!(response.qname().local(), "Response");
        let assertion = doc.element(assertion_id).unwrap();
        assert_eq!(assertion.qname().local(), "Assertion");
    }

    #[test]
    fn xml_id_attribute_is_indexed() {
        let xml = r#"<root xml:id="rooted"><x xml:id="inner"/></root>"#;
        let doc = parse(xml);
        assert_eq!(doc.element_by_id_attr("rooted"), Some(doc.root().id()));
        assert!(doc.element_by_id_attr("inner").is_some());
    }

    #[test]
    fn duplicate_id_rejected() {
        let xml = r#"<root><a ID="dup"/><b ID="dup"/></root>"#;
        let err = Document::parse(xml.as_bytes()).unwrap_err();
        match err {
            Error::XmlParse(msg) => assert!(msg.contains("duplicate ID"), "got: {msg}"),
            _ => panic!("expected XmlParse"),
        }
    }

    #[test]
    fn dtd_rejected() {
        let xml = r"<!DOCTYPE foo><root/>";
        let err = Document::parse(xml.as_bytes()).unwrap_err();
        match err {
            Error::XmlParse(msg) => assert!(msg.contains("DTDs"), "got: {msg}"),
            _ => panic!("expected XmlParse"),
        }
    }

    #[test]
    fn processing_instruction_rejected() {
        let xml = r"<?php evil ?><root/>";
        let err = Document::parse(xml.as_bytes()).unwrap_err();
        match err {
            Error::XmlParse(msg) => assert!(msg.contains("processing instruction"), "got: {msg}"),
            _ => panic!("expected XmlParse"),
        }
    }

    #[test]
    fn comments_preserved() {
        let xml = r"<root><!-- hello --><child/><!-- world --></root>";
        let doc = parse(xml);
        let kinds: Vec<&str> = doc
            .root()
            .children()
            .map(|n| match n {
                Node::Element(_) => "elem",
                Node::Text(_) => "text",
                Node::Comment(_) => "comment",
            })
            .collect();
        assert_eq!(kinds, vec!["comment", "elem", "comment"]);
        let comments: Vec<String> = doc
            .root()
            .children()
            .filter_map(|n| match n {
                Node::Comment(c) => Some(c.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(comments, vec![" hello ".to_string(), " world ".to_string()]);
    }

    #[test]
    fn depth_limit_triggers() {
        let depth = 50;
        let mut xml = String::new();
        for _ in 0..depth {
            xml.push_str("<a>");
        }
        for _ in 0..depth {
            xml.push_str("</a>");
        }
        let limits = XmlLimits {
            max_depth: 10,
            ..XmlLimits::default()
        };
        let err = Document::parse_with_limits(xml.as_bytes(), limits).unwrap_err();
        match err {
            Error::XmlParse(msg) => assert!(msg.contains("max depth"), "got: {msg}"),
            _ => panic!("expected XmlParse"),
        }
    }

    #[test]
    fn node_count_limit_triggers() {
        let mut xml = String::from("<root>");
        for _ in 0..20 {
            xml.push_str("<x/>");
        }
        xml.push_str("</root>");
        let limits = XmlLimits {
            max_total_nodes: 5,
            ..XmlLimits::default()
        };
        let err = Document::parse_with_limits(xml.as_bytes(), limits).unwrap_err();
        match err {
            Error::XmlParse(msg) => assert!(msg.contains("max nodes"), "got: {msg}"),
            _ => panic!("expected XmlParse"),
        }
    }

    #[test]
    fn attribute_count_limit_triggers() {
        let mut xml = String::from("<root");
        for i in 0..20 {
            write!(xml, r#" a{i}="v""#).unwrap();
        }
        xml.push_str("/>");
        let limits = XmlLimits {
            max_attribute_count: 5,
            ..XmlLimits::default()
        };
        let err = Document::parse_with_limits(xml.as_bytes(), limits).unwrap_err();
        match err {
            Error::XmlParse(msg) => assert!(msg.contains("max attributes"), "got: {msg}"),
            _ => panic!("expected XmlParse"),
        }
    }

    #[test]
    fn text_length_limit_triggers() {
        let big = "x".repeat(2048);
        let xml = format!("<root>{big}</root>");
        let limits = XmlLimits {
            max_text_length: 1024,
            ..XmlLimits::default()
        };
        let err = Document::parse_with_limits(xml.as_bytes(), limits).unwrap_err();
        match err {
            Error::XmlParse(msg) => assert!(msg.contains("max text length"), "got: {msg}"),
            _ => panic!("expected XmlParse"),
        }
    }

    #[test]
    fn find_first_recursive() {
        let xml = r#"<a xmlns="urn:n"><b><c>found</c></b></a>"#;
        let doc = parse(xml);
        let c = doc.find_first(Some("urn:n"), "c").unwrap();
        assert_eq!(c.text_content(), "found");
    }

    #[test]
    fn text_content_preserves_internal_whitespace() {
        let xml = "<root>hello   world\n</root>";
        let doc = parse(xml);
        assert_eq!(doc.root().text_content(), "hello   world\n");
    }

    #[test]
    fn unbound_prefix_is_rejected() {
        let xml = r"<a:root/>";
        let err = Document::parse(xml.as_bytes()).unwrap_err();
        assert!(matches!(err, Error::XmlParse(_)));
    }

    #[test]
    fn element_handle_resolution_round_trip() {
        let xml = r"<root><a/><b><c/></b></root>";
        let doc = parse(xml);
        let b = doc.root().child_element(None, "b").unwrap();
        let c = b.child_element(None, "c").unwrap();
        // Resolving each element's own ID should give back the same element.
        assert_eq!(doc.element(c.id()).unwrap().qname().local(), "c");
        assert_eq!(doc.element(b.id()).unwrap().qname().local(), "b");
        assert_eq!(
            doc.element(doc.root().id()).unwrap().qname().local(),
            "root"
        );
    }
}
