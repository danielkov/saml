//! XML-DSig `<ds:Reference>` resolution + Transforms whitelist.
//!
//! See `docs/rfcs/RFC-002-xml-crypto-core.md` §3.1.
//!
//! Design notes
//! ------------
//! - The transforms accepted by `AllowedTransform` form a hard whitelist;
//!   any other URI is rejected at verification time with
//!   `Error::DisallowedTransform`. This is the structural defense against
//!   XSLT/XPath/base64-transform escalation vectors (RFC-002 §8).
//! - `URI` resolution is constrained to the empty string (the document root)
//!   and `#xyz` ID references. Arbitrary XPointer fragments and external
//!   references are rejected with `Error::ReferenceResolution`. ID lookup
//!   goes through the parser's `id_index`, which is unique by construction
//!   because duplicate `ID` attributes fail the parse (RFC-002 §1.1).
//! - Enveloped-signature handling is implemented as a *clone-then-canonicalize*
//!   pass: we copy the resolved subtree into a fresh tree, dropping the
//!   `<ds:Signature>` descendant during the copy, then canonicalize. This
//!   avoids any mutation of the original `Document` and keeps c14n's API
//!   untouched.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;

use crate::dsig::algorithms::{C14nAlgorithm, DigestAlgorithm};
use crate::dsig::c14n::canonicalize;
use crate::error::Error;
use crate::xml::parse::{Document, Element, ElementId, Node};

/// XML-DSig namespace URI.
pub(crate) const DS_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
/// Exclusive XML Canonicalization namespace URI (used by
/// `<ec:InclusiveNamespaces>`).
pub(crate) const EC_NS: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";

/// Algorithm URI for the enveloped-signature transform.
pub(crate) const ENVELOPED_SIGNATURE_URI: &str =
    "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

/// Transforms the library accepts inside `<ds:Reference/Transforms>`. Per
/// RFC-002 §3.1 step 1: any transform NOT in this whitelist is rejected at
/// verification time with `Error::DisallowedTransform`. XSLT, XPath, and
/// base64 transforms are explicitly excluded — they are common XSW escalation
/// vectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AllowedTransform {
    /// `http://www.w3.org/2000/09/xmldsig#enveloped-signature` — strip the
    /// `<ds:Signature>` element from the subtree before hashing.
    EnvelopedSignature,
    /// `http://www.w3.org/2001/10/xml-exc-c14n#`
    ExclusiveCanonical,
    /// `http://www.w3.org/2001/10/xml-exc-c14n#WithComments`
    ExclusiveCanonicalWithComments,
    /// `http://www.w3.org/TR/2001/REC-xml-c14n-20010315`
    InclusiveCanonical,
    /// `http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments`
    InclusiveCanonicalWithComments,
}

impl AllowedTransform {
    pub(crate) fn from_uri(uri: &str) -> Result<Self, Error> {
        match uri {
            ENVELOPED_SIGNATURE_URI => Ok(Self::EnvelopedSignature),
            "http://www.w3.org/2001/10/xml-exc-c14n#" => Ok(Self::ExclusiveCanonical),
            "http://www.w3.org/2001/10/xml-exc-c14n#WithComments" => {
                Ok(Self::ExclusiveCanonicalWithComments)
            }
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315" => Ok(Self::InclusiveCanonical),
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments" => {
                Ok(Self::InclusiveCanonicalWithComments)
            }
            _ => Err(Error::DisallowedTransform {
                transform: uri.to_owned(),
            }),
        }
    }

/// Map a transform to its corresponding [`C14nAlgorithm`], if any. The
    /// enveloped-signature transform has no canonicalization counterpart and
    /// returns `None`.
    pub(crate) fn as_c14n_algorithm(self) -> Option<C14nAlgorithm> {
        match self {
            Self::EnvelopedSignature => None,
            Self::ExclusiveCanonical => Some(C14nAlgorithm::ExclusiveCanonical),
            Self::ExclusiveCanonicalWithComments => {
                Some(C14nAlgorithm::ExclusiveCanonicalWithComments)
            }
            Self::InclusiveCanonical => Some(C14nAlgorithm::InclusiveCanonical),
            Self::InclusiveCanonicalWithComments => {
                Some(C14nAlgorithm::InclusiveCanonicalWithComments)
            }
        }
    }
}

/// Parsed `<ds:Reference>` ready for digest computation.
#[derive(Debug, Clone)]
pub(crate) struct ParsedReference {
    /// The `ElementId` of the element referenced by `Reference/@URI`. For
    /// `URI=""` (root), this is `document.root().id()`. For `URI="#xyz"`, this
    /// is the result of `document.element_by_id_attr("xyz")` — which is unique
    /// by construction because duplicate IDs are rejected at parse time
    /// (RFC-002 §1.1).
    pub target: ElementId,
    /// Transforms to apply, in declared order.
    pub transforms: Vec<AllowedTransform>,
    /// `DigestMethod/@Algorithm` parsed to enum.
    pub digest_algorithm: DigestAlgorithm,
    /// `DigestValue` base64-decoded.
    pub digest_value: Vec<u8>,
    /// Optional `<ec:InclusiveNamespaces PrefixList="…">` from the Transforms
    /// chain. Used by `c14n` when an Exclusive transform is applied. The
    /// literal token strings are preserved here (including the `#default`
    /// sentinel, which the c14n module knows how to interpret).
    pub inclusive_namespace_prefixes: Vec<String>,
}

/// Parse one `<ds:Reference>` element. Multiple references in a `<ds:SignedInfo>`
/// are rejected by the caller (`verify::parse_signed_info`), per RFC-002 §3.1.
pub(crate) fn parse_reference(
    document: &Document,
    reference: &Element,
) -> Result<ParsedReference, Error> {
    // ---- @URI -> target ElementId ------------------------------------------
    let uri_attr = reference.attribute(None, "URI").unwrap_or("");
    let target = resolve_uri(document, uri_attr)?;

    // ---- <ds:Transforms> ---------------------------------------------------
    let mut transforms: Vec<AllowedTransform> = Vec::new();
    let mut inclusive_namespace_prefixes: Vec<String> = Vec::new();

    if let Some(transforms_elem) = reference.child_element(Some(DS_NS), "Transforms") {
        for transform_elem in transforms_elem.all_child_elements(Some(DS_NS), "Transform") {
            let alg_uri = transform_elem
                .attribute(None, "Algorithm")
                .ok_or_else(|| Error::DisallowedTransform {
                    transform: String::new(),
                })?;
            let kind = AllowedTransform::from_uri(alg_uri)?;
            transforms.push(kind);

            // Capture any <ec:InclusiveNamespaces PrefixList="..."> nested
            // inside this <ds:Transform>. The PrefixList belongs to whichever
            // Exclusive c14n transform it sits under; we collect it into a
            // single list because v0.1 SAML signatures have at most one
            // Exclusive transform in the chain, so the lists never compete.
            if let Some(incl) = transform_elem.child_element(Some(EC_NS), "InclusiveNamespaces")
                && let Some(list) = incl.attribute(None, "PrefixList")
            {
                for token in list.split_whitespace() {
                    inclusive_namespace_prefixes.push(token.to_owned());
                }
            }
        }
    }

    // SAML profile: c14n must be the LAST transform applied (or only). This
    // means at most one c14n transform and, if present, it must be the final
    // entry. enveloped-signature must precede it.
    let c14n_indices: Vec<usize> = transforms
        .iter()
        .enumerate()
        .filter(|(_, t)| t.as_c14n_algorithm().is_some())
        .map(|(i, _)| i)
        .collect();
    if c14n_indices.len() > 1 {
        return Err(Error::DisallowedTransform {
            transform: "multiple c14n transforms in Reference".to_owned(),
        });
    }
    if let Some(&idx) = c14n_indices.first()
        && Some(idx) != transforms.len().checked_sub(1)
    {
        return Err(Error::DisallowedTransform {
            transform: "c14n transform must be the final transform".to_owned(),
        });
    }

    // ---- <ds:DigestMethod> -------------------------------------------------
    let digest_method = reference
        .child_element(Some(DS_NS), "DigestMethod")
        .ok_or(Error::SignatureVerification {
            reason: "Reference missing DigestMethod",
        })?;
    let digest_alg_uri = digest_method
        .attribute(None, "Algorithm")
        .ok_or(Error::SignatureVerification {
            reason: "DigestMethod missing Algorithm",
        })?;
    let digest_algorithm = DigestAlgorithm::from_uri(digest_alg_uri)?;

    // ---- <ds:DigestValue> --------------------------------------------------
    let digest_value_elem =
        reference
            .child_element(Some(DS_NS), "DigestValue")
            .ok_or(Error::SignatureVerification {
                reason: "Reference missing DigestValue",
            })?;
    let digest_text = digest_value_elem.text_content();
    let digest_value = decode_base64_lenient(&digest_text)?;

    Ok(ParsedReference {
        target,
        transforms,
        digest_algorithm,
        digest_value,
        inclusive_namespace_prefixes,
    })
}

/// Resolve a `Reference/@URI` value to a target [`ElementId`].
///
/// Empty (or missing) `URI` resolves to the document root. `#xyz` resolves via
/// the `id_index` populated at parse time. Anything else — including arbitrary
/// XPointer fragments — is rejected with `Error::ReferenceResolution`. We
/// deliberately do not support external references or XPointer beyond plain
/// ID lookup.
fn resolve_uri(document: &Document, uri: &str) -> Result<ElementId, Error> {
    if uri.is_empty() {
        return Ok(document.root().id());
    }
    if let Some(rest) = uri.strip_prefix('#') {
        // Reject anything that looks like an XPointer expression: a bare ID
        // is just `name`, never `xpointer(...)` or similar.
        if rest.is_empty() || rest.starts_with("xpointer") || rest.contains('(') {
            return Err(Error::ReferenceResolution);
        }
        return document
            .element_by_id_attr(rest)
            .ok_or(Error::ReferenceResolution);
    }
    Err(Error::ReferenceResolution)
}

/// Tolerate XML whitespace inside the base64 payload of `<ds:DigestValue>`,
/// `<ds:SignatureValue>`, and inline `<ds:X509Certificate>` blobs. SAML
/// emitters routinely insert line breaks at 76 columns; we strip them rather
/// than failing the decode. Whitespace is stripped into a byte buffer (no
/// intermediate `String` allocation).
pub(crate) fn decode_base64_lenient(input: &str) -> Result<Vec<u8>, Error> {
    let mut cleaned: Vec<u8> = Vec::with_capacity(input.len());
    for &b in input.as_bytes() {
        // ASCII whitespace: space, tab, LF, CR, VT, FF. base64 alphabet is
        // pure ASCII, so byte-level filtering is sufficient.
        if !matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c) {
            cleaned.push(b);
        }
    }
    BASE64_STANDARD
        .decode(&cleaned)
        .map_err(|_e| Error::Base64Decode)
}

/// Compute the digest of the resolved reference target, applying transforms
/// in declared order. Returns the byte digest; caller compares to
/// `digest_value`.
///
/// `enclosing_signature` is the `ElementId` of the `<ds:Signature>` whose
/// `<ds:SignedInfo>` contains this `<ds:Reference>`. When the
/// `enveloped-signature` transform is in the chain, *only that one* signature
/// is removed from the subtree before canonicalization — per the XML-DSig
/// spec, the enveloped-signature transform removes the Signature element
/// containing the SignedInfo containing the Reference containing the
/// transform definition. Other `<ds:Signature>` elements nested inside the
/// signed subtree (e.g. an inner `<saml:Assertion>` signature on a
/// double-signed `<samlp:Response>`) must be preserved verbatim.
///
/// Implementation notes
/// --------------------
/// - The enveloped-signature transform is implemented by cloning the resolved
///   subtree, omitting *only the enclosing* `<ds:Signature>` (identified by
///   its `ElementId`) during the clone. The clone preserves the ancestor
///   namespace context (which c14n walks via the unchanged `ancestor_chain`
///   arg), so the canonical output is byte-identical to what an in-place
///   removal of that one signature would produce.
/// - The SAML profile mandates that c14n is the *last* transform; that is
///   validated by `parse_reference`. Multiple c14n transforms in a row would
///   require feeding bytes into another transform, which we do not support
///   in v0.1.
/// - If no c14n transform is declared, we fall back to Exclusive C14N (no
///   comments) which is the SAML default. This matches what most real-world
///   IdPs emit; per RFC 3275 a missing c14n on the Reference is technically a
///   degenerate case but pragmatically common enough that hard-rejecting it
///   would break interop.
pub(crate) fn compute_reference_digest(
    document: &Document,
    parsed: &ParsedReference,
    enclosing_signature: ElementId,
) -> Result<Vec<u8>, Error> {
    let target = document
        .element(parsed.target)
        .ok_or(Error::ReferenceResolution)?;

    // Build the ancestor chain (root .. parent-of-target) from the document.
    let chain = ancestor_chain(document, parsed.target).ok_or(Error::ReferenceResolution)?;

    // Decide whether to strip the <ds:Signature> child before c14n.
    let strip_signature = parsed
        .transforms
        .contains(&AllowedTransform::EnvelopedSignature);

    // Pick the c14n algorithm. SAML's overwhelming default is Exclusive
    // (no comments) and that's what we use when no c14n transform is
    // declared in the Reference.
    let c14n_alg = parsed
        .transforms
        .iter()
        .find_map(|t| t.as_c14n_algorithm())
        .unwrap_or(C14nAlgorithm::ExclusiveCanonical);

    let prefix_refs: Vec<&str> = parsed
        .inclusive_namespace_prefixes
        .iter()
        .map(String::as_str)
        .collect();

    let canonical_bytes = if strip_signature {
        // Clone the target subtree, dropping *only* the enclosing
        // <ds:Signature> (identified by its ElementId) during the clone. Any
        // other <ds:Signature> elements nested inside the subtree (e.g. a
        // separately-signed <saml:Assertion>) are preserved — those signatures
        // are part of the bytes the outer signer committed to. The original
        // ancestor chain is reused — `canonicalize` only reads
        // `namespaces_declared_here` off ancestor elements, never their
        // `ElementId` or children, so mixing a cloned target with
        // originally-borrowed ancestors is safe.
        let pruned = clone_excluding_id(target, enclosing_signature);
        canonicalize(document, &pruned, &chain, c14n_alg, &prefix_refs)?
    } else {
        canonicalize(document, target, &chain, c14n_alg, &prefix_refs)?
    };

    Ok(parsed.digest_algorithm.digest(&canonical_bytes))
}

/// Build the document-order ancestor chain (root .. parent-of-target) of a
/// given element. Returns `None` if the ID is not valid for the document.
///
/// Implementation: walks the `paths` index — every `ElementId` resolves to a
/// sequence of child-indices from the root. Walking all but the last index
/// yields the parent chain.
pub(crate) fn ancestor_chain(
    document: &Document,
    target: ElementId,
) -> Option<Vec<&Element>> {
    let path = document.paths.get(target.0 as usize)?;
    let mut chain: Vec<&Element> = Vec::with_capacity(path.len());
    let mut current: &Element = &document.root;
    if path.is_empty() {
        // Target is the root itself; no ancestors.
        return Some(Vec::new());
    }
    chain.push(current);
    // Walk all but the last path step (which would land *on* the target).
    // `path` is non-empty (handled above), so the slice up to len-1 is well
    // defined; use a checked range to avoid the indexing/arithmetic lints.
    let last = path.len().checked_sub(1)?;
    let parents = path.get(..last)?;
    for &idx in parents {
        let child_node = current.children().nth(idx as usize)?;
        match child_node {
            Node::Element(child) => {
                current = child;
                chain.push(current);
            }
            _ => return None,
        }
    }
    Some(chain)
}

/// Deep-clone `element`, dropping any descendant element whose `ElementId`
/// matches `excluded`. The clone preserves namespace declarations,
/// attributes, and text content verbatim.
///
/// SAML's enveloped-signature transform calls for stripping the `<ds:Signature>`
/// element *that contains the SignedInfo containing the Reference being
/// computed* — i.e. exactly one specific signature, not every signature in
/// the subtree. On a double-signed payload (e.g. `<samlp:Response>` carrying
/// an inner-signed `<saml:Assertion>`), the inner signature is part of the
/// bytes the outer signer committed to and must survive canonicalization.
fn clone_excluding_id(element: &Element, excluded: ElementId) -> Element {
    let mut cloned_children: Vec<Node> = Vec::with_capacity(element.children.len());
    for child in &element.children {
        match child {
            Node::Element(child_elem) => {
                if child_elem.id() == excluded {
                    // Drop *only* this element entirely from the clone.
                    continue;
                }
                cloned_children.push(Node::Element(clone_excluding_id(child_elem, excluded)));
            }
            Node::Text(t) => cloned_children.push(Node::Text(t.clone())),
            Node::Comment(c) => cloned_children.push(Node::Comment(c.clone())),
        }
    }
    Element {
        qname: element.qname.clone(),
        source_prefix: element.source_prefix.clone(),
        namespaces_declared_here: element.namespaces_declared_here.clone(),
        attributes: element.attributes.clone(),
        children: cloned_children,
        id: element.id, // preserve the original ID for diagnostics; not used by c14n.
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
    fn from_uri_accepts_whitelisted_transforms() {
        for uri in [
            ENVELOPED_SIGNATURE_URI,
            "http://www.w3.org/2001/10/xml-exc-c14n#",
            "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments",
        ] {
            AllowedTransform::from_uri(uri).expect("whitelisted");
        }
    }

    #[test]
    fn from_uri_rejects_xslt() {
        let err =
            AllowedTransform::from_uri("http://www.w3.org/TR/1999/REC-xslt-19991116").unwrap_err();
        match err {
            Error::DisallowedTransform { transform } => {
                assert!(transform.contains("xslt"), "got: {transform}");
            }
            other => panic!("expected DisallowedTransform, got {other:?}"),
        }
    }

    #[test]
    fn from_uri_rejects_xpath() {
        let err = AllowedTransform::from_uri("http://www.w3.org/TR/1999/REC-xpath-19991116")
            .unwrap_err();
        assert!(matches!(err, Error::DisallowedTransform { .. }));
    }

    #[test]
    fn from_uri_rejects_base64() {
        let err =
            AllowedTransform::from_uri("http://www.w3.org/2000/09/xmldsig#base64").unwrap_err();
        assert!(matches!(err, Error::DisallowedTransform { .. }));
    }

    #[test]
    fn resolve_uri_empty_returns_root() {
        let doc = parse(r#"<Root xmlns="urn:p" ID="r"/>"#);
        let id = resolve_uri(&doc, "").unwrap();
        assert_eq!(id, doc.root().id());
    }

    #[test]
    fn resolve_uri_hash_resolves_via_id_index() {
        let doc = parse(r#"<Root xmlns="urn:p" ID="r"><Child ID="abc"/></Root>"#);
        let id = resolve_uri(&doc, "#abc").unwrap();
        assert_eq!(id, doc.element_by_id_attr("abc").unwrap());
    }

    #[test]
    fn resolve_uri_unknown_id_errors() {
        let doc = parse(r#"<Root ID="r"/>"#);
        let err = resolve_uri(&doc, "#nope").unwrap_err();
        assert!(matches!(err, Error::ReferenceResolution));
    }

    #[test]
    fn resolve_uri_external_rejected() {
        let doc = parse(r#"<Root ID="r"/>"#);
        let err = resolve_uri(&doc, "https://attacker.example/x.xml").unwrap_err();
        assert!(matches!(err, Error::ReferenceResolution));
    }

    #[test]
    fn resolve_uri_xpointer_rejected() {
        let doc = parse(r#"<Root ID="r"/>"#);
        let err = resolve_uri(&doc, "#xpointer(/Root)").unwrap_err();
        assert!(matches!(err, Error::ReferenceResolution));
    }

    #[test]
    fn ancestor_chain_root_has_empty() {
        let doc = parse(r"<Root><A/></Root>");
        let chain = ancestor_chain(&doc, doc.root().id()).unwrap();
        assert!(chain.is_empty());
    }

    #[test]
    fn ancestor_chain_deep_walks_to_parent() {
        let doc = parse(r"<Root><A><B><C/></B></A></Root>");
        let c_id = {
            let a = doc.root().child_element(None, "A").unwrap();
            let b = a.child_element(None, "B").unwrap();
            b.child_element(None, "C").unwrap().id()
        };
        let chain = ancestor_chain(&doc, c_id).unwrap();
        let names: Vec<&str> = chain.iter().map(|e| e.qname().local()).collect();
        assert_eq!(names, vec!["Root", "A", "B"]);
    }

    #[test]
    fn clone_excluding_id_drops_only_the_named_signature() {
        // Two ds:Signature elements: one direct child of Root, one nested
        // inside B. Excluding *only* the outer one's ElementId must drop that
        // signature and leave the inner one intact — this is the
        // double-signed Response/Assertion shape.
        let xml = r#"<Root xmlns="urn:p" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><A/><ds:Signature/><B><ds:Signature/></B></Root>"#;
        let doc = parse(xml);
        let outer_sig_id = doc
            .root()
            .child_element(Some(DS_NS), "Signature")
            .unwrap()
            .id();
        let cloned = clone_excluding_id(doc.root(), outer_sig_id);
        let kinds: Vec<&str> = cloned
            .children()
            .filter_map(|n| match n {
                Node::Element(e) => Some(e.qname().local()),
                _ => None,
            })
            .collect();
        assert_eq!(kinds, vec!["A", "B"]);
        // The inner ds:Signature inside B must survive.
        let b = cloned.child_element(Some("urn:p"), "B").unwrap();
        assert!(
            b.child_element(Some(DS_NS), "Signature").is_some(),
            "nested ds:Signature with a different ElementId must be preserved"
        );
    }

    /// Build a synthetic `<ds:Reference URI="#X">` for parse_reference tests.
    fn synth_reference(uri: &str, digest_b64: &str) -> String {
        format!(
            r#"<Root xmlns="urn:p" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="X">
                <ds:Reference URI="{uri}">
                    <ds:Transforms>
                        <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                    </ds:Transforms>
                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                    <ds:DigestValue>{digest_b64}</ds:DigestValue>
                </ds:Reference>
            </Root>"#
        )
    }

    #[test]
    fn parse_reference_resolves_uri_and_transforms() {
        let xml = synth_reference("#X", "AAAA");
        let doc = parse(&xml);
        let reference = doc
            .root()
            .child_element(Some(DS_NS), "Reference")
            .expect("ds:Reference");
        let parsed = parse_reference(&doc, reference).expect("parse_reference");
        assert_eq!(parsed.target, doc.element_by_id_attr("X").unwrap());
        assert_eq!(parsed.digest_algorithm, DigestAlgorithm::Sha256);
        assert_eq!(
            parsed.transforms,
            vec![
                AllowedTransform::EnvelopedSignature,
                AllowedTransform::ExclusiveCanonical,
            ]
        );
        assert_eq!(parsed.digest_value, vec![0u8, 0, 0]);
    }

    #[test]
    fn parse_reference_empty_uri_targets_root() {
        let xml = synth_reference("", "AAAA");
        let doc = parse(&xml);
        let reference = doc.root().child_element(Some(DS_NS), "Reference").unwrap();
        let parsed = parse_reference(&doc, reference).unwrap();
        assert_eq!(parsed.target, doc.root().id());
    }

    #[test]
    fn parse_reference_rejects_xslt_transform() {
        let xml = r##"<Root xmlns="urn:p" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="X">
            <ds:Reference URI="#X">
                <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xslt-19991116"/>
                </ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <ds:DigestValue>AAAA</ds:DigestValue>
            </ds:Reference>
        </Root>"##;
        let doc = parse(xml);
        let reference = doc.root().child_element(Some(DS_NS), "Reference").unwrap();
        let err = parse_reference(&doc, reference).unwrap_err();
        assert!(matches!(err, Error::DisallowedTransform { .. }));
    }

    #[test]
    fn parse_reference_rejects_c14n_not_last() {
        // c14n followed by enveloped-signature: spec requires c14n be last
        // (in our v0.1 subset).
        let xml = r##"<Root xmlns="urn:p" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="X">
            <ds:Reference URI="#X">
                <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                    <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                </ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <ds:DigestValue>AAAA</ds:DigestValue>
            </ds:Reference>
        </Root>"##;
        let doc = parse(xml);
        let reference = doc.root().child_element(Some(DS_NS), "Reference").unwrap();
        let err = parse_reference(&doc, reference).unwrap_err();
        assert!(matches!(err, Error::DisallowedTransform { .. }));
    }

    #[test]
    fn parse_reference_parses_inclusive_namespaces_prefix_list() {
        let xml = r##"<Root xmlns="urn:p" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="X">
            <ds:Reference URI="#X">
                <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                    <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
                        <ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="ds saml #default"/>
                    </ds:Transform>
                </ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <ds:DigestValue>AAAA</ds:DigestValue>
            </ds:Reference>
        </Root>"##;
        let doc = parse(xml);
        let reference = doc.root().child_element(Some(DS_NS), "Reference").unwrap();
        let parsed = parse_reference(&doc, reference).unwrap();
        assert_eq!(
            parsed.inclusive_namespace_prefixes,
            vec!["ds".to_owned(), "saml".to_owned(), "#default".to_owned()]
        );
    }

    #[test]
    fn compute_digest_round_trip_simple_element() {
        // Construct a minimal "signed" element with a well-known canonical form
        // and a stub Reference whose digest matches.
        let xml = r#"<Root xmlns="urn:p" ID="X"><Inner>hello</Inner></Root>"#;
        let doc = parse(xml);

        // Compute the canonical form + digest of the Root subtree directly so
        // the test's expected digest is computed by the same c14n path.
        let target = doc.root();
        let chain = ancestor_chain(&doc, target.id()).unwrap();
        let bytes = canonicalize(
            &doc,
            target,
            &chain,
            C14nAlgorithm::ExclusiveCanonical,
            &[],
        )
        .unwrap();
        let expected_digest = DigestAlgorithm::Sha256.digest(&bytes);

        let parsed = ParsedReference {
            target: target.id(),
            transforms: vec![AllowedTransform::ExclusiveCanonical],
            digest_algorithm: DigestAlgorithm::Sha256,
            digest_value: expected_digest.clone(),
            inclusive_namespace_prefixes: Vec::new(),
        };

        // No enveloped-signature transform here, so the enclosing-signature
        // id is unused by `compute_reference_digest`; pass the root's id.
        let got = compute_reference_digest(&doc, &parsed, doc.root().id()).unwrap();
        assert_eq!(got, expected_digest);
    }

    #[test]
    fn compute_digest_with_enveloped_signature_strips_ds_signature() {
        // Two documents that differ only by the presence of a <ds:Signature>
        // child must produce the same digest under EnvelopedSignature+c14n —
        // because Exclusive C14N drops the unused `ds:` declaration from the
        // canonical output once its only consumer (the Signature subtree) is
        // stripped.
        let with_sig = r#"<Root xmlns="urn:p" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="X"><Inner>hello</Inner><ds:Signature><ds:SignedInfo/></ds:Signature></Root>"#;
        let without_sig = r#"<Root xmlns="urn:p" ID="X"><Inner>hello</Inner></Root>"#;
        let doc_a = parse(with_sig);
        let doc_b = parse(without_sig);

        // Reference (enveloped-signature + c14n) computed against doc_a.
        let parsed_a = ParsedReference {
            target: doc_a.root().id(),
            transforms: vec![
                AllowedTransform::EnvelopedSignature,
                AllowedTransform::ExclusiveCanonical,
            ],
            digest_algorithm: DigestAlgorithm::Sha256,
            digest_value: Vec::new(),
            inclusive_namespace_prefixes: Vec::new(),
        };
        // The signature being verified is the direct ds:Signature child of
        // the Root in doc_a — identify it for the enveloped-signature strip.
        let outer_sig_id = doc_a
            .root()
            .child_element(Some(DS_NS), "Signature")
            .unwrap()
            .id();
        let digest_a = compute_reference_digest(&doc_a, &parsed_a, outer_sig_id).unwrap();

        // Canonicalize doc_b directly (no enveloped-signature needed; nothing
        // to strip) and digest.
        let chain_b = ancestor_chain(&doc_b, doc_b.root().id()).unwrap();
        let bytes_b = canonicalize(
            &doc_b,
            doc_b.root(),
            &chain_b,
            C14nAlgorithm::ExclusiveCanonical,
            &[],
        )
        .unwrap();
        let digest_b = DigestAlgorithm::Sha256.digest(&bytes_b);

        // After stripping <ds:Signature> from doc_a's root, the only
        // namespaces visibly used in the canonical output are the default
        // `urn:p` — `ds:` is dropped by Exclusive C14N. So doc_a's enveloped
        // digest matches doc_b's plain digest.
        assert_eq!(
            digest_a, digest_b,
            "enveloped-signature must produce the same digest as the un-signed equivalent",
        );

        // Belt-and-suspenders: the canonical pruned bytes do not contain any
        // `ds:Signature` substring.
        let pruned = clone_excluding_id(doc_a.root(), outer_sig_id);
        let chain_a = ancestor_chain(&doc_a, doc_a.root().id()).unwrap();
        let canonical_pruned = canonicalize(
            &doc_a,
            &pruned,
            &chain_a,
            C14nAlgorithm::ExclusiveCanonical,
            &[],
        )
        .unwrap();
        assert!(
            !canonical_pruned
                .windows(b"ds:Signature".len())
                .any(|w| w == b"ds:Signature"),
            "ds:Signature must be absent from canonical bytes after enveloped-signature transform",
        );
    }

    #[test]
    fn parse_reference_missing_digest_method_errors() {
        let xml = r##"<Root xmlns="urn:p" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="X">
            <ds:Reference URI="#X">
                <ds:DigestValue>AAAA</ds:DigestValue>
            </ds:Reference>
        </Root>"##;
        let doc = parse(xml);
        let reference = doc.root().child_element(Some(DS_NS), "Reference").unwrap();
        let err = parse_reference(&doc, reference).unwrap_err();
        assert!(matches!(err, Error::SignatureVerification { .. }));
    }

    #[test]
    fn parse_reference_bad_base64_digest_errors() {
        let xml = synth_reference("#X", "not!base64!");
        let doc = parse(&xml);
        let reference = doc.root().child_element(Some(DS_NS), "Reference").unwrap();
        let err = parse_reference(&doc, reference).unwrap_err();
        assert!(matches!(err, Error::Base64Decode));
    }
}
