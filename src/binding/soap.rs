//! SOAP 1.1 envelope binding (SAML 2.0 Bindings §3.2, "SAML SOAP Binding").
//!
//! SOAP is the back-channel binding the SAML protocol uses for synchronous
//! request/response exchanges that do not pass through the user agent:
//! artifact resolution (`ArtifactResolve` / `ArtifactResponse`, Bindings §3.6)
//! and back-channel Single Logout (`LogoutRequest` / `LogoutResponse` over
//! SOAP, Profiles §4.4). The PAOS / ECP profile (Profiles §4.2) layers on the
//! same envelope, so this module is deliberately **binding-agnostic**: it
//! knows how to wrap and unwrap a single SOAP `<soap:Body>` payload and how to
//! recognise a `<soap:Fault>`, and nothing about SAML message structure.
//!
//! # SOAP 1.1, not 1.2
//!
//! SAML 2.0 Bindings §3.2.1 pins the binding to SOAP 1.1
//! (`http://schemas.xmlsoap.org/soap/envelope/`). The HTTP conventions
//! (Bindings §3.2.3) are `Content-Type: text/xml` and a `SOAPAction` header;
//! SAML requires neither a specific `SOAPAction` value nor SOAP headers, so
//! we emit an empty quoted `SOAPAction: ""`.
//!
//! # Feature gating
//!
//! This module compiles whenever a binding that uses it is enabled — the
//! HTTP-Artifact binding (`artifact-binding`), back-channel SLO (`slo`), or the
//! ECP / PAOS profile (`ecp`). It does **not** require `weak-algos`: the
//! envelope itself carries no SHA-1 dependency (only the artifact `SourceID`
//! does), so ECP reuses it without opting into weak algorithms.
//!
//! # SOAP headers
//!
//! Most callers (artifact, SLO) wrap a bare `<soap:Body>` with no
//! `<soap:Header>`. ECP (Profiles §4.2) needs header blocks — `<paos:Request>`,
//! `<ecp:Request>`, `<ecp:Response>`, `<paos:Response>` — so this module also
//! exposes `wrap_with_header` (build an envelope carrying caller-supplied
//! header element blocks) and `UnwrappedEnvelope` (recover both the header
//! blocks and the body payload), both `pub(crate)` and gated on `ecp`. They
//! reuse the same element/parse machinery as [`wrap`] / [`unwrap`]; ECP does
//! not fork a second envelope builder.

#![cfg(any(feature = "artifact-binding", feature = "slo", feature = "ecp"))]

use crate::error::Error;
use crate::xml::emit::{emit_document, emit_element};
use crate::xml::parse::{Document, Element, Node, QName};

/// SOAP 1.1 envelope namespace (Bindings §3.2.1).
pub const SOAP_NS: &str = "http://schemas.xmlsoap.org/soap/envelope/";

/// `Content-Type` header value for the SOAP 1.1 HTTP binding (Bindings §3.2.3).
pub const CONTENT_TYPE: &str = "text/xml; charset=utf-8";

/// `SOAPAction` header value. SAML places no requirement on the action URI
/// (Bindings §3.2.3), so the conventional empty quoted string is used.
pub const SOAP_ACTION: &str = "\"\"";

/// The canonical SOAP back-channel HTTP request headers: `Content-Type` and
/// `SOAPAction`. Returned as owned pairs ready to drop into an
/// [`HttpRequest`](crate::http::HttpRequest).
#[must_use]
pub fn request_headers() -> Vec<(String, String)> {
    vec![
        ("Content-Type".to_owned(), CONTENT_TYPE.to_owned()),
        ("SOAPAction".to_owned(), SOAP_ACTION.to_owned()),
    ]
}

/// Wrap an already-serialized SAML protocol message in a SOAP 1.1 envelope.
///
/// `payload_xml` is the textual XML of the single `<soap:Body>` child (e.g. a
/// `<samlp:ArtifactResolve>` or `<samlp:LogoutRequest>`). The payload is
/// re-parsed and grafted into the envelope tree rather than string-spliced, so
/// the result goes through the same well-formedness and ID-uniqueness checks
/// as any other emitted document — a signed payload's `<ds:Signature>` is
/// preserved byte-structure-for-structure because the subtree is moved, not
/// reserialized through string concatenation.
pub fn wrap(payload_xml: &str) -> Result<String, Error> {
    let payload_doc = Document::parse(payload_xml.as_bytes())?;
    let payload_elem = payload_doc.root().clone();
    wrap_element(payload_elem)
}

/// Wrap an in-memory payload [`Element`] subtree in a SOAP 1.1 envelope and
/// serialize the whole envelope. Avoids a parse round-trip when the caller
/// already holds the payload as a tree (the common case on the emit side).
///
/// `Element` is a crate-internal type, so this is `pub(crate)`; external
/// callers use [`wrap`] with serialized XML.
pub(crate) fn wrap_element(payload: Element) -> Result<String, Error> {
    let body = Element::build(QName::new(Some(SOAP_NS.to_owned()), "Body"))
        .with_child(Node::Element(payload))
        .finish();
    let envelope = Element::build(QName::new(Some(SOAP_NS.to_owned()), "Envelope"))
        .with_namespace(Some("soap".to_owned()), SOAP_NS)
        .with_child(Node::Element(body))
        .finish();
    let doc = Document::new(envelope)?;
    emit_document(&doc)
}

/// Wrap a payload [`Element`] in a SOAP 1.1 envelope that also carries a
/// `<soap:Header>` with the given header element blocks, then serialize.
///
/// `header_blocks` are grafted, in order, as children of `<soap:Header>`; the
/// `payload` becomes the single `<soap:Body>` child. The `soap` prefix is
/// declared once on `<soap:Envelope>`; header blocks that reference the SOAP
/// namespace (for `soap:mustUnderstand` / `soap:actor`, ECP Profiles §4.2)
/// resolve it from that in-scope declaration, so callers do **not** redeclare
/// it on each block.
///
/// `Element` is crate-internal, so this is `pub(crate)`; the ECP module is the
/// only caller and always holds its header blocks and payload as trees.
#[cfg(feature = "ecp")]
pub(crate) fn wrap_with_header(
    header_blocks: Vec<Element>,
    payload: Element,
) -> Result<String, Error> {
    let mut header = Element::build(QName::new(Some(SOAP_NS.to_owned()), "Header"));
    for block in header_blocks {
        header = header.with_child(Node::Element(block));
    }
    let header = header.finish();
    let body = Element::build(QName::new(Some(SOAP_NS.to_owned()), "Body"))
        .with_child(Node::Element(payload))
        .finish();
    let envelope = Element::build(QName::new(Some(SOAP_NS.to_owned()), "Envelope"))
        .with_namespace(Some("soap".to_owned()), SOAP_NS)
        .with_child(Node::Element(header))
        .with_child(Node::Element(body))
        .finish();
    let doc = Document::new(envelope)?;
    emit_document(&doc)
}

/// The single payload element recovered from a SOAP `<soap:Body>`, alongside
/// the parsed document that owns it. The borrow keeps the underlying arena
/// alive so callers can inspect or re-serialize the element.
#[derive(Debug)]
pub struct UnwrappedBody {
    document: Document,
}

impl UnwrappedBody {
    /// The first element child of `<soap:Body>` — the SAML protocol message.
    ///
    /// `Element` is a crate-internal type, so this accessor is `pub(crate)`;
    /// external callers use [`UnwrappedBody::payload_xml`] to get the bytes.
    /// Only the artifact binding inspects the element directly; SLO unwrapping
    /// re-serializes via `payload_xml`.
    #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
    pub(crate) fn payload(&self) -> &Element {
        self.document.root()
    }

    /// Re-serialize the recovered payload element to standalone XML bytes,
    /// ready to hand to a SAML message parser.
    pub fn payload_xml(&self) -> Result<Vec<u8>, Error> {
        Ok(emit_element(self.document.root())?.into_bytes())
    }

    /// The standalone [`Document`] that re-roots the payload element. Exposed
    /// for the back-channel client's signature verification, which needs the
    /// owning arena to run the XSW `signed_element == root` check. Only the
    /// artifact binding consumes this; SLO unwrapping uses `payload_xml`.
    #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
    pub(crate) fn document_ref(&self) -> &Document {
        &self.document
    }
}

/// Parse an inbound SOAP 1.1 envelope and recover the single `<soap:Body>`
/// child element.
///
/// Detects a `<soap:Fault>` body (SOAP 1.1 §4.4) and surfaces it as
/// [`Error::SoapFault`] carrying the `<faultcode>` and `<faultstring>` so the
/// caller can distinguish a transport-level SOAP refusal from a SAML-level
/// non-Success status. Any other single element child of `<soap:Body>` is
/// recovered and returned via [`UnwrappedBody`].
///
/// The returned payload element is *not* further validated here — recovering
/// it is the SOAP layer's only job; SAML-level checks (status, signature,
/// issuer) belong to the binding that called in.
pub fn unwrap(envelope_bytes: &[u8]) -> Result<UnwrappedBody, Error> {
    let doc = Document::parse(envelope_bytes)?;
    let envelope = doc.root();
    if envelope.qname().namespace() != Some(SOAP_NS) || envelope.qname().local() != "Envelope" {
        return Err(Error::XmlParse(
            "SOAP: envelope root is not soap:Envelope".to_string(),
        ));
    }

    let body = envelope
        .child_element(Some(SOAP_NS), "Body")
        .ok_or_else(|| Error::XmlParse("SOAP: missing soap:Body".to_string()))?;

    // A Fault is a legal Body child; detect it before treating the first
    // element child as a payload so callers get a typed error, not a confusing
    // "payload was <Fault>" downstream.
    if let Some(fault) = body.child_element(Some(SOAP_NS), "Fault") {
        // faultcode / faultstring are unqualified per SOAP 1.1 §4.4 (they live
        // in no namespace, even though their *values* are QNames).
        let faultcode = fault
            .child_element(None, "faultcode")
            .map(Element::text_content)
            .unwrap_or_default();
        let faultstring = fault.child_element(None, "faultstring").map(|e| {
            // text_content trims nothing; an empty faultstring becomes None so
            // the Display impl doesn't render a dangling separator.
            e.text_content()
        });
        return Err(Error::SoapFault {
            faultcode,
            faultstring: faultstring.filter(|s| !s.is_empty()),
        });
    }

    let payload = body.child_elements().next().ok_or_else(|| {
        Error::XmlParse("SOAP: soap:Body contains no payload element".to_string())
    })?;

    // Security: re-root the payload as a *standalone document* by emitting it
    // and reparsing, rather than handing back the payload element in place
    // under `<soap:Envelope>`. This is load-bearing for signature
    // canonicalization, not a mere "relocate the root" convenience: the IdP
    // signs the `<samlp:ArtifactResponse>` (or other payload) as its own
    // document root, with no `soap:Envelope` ancestor in scope. Verification
    // must canonicalize it the same way the IdP did — standalone, WITHOUT the
    // envelope's ancestor namespace context. Verifying the element in place
    // under the envelope would change the canonical bytes (notably under
    // inclusive C14N, where ancestor namespace decls are pulled in) and break
    // interop with real IdPs. Do NOT "optimize" this into comparing the
    // signed element against the in-place envelope tree.
    let payload_xml = emit_element(payload)?;
    let document = Document::parse(payload_xml.as_bytes())?;
    Ok(UnwrappedBody { document })
}

/// A parsed SOAP 1.1 envelope that retains its `<soap:Header>` blocks as well
/// as its `<soap:Body>` payload. Used by the ECP profile (Profiles §4.2),
/// which carries SAML control information in header blocks (`<paos:Request>`,
/// `<ecp:Request>`, `<ecp:Response>`, `<paos:Response>`) alongside the SAML
/// protocol message in the body.
///
/// The owned [`Document`] keeps the arena alive so callers can borrow header
/// elements and re-serialize the body payload.
#[cfg(feature = "ecp")]
#[derive(Debug)]
pub(crate) struct UnwrappedEnvelope {
    document: Document,
}

#[cfg(feature = "ecp")]
impl UnwrappedEnvelope {
    /// First `<soap:Header>` child element matching the expanded name, or
    /// `None` if there is no header or no such block.
    pub(crate) fn header_block(&self, namespace: &str, local: &str) -> Option<&Element> {
        self.document
            .root()
            .child_element(Some(SOAP_NS), "Header")
            .and_then(|h| h.child_element(Some(namespace), local))
    }

    /// Count of `<soap:Header>` child blocks matching the expanded name. Used
    /// to reject envelopes carrying more than one trust-bearing block (a
    /// duplicate `<paos:Request>` / `<ecp:Response>` is malformed and could
    /// hide a second value from the first-match [`Self::header_block`] read).
    pub(crate) fn header_block_count(&self, namespace: &str, local: &str) -> usize {
        self.document
            .root()
            .child_element(Some(SOAP_NS), "Header")
            .map_or(0, |h| h.all_child_elements(Some(namespace), local).count())
    }

    /// The first element child of `<soap:Body>` — the SAML protocol message.
    pub(crate) fn body_payload(&self) -> Option<&Element> {
        self.document
            .root()
            .child_element(Some(SOAP_NS), "Body")
            .and_then(|b| b.child_elements().next())
    }

    /// Re-serialize the body payload element to standalone XML bytes.
    ///
    /// As with [`unwrap`], the payload is emitted and reparsed so its canonical
    /// bytes match how the signer produced it (no `soap:Envelope` ancestor
    /// namespace context in scope). This is load-bearing for signature
    /// verification of a signed `<samlp:Response>` carried in the ECP body.
    pub(crate) fn body_payload_xml(&self) -> Result<Vec<u8>, Error> {
        let payload = self.body_payload().ok_or_else(|| {
            Error::XmlParse("SOAP: soap:Body contains no payload element".to_string())
        })?;
        Ok(emit_element(payload)?.into_bytes())
    }
}

/// Parse an inbound SOAP 1.1 envelope, retaining its header blocks.
///
/// Unlike [`unwrap`] (which discards the header and re-roots only the body
/// payload), this keeps the whole parsed envelope so ECP callers can read
/// `<soap:Header>` control blocks. A `<soap:Fault>` body is still surfaced as
/// [`Error::SoapFault`] before any payload handling.
#[cfg(feature = "ecp")]
pub(crate) fn unwrap_envelope(envelope_bytes: &[u8]) -> Result<UnwrappedEnvelope, Error> {
    let doc = Document::parse(envelope_bytes)?;
    let envelope = doc.root();
    if envelope.qname().namespace() != Some(SOAP_NS) || envelope.qname().local() != "Envelope" {
        return Err(Error::XmlParse(
            "SOAP: envelope root is not soap:Envelope".to_string(),
        ));
    }
    let body = envelope
        .child_element(Some(SOAP_NS), "Body")
        .ok_or_else(|| Error::XmlParse("SOAP: missing soap:Body".to_string()))?;
    if let Some(fault) = body.child_element(Some(SOAP_NS), "Fault") {
        let faultcode = fault
            .child_element(None, "faultcode")
            .map(Element::text_content)
            .unwrap_or_default();
        let faultstring = fault
            .child_element(None, "faultstring")
            .map(Element::text_content);
        return Err(Error::SoapFault {
            faultcode,
            faultstring: faultstring.filter(|s| !s.is_empty()),
        });
    }
    Ok(UnwrappedEnvelope { document: doc })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMLP_NS: &str = "urn:oasis:names:tc:SAML:2.0:protocol";

    #[test]
    fn wrap_then_unwrap_round_trips_payload() {
        let payload = r#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_lr1"/>"#;
        let envelope = wrap(payload).expect("wrap");

        // Envelope shape.
        let doc = Document::parse(envelope.as_bytes()).expect("re-parse");
        assert_eq!(doc.root().qname().namespace(), Some(SOAP_NS));
        assert_eq!(doc.root().qname().local(), "Envelope");
        let body = doc.root().child_element(Some(SOAP_NS), "Body").unwrap();
        assert!(
            body.child_element(Some(SAMLP_NS), "LogoutRequest")
                .is_some()
        );

        // Round-trip recovers the payload.
        let unwrapped = unwrap(envelope.as_bytes()).expect("unwrap");
        let bytes = unwrapped.payload_xml().expect("payload_xml");
        let reparsed = Document::parse(&bytes).expect("payload reparse");
        assert_eq!(reparsed.root().qname().local(), "LogoutRequest");
        assert_eq!(reparsed.root().attribute(None, "ID"), Some("_lr1"));
    }

    #[test]
    fn unwrap_rejects_non_envelope_root() {
        let err = unwrap(b"<not-soap/>").unwrap_err();
        assert!(matches!(err, Error::XmlParse(_)));
    }

    #[test]
    fn unwrap_rejects_missing_body() {
        let xml = format!(r#"<soap:Envelope xmlns:soap="{SOAP_NS}"/>"#);
        let err = unwrap(xml.as_bytes()).unwrap_err();
        match err {
            Error::XmlParse(msg) => assert!(msg.contains("soap:Body"), "got: {msg}"),
            other => panic!("expected XmlParse, got {other:?}"),
        }
    }

    #[test]
    fn unwrap_rejects_empty_body() {
        let xml = format!(r#"<soap:Envelope xmlns:soap="{SOAP_NS}"><soap:Body/></soap:Envelope>"#);
        let err = unwrap(xml.as_bytes()).unwrap_err();
        match err {
            Error::XmlParse(msg) => assert!(msg.contains("payload"), "got: {msg}"),
            other => panic!("expected XmlParse, got {other:?}"),
        }
    }

    #[test]
    fn unwrap_surfaces_soap_fault_with_code_and_string() {
        let xml = format!(
            r#"<soap:Envelope xmlns:soap="{SOAP_NS}">
  <soap:Body>
    <soap:Fault>
      <faultcode>soap:Server</faultcode>
      <faultstring>artifact resolution failed</faultstring>
    </soap:Fault>
  </soap:Body>
</soap:Envelope>"#
        );
        let err = unwrap(xml.as_bytes()).unwrap_err();
        match err {
            Error::SoapFault {
                faultcode,
                faultstring,
            } => {
                assert_eq!(faultcode, "soap:Server");
                assert_eq!(faultstring.as_deref(), Some("artifact resolution failed"));
            }
            other => panic!("expected SoapFault, got {other:?}"),
        }
    }

    #[test]
    fn unwrap_fault_without_faultstring_yields_none() {
        let xml = format!(
            r#"<soap:Envelope xmlns:soap="{SOAP_NS}">
  <soap:Body><soap:Fault><faultcode>soap:Client</faultcode></soap:Fault></soap:Body>
</soap:Envelope>"#
        );
        let err = unwrap(xml.as_bytes()).unwrap_err();
        match err {
            Error::SoapFault {
                faultcode,
                faultstring,
            } => {
                assert_eq!(faultcode, "soap:Client");
                assert!(faultstring.is_none());
            }
            other => panic!("expected SoapFault, got {other:?}"),
        }
    }

    #[test]
    fn request_headers_use_soap_conventions() {
        let headers = request_headers();
        assert!(
            headers
                .iter()
                .any(|(k, v)| k == "Content-Type" && v == "text/xml; charset=utf-8")
        );
        assert!(
            headers
                .iter()
                .any(|(k, v)| k == "SOAPAction" && v == "\"\"")
        );
    }
}
