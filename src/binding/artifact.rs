//! HTTP-Artifact binding per SAML 2.0 Bindings §3.6.
//!
//! Outbound (IdP-side): construct a `SAMLart` artifact value + the
//! [`ArtifactRedirect`] carrying the artifact + the response XML keyed by it.
//! The caller persists `artifact -> response_xml` and redirects the browser to
//! the SP's ACS URL with `?SAMLart=<artifact>`.
//!
//! Inbound (SP-side): the SP receives `?SAMLart=<artifact>` at its ACS,
//! constructs a `<samlp:ArtifactResolve>` SOAP request, sends it to the IdP's
//! `ArtifactResolutionService` via the caller's [`HttpClient`], and parses the
//! returned `<samlp:ArtifactResponse>` SOAP envelope to recover the embedded
//! `<samlp:Response>` XML.
//!
//! # Feature gating
//!
//! This module compiles only when **both** the `artifact-binding` and
//! `weak-algos` features are enabled. The SAML 2.0 spec mandates SHA-1 for the
//! 20-byte `SourceID` (Bindings §3.6.4); SHA-1 here is **not** used for any
//! security property — it is an identity-matching tag for routing artifact
//! resolves to the correct IdP — but we still want callers to opt in to the
//! `weak-algos` feature flag so the dependency on the `sha1` crate is
//! explicit. When `weak-algos` is off the module's body is empty (the surface
//! disappears) which is what the spec calls for in environments that ban all
//! SHA-1 transitively.

#![cfg(all(feature = "artifact-binding", feature = "weak-algos"))]

use std::time::SystemTime;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use rsa::rand_core::{OsRng, RngCore as _};
use sha1::{Digest as _, Sha1};
use url::Url;

use crate::binding::ArtifactRedirect;
use crate::error::Error;
use crate::http::{HttpClient, HttpRequest, HttpResponse};
use crate::time::format_xs_datetime;
use crate::xml::emit::{emit_document, emit_element};
use crate::xml::parse::{Document, Element, Node, QName};

/// SAML protocol namespace.
pub const SAMLP_NS: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
/// SAML assertion namespace.
pub const SAML_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
/// SOAP 1.1 envelope namespace.
pub const SOAP_NS: &str = "http://schemas.xmlsoap.org/soap/envelope/";

/// `Status/StatusCode/@Value` for the success case.
const STATUS_SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";

/// SAML 2.0 artifact Type 4. The only artifact type defined by the spec
/// for HTTP-Artifact.
const ARTIFACT_TYPE_CODE: u16 = 0x0004;

// =============================================================================
// Outbound (IdP side): SAMLart construction
// =============================================================================

/// Generate an outbound artifact for delivery via HTTP-Artifact.
///
/// The artifact is a base64-encoded 44-byte structure per Bindings §3.6.4:
///
/// - 2 bytes type code (`0x0004` = SAML 2.0 Type 4).
/// - 2 bytes endpoint index (which ARS endpoint will resolve this).
/// - 20 bytes `SourceID` = SHA-1 of the issuer's `entity_id`.
/// - 20 bytes `MessageHandle` = cryptographically random.
///
/// The result is base64-encoded with the standard alphabet (padded).
pub fn make_artifact(
    issuer_entity_id: &str,
    endpoint_index: u16,
) -> Result<String, Error> {
    let mut buf = [0u8; 44];

    // Bytes 0..2: type code.
    buf[0..2].copy_from_slice(&ARTIFACT_TYPE_CODE.to_be_bytes());
    // Bytes 2..4: endpoint index.
    buf[2..4].copy_from_slice(&endpoint_index.to_be_bytes());
    // Bytes 4..24: SourceID = SHA-1(entity_id).
    let source_id = Sha1::digest(issuer_entity_id.as_bytes());
    buf[4..24].copy_from_slice(&source_id);
    // Bytes 24..44: MessageHandle = 20 random bytes.
    OsRng
        .try_fill_bytes(&mut buf[24..44])
        .map_err(|_err| Error::InvalidConfiguration {
            reason: "RNG failure generating artifact MessageHandle",
        })?;

    Ok(BASE64.encode(buf))
}

/// Construct an [`ArtifactRedirect`] for an outbound SSO `<samlp:Response>`.
///
/// `sp_acs_url` is the SP's ACS endpoint URL (where the browser lands).
/// `response_xml` is the full `<samlp:Response>` XML the IdP will return when
/// the SP resolves the artifact via SOAP — the library does not persist this;
/// the caller MUST stash it keyed by the returned `artifact` string and serve
/// it from its `ArtifactResolutionService`.
pub fn build_artifact_redirect(
    sp_acs_url: &Url,
    issuer_entity_id: &str,
    endpoint_index: u16,
    response_xml: String,
    relay_state: Option<&str>,
) -> Result<ArtifactRedirect, Error> {
    let artifact = make_artifact(issuer_entity_id, endpoint_index)?;

    // `Url::query_pairs_mut()` handles percent-encoding for us (the base64
    // alphabet includes `+`, `/`, `=` which all need encoding on the wire).
    let mut redirect_to = sp_acs_url.clone();
    {
        let mut pairs = redirect_to.query_pairs_mut();
        pairs.append_pair("SAMLart", &artifact);
        if let Some(rs) = relay_state {
            pairs.append_pair("RelayState", rs);
        }
    }

    Ok(ArtifactRedirect {
        redirect_to,
        artifact,
        response_xml,
    })
}

// =============================================================================
// Inbound (SP side): SOAP ArtifactResolve / ArtifactResponse
// =============================================================================

/// Build a `<samlp:ArtifactResolve>` SOAP envelope to send to the IdP's
/// `ArtifactResolutionService`.
///
/// The wrapper SOAP envelope is generated fresh each call. The `IssueInstant`
/// is sourced from `SystemTime::now()` because this is an outbound-message
/// construction — fresh-now is fine here; no security check threads a `now`
/// parameter into this code path.
pub fn build_artifact_resolve(
    issuer_entity_id: &str,
    destination: &str,
    artifact: &str,
) -> Result<String, Error> {
    let id = random_xml_id()?;
    let issue_instant = format_xs_datetime(SystemTime::now())?;

    // <samlp:Artifact>{artifact}</samlp:Artifact>
    let artifact_elem = Element::build(QName::new(Some(SAMLP_NS.to_owned()), "Artifact"))
        .with_text(artifact.to_owned())
        .finish();

    // <saml:Issuer>{sp_entity_id}</saml:Issuer>
    let issuer_elem = Element::build(QName::new(Some(SAML_NS.to_owned()), "Issuer"))
        .with_text(issuer_entity_id.to_owned())
        .finish();

    // <samlp:ArtifactResolve ...>
    let resolve_elem = Element::build(QName::new(Some(SAMLP_NS.to_owned()), "ArtifactResolve"))
        .with_namespace(Some("samlp".to_owned()), SAMLP_NS)
        .with_namespace(Some("saml".to_owned()), SAML_NS)
        .with_attribute(QName::new(None, "ID"), id)
        .with_attribute(QName::new(None, "Version"), "2.0")
        .with_attribute(QName::new(None, "IssueInstant"), issue_instant)
        .with_attribute(QName::new(None, "Destination"), destination.to_owned())
        .with_child(Node::Element(issuer_elem))
        .with_child(Node::Element(artifact_elem))
        .finish();

    // <soap:Body>...</soap:Body>
    let body_elem = Element::build(QName::new(Some(SOAP_NS.to_owned()), "Body"))
        .with_child(Node::Element(resolve_elem))
        .finish();

    // <soap:Envelope xmlns:soap="...">...</soap:Envelope>
    let envelope_elem = Element::build(QName::new(Some(SOAP_NS.to_owned()), "Envelope"))
        .with_namespace(Some("soap".to_owned()), SOAP_NS)
        .with_child(Node::Element(body_elem))
        .finish();

    let doc = Document::new(envelope_elem)?;
    emit_document(&doc)
}

/// Parse a `<samlp:ArtifactResponse>` SOAP envelope and extract the inner
/// SAML protocol message (typically `<samlp:Response>`) as XML bytes.
///
/// Validates that:
///
/// 1. The envelope contains `soap:Envelope/soap:Body/samlp:ArtifactResponse`.
/// 2. The `samlp:Status/samlp:StatusCode/@Value` equals the SAML 2.0
///    `urn:oasis:names:tc:SAML:2.0:status:Success` URI. A non-Success status
///    is surfaced as [`Error::StatusNotSuccess`] carrying the actual code (and
///    optional `StatusMessage`), so callers can branch precisely rather than
///    pattern-matching a stringly-typed `XmlParse`.
/// 3. The `ArtifactResponse` contains a payload protocol message — the first
///    `samlp:*` child that is neither `Status` nor `Issuer`. The whole subtree
///    of that payload is serialized and returned.
pub fn parse_artifact_response(soap_envelope: &[u8]) -> Result<Vec<u8>, Error> {
    let doc = Document::parse(soap_envelope)?;

    let envelope = doc.root();
    if envelope.qname().namespace() != Some(SOAP_NS) || envelope.qname().local() != "Envelope" {
        return Err(Error::XmlParse(
            "ArtifactResponse: SOAP envelope root is not soap:Envelope".to_string(),
        ));
    }

    let body = envelope
        .child_element(Some(SOAP_NS), "Body")
        .ok_or_else(|| Error::XmlParse("ArtifactResponse: missing soap:Body".to_string()))?;

    let artifact_response = body
        .child_element(Some(SAMLP_NS), "ArtifactResponse")
        .ok_or_else(|| {
            Error::XmlParse("ArtifactResponse: missing samlp:ArtifactResponse".to_string())
        })?;

    // ---- Status check -----------------------------------------------------
    let status = artifact_response
        .child_element(Some(SAMLP_NS), "Status")
        .ok_or_else(|| {
            Error::XmlParse(
                "ArtifactResponse: missing samlp:Status inside ArtifactResponse".to_string(),
            )
        })?;
    let status_code = status
        .child_element(Some(SAMLP_NS), "StatusCode")
        .ok_or_else(|| {
            Error::XmlParse(
                "ArtifactResponse: missing samlp:StatusCode inside Status".to_string(),
            )
        })?;
    let code_value = status_code.attribute(None, "Value").ok_or_else(|| {
        Error::XmlParse("ArtifactResponse: StatusCode missing @Value".to_string())
    })?;
    if code_value != STATUS_SUCCESS {
        let message = status
            .child_element(Some(SAMLP_NS), "StatusMessage")
            .map(Element::text_content);
        return Err(Error::StatusNotSuccess {
            code: code_value.to_owned(),
            message,
        });
    }

    // ---- Extract the payload protocol message ----------------------------
    // The first child of <ArtifactResponse> in the samlp namespace that is
    // neither <Status> nor <Issuer> is the wrapped message. In a well-formed
    // success response from a SAML 2.0 IdP this is <samlp:Response>; the spec
    // does also allow other protocol messages (e.g. AuthnRequest in proxying
    // scenarios), so we don't hard-code the local name here.
    let payload = artifact_response
        .child_elements()
        .find(|child| {
            child.qname().namespace() == Some(SAMLP_NS)
                && child.qname().local() != "Status"
        })
        .ok_or_else(|| {
            Error::XmlParse(
                "ArtifactResponse: no samlp:* payload message present".to_string(),
            )
        })?;

    let serialized = emit_element(payload)?;
    Ok(serialized.into_bytes())
}

/// Resolve an artifact against the IdP via SOAP. Returns the embedded
/// `<samlp:Response>` (or other protocol message) XML bytes.
///
/// - `http`: caller-supplied [`HttpClient`].
/// - `ars_url`: IdP's `ArtifactResolutionService` endpoint.
/// - `issuer_entity_id`: the SP's entity ID (echoed in the
///   `ArtifactResolve/<saml:Issuer>`).
/// - `artifact`: the opaque `SAMLart` value as received.
///
/// The HTTP request sets `Content-Type: text/xml` and an empty quoted
/// `SOAPAction: ""` header per SOAP 1.1 binding conventions and SAML 2.0
/// Bindings §3.2.3.
pub async fn resolve_artifact<H: HttpClient>(
    http: &H,
    ars_url: &str,
    issuer_entity_id: &str,
    artifact: &str,
) -> Result<Vec<u8>, Error> {
    let soap_body = build_artifact_resolve(issuer_entity_id, ars_url, artifact)?;

    let request = HttpRequest {
        method: http::Method::POST,
        url: ars_url.to_owned(),
        headers: vec![
            ("Content-Type".to_owned(), "text/xml".to_owned()),
            ("SOAPAction".to_owned(), "\"\"".to_owned()),
        ],
        body: soap_body.into_bytes(),
    };

    let HttpResponse { body, .. } = http.send(request).await.map_err(Error::Http)?;
    parse_artifact_response(&body)
}

// =============================================================================
// IdP-side: parse inbound ArtifactResolve, build outbound ArtifactResponse
// =============================================================================

/// Inbound `<samlp:ArtifactResolve>` SOAP request, as received at the IdP's
/// `ArtifactResolutionService` endpoint.
#[derive(Debug, Clone)]
pub struct ArtifactResolveRequest {
    /// `samlp:ArtifactResolve/@ID` — echoed back in the response's
    /// `InResponseTo`.
    pub request_id: String,
    /// `samlp:Issuer` text content — the SP entity ID requesting resolution.
    pub issuer: String,
    /// `samlp:Artifact` text content — the opaque token to look up.
    pub artifact: String,
}

/// Parse a `<samlp:ArtifactResolve>` SOAP envelope received at the IdP's
/// `ArtifactResolutionService`. Returns the request ID, requesting SP issuer,
/// and the artifact value to look up.
pub fn parse_artifact_resolve(soap_envelope: &[u8]) -> Result<ArtifactResolveRequest, Error> {
    let doc = Document::parse(soap_envelope)?;

    let envelope = doc.root();
    if envelope.qname().namespace() != Some(SOAP_NS) || envelope.qname().local() != "Envelope" {
        return Err(Error::XmlParse(
            "ArtifactResolve: SOAP envelope root is not soap:Envelope".to_string(),
        ));
    }

    let body = envelope
        .child_element(Some(SOAP_NS), "Body")
        .ok_or_else(|| Error::XmlParse("ArtifactResolve: missing soap:Body".to_string()))?;

    let resolve = body
        .child_element(Some(SAMLP_NS), "ArtifactResolve")
        .ok_or_else(|| {
            Error::XmlParse("ArtifactResolve: missing samlp:ArtifactResolve".to_string())
        })?;

    let request_id = resolve
        .attribute(None, "ID")
        .ok_or_else(|| Error::XmlParse("ArtifactResolve: missing @ID".to_string()))?
        .to_owned();

    let issuer = resolve
        .child_element(Some(SAML_NS), "Issuer")
        .ok_or_else(|| Error::XmlParse("ArtifactResolve: missing saml:Issuer".to_string()))?
        .text_content();

    let artifact = resolve
        .child_element(Some(SAMLP_NS), "Artifact")
        .ok_or_else(|| Error::XmlParse("ArtifactResolve: missing samlp:Artifact".to_string()))?
        .text_content();

    Ok(ArtifactResolveRequest {
        request_id,
        issuer,
        artifact,
    })
}

/// Build a `<samlp:ArtifactResponse>` SOAP envelope wrapping the IdP's stashed
/// SAML protocol message (typically a `<samlp:Response>`).
///
/// `idp_entity_id` is the IdP's entity ID (emitted as `saml:Issuer`).
/// `in_response_to` is the `ArtifactResolve/@ID` from the incoming request.
/// `payload_xml` is the inner SAML message XML (e.g. the stashed Response).
pub fn build_artifact_response(
    idp_entity_id: &str,
    in_response_to: &str,
    payload_xml: &str,
) -> Result<String, Error> {
    let id = random_xml_id()?;
    let issue_instant = format_xs_datetime(SystemTime::now())?;

    // Parse the payload XML so we can graft its element subtree into the
    // ArtifactResponse without re-serializing through string concatenation.
    let payload_doc = Document::parse(payload_xml.as_bytes())?;
    let payload_elem = payload_doc.root().clone();

    let issuer_elem = Element::build(QName::new(Some(SAML_NS.to_owned()), "Issuer"))
        .with_text(idp_entity_id.to_owned())
        .finish();

    let status_code = Element::build(QName::new(Some(SAMLP_NS.to_owned()), "StatusCode"))
        .with_attribute(QName::new(None, "Value"), STATUS_SUCCESS.to_owned())
        .finish();
    let status = Element::build(QName::new(Some(SAMLP_NS.to_owned()), "Status"))
        .with_child(Node::Element(status_code))
        .finish();

    let artifact_response =
        Element::build(QName::new(Some(SAMLP_NS.to_owned()), "ArtifactResponse"))
            .with_namespace(Some("samlp".to_owned()), SAMLP_NS)
            .with_namespace(Some("saml".to_owned()), SAML_NS)
            .with_attribute(QName::new(None, "ID"), id)
            .with_attribute(QName::new(None, "Version"), "2.0")
            .with_attribute(QName::new(None, "IssueInstant"), issue_instant)
            .with_attribute(
                QName::new(None, "InResponseTo"),
                in_response_to.to_owned(),
            )
            .with_child(Node::Element(issuer_elem))
            .with_child(Node::Element(status))
            .with_child(Node::Element(payload_elem))
            .finish();

    let body = Element::build(QName::new(Some(SOAP_NS.to_owned()), "Body"))
        .with_child(Node::Element(artifact_response))
        .finish();
    let envelope = Element::build(QName::new(Some(SOAP_NS.to_owned()), "Envelope"))
        .with_namespace(Some("soap".to_owned()), SOAP_NS)
        .with_child(Node::Element(body))
        .finish();

    let doc = Document::new(envelope)?;
    emit_document(&doc)
}

// =============================================================================
// Helpers
// =============================================================================

/// Generate a fresh XML `ID` value of the shape `_<32 hex chars>` (16 random
/// bytes, hex-encoded with a leading underscore so the value is a valid XML
/// `xs:ID`, which must start with a letter or `_`).
fn random_xml_id() -> Result<String, Error> {
    let mut bytes = [0u8; 16];
    // Propagate RNG failures so the outer flow can surface a configuration
    // error rather than emitting an ID built from uninitialized entropy.
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_err| Error::InvalidConfiguration {
            reason: "RNG failure generating random XML ID",
        })?;

    // Two-char lowercase hex for each byte, no formatter overhead.
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut out = String::with_capacity(1 + 32);
    out.push('_');
    for b in bytes {
        let hi = usize::from(b >> 4);
        let lo = usize::from(b & 0x0f);
        // hi and lo are both <16, so .get() always returns Some. We avoid
        // panicking indexing by using .get() + a defensive fallback.
        if let (Some(&h), Some(&l)) = (HEX.get(hi), HEX.get(lo)) {
            out.push(h as char);
            out.push(l as char);
        }
    }
    Ok(out)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;

    // --- make_artifact ------------------------------------------------------

    #[test]
    fn make_artifact_produces_44_byte_payload_base64() {
        let s = make_artifact("https://idp.example.com/saml", 0).unwrap();
        // 44 bytes → base64 with padding is exactly 60 chars (ceil(44/3)*4).
        assert_eq!(
            s.len(),
            60,
            "expected 60-char padded base64, got {} ({s:?})",
            s.len()
        );
        let decoded = BASE64.decode(s.as_bytes()).expect("base64");
        assert_eq!(decoded.len(), 44, "artifact must decode to 44 bytes");

        // Layout sanity.
        assert_eq!(&decoded[0..2], &ARTIFACT_TYPE_CODE.to_be_bytes());
        assert_eq!(&decoded[2..4], &0u16.to_be_bytes());

        // SourceID = SHA-1(entity_id).
        let expected_source = Sha1::digest(b"https://idp.example.com/saml");
        assert_eq!(&decoded[4..24], expected_source.as_slice());
    }

    #[test]
    fn make_artifact_endpoint_index_encodes_correctly() {
        let s = make_artifact("anything", 0x1234).unwrap();
        let decoded = BASE64.decode(s.as_bytes()).unwrap();
        assert_eq!(&decoded[2..4], &[0x12, 0x34]);
    }

    #[test]
    fn make_artifact_message_handle_is_unique_across_calls() {
        // Two calls with identical inputs must differ in the MessageHandle
        // bytes (24..44). Probabilistic, but P(collision) ~ 2^-160.
        let a = make_artifact("issuer", 0).unwrap();
        let b = make_artifact("issuer", 0).unwrap();
        assert_ne!(a, b, "MessageHandle should be random");
        let da = BASE64.decode(a.as_bytes()).unwrap();
        let db = BASE64.decode(b.as_bytes()).unwrap();
        assert_eq!(&da[0..24], &db[0..24], "header+SourceID match");
        assert_ne!(&da[24..44], &db[24..44], "MessageHandle differs");
    }

    // --- build_artifact_redirect -------------------------------------------

    #[test]
    fn build_artifact_redirect_emits_samlart_query_param() {
        let acs = Url::parse("https://sp.example.com/acs").unwrap();
        let redirect = build_artifact_redirect(
            &acs,
            "https://idp.example.com",
            0,
            "<samlp:Response/>".to_owned(),
            None,
        )
        .unwrap();

        let query = redirect.redirect_to.query().expect("query present");
        assert!(query.starts_with("SAMLart="), "query: {query}");
        assert!(
            !query.contains("RelayState"),
            "RelayState should be omitted: {query}"
        );

        // Round-trip the SAMLart value via the URL parser to confirm it
        // matches the returned `artifact` field.
        let parsed_artifact = redirect
            .redirect_to
            .query_pairs()
            .find(|(k, _)| k == "SAMLart")
            .map(|(_, v)| v.into_owned())
            .unwrap();
        assert_eq!(parsed_artifact, redirect.artifact);
        assert_eq!(redirect.response_xml, "<samlp:Response/>");
    }

    #[test]
    fn build_artifact_redirect_includes_relay_state_when_present() {
        let acs = Url::parse("https://sp.example.com/acs").unwrap();
        let redirect = build_artifact_redirect(
            &acs,
            "https://idp.example.com",
            1,
            "<samlp:Response/>".to_owned(),
            Some("opaque-relay-state"),
        )
        .unwrap();

        let pairs: Vec<(String, String)> = redirect
            .redirect_to
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].0, "SAMLart");
        assert_eq!(pairs[1].0, "RelayState");
        assert_eq!(pairs[1].1, "opaque-relay-state");
    }

    #[test]
    fn build_artifact_redirect_percent_encodes_relay_state_with_specials() {
        let acs = Url::parse("https://sp.example.com/acs").unwrap();
        let redirect = build_artifact_redirect(
            &acs,
            "issuer",
            0,
            String::new(),
            Some("a&b=c d"),
        )
        .unwrap();
        // url::Url percent-encodes `&`, `=`, and ` ` in the value.
        let raw_query = redirect.redirect_to.query().unwrap();
        assert!(raw_query.contains("RelayState="), "{raw_query}");
        // The decoded value matches what we put in.
        let rs = redirect
            .redirect_to
            .query_pairs()
            .find(|(k, _)| k == "RelayState")
            .map(|(_, v)| v.into_owned())
            .unwrap();
        assert_eq!(rs, "a&b=c d");
    }

    // --- build_artifact_resolve --------------------------------------------

    #[test]
    fn build_artifact_resolve_is_well_formed_soap() {
        let xml = build_artifact_resolve(
            "https://sp.example.com",
            "https://idp.example.com/ars",
            "AAQAA...",
        )
        .unwrap();

        let doc = Document::parse(xml.as_bytes()).expect("re-parse");
        let env = doc.root();
        assert_eq!(env.qname().namespace(), Some(SOAP_NS));
        assert_eq!(env.qname().local(), "Envelope");

        let body = env.child_element(Some(SOAP_NS), "Body").unwrap();
        let resolve = body
            .child_element(Some(SAMLP_NS), "ArtifactResolve")
            .unwrap();

        // Required attributes.
        assert_eq!(resolve.attribute(None, "Version"), Some("2.0"));
        assert!(
            resolve
                .attribute(None, "ID")
                .is_some_and(|v| v.starts_with('_') && v.len() == 33)
        );
        assert!(resolve.attribute(None, "IssueInstant").is_some());
        assert_eq!(
            resolve.attribute(None, "Destination"),
            Some("https://idp.example.com/ars")
        );

        // Children.
        let issuer = resolve.child_element(Some(SAML_NS), "Issuer").unwrap();
        assert_eq!(issuer.text_content(), "https://sp.example.com");

        let artifact_node = resolve.child_element(Some(SAMLP_NS), "Artifact").unwrap();
        assert_eq!(artifact_node.text_content(), "AAQAA...");
    }

    // --- parse_artifact_response -------------------------------------------

    fn success_envelope_xml(payload_xml: &str) -> Vec<u8> {
        format!(
            r#"<soap:Envelope xmlns:soap="{SOAP_NS}">
  <soap:Body>
    <samlp:ArtifactResponse xmlns:samlp="{SAMLP_NS}" xmlns:saml="{SAML_NS}"
                            ID="_resp1" Version="2.0"
                            InResponseTo="_req1"
                            IssueInstant="2026-01-01T00:00:00Z">
      <saml:Issuer>https://idp.example.com</saml:Issuer>
      <samlp:Status>
        <samlp:StatusCode Value="{STATUS_SUCCESS}"/>
      </samlp:Status>
      {payload_xml}
    </samlp:ArtifactResponse>
  </soap:Body>
</soap:Envelope>"#,
        )
        .into_bytes()
    }

    #[test]
    fn parse_artifact_response_extracts_inner_response() {
        let payload = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                                          xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                                          ID="_inner" Version="2.0"
                                          IssueInstant="2026-01-01T00:00:00Z">
            <saml:Issuer>https://idp.example.com</saml:Issuer>
        </samlp:Response>"#;
        let env = success_envelope_xml(payload);

        let inner_bytes = parse_artifact_response(&env).expect("parse");
        let inner_doc = Document::parse(&inner_bytes).expect("re-parse inner");
        assert_eq!(inner_doc.root().qname().namespace(), Some(SAMLP_NS));
        assert_eq!(inner_doc.root().qname().local(), "Response");
        assert_eq!(inner_doc.root().attribute(None, "ID"), Some("_inner"));
    }

    #[test]
    fn parse_artifact_response_rejects_non_success_status() {
        let xml = format!(
            r#"<soap:Envelope xmlns:soap="{SOAP_NS}">
  <soap:Body>
    <samlp:ArtifactResponse xmlns:samlp="{SAMLP_NS}" xmlns:saml="{SAML_NS}"
                            ID="_resp1" Version="2.0"
                            IssueInstant="2026-01-01T00:00:00Z">
      <saml:Issuer>https://idp.example.com</saml:Issuer>
      <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"/>
        <samlp:StatusMessage>artifact expired</samlp:StatusMessage>
      </samlp:Status>
    </samlp:ArtifactResponse>
  </soap:Body>
</soap:Envelope>"#,
        );
        let err = parse_artifact_response(xml.as_bytes()).unwrap_err();
        match err {
            Error::StatusNotSuccess { code, message } => {
                assert_eq!(code, "urn:oasis:names:tc:SAML:2.0:status:Responder");
                assert_eq!(message.as_deref(), Some("artifact expired"));
            }
            other => panic!("expected StatusNotSuccess, got {other:?}"),
        }
    }

    #[test]
    fn parse_artifact_response_rejects_missing_envelope() {
        // Wrong root element.
        let xml = r"<not-soap/>";
        let err = parse_artifact_response(xml.as_bytes()).unwrap_err();
        assert!(matches!(err, Error::XmlParse(_)));
    }

    #[test]
    fn parse_artifact_response_rejects_missing_payload_message() {
        // Status is Success but there's no protocol-message child.
        let xml = format!(
            r#"<soap:Envelope xmlns:soap="{SOAP_NS}">
  <soap:Body>
    <samlp:ArtifactResponse xmlns:samlp="{SAMLP_NS}" xmlns:saml="{SAML_NS}"
                            ID="_resp1" Version="2.0"
                            IssueInstant="2026-01-01T00:00:00Z">
      <saml:Issuer>https://idp.example.com</saml:Issuer>
      <samlp:Status><samlp:StatusCode Value="{STATUS_SUCCESS}"/></samlp:Status>
    </samlp:ArtifactResponse>
  </soap:Body>
</soap:Envelope>"#,
        );
        let err = parse_artifact_response(xml.as_bytes()).unwrap_err();
        match err {
            Error::XmlParse(msg) => {
                assert!(msg.contains("payload"), "got: {msg}");
            }
            other => panic!("expected XmlParse, got {other:?}"),
        }
    }

    // --- resolve_artifact (end-to-end via mock client) --------------------

    /// Mock `HttpClient` that returns a pre-built ArtifactResponse SOAP
    /// envelope and records the request it received for assertion.
    struct MockClient {
        response: Vec<u8>,
        last_request: std::sync::Mutex<Option<HttpRequest>>,
    }

    impl MockClient {
        fn new(response: Vec<u8>) -> Self {
            Self {
                response,
                last_request: std::sync::Mutex::new(None),
            }
        }
    }

    impl HttpClient for MockClient {
        fn send(
            &self,
            request: HttpRequest,
        ) -> impl Future<
            Output = Result<HttpResponse, Box<dyn std::error::Error + Send + Sync>>,
        > + Send {
            *self.last_request.lock().unwrap() = Some(request);
            let body = self.response.clone();
            async move {
                Ok(HttpResponse {
                    status: 200,
                    headers: vec![("Content-Type".to_owned(), "text/xml".to_owned())],
                    body,
                })
            }
        }
    }

    #[tokio::test]
    async fn resolve_artifact_end_to_end_returns_inner_response_xml() {
        let payload = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                                          xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                                          ID="_inner-roundtrip" Version="2.0"
                                          IssueInstant="2026-05-26T12:00:00Z">
            <saml:Issuer>https://idp.example.com</saml:Issuer>
        </samlp:Response>"#;
        let envelope = success_envelope_xml(payload);
        let client = MockClient::new(envelope);

        let inner = resolve_artifact(
            &client,
            "https://idp.example.com/ars",
            "https://sp.example.com",
            "AAQAA-sample-artifact",
        )
        .await
        .expect("resolve");

        let doc = Document::parse(&inner).expect("inner re-parse");
        assert_eq!(doc.root().qname().local(), "Response");
        assert_eq!(
            doc.root().attribute(None, "ID"),
            Some("_inner-roundtrip")
        );

        // Verify the outbound request looked correct.
        let sent = client.last_request.lock().unwrap().clone().unwrap();
        assert_eq!(sent.method, http::Method::POST);
        assert_eq!(sent.url, "https://idp.example.com/ars");
        assert!(
            sent.headers
                .iter()
                .any(|(k, v)| k == "Content-Type" && v == "text/xml"),
            "headers: {:?}",
            sent.headers
        );
        assert!(
            sent.headers
                .iter()
                .any(|(k, v)| k == "SOAPAction" && v == "\"\""),
            "headers: {:?}",
            sent.headers
        );

        let sent_body = std::str::from_utf8(&sent.body).expect("utf-8");
        // Re-parse the outbound SOAP body to verify it's well-formed and
        // carries the expected artifact and issuer.
        let req_doc = Document::parse(sent_body.as_bytes()).expect("outbound parse");
        let resolve = req_doc
            .find_first(Some(SAMLP_NS), "ArtifactResolve")
            .expect("ArtifactResolve");
        assert_eq!(
            resolve.attribute(None, "Destination"),
            Some("https://idp.example.com/ars")
        );
        let artifact_node = resolve.child_element(Some(SAMLP_NS), "Artifact").unwrap();
        assert_eq!(artifact_node.text_content(), "AAQAA-sample-artifact");
        let issuer = resolve.child_element(Some(SAML_NS), "Issuer").unwrap();
        assert_eq!(issuer.text_content(), "https://sp.example.com");
    }

    #[tokio::test]
    async fn resolve_artifact_propagates_status_error() {
        let envelope = format!(
            r#"<soap:Envelope xmlns:soap="{SOAP_NS}">
  <soap:Body>
    <samlp:ArtifactResponse xmlns:samlp="{SAMLP_NS}" xmlns:saml="{SAML_NS}"
                            ID="_resp1" Version="2.0"
                            IssueInstant="2026-01-01T00:00:00Z">
      <saml:Issuer>https://idp.example.com</saml:Issuer>
      <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"/></samlp:Status>
    </samlp:ArtifactResponse>
  </soap:Body>
</soap:Envelope>"#,
        )
        .into_bytes();

        let client = MockClient::new(envelope);
        let err = resolve_artifact(
            &client,
            "https://idp.example.com/ars",
            "https://sp.example.com",
            "AAQAA",
        )
        .await
        .unwrap_err();

        match err {
            Error::StatusNotSuccess { code, .. } => {
                assert_eq!(code, "urn:oasis:names:tc:SAML:2.0:status:Requester");
            }
            other => panic!("expected StatusNotSuccess, got {other:?}"),
        }
    }

    // --- random_xml_id ------------------------------------------------------

    #[test]
    fn random_xml_id_shape_underscore_plus_32_hex_lowercase() {
        let id = random_xml_id().unwrap();
        assert_eq!(id.len(), 33);
        assert!(id.starts_with('_'));
        assert!(
            id.bytes()
                .skip(1)
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "non-lowercase-hex char in {id}"
        );
    }
}
