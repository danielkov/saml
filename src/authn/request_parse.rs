//! Parse inbound `<samlp:AuthnRequest>` per SAML 2.0 Core §3.4.1.
//!
//! Used by `IdentityProvider::consume_authn_request` (RFC-004 §2).
//!
//! This module produces a `RawParsedAuthnRequest` — a faithful view of the
//! wire-format attributes and children, without cross-checking against any SP
//! metadata. The cross-checks (Issuer match, Destination registry, ACS
//! resolution, binding consistency) live in [`super::request_validate`]; the
//! split lets the IdP role verify the AuthnRequest's signature against the
//! element handle returned here before doing any metadata-dependent work.
//!
//! ## ProtocolBinding check at parse time
//!
//! Per RFC-004 §2.1 step 5a, when `@ProtocolBinding` is present we narrow it
//! via [`SsoResponseBinding::from_uri`]. Redirect and SOAP URIs are not legal
//! for SSO Responses (SAML 2.0 Profiles §4.1.4) and surface as
//! [`Error::IllegalResponseBinding`]; this rejection happens before the
//! caller has a chance to act on the AuthnRequest, closing the gap where an
//! attacker asks the IdP to deliver the Response via Redirect (bypassing the
//! embedded XML-DSig that POST profile mandates).

use std::time::SystemTime;

use crate::authn::{SAML_NS, SAMLP_NS};
use crate::authn_context::{AuthnContextClassRef, AuthnContextComparison, RequestedAuthnContext};
use crate::binding::SsoResponseBinding;
use crate::error::Error;
use crate::nameid::NameIdFormat;
use crate::time::parse_xs_datetime;
use crate::xml::parse::{Document, Element};

/// Lower-level parsed-AuthnRequest. The full `ParsedAuthnRequest` from RFC-004
/// §2 is built in `request_validate.rs` (it carries a resolved
/// `SsoResponseEndpoint` rather than the raw selection).
#[derive(Debug, Clone)]
pub(crate) struct RawParsedAuthnRequest {
    pub id: String,
    pub issue_instant: SystemTime,
    pub destination: Option<String>,
    pub force_authn: bool,
    pub is_passive: bool,
    pub issuer: String,
    pub assertion_consumer_service_url: Option<String>,
    pub assertion_consumer_service_index: Option<u16>,
    pub protocol_binding: Option<SsoResponseBinding>,
    pub requested_name_id_format: Option<NameIdFormat>,
    pub requested_authn_context: Option<RequestedAuthnContext>,
}

/// Parse `<samlp:AuthnRequest>` XML. Returns the raw view plus a handle to the
/// root element (for signature verification by the caller, which needs to
/// pass an `ElementId` to the dsig layer).
pub(crate) fn parse_authn_request(
    document: &Document,
) -> Result<(RawParsedAuthnRequest, &Element), Error> {
    let root = document.root();

    if !is_samlp_element(root, "AuthnRequest") {
        return Err(Error::XmlParse(
            "expected samlp:AuthnRequest root".to_string(),
        ));
    }

    // Structural schema gate. See `crate::schema` for the rule set.
    #[cfg(feature = "xsd-validate")]
    crate::schema::validate_authn_request(root)?;

    let version = required_attr(root, "Version")?;
    if version != "2.0" {
        return Err(Error::XmlParse("unsupported SAML version".to_string()));
    }

    let id = required_attr(root, "ID")?;
    let issue_instant_str = required_attr(root, "IssueInstant")?;
    let issue_instant = parse_xs_datetime(&issue_instant_str)?;

    let destination = root.attribute(None, "Destination").map(str::to_owned);
    let force_authn = parse_optional_xs_bool(root.attribute(None, "ForceAuthn"))?.unwrap_or(false);
    let is_passive = parse_optional_xs_bool(root.attribute(None, "IsPassive"))?.unwrap_or(false);

    // ProtocolBinding: narrow at parse time per RFC-004 §2.1 step 5a.
    //
    // `SsoResponseBinding::from_uri` already returns `IllegalResponseBinding`
    // for Redirect / SOAP and `InvalidConfiguration` for unknown URIs. We
    // propagate the former unchanged (caller wants the structured variant)
    // and re-shape the latter as an XmlParse error, since an unknown
    // ProtocolBinding URI is a wire-format issue, not a caller-side
    // configuration bug.
    let protocol_binding = match root.attribute(None, "ProtocolBinding") {
        None => None,
        Some(uri) => match SsoResponseBinding::from_uri(uri) {
            Ok(b) => Some(b),
            Err(e @ Error::IllegalResponseBinding { .. }) => return Err(e),
            Err(_) => {
                return Err(Error::XmlParse(format!(
                    "unknown ProtocolBinding URI: {uri}"
                )));
            }
        },
    };

    let assertion_consumer_service_url = root
        .attribute(None, "AssertionConsumerServiceURL")
        .map(str::to_owned);
    let assertion_consumer_service_index = root
        .attribute(None, "AssertionConsumerServiceIndex")
        .map(|s| {
            s.parse::<u16>().map_err(|source| {
                Error::XmlParse(format!("AssertionConsumerServiceIndex not u16: {source}"))
            })
        })
        .transpose()?;

    let issuer_elem = root
        .child_element(Some(SAML_NS), "Issuer")
        .ok_or_else(|| Error::XmlParse("AuthnRequest missing saml:Issuer".to_string()))?;
    let issuer = issuer_elem.text_content().trim().to_owned();
    if issuer.is_empty() {
        return Err(Error::XmlParse(
            "AuthnRequest saml:Issuer is empty".to_string(),
        ));
    }

    let requested_name_id_format = root
        .child_element(Some(SAMLP_NS), "NameIDPolicy")
        .and_then(|p| p.attribute(None, "Format"))
        .map(NameIdFormat::from_uri);

    let requested_authn_context = parse_requested_authn_context(root)?;

    let parsed = RawParsedAuthnRequest {
        id,
        issue_instant,
        destination,
        force_authn,
        is_passive,
        issuer,
        assertion_consumer_service_url,
        assertion_consumer_service_index,
        protocol_binding,
        requested_name_id_format,
        requested_authn_context,
    };
    Ok((parsed, root))
}

fn parse_requested_authn_context(root: &Element) -> Result<Option<RequestedAuthnContext>, Error> {
    let Some(rac) = root.child_element(Some(SAMLP_NS), "RequestedAuthnContext") else {
        return Ok(None);
    };
    let comparison = match rac.attribute(None, "Comparison") {
        None | Some("exact") => AuthnContextComparison::Exact,
        Some("minimum") => AuthnContextComparison::Minimum,
        Some("maximum") => AuthnContextComparison::Maximum,
        Some("better") => AuthnContextComparison::Better,
        Some(other) => {
            return Err(Error::XmlParse(format!(
                "unknown RequestedAuthnContext Comparison: {other}"
            )));
        }
    };
    let class_refs: Vec<AuthnContextClassRef> = rac
        .all_child_elements(Some(SAML_NS), "AuthnContextClassRef")
        .map(|e| AuthnContextClassRef::from_uri(e.text_content().trim()))
        .collect();
    Ok(Some(RequestedAuthnContext {
        class_refs,
        comparison,
    }))
}

fn is_samlp_element(element: &Element, local: &str) -> bool {
    element.qname().local() == local && element.qname().namespace() == Some(SAMLP_NS)
}

fn required_attr(element: &Element, local: &str) -> Result<String, Error> {
    element
        .attribute(None, local)
        .ok_or_else(|| Error::XmlParse(format!("AuthnRequest missing required attribute: {local}")))
        .map(str::to_owned)
}

fn parse_optional_xs_bool(value: Option<&str>) -> Result<Option<bool>, Error> {
    match value {
        None => Ok(None),
        Some("true" | "1") => Ok(Some(true)),
        Some("false" | "0") => Ok(Some(false)),
        Some(other) => Err(Error::XmlParse(format!(
            "invalid xs:boolean attribute value: {other}"
        ))),
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::Binding;

    fn parse(xml: &str) -> Result<RawParsedAuthnRequest, Error> {
        let doc = Document::parse(xml.as_bytes())?;
        parse_authn_request(&doc).map(|(p, _)| p)
    }

    const VALID_REQUEST: &str = r#"<samlp:AuthnRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_abc123" Version="2.0"
            IssueInstant="2026-05-26T12:34:56Z"
            Destination="https://idp.example.com/sso"
            AssertionConsumerServiceIndex="0"
            ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            ForceAuthn="true" IsPassive="false">
          <saml:Issuer>https://sp.example.com/saml</saml:Issuer>
          <samlp:NameIDPolicy
            Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
            AllowCreate="true"/>
        </samlp:AuthnRequest>"#;

    #[test]
    fn parses_valid_request() {
        let p = parse(VALID_REQUEST).expect("ok");
        assert_eq!(p.id, "_abc123");
        assert_eq!(
            p.destination.as_deref(),
            Some("https://idp.example.com/sso")
        );
        assert_eq!(p.issuer, "https://sp.example.com/saml");
        assert_eq!(p.assertion_consumer_service_index, Some(0));
        assert!(p.assertion_consumer_service_url.is_none());
        assert_eq!(p.protocol_binding, Some(SsoResponseBinding::HttpPost));
        assert!(p.force_authn);
        assert!(!p.is_passive);
        assert_eq!(
            p.requested_name_id_format
                .as_ref()
                .map(NameIdFormat::as_uri),
            Some("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent")
        );
        assert!(p.requested_authn_context.is_none());
    }

    #[test]
    fn parses_request_with_requested_authn_context() {
        let xml = r#"<samlp:AuthnRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_id" Version="2.0"
            IssueInstant="2026-05-26T12:34:56Z"
            Destination="https://idp.example.com/sso">
          <saml:Issuer>https://sp.example.com/saml</saml:Issuer>
          <samlp:RequestedAuthnContext Comparison="minimum">
            <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
            <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactorAuthentication</saml:AuthnContextClassRef>
          </samlp:RequestedAuthnContext>
        </samlp:AuthnRequest>"#;
        let p = parse(xml).expect("ok");
        let rac = p.requested_authn_context.expect("RAC present");
        assert_eq!(rac.comparison, AuthnContextComparison::Minimum);
        assert_eq!(rac.class_refs.len(), 2);
        assert_eq!(
            rac.class_refs[0],
            AuthnContextClassRef::PasswordProtectedTransport
        );
        assert_eq!(rac.class_refs[1], AuthnContextClassRef::MultiFactorAuth);
    }

    #[test]
    fn comparison_defaults_to_exact_when_absent() {
        let xml = r#"<samlp:AuthnRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_id" Version="2.0"
            IssueInstant="2026-05-26T12:34:56Z"
            Destination="https://idp.example.com/sso">
          <saml:Issuer>https://sp.example.com/saml</saml:Issuer>
          <samlp:RequestedAuthnContext>
            <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
          </samlp:RequestedAuthnContext>
        </samlp:AuthnRequest>"#;
        let p = parse(xml).expect("ok");
        let rac = p.requested_authn_context.unwrap();
        assert_eq!(rac.comparison, AuthnContextComparison::Exact);
    }

    #[test]
    fn protocol_binding_redirect_rejected_as_illegal() {
        let xml = r#"<samlp:AuthnRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_id" Version="2.0"
            IssueInstant="2026-05-26T12:34:56Z"
            Destination="https://idp.example.com/sso"
            ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect">
          <saml:Issuer>https://sp.example.com/saml</saml:Issuer>
        </samlp:AuthnRequest>"#;
        let err = parse(xml).unwrap_err();
        match err {
            Error::IllegalResponseBinding { requested } => {
                assert_eq!(requested, Binding::HttpRedirect);
            }
            other => panic!("expected IllegalResponseBinding, got {other:?}"),
        }
    }

    #[test]
    fn protocol_binding_soap_rejected_as_illegal() {
        let xml = r#"<samlp:AuthnRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_id" Version="2.0"
            IssueInstant="2026-05-26T12:34:56Z"
            Destination="https://idp.example.com/sso"
            ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP">
          <saml:Issuer>https://sp.example.com/saml</saml:Issuer>
        </samlp:AuthnRequest>"#;
        let err = parse(xml).unwrap_err();
        match err {
            Error::IllegalResponseBinding { requested } => {
                assert_eq!(requested, Binding::Soap);
            }
            other => panic!("expected IllegalResponseBinding, got {other:?}"),
        }
    }

    #[test]
    fn protocol_binding_unknown_uri_is_xml_parse_error() {
        let xml = r#"<samlp:AuthnRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_id" Version="2.0"
            IssueInstant="2026-05-26T12:34:56Z"
            Destination="https://idp.example.com/sso"
            ProtocolBinding="urn:nonsense">
          <saml:Issuer>https://sp.example.com/saml</saml:Issuer>
        </samlp:AuthnRequest>"#;
        let err = parse(xml).unwrap_err();
        match err {
            Error::XmlParse(msg) => {
                assert!(msg.contains("ProtocolBinding"), "got: {msg}");
            }
            other => panic!("expected XmlParse, got {other:?}"),
        }
    }

    #[test]
    fn unknown_root_element_rejected() {
        let xml = r#"<samlp:LogoutRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            ID="_id" Version="2.0" IssueInstant="2026-05-26T12:34:56Z"/>"#;
        let err = parse(xml).unwrap_err();
        match err {
            Error::XmlParse(msg) => {
                assert!(msg.contains("AuthnRequest"), "got: {msg}");
            }
            other => panic!("expected XmlParse, got {other:?}"),
        }
    }

    #[test]
    fn unsupported_version_rejected() {
        let xml = r#"<samlp:AuthnRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_id" Version="1.1"
            IssueInstant="2026-05-26T12:34:56Z"
            Destination="https://idp.example.com/sso">
          <saml:Issuer>https://sp.example.com/saml</saml:Issuer>
        </samlp:AuthnRequest>"#;
        let err = parse(xml).unwrap_err();
        match err {
            Error::XmlParse(msg) => {
                assert!(msg.contains("version"), "got: {msg}");
            }
            other => panic!("expected XmlParse, got {other:?}"),
        }
    }

    #[test]
    fn missing_issue_instant_rejected() {
        let xml = r#"<samlp:AuthnRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_id" Version="2.0"
            Destination="https://idp.example.com/sso">
          <saml:Issuer>https://sp.example.com/saml</saml:Issuer>
        </samlp:AuthnRequest>"#;
        let err = parse(xml).unwrap_err();
        // Under default features the structural schema gate fires first
        // (SchemaViolation); when `xsd-validate` is off the manual
        // `required_attr` check below surfaces XmlParse. Both express the
        // same rule.
        match err {
            Error::XmlParse(msg) => {
                assert!(msg.contains("IssueInstant"), "got: {msg}");
            }
            Error::SchemaViolation { reason, .. } => {
                assert!(reason.contains("IssueInstant"), "got: {reason}");
            }
            other => panic!("expected XmlParse or SchemaViolation, got {other:?}"),
        }
    }

    #[test]
    fn missing_id_rejected() {
        let xml = r#"<samlp:AuthnRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            Version="2.0" IssueInstant="2026-05-26T12:34:56Z"
            Destination="https://idp.example.com/sso">
          <saml:Issuer>https://sp.example.com/saml</saml:Issuer>
        </samlp:AuthnRequest>"#;
        let err = parse(xml).unwrap_err();
        match err {
            Error::XmlParse(msg) => assert!(msg.contains("ID"), "got: {msg}"),
            Error::SchemaViolation { reason, .. } => {
                assert!(reason.contains("ID"), "got: {reason}")
            }
            other => panic!("expected XmlParse or SchemaViolation, got {other:?}"),
        }
    }

    #[test]
    fn missing_issuer_rejected() {
        let xml = r#"<samlp:AuthnRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_id" Version="2.0"
            IssueInstant="2026-05-26T12:34:56Z"
            Destination="https://idp.example.com/sso"/>"#;
        let err = parse(xml).unwrap_err();
        match err {
            Error::XmlParse(msg) => assert!(msg.contains("Issuer"), "got: {msg}"),
            other => panic!("expected XmlParse, got {other:?}"),
        }
    }

    #[test]
    fn invalid_force_authn_value_rejected() {
        let xml = r#"<samlp:AuthnRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_id" Version="2.0"
            IssueInstant="2026-05-26T12:34:56Z"
            Destination="https://idp.example.com/sso"
            ForceAuthn="banana">
          <saml:Issuer>https://sp.example.com/saml</saml:Issuer>
        </samlp:AuthnRequest>"#;
        let err = parse(xml).unwrap_err();
        match err {
            Error::XmlParse(msg) => assert!(msg.contains("xs:boolean"), "got: {msg}"),
            other => panic!("expected XmlParse, got {other:?}"),
        }
    }

    #[test]
    fn root_element_handle_returned() {
        let doc = Document::parse(VALID_REQUEST.as_bytes()).unwrap();
        let (_parsed, elem) = parse_authn_request(&doc).unwrap();
        // The returned handle must point at the root <AuthnRequest>.
        assert_eq!(elem.qname().local(), "AuthnRequest");
        assert_eq!(elem.qname().namespace(), Some(SAMLP_NS));
        assert_eq!(elem.id(), doc.root().id());
    }
}
