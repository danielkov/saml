//! Cross-check parsed AuthnRequest against SP metadata + caller-supplied
//! destination, producing the public [`ParsedAuthnRequest`].
//!
//! Implements RFC-004 §2.1 steps 4 (Issuer match), 5 (Destination check),
//! 5a + 7 (ACS resolution), 7a (binding consistency). Step 5a is performed at
//! parse time in [`super::request_parse`] (it depends only on the wire
//! ProtocolBinding URI, not on metadata); the rest live here.
//!
//! The key security property below is **echo prevention** on the ACS URL:
//! the SP-supplied `AssertionConsumerServiceURL` is *never* trusted directly.
//! It must match a URL already advertised in `SpDescriptor`, otherwise the
//! request is rejected with [`Error::UnregisteredAcs`]. The resolved endpoint
//! flows into [`ParsedAuthnRequest::assertion_consumer_service`] as an
//! [`SsoResponseEndpoint`] cloned from the descriptor — by construction it
//! can only be a registered URL, and by the type's invariants it can only
//! carry a POST or Artifact binding.

use std::time::SystemTime;

use crate::authn::request_parse::RawParsedAuthnRequest;
use crate::authn_context::RequestedAuthnContext;
use crate::binding::{SsoResponseBinding, SsoResponseEndpoint};
use crate::descriptor::sp::SpDescriptor;
use crate::error::Error;
use crate::nameid::NameIdFormat;

/// The validated AuthnRequest the IdP role hands back to its caller. Mirrors
/// RFC-004 §2 `ParsedAuthnRequest` verbatim.
#[derive(Debug, Clone)]
pub struct ParsedAuthnRequest {
    pub id: String,
    pub issuer: String,
    pub issue_instant: SystemTime,
    pub destination: Option<String>,
    /// Resolved ACS endpoint — always points at a registered SP endpoint
    /// (never the SP-supplied URL). RFC-004 §2.1 step 7 (echo-prevention).
    pub assertion_consumer_service: SsoResponseEndpoint,
    /// What binding the SP requested for the Response. Parser already
    /// narrowed to POST/Artifact (illegal Redirect/SOAP rejected at parse
    /// time). `None` means the AuthnRequest carried no `@ProtocolBinding`.
    pub protocol_binding: Option<SsoResponseBinding>,
    /// Raw selection from the request, kept for logging.
    pub assertion_consumer_service_selection: AcsSelection,
    pub force_authn: bool,
    pub is_passive: bool,
    pub requested_name_id_format: Option<NameIdFormat>,
    pub requested_authn_context: Option<RequestedAuthnContext>,
    /// RelayState forwarded from the binding layer (Redirect query string, or
    /// POST form). Optional. Set by the caller (sp/idp role), not here —
    /// `validate_authn_request` initializes this to `None`; the caller
    /// overwrites it after a successful validate.
    pub relay_state: Option<String>,
}

/// How the SP nominated its ACS endpoint on the wire. Retained on the
/// validated request for logging / metrics; resolution has already happened.
#[derive(Debug, Clone)]
pub enum AcsSelection {
    /// SP specified `AssertionConsumerServiceIndex`.
    Index(u16),
    /// SP specified `AssertionConsumerServiceURL`.
    Url(String),
    /// SP specified neither — IdP used SP metadata's default endpoint.
    Default,
}

/// Apply RFC-004 §2.1 steps 4, 5, 7, 7a to the raw parsed request.
///
/// `expected_destination` is the URL of the IdP SSO endpoint that received
/// the message; `sp_sso_endpoint_urls` is the IdP's own registered SSO
/// endpoint URL set (so this function can reject callers that pass a
/// destination not registered in their own metadata — the
/// "RFC-004 §2.1 step 5 caller-bug guard").
pub(crate) fn validate_authn_request(
    raw: RawParsedAuthnRequest,
    sp: &SpDescriptor,
    expected_destination: &str,
    sp_sso_endpoint_urls: &[String],
) -> Result<ParsedAuthnRequest, Error> {
    // Step 4: Issuer match.
    if raw.issuer != sp.entity_id {
        return Err(Error::IssuerMismatch {
            expected: sp.entity_id.clone(),
            got: Some(raw.issuer),
        });
    }

    // Step 5: Destination binding.
    //
    // First, the caller must have routed this AuthnRequest to an endpoint
    // they actually advertise in metadata. Treat the absence as an
    // InvalidConfiguration (caller bug, not wire-format issue).
    if !sp_sso_endpoint_urls
        .iter()
        .any(|u| u == expected_destination)
    {
        return Err(Error::InvalidConfiguration {
            reason: "expected_destination is not a registered SSO endpoint",
        });
    }
    // Second, if the AuthnRequest carries `@Destination`, it MUST match.
    // Absence is permitted (the spec marks Destination as optional on
    // AuthnRequest); presence is binding.
    if let Some(dest) = raw.destination.as_deref()
        && dest != expected_destination
    {
        return Err(Error::DestinationMismatch);
    }

    // Step 7: ACS resolution.
    //
    // The order — Index → URL → Default — mirrors the SAML 2.0 schema's
    // attribute precedence: when both Index and URL are supplied, the
    // schema is ambiguous and most IdPs (Okta, Auth0) honor Index. We never
    // reach the `URL` branch when an `Index` was supplied; the parser
    // surfaces both, but validation deliberately prefers the indirection
    // (an index can only point at a registered endpoint, so it is strictly
    // safer than a URL lookup).
    let unregistered = || Error::UnregisteredAcs {
        entity_id: sp.entity_id.clone(),
    };
    let (resolved, selection): (SsoResponseEndpoint, AcsSelection) =
        if let Some(index) = raw.assertion_consumer_service_index {
            let endpoint = sp.acs_endpoint_by_index(index).cloned().ok_or_else(unregistered)?;
            (endpoint, AcsSelection::Index(index))
        } else if let Some(url) = raw.assertion_consumer_service_url.as_deref() {
            let endpoint = sp.acs_endpoint_by_url(url).cloned().ok_or_else(unregistered)?;
            (endpoint, AcsSelection::Url(url.to_owned()))
        } else {
            let endpoint = sp.default_acs().cloned().ok_or_else(unregistered)?;
            (endpoint, AcsSelection::Default)
        };

    // Step 7a: binding consistency.
    //
    // If the SP requested a specific Response binding via `@ProtocolBinding`,
    // it must match the binding registered on the resolved ACS endpoint. We
    // already know the request value is a `SsoResponseBinding` (Redirect /
    // SOAP rejected at parse time), and the registry endpoint binding is
    // also a `SsoResponseBinding`, so the comparison is a direct equality
    // check.
    if let Some(requested) = raw.protocol_binding
        && requested != resolved.binding
    {
        return Err(Error::IllegalResponseBinding {
            requested: requested.as_binding(),
        });
    }

    Ok(ParsedAuthnRequest {
        id: raw.id,
        issuer: raw.issuer,
        issue_instant: raw.issue_instant,
        destination: raw.destination,
        assertion_consumer_service: resolved,
        protocol_binding: raw.protocol_binding,
        assertion_consumer_service_selection: selection,
        force_authn: raw.force_authn,
        is_passive: raw.is_passive,
        requested_name_id_format: raw.requested_name_id_format,
        requested_authn_context: raw.requested_authn_context,
        relay_state: None,
    })
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authn::request_parse::parse_authn_request;
    use crate::binding::SsoResponseBinding;
    use crate::xml::parse::Document;

    /// Build an `SpDescriptor` directly via metadata XML (no encryption /
    /// signing certs needed for these tests — validation reads only the
    /// `entity_id` + ACS list).
    fn sp_with_acs_layout(acs_xml: &str) -> SpDescriptor {
        let xml = format!(
            r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                                     entityID="https://sp.example.com/saml">
              <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                {acs_xml}
              </md:SPSSODescriptor>
            </md:EntityDescriptor>"#
        );
        SpDescriptor::from_metadata_xml(xml.as_bytes()).unwrap()
    }

    fn default_sp() -> SpDescriptor {
        sp_with_acs_layout(
            r#"<md:AssertionConsumerService index="0" isDefault="true"
                    Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                    Location="https://sp.example.com/acs/post"/>
              <md:AssertionConsumerService index="1"
                    Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"
                    Location="https://sp.example.com/acs/artifact"/>"#,
        )
    }

    fn sso_urls() -> Vec<String> {
        vec!["https://idp.example.com/sso".to_string()]
    }

    fn raw_request(xml: &str) -> RawParsedAuthnRequest {
        let doc = Document::parse(xml.as_bytes()).unwrap();
        parse_authn_request(&doc).unwrap().0
    }

    const REQ_INDEX_0_POST: &str = r#"<samlp:AuthnRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_id" Version="2.0"
            IssueInstant="2026-05-26T12:34:56Z"
            Destination="https://idp.example.com/sso"
            AssertionConsumerServiceIndex="0"
            ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
          <saml:Issuer>https://sp.example.com/saml</saml:Issuer>
        </samlp:AuthnRequest>"#;

    #[test]
    fn happy_path_index_resolution() {
        let sp = default_sp();
        let parsed = validate_authn_request(
            raw_request(REQ_INDEX_0_POST),
            &sp,
            "https://idp.example.com/sso",
            &sso_urls(),
        )
        .expect("validate ok");

        assert_eq!(parsed.id, "_id");
        assert_eq!(parsed.issuer, "https://sp.example.com/saml");
        assert_eq!(
            parsed.assertion_consumer_service.url,
            "https://sp.example.com/acs/post"
        );
        assert_eq!(
            parsed.assertion_consumer_service.binding,
            SsoResponseBinding::HttpPost
        );
        match parsed.assertion_consumer_service_selection {
            AcsSelection::Index(0) => {}
            other => panic!("expected Index(0), got {other:?}"),
        }
        assert_eq!(parsed.protocol_binding, Some(SsoResponseBinding::HttpPost));
        assert!(parsed.relay_state.is_none());
    }

    #[test]
    fn happy_path_default_when_no_acs_attrs() {
        let xml = r#"<samlp:AuthnRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_id" Version="2.0"
            IssueInstant="2026-05-26T12:34:56Z"
            Destination="https://idp.example.com/sso">
          <saml:Issuer>https://sp.example.com/saml</saml:Issuer>
        </samlp:AuthnRequest>"#;
        let sp = default_sp();
        let parsed = validate_authn_request(
            raw_request(xml),
            &sp,
            "https://idp.example.com/sso",
            &sso_urls(),
        )
        .expect("validate ok");
        assert!(matches!(
            parsed.assertion_consumer_service_selection,
            AcsSelection::Default
        ));
        // Default ACS is the entry flagged isDefault="true".
        assert_eq!(
            parsed.assertion_consumer_service.url,
            "https://sp.example.com/acs/post"
        );
    }

    #[test]
    fn happy_path_url_resolution() {
        let xml = r#"<samlp:AuthnRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_id" Version="2.0"
            IssueInstant="2026-05-26T12:34:56Z"
            Destination="https://idp.example.com/sso"
            AssertionConsumerServiceURL="https://sp.example.com/acs/artifact">
          <saml:Issuer>https://sp.example.com/saml</saml:Issuer>
        </samlp:AuthnRequest>"#;
        let sp = default_sp();
        let parsed = validate_authn_request(
            raw_request(xml),
            &sp,
            "https://idp.example.com/sso",
            &sso_urls(),
        )
        .expect("validate ok");
        assert!(matches!(
            parsed.assertion_consumer_service_selection,
            AcsSelection::Url(ref u) if u == "https://sp.example.com/acs/artifact"
        ));
        assert_eq!(
            parsed.assertion_consumer_service.binding,
            SsoResponseBinding::HttpArtifact
        );
    }

    #[test]
    fn issuer_mismatch_is_structured_error() {
        let xml = r#"<samlp:AuthnRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_id" Version="2.0"
            IssueInstant="2026-05-26T12:34:56Z"
            Destination="https://idp.example.com/sso"
            AssertionConsumerServiceIndex="0">
          <saml:Issuer>https://other-sp.example.com/saml</saml:Issuer>
        </samlp:AuthnRequest>"#;
        let sp = default_sp();
        let err = validate_authn_request(
            raw_request(xml),
            &sp,
            "https://idp.example.com/sso",
            &sso_urls(),
        )
        .unwrap_err();
        match err {
            Error::IssuerMismatch { expected, got } => {
                assert_eq!(expected, "https://sp.example.com/saml");
                assert_eq!(got.as_deref(), Some("https://other-sp.example.com/saml"));
            }
            other => panic!("expected IssuerMismatch, got {other:?}"),
        }
    }

    #[test]
    fn destination_not_in_sso_list_is_invalid_configuration() {
        let sp = default_sp();
        let err = validate_authn_request(
            raw_request(REQ_INDEX_0_POST),
            &sp,
            "https://idp.example.com/sso", // request's @Destination
            // Empty: caller is asking us to validate against a destination
            // they don't actually advertise.
            &[],
        )
        .unwrap_err();
        match err {
            Error::InvalidConfiguration { reason } => {
                assert_eq!(reason, "expected_destination is not a registered SSO endpoint");
            }
            other => panic!("expected InvalidConfiguration, got {other:?}"),
        }
    }

    #[test]
    fn destination_mismatch_with_request_attr() {
        let xml = r#"<samlp:AuthnRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_id" Version="2.0"
            IssueInstant="2026-05-26T12:34:56Z"
            Destination="https://idp.example.com/sso-other"
            AssertionConsumerServiceIndex="0">
          <saml:Issuer>https://sp.example.com/saml</saml:Issuer>
        </samlp:AuthnRequest>"#;
        let sp = default_sp();
        let err = validate_authn_request(
            raw_request(xml),
            &sp,
            "https://idp.example.com/sso",
            &sso_urls(),
        )
        .unwrap_err();
        match err {
            Error::DestinationMismatch => {}
            other => panic!("expected DestinationMismatch, got {other:?}"),
        }
    }

    #[test]
    fn destination_absent_on_request_is_accepted() {
        let xml = r#"<samlp:AuthnRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_id" Version="2.0"
            IssueInstant="2026-05-26T12:34:56Z"
            AssertionConsumerServiceIndex="0">
          <saml:Issuer>https://sp.example.com/saml</saml:Issuer>
        </samlp:AuthnRequest>"#;
        let sp = default_sp();
        let parsed = validate_authn_request(
            raw_request(xml),
            &sp,
            "https://idp.example.com/sso",
            &sso_urls(),
        )
        .expect("validate ok");
        assert!(parsed.destination.is_none());
    }

    #[test]
    fn acs_index_unknown_is_unregistered() {
        let xml = r#"<samlp:AuthnRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_id" Version="2.0"
            IssueInstant="2026-05-26T12:34:56Z"
            Destination="https://idp.example.com/sso"
            AssertionConsumerServiceIndex="42">
          <saml:Issuer>https://sp.example.com/saml</saml:Issuer>
        </samlp:AuthnRequest>"#;
        let sp = default_sp();
        let err = validate_authn_request(
            raw_request(xml),
            &sp,
            "https://idp.example.com/sso",
            &sso_urls(),
        )
        .unwrap_err();
        match err {
            Error::UnregisteredAcs { entity_id } => {
                assert_eq!(entity_id, "https://sp.example.com/saml");
            }
            other => panic!("expected UnregisteredAcs, got {other:?}"),
        }
    }

    #[test]
    fn acs_url_unknown_is_unregistered() {
        // Echo-attack defense: an SP claiming an off-list ACS URL must NOT
        // be honored. The validator's resolved endpoint is structurally
        // unable to point at a non-registered URL.
        let xml = r#"<samlp:AuthnRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_id" Version="2.0"
            IssueInstant="2026-05-26T12:34:56Z"
            Destination="https://idp.example.com/sso"
            AssertionConsumerServiceURL="https://attacker.example.com/exfil">
          <saml:Issuer>https://sp.example.com/saml</saml:Issuer>
        </samlp:AuthnRequest>"#;
        let sp = default_sp();
        let err = validate_authn_request(
            raw_request(xml),
            &sp,
            "https://idp.example.com/sso",
            &sso_urls(),
        )
        .unwrap_err();
        match err {
            Error::UnregisteredAcs { entity_id } => {
                assert_eq!(entity_id, "https://sp.example.com/saml");
            }
            other => panic!("expected UnregisteredAcs, got {other:?}"),
        }
    }

    #[test]
    fn protocol_binding_mismatch_against_resolved_acs() {
        // ProtocolBinding=Artifact, but Index=0 resolves to POST → error.
        let xml = r#"<samlp:AuthnRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_id" Version="2.0"
            IssueInstant="2026-05-26T12:34:56Z"
            Destination="https://idp.example.com/sso"
            AssertionConsumerServiceIndex="0"
            ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact">
          <saml:Issuer>https://sp.example.com/saml</saml:Issuer>
        </samlp:AuthnRequest>"#;
        let sp = default_sp();
        let err = validate_authn_request(
            raw_request(xml),
            &sp,
            "https://idp.example.com/sso",
            &sso_urls(),
        )
        .unwrap_err();
        match err {
            Error::IllegalResponseBinding { requested } => {
                assert_eq!(requested, crate::binding::Binding::HttpArtifact);
            }
            other => panic!("expected IllegalResponseBinding, got {other:?}"),
        }
    }

    #[test]
    fn no_default_acs_and_no_attrs_is_unregistered() {
        // An SP with no ACS endpoints at all is technically conformant to
        // the SAML schema (the role descriptor permits zero ACS entries),
        // but in practice means "I cannot receive Responses". Validating
        // an AuthnRequest that didn't pick an ACS must fail loudly rather
        // than the IdP silently choosing nothing.
        let sp = sp_with_acs_layout("");
        let xml = r#"<samlp:AuthnRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_id" Version="2.0"
            IssueInstant="2026-05-26T12:34:56Z"
            Destination="https://idp.example.com/sso">
          <saml:Issuer>https://sp.example.com/saml</saml:Issuer>
        </samlp:AuthnRequest>"#;
        let err = validate_authn_request(
            raw_request(xml),
            &sp,
            "https://idp.example.com/sso",
            &sso_urls(),
        )
        .unwrap_err();
        match err {
            Error::UnregisteredAcs { entity_id } => {
                assert_eq!(entity_id, "https://sp.example.com/saml");
            }
            other => panic!("expected UnregisteredAcs, got {other:?}"),
        }
    }

    #[test]
    fn protocol_binding_none_uses_resolved_acs_binding() {
        // No `@ProtocolBinding` on the wire → step 7a accepts; the resolved
        // ACS endpoint's binding is authoritative downstream.
        let xml = r#"<samlp:AuthnRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_id" Version="2.0"
            IssueInstant="2026-05-26T12:34:56Z"
            Destination="https://idp.example.com/sso"
            AssertionConsumerServiceIndex="1">
          <saml:Issuer>https://sp.example.com/saml</saml:Issuer>
        </samlp:AuthnRequest>"#;
        let sp = default_sp();
        let parsed = validate_authn_request(
            raw_request(xml),
            &sp,
            "https://idp.example.com/sso",
            &sso_urls(),
        )
        .unwrap();
        assert!(parsed.protocol_binding.is_none());
        assert_eq!(
            parsed.assertion_consumer_service.binding,
            SsoResponseBinding::HttpArtifact
        );
    }
}
