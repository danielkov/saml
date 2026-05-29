//! Integration tests for the structural XSD-style validator
//! (`crate::schema`). The module is only exposed under the default-on
//! `xsd-validate` feature gate.
//!
//! Positive cases assert that a well-formed message survives the schema
//! pre-check and reaches the downstream pipeline (where it then fails for
//! some other reason — typically `SignatureMissing` or
//! `UnsolicitedNotAllowed` on these unsigned fixtures — but crucially NOT
//! `SchemaViolation`). Negative cases assert that the schema gate fires
//! *before* the signature / content-policy pipeline, surfacing
//! `Error::SchemaViolation { reason, .. }` with a useful reason string.

#![cfg(feature = "xsd-validate")]

#[path = "common/mod.rs"]
mod common;

use std::time::Duration;

use saml::binding::SsoResponseBinding;
use saml::error::Error;
use saml::replay::ReplayMode;
use saml::sp::ConsumeResponse;

const SAMLP_NS: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const SAML_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";

const SP_ENTITY_ID: &str = "https://sp.example.com";
const SP_ACS: &str = "https://sp.example.com/acs";
const IDP_ENTITY_ID: &str = "https://idp.example.com";

const IDP_SSO_URL: &str = "https://idp.example.com/sso";

// =============================================================================
// Positive tests
// =============================================================================

/// A well-formed Response survives the schema gate. The downstream pipeline
/// then fails for a non-schema reason (unsolicited, signature missing, etc.).
/// The important assertion: the error is NOT `SchemaViolation`.
#[test]
fn well_formed_response_clears_schema_gate() {
    let sp = common::make_sp(SP_ENTITY_ID, SP_ACS, false).expect("sp builds");
    let idp = common::make_idp(IDP_ENTITY_ID, IDP_SSO_URL).expect("idp builds");
    let idp_descriptor = common::idp_descriptor(&idp).expect("idp descriptor");
    let now = common::fixed_now().expect("fixed_now");

    let xml = format!(
        r#"<samlp:Response xmlns:samlp="{SAMLP_NS}" xmlns:saml="{SAML_NS}"
              ID="_resp1" Version="2.0"
              IssueInstant="2026-05-26T12:00:00Z"
              Destination="{SP_ACS}">
            <saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>
            <samlp:Status>
              <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
            </samlp:Status>
            <saml:Assertion ID="_a1" Version="2.0" IssueInstant="2026-05-26T12:00:00Z">
              <saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>
              <saml:Subject>
                <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">a@e</saml:NameID>
                <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                  <saml:SubjectConfirmationData Recipient="{SP_ACS}"
                                                NotOnOrAfter="2026-05-26T12:05:00Z"/>
                </saml:SubjectConfirmation>
              </saml:Subject>
              <saml:Conditions NotBefore="2026-05-26T11:59:00Z"
                               NotOnOrAfter="2026-05-26T12:10:00Z">
                <saml:AudienceRestriction>
                  <saml:Audience>{SP_ENTITY_ID}</saml:Audience>
                </saml:AudienceRestriction>
              </saml:Conditions>
              <saml:AuthnStatement AuthnInstant="2026-05-26T11:59:30Z">
                <saml:AuthnContext>
                  <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
                </saml:AuthnContext>
              </saml:AuthnStatement>
            </saml:Assertion>
          </samlp:Response>"#
    );
    let err = sp
        .consume_response(ConsumeResponse {
            idp: &idp_descriptor,
            peer_crypto_policy: None,
            saml_response: xml.as_bytes(),
            binding: SsoResponseBinding::HttpPost,
            relay_state: None,
            tracker: None,
            expected_destination: SP_ACS,
            now,
            clock_skew: Duration::from_mins(1),
            replay_cache: None,
            replay_mode: ReplayMode::All,
        })
        .expect_err("unsigned Response cannot succeed");
    if let Error::SchemaViolation { element, reason } = &err {
        panic!(
            "well-formed Response should clear the schema gate, but got \
             SchemaViolation at {element}: {reason}"
        );
    }
}

/// An Assertion carrying a `<saml:Condition xsi:type="...">` extension under
/// `<saml:Conditions>` must NOT be schema-rejected. The OASIS XSD models
/// Condition as the xs:abstract extension hook; we admit it via the
/// SAML_NS wildcard on `<saml:Conditions>`.
#[test]
fn condition_extension_via_wildcard_clears_schema_gate() {
    let sp = common::make_sp(SP_ENTITY_ID, SP_ACS, false).expect("sp builds");
    let idp = common::make_idp(IDP_ENTITY_ID, IDP_SSO_URL).expect("idp builds");
    let idp_descriptor = common::idp_descriptor(&idp).expect("idp descriptor");
    let now = common::fixed_now().expect("fixed_now");

    let xml = format!(
        r#"<samlp:Response xmlns:samlp="{SAMLP_NS}" xmlns:saml="{SAML_NS}"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              ID="_resp1" Version="2.0"
              IssueInstant="2026-05-26T12:00:00Z"
              Destination="{SP_ACS}">
            <saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>
            <samlp:Status>
              <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
            </samlp:Status>
            <saml:Assertion ID="_a1" Version="2.0" IssueInstant="2026-05-26T12:00:00Z">
              <saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>
              <saml:Subject>
                <saml:NameID>u</saml:NameID>
                <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                  <saml:SubjectConfirmationData Recipient="{SP_ACS}"
                                                NotOnOrAfter="2026-05-26T12:05:00Z"/>
                </saml:SubjectConfirmation>
              </saml:Subject>
              <saml:Conditions NotBefore="2026-05-26T11:59:00Z"
                               NotOnOrAfter="2026-05-26T12:10:00Z">
                <saml:AudienceRestriction>
                  <saml:Audience>{SP_ENTITY_ID}</saml:Audience>
                </saml:AudienceRestriction>
                <saml:Condition xsi:type="ext:CustomCondition"/>
              </saml:Conditions>
              <saml:AuthnStatement AuthnInstant="2026-05-26T11:59:30Z">
                <saml:AuthnContext>
                  <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
                </saml:AuthnContext>
              </saml:AuthnStatement>
            </saml:Assertion>
          </samlp:Response>"#
    );
    let err = sp
        .consume_response(ConsumeResponse {
            idp: &idp_descriptor,
            peer_crypto_policy: None,
            saml_response: xml.as_bytes(),
            binding: SsoResponseBinding::HttpPost,
            relay_state: None,
            tracker: None,
            expected_destination: SP_ACS,
            now,
            clock_skew: Duration::from_mins(1),
            replay_cache: None,
            replay_mode: ReplayMode::All,
        })
        .expect_err("unsigned Response cannot succeed");
    if let Error::SchemaViolation { element, reason } = &err {
        panic!(
            "Condition extension should be accepted via wildcard, got \
             SchemaViolation at {element}: {reason}"
        );
    }
}

// =============================================================================
// Negative tests
// =============================================================================

/// A Response missing the required `<samlp:Status>` child must surface
/// `SchemaViolation` from `consume_response` — and crucially must surface
/// it BEFORE the SP gets to any downstream signature / status check.
#[test]
fn response_missing_status_surfaces_schema_violation() {
    let sp = common::make_sp(SP_ENTITY_ID, SP_ACS, false).expect("sp builds");
    let idp = common::make_idp(IDP_ENTITY_ID, IDP_SSO_URL).expect("idp builds");
    let idp_descriptor = common::idp_descriptor(&idp).expect("idp descriptor");
    let now = common::fixed_now().expect("fixed_now");

    let xml = format!(
        r#"<samlp:Response xmlns:samlp="{SAMLP_NS}" xmlns:saml="{SAML_NS}"
              ID="_resp1" Version="2.0"
              IssueInstant="2026-05-26T12:00:00Z"
              Destination="{SP_ACS}">
            <saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>
            <saml:Assertion ID="_a1" Version="2.0" IssueInstant="2026-05-26T12:00:00Z">
              <saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>
              <saml:Subject><saml:NameID>a</saml:NameID></saml:Subject>
            </saml:Assertion>
          </samlp:Response>"#
    );
    let err = sp
        .consume_response(ConsumeResponse {
            idp: &idp_descriptor,
            peer_crypto_policy: None,
            saml_response: xml.as_bytes(),
            binding: SsoResponseBinding::HttpPost,
            relay_state: None,
            tracker: None,
            expected_destination: SP_ACS,
            now,
            clock_skew: Duration::from_mins(1),
            replay_cache: None,
            replay_mode: ReplayMode::All,
        })
        .expect_err("missing Status must be rejected");
    match err {
        Error::SchemaViolation { element, reason } => {
            assert!(
                element.contains("Response"),
                "element should locate the violating ancestor, got {element}"
            );
            assert!(
                reason.contains("<samlp:Status>"),
                "reason should explain the missing required child, got {reason}"
            );
        }
        other => panic!("expected SchemaViolation, got {other:?}"),
    }
}

/// A Response with an unknown top-level element from a foreign namespace is
/// structurally invalid — the schema only admits `xs:any` inside
/// `<samlp:Extensions>`, not as a sibling of `<samlp:Status>`.
#[test]
fn response_with_unknown_top_level_element_rejected() {
    let sp = common::make_sp(SP_ENTITY_ID, SP_ACS, false).expect("sp builds");
    let idp = common::make_idp(IDP_ENTITY_ID, IDP_SSO_URL).expect("idp builds");
    let idp_descriptor = common::idp_descriptor(&idp).expect("idp descriptor");
    let now = common::fixed_now().expect("fixed_now");

    let xml = format!(
        r#"<samlp:Response xmlns:samlp="{SAMLP_NS}" xmlns:saml="{SAML_NS}"
              xmlns:bogus="urn:bogus:vendor:1.0"
              ID="_resp1" Version="2.0"
              IssueInstant="2026-05-26T12:00:00Z"
              Destination="{SP_ACS}">
            <saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>
            <bogus:UnknownTopLevel>data</bogus:UnknownTopLevel>
            <samlp:Status>
              <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
            </samlp:Status>
          </samlp:Response>"#
    );
    let err = sp
        .consume_response(ConsumeResponse {
            idp: &idp_descriptor,
            peer_crypto_policy: None,
            saml_response: xml.as_bytes(),
            binding: SsoResponseBinding::HttpPost,
            relay_state: None,
            tracker: None,
            expected_destination: SP_ACS,
            now,
            clock_skew: Duration::from_mins(1),
            replay_cache: None,
            replay_mode: ReplayMode::All,
        })
        .expect_err("unknown top-level element must be rejected");
    match err {
        Error::SchemaViolation { reason, .. } => {
            assert!(
                reason.contains("unexpected child"),
                "reason should flag unknown child, got: {reason}"
            );
        }
        other => panic!("expected SchemaViolation, got {other:?}"),
    }
}

/// A Response whose root is missing the required `@Version` attribute must
/// fail the schema gate, NOT the downstream `Version != "2.0"` check.
#[test]
fn response_missing_version_surfaces_schema_violation() {
    let sp = common::make_sp(SP_ENTITY_ID, SP_ACS, false).expect("sp builds");
    let idp = common::make_idp(IDP_ENTITY_ID, IDP_SSO_URL).expect("idp builds");
    let idp_descriptor = common::idp_descriptor(&idp).expect("idp descriptor");
    let now = common::fixed_now().expect("fixed_now");

    let xml = format!(
        r#"<samlp:Response xmlns:samlp="{SAMLP_NS}" xmlns:saml="{SAML_NS}"
              ID="_resp1"
              IssueInstant="2026-05-26T12:00:00Z"
              Destination="{SP_ACS}">
            <saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>
            <samlp:Status>
              <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
            </samlp:Status>
          </samlp:Response>"#
    );
    let err = sp
        .consume_response(ConsumeResponse {
            idp: &idp_descriptor,
            peer_crypto_policy: None,
            saml_response: xml.as_bytes(),
            binding: SsoResponseBinding::HttpPost,
            relay_state: None,
            tracker: None,
            expected_destination: SP_ACS,
            now,
            clock_skew: Duration::from_mins(1),
            replay_cache: None,
            replay_mode: ReplayMode::All,
        })
        .expect_err("missing @Version must be rejected");
    match err {
        Error::SchemaViolation { reason, .. } => {
            assert!(reason.contains("@Version"), "got: {reason}");
        }
        other => panic!("expected SchemaViolation, got {other:?}"),
    }
}

/// An Assertion subtree whose `<saml:Subject>` appears before its
/// `<saml:Issuer>` violates the OASIS xs:sequence. The walker should surface
/// `SchemaViolation` with an order-related reason — and we drive it through
/// the full pipeline to confirm the gate fires inside `parse_response` →
/// schema validation of the nested Assertion shape.
#[test]
fn assertion_subject_before_issuer_rejected() {
    let sp = common::make_sp(SP_ENTITY_ID, SP_ACS, false).expect("sp builds");
    let idp = common::make_idp(IDP_ENTITY_ID, IDP_SSO_URL).expect("idp builds");
    let idp_descriptor = common::idp_descriptor(&idp).expect("idp descriptor");
    let now = common::fixed_now().expect("fixed_now");

    let xml = format!(
        r#"<samlp:Response xmlns:samlp="{SAMLP_NS}" xmlns:saml="{SAML_NS}"
              ID="_resp1" Version="2.0"
              IssueInstant="2026-05-26T12:00:00Z"
              Destination="{SP_ACS}">
            <saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>
            <samlp:Status>
              <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
            </samlp:Status>
            <saml:Assertion ID="_a1" Version="2.0" IssueInstant="2026-05-26T12:00:00Z">
              <saml:Subject>
                <saml:NameID>x</saml:NameID>
              </saml:Subject>
              <saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>
            </saml:Assertion>
          </samlp:Response>"#
    );
    let err = sp
        .consume_response(ConsumeResponse {
            idp: &idp_descriptor,
            peer_crypto_policy: None,
            saml_response: xml.as_bytes(),
            binding: SsoResponseBinding::HttpPost,
            relay_state: None,
            tracker: None,
            expected_destination: SP_ACS,
            now,
            clock_skew: Duration::from_mins(1),
            replay_cache: None,
            replay_mode: ReplayMode::All,
        })
        .expect_err("out-of-order children must be rejected");
    match err {
        Error::SchemaViolation { reason, .. } => {
            assert!(
                reason.contains("out of schema order"),
                "reason should flag ordering, got: {reason}"
            );
        }
        other => panic!("expected SchemaViolation, got {other:?}"),
    }
}
