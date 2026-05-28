//! Parse inbound `<samlp:LogoutResponse>` per SAML 2.0 Core §3.7.2.
//!
//! Used by `ServiceProvider::consume_logout_response` /
//! `IdentityProvider::consume_logout_response` (RFC-007 §2 / §3 / §5.2) after
//! the binding layer has decoded the wire envelope and the XML hardening pass
//! (RFC-002 §1) has parsed the body into a `Document`.
//!
//! This module produces a `ParsedLogoutResponse` that exposes the two-level
//! `<samlp:StatusCode>` chain verbatim; the public [`LogoutOutcome`] view is
//! derived via `ParsedLogoutResponse::to_outcome` so callers can branch on
//! Success / PartialLogout / Failure without learning the SAML status URIs.
//!
//! Like `request_parse`, this module does NOT validate Issuer / Destination /
//! signature / `InResponseTo` — those are caller responsibilities per
//! RFC-007 §5.2 so the parser stays single-purpose.

use crate::error::Error;
use crate::logout::{LogoutOutcome, SAML_NS, SAMLP_NS};
use crate::time::parse_xs_datetime;
use crate::xml::parse::{Document, Element, ElementId};

/// Raw parsed view of `<samlp:LogoutResponse>`. The status chain is exposed
/// at full fidelity; [`to_outcome`](Self::to_outcome) collapses it to the
/// caller-facing three-variant enum.
#[derive(Debug, Clone)]
pub(crate) struct ParsedLogoutResponse {
    pub issuer: String,
    pub destination: Option<String>,
    pub in_response_to: String,
    pub status_code: String,
    pub second_level_status_code: Option<String>,
    pub status_message: Option<String>,
}

impl ParsedLogoutResponse {
    /// Collapse the two-level status chain into a [`LogoutOutcome`].
    ///
    /// Logic mirrors RFC-007 §5.2 step 7:
    /// - Top-level `Success` → `LogoutOutcome::Success` (the second-level
    ///   code is irrelevant — `Success` is terminal in the SAML status
    ///   table).
    /// - Top-level `Responder` with second-level `PartialLogout`, OR a
    ///   top-level `PartialLogout` (some implementations flatten this
    ///   incorrectly but we accept it) → `PartialLogout`.
    /// - Anything else → `Failure { status, message }`, where `status` is
    ///   whichever code is most specific (second-level if present, else
    ///   top-level), so callers logging the failure see the actionable URI.
    pub(crate) fn to_outcome(&self) -> LogoutOutcome {
        const SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
        const PARTIAL: &str = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout";

        if self.status_code == SUCCESS {
            return LogoutOutcome::Success;
        }
        // PartialLogout can appear at top-level (technically wrong per spec
        // but observed in the wild) or as a second-level under Responder.
        if self.status_code == PARTIAL
            || self.second_level_status_code.as_deref() == Some(PARTIAL)
        {
            return LogoutOutcome::PartialLogout {
                message: self.status_message.clone(),
            };
        }
        // Failure: surface the most specific URI present.
        let status = self
            .second_level_status_code
            .clone()
            .unwrap_or_else(|| self.status_code.clone());
        LogoutOutcome::Failure {
            status,
            message: self.status_message.clone(),
        }
    }
}

/// Parse a `<samlp:LogoutResponse>` document into the structured view.
///
/// Returns the parsed payload alongside the root [`ElementId`] so the caller
/// can hand the same handle to `dsig::verify::verify_signature` without
/// re-walking the tree (RFC-002 §3).
pub(crate) fn parse_logout_response(
    document: &Document,
) -> Result<(ParsedLogoutResponse, ElementId), Error> {
    let root = document.root();
    if root.qname().namespace() != Some(SAMLP_NS) || root.qname().local() != "LogoutResponse" {
        return Err(Error::XmlParse(format!(
            "expected <samlp:LogoutResponse>, got <{}>",
            root.qname()
        )));
    }

    // Structural schema gate. See `crate::schema` for the rule set.
    #[cfg(feature = "xsd-validate")]
    crate::schema::validate_logout_response(root)?;

    let version = root
        .attribute(None, "Version")
        .ok_or_else(|| Error::XmlParse("LogoutResponse missing Version".to_string()))?;
    if version != "2.0" {
        return Err(Error::XmlParse(format!(
            "unsupported LogoutResponse Version: {version}"
        )));
    }

    root.attribute(None, "ID")
        .ok_or_else(|| Error::XmlParse("LogoutResponse missing ID".to_string()))?;
    let issue_instant_str = root
        .attribute(None, "IssueInstant")
        .ok_or_else(|| Error::XmlParse("LogoutResponse missing IssueInstant".to_string()))?;
    parse_xs_datetime(issue_instant_str)?;
    let destination = root.attribute(None, "Destination").map(str::to_owned);
    let in_response_to = root
        .attribute(None, "InResponseTo")
        .ok_or_else(|| Error::XmlParse("LogoutResponse missing InResponseTo".to_string()))?
        .to_owned();

    let issuer_el = root
        .child_element(Some(SAML_NS), "Issuer")
        .ok_or_else(|| Error::XmlParse("LogoutResponse missing <saml:Issuer>".to_string()))?;
    let issuer = issuer_el.text_content();
    if issuer.trim().is_empty() {
        return Err(Error::XmlParse(
            "LogoutResponse <saml:Issuer> is empty".to_string(),
        ));
    }

    let status_el = root
        .child_element(Some(SAMLP_NS), "Status")
        .ok_or_else(|| Error::XmlParse("LogoutResponse missing <samlp:Status>".to_string()))?;
    let top_code_el = status_el
        .child_element(Some(SAMLP_NS), "StatusCode")
        .ok_or_else(|| {
            Error::XmlParse("LogoutResponse Status missing <samlp:StatusCode>".to_string())
        })?;
    let status_code = top_code_el
        .attribute(None, "Value")
        .ok_or_else(|| Error::XmlParse("StatusCode missing Value attribute".to_string()))?
        .to_owned();
    let second_level_status_code = top_code_el
        .child_element(Some(SAMLP_NS), "StatusCode")
        .and_then(|el| el.attribute(None, "Value").map(str::to_owned));
    let status_message = status_el
        .child_element(Some(SAMLP_NS), "StatusMessage")
        .map(Element::text_content);

    let parsed = ParsedLogoutResponse {
        issuer,
        destination,
        in_response_to,
        status_code,
        second_level_status_code,
        status_message,
    };
    Ok((parsed, root.id()))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logout::LogoutStatus;
    use crate::logout::response_build::{BuildLogoutResponse, build_logout_response_xml};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn fixed_instant() -> SystemTime {
        UNIX_EPOCH
            .checked_add(Duration::from_secs(1_779_798_896))
            .expect("UNIX_EPOCH + small duration fits in SystemTime")
    }

    fn parse(xml: &str) -> Result<(ParsedLogoutResponse, ElementId), Error> {
        let doc = Document::parse(xml.as_bytes())?;
        parse_logout_response(&doc)
    }

    #[test]
    fn parses_success_response() {
        let xml = r#"<samlp:LogoutResponse
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_r" Version="2.0" IssueInstant="2026-05-26T12:34:56Z"
            Destination="https://sp.example.com/slo" InResponseTo="_req-1">
            <saml:Issuer>https://idp.example.com/saml</saml:Issuer>
            <samlp:Status>
                <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
            </samlp:Status>
        </samlp:LogoutResponse>"#;
        let (resp, eid) = parse(xml).expect("parse");
        assert_eq!(resp.issuer, "https://idp.example.com/saml");
        assert_eq!(
            resp.destination.as_deref(),
            Some("https://sp.example.com/slo")
        );
        assert_eq!(resp.in_response_to, "_req-1");
        assert_eq!(resp.status_code, "urn:oasis:names:tc:SAML:2.0:status:Success");
        assert!(resp.second_level_status_code.is_none());
        assert!(resp.status_message.is_none());

        let outcome = resp.to_outcome();
        assert!(matches!(outcome, LogoutOutcome::Success));

        // ElementId resolves to the root.
        let doc = Document::parse(xml.as_bytes()).unwrap();
        assert_eq!(eid, doc.root().id());
    }

    #[test]
    fn partial_logout_at_second_level_maps_to_outcome() {
        let xml = r#"<samlp:LogoutResponse
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_r" Version="2.0" IssueInstant="2026-05-26T12:34:56Z" InResponseTo="_req-1">
            <saml:Issuer>idp</saml:Issuer>
            <samlp:Status>
                <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder">
                    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:PartialLogout"/>
                </samlp:StatusCode>
                <samlp:StatusMessage>SP-B was unreachable</samlp:StatusMessage>
            </samlp:Status>
        </samlp:LogoutResponse>"#;
        let (resp, _) = parse(xml).unwrap();
        assert_eq!(
            resp.status_code,
            "urn:oasis:names:tc:SAML:2.0:status:Responder"
        );
        assert_eq!(
            resp.second_level_status_code.as_deref(),
            Some("urn:oasis:names:tc:SAML:2.0:status:PartialLogout")
        );
        assert_eq!(resp.status_message.as_deref(), Some("SP-B was unreachable"));

        match resp.to_outcome() {
            LogoutOutcome::PartialLogout { message } => {
                assert_eq!(message.as_deref(), Some("SP-B was unreachable"));
            }
            other => panic!("expected PartialLogout, got {other:?}"),
        }
    }

    #[test]
    fn request_denied_failure_with_message() {
        let xml = r#"<samlp:LogoutResponse
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_r" Version="2.0" IssueInstant="2026-05-26T12:34:56Z" InResponseTo="_req-1">
            <saml:Issuer>idp</saml:Issuer>
            <samlp:Status>
                <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester">
                    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:RequestDenied"/>
                </samlp:StatusCode>
                <samlp:StatusMessage>session not found</samlp:StatusMessage>
            </samlp:Status>
        </samlp:LogoutResponse>"#;
        let (resp, _) = parse(xml).unwrap();
        match resp.to_outcome() {
            LogoutOutcome::Failure { status, message } => {
                assert_eq!(status, "urn:oasis:names:tc:SAML:2.0:status:RequestDenied");
                assert_eq!(message.as_deref(), Some("session not found"));
            }
            other => panic!("expected Failure, got {other:?}"),
        }
    }

    #[test]
    fn responder_only_failure_no_message() {
        let xml = r#"<samlp:LogoutResponse
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_r" Version="2.0" IssueInstant="2026-05-26T12:34:56Z" InResponseTo="_req-1">
            <saml:Issuer>idp</saml:Issuer>
            <samlp:Status>
                <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"/>
            </samlp:Status>
        </samlp:LogoutResponse>"#;
        let (resp, _) = parse(xml).unwrap();
        match resp.to_outcome() {
            LogoutOutcome::Failure { status, message } => {
                assert_eq!(status, "urn:oasis:names:tc:SAML:2.0:status:Responder");
                assert!(message.is_none());
            }
            other => panic!("expected Failure, got {other:?}"),
        }
    }

    #[test]
    fn partial_logout_at_top_level_also_maps() {
        // Some implementations flatten the two-level chain. Be lenient.
        let xml = r#"<samlp:LogoutResponse
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_r" Version="2.0" IssueInstant="2026-05-26T12:34:56Z" InResponseTo="_req-1">
            <saml:Issuer>idp</saml:Issuer>
            <samlp:Status>
                <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:PartialLogout"/>
            </samlp:Status>
        </samlp:LogoutResponse>"#;
        let (resp, _) = parse(xml).unwrap();
        assert!(matches!(
            resp.to_outcome(),
            LogoutOutcome::PartialLogout { .. }
        ));
    }

    #[test]
    fn wrong_root_element_rejected() {
        let xml = r#"<samlp:LogoutRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            ID="_x" Version="2.0" IssueInstant="2026-05-26T12:34:56Z"/>"#;
        let err = parse(xml).unwrap_err();
        match err {
            Error::XmlParse(msg) => assert!(msg.contains("LogoutResponse"), "got: {msg}"),
            other => panic!("expected XmlParse, got {other:?}"),
        }
    }

    #[test]
    fn missing_in_response_to_rejected() {
        let xml = r#"<samlp:LogoutResponse
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_r" Version="2.0" IssueInstant="2026-05-26T12:34:56Z">
            <saml:Issuer>idp</saml:Issuer>
            <samlp:Status>
                <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
            </samlp:Status>
        </samlp:LogoutResponse>"#;
        let err = parse(xml).unwrap_err();
        match err {
            Error::XmlParse(msg) => assert!(msg.contains("InResponseTo"), "got: {msg}"),
            other => panic!("expected XmlParse, got {other:?}"),
        }
    }

    #[test]
    fn missing_status_rejected() {
        let xml = r#"<samlp:LogoutResponse
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_r" Version="2.0" IssueInstant="2026-05-26T12:34:56Z" InResponseTo="_req-1">
            <saml:Issuer>idp</saml:Issuer>
        </samlp:LogoutResponse>"#;
        let err = parse(xml).unwrap_err();
        match err {
            Error::XmlParse(msg) => assert!(msg.contains("Status"), "got: {msg}"),
            Error::SchemaViolation { reason, .. } => {
                assert!(reason.contains("Status"), "got: {reason}");
            }
            other => panic!("expected XmlParse or SchemaViolation, got {other:?}"),
        }
    }

    #[test]
    fn missing_status_code_value_rejected() {
        let xml = r#"<samlp:LogoutResponse
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_r" Version="2.0" IssueInstant="2026-05-26T12:34:56Z" InResponseTo="_req-1">
            <saml:Issuer>idp</saml:Issuer>
            <samlp:Status>
                <samlp:StatusCode/>
            </samlp:Status>
        </samlp:LogoutResponse>"#;
        let err = parse(xml).unwrap_err();
        match err {
            Error::XmlParse(msg) => assert!(msg.contains("Value"), "got: {msg}"),
            Error::SchemaViolation { reason, .. } => {
                assert!(reason.contains("Value"), "got: {reason}");
            }
            other => panic!("expected XmlParse or SchemaViolation, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------------
    // Round-trip tests: build → parse → outcome matches input status.
    // -------------------------------------------------------------------------

    fn build_and_parse(status: LogoutStatus, msg: Option<&str>) -> LogoutOutcome {
        let input = BuildLogoutResponse {
            id: "_round",
            issue_instant: fixed_instant(),
            issuer_entity_id: "https://idp.example.com/saml",
            destination: Some("https://sp.example.com/slo"),
            in_response_to: "_req-1",
            status,
            status_message: msg,
        };
        let xml = build_logout_response_xml(&input).unwrap();
        let (resp, _) = parse(std::str::from_utf8(&xml).unwrap()).unwrap();
        resp.to_outcome()
    }

    #[test]
    fn round_trip_success() {
        assert!(matches!(
            build_and_parse(LogoutStatus::Success, None),
            LogoutOutcome::Success
        ));
    }

    #[test]
    fn round_trip_partial_logout_carries_message() {
        match build_and_parse(LogoutStatus::PartialLogout, Some("3 of 5 OK")) {
            LogoutOutcome::PartialLogout { message } => {
                assert_eq!(message.as_deref(), Some("3 of 5 OK"));
            }
            other => panic!("expected PartialLogout, got {other:?}"),
        }
    }

    #[test]
    fn round_trip_request_denied_failure() {
        match build_and_parse(LogoutStatus::RequestDenied, Some("nope")) {
            LogoutOutcome::Failure { status, message } => {
                assert_eq!(status, "urn:oasis:names:tc:SAML:2.0:status:RequestDenied");
                assert_eq!(message.as_deref(), Some("nope"));
            }
            other => panic!("expected Failure, got {other:?}"),
        }
    }

    #[test]
    fn round_trip_responder_failure() {
        match build_and_parse(LogoutStatus::Responder, None) {
            LogoutOutcome::Failure { status, message } => {
                assert_eq!(status, "urn:oasis:names:tc:SAML:2.0:status:Responder");
                assert!(message.is_none());
            }
            other => panic!("expected Failure, got {other:?}"),
        }
    }

    #[test]
    fn round_trip_requester_failure() {
        match build_and_parse(LogoutStatus::Requester, None) {
            LogoutOutcome::Failure { status, message } => {
                assert_eq!(status, "urn:oasis:names:tc:SAML:2.0:status:Requester");
                assert!(message.is_none());
            }
            other => panic!("expected Failure, got {other:?}"),
        }
    }
}
