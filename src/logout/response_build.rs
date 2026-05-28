//! Build outbound `<samlp:LogoutResponse>` per SAML 2.0 Core §3.7.2.
//!
//! Used by both `ServiceProvider::build_logout_response` and
//! `IdentityProvider::build_logout_response` (RFC-007 §2 / §3). The output of
//! [`build_logout_response_element`] is an [`Element`] ready to be wrapped in
//! a [`Document`] (and optionally signed via `dsig::sign::sign_element`)
//! before being handed to the binding layer.
//!
//! The `<samlp:Status>` element is the protocol-defining payload. SAML uses a
//! two-level status code chain — top-level (`Success` / `Requester` /
//! `Responder`) optionally nested with a second-level code such as
//! `PartialLogout` or `RequestDenied`. [`LogoutStatus`] collapses both layers
//! into a flat enum; this module expands it back into the schema-correct
//! nested form on emit so callers don't have to know the SAML two-level dance.

use crate::error::Error;
use crate::logout::{LogoutStatus, SAML_NS, SAMLP_NS, saml_qname, samlp_qname};
use crate::time::format_xs_datetime;
use crate::xml::emit::emit_document;
use crate::xml::parse::{Document, Element, Node, QName};
use std::time::SystemTime;

/// Inputs for building a `<samlp:LogoutResponse>` element.
pub(crate) struct BuildLogoutResponse<'a> {
    pub id: &'a str,
    pub issue_instant: SystemTime,
    pub issuer_entity_id: &'a str,
    pub destination: Option<&'a str>,
    /// The `ID` of the `<samlp:LogoutRequest>` this response echoes.
    pub in_response_to: &'a str,
    pub status: LogoutStatus,
    pub status_message: Option<&'a str>,
}

/// Build the `<samlp:LogoutResponse>` element. Returned [`Element`] is NOT yet
/// wrapped in a [`Document`]; the caller wraps via `Document::new` and may
/// then call `dsig::sign::sign_element` before emitting.
pub(crate) fn build_logout_response_element(
    input: &BuildLogoutResponse<'_>,
) -> Result<Element, Error> {
    // Element ordering inside <samlp:LogoutResponse> (Core §3.2.2):
    //   <saml:Issuer> → (Signature)? → (Extensions)? → <samlp:Status>.

    let mut builder = Element::build(samlp_qname("LogoutResponse"))
        .with_namespace(Some("samlp".to_owned()), SAMLP_NS)
        .with_namespace(Some("saml".to_owned()), SAML_NS)
        .with_attribute(QName::new(None, "ID"), input.id.to_owned())
        .with_attribute(QName::new(None, "Version"), "2.0")
        .with_attribute(
            QName::new(None, "IssueInstant"),
            format_xs_datetime(input.issue_instant)?,
        )
        .with_attribute(
            QName::new(None, "InResponseTo"),
            input.in_response_to.to_owned(),
        );

    if let Some(dest) = input.destination {
        builder = builder.with_attribute(QName::new(None, "Destination"), dest.to_owned());
    }

    // <saml:Issuer>
    let issuer = Element::build(saml_qname("Issuer"))
        .with_text(input.issuer_entity_id.to_owned())
        .finish();
    builder = builder.with_child(Node::Element(issuer));

    // <samlp:Status>
    builder = builder.with_child(Node::Element(build_status(input.status, input.status_message)));

    Ok(builder.finish())
}

fn build_status(status: LogoutStatus, message: Option<&str>) -> Element {
    // Top-level <samlp:StatusCode Value="...">
    let mut top_code = Element::build(samlp_qname("StatusCode"))
        .with_attribute(QName::new(None, "Value"), status.top_level_uri().to_owned());
    // Second-level code, if any.
    if let Some(second) = status.second_level_uri() {
        let nested = Element::build(samlp_qname("StatusCode"))
            .with_attribute(QName::new(None, "Value"), second.to_owned())
            .finish();
        top_code = top_code.with_child(Node::Element(nested));
    }
    let mut status_el = Element::build(samlp_qname("Status"))
        .with_child(Node::Element(top_code.finish()));
    if let Some(msg) = message {
        let m = Element::build(samlp_qname("StatusMessage"))
            .with_text(msg.to_owned())
            .finish();
        status_el = status_el.with_child(Node::Element(m));
    }
    status_el.finish()
}

/// Build, wrap in a [`Document`], and serialize.
pub(crate) fn build_logout_response_xml(
    input: &BuildLogoutResponse<'_>,
) -> Result<Vec<u8>, Error> {
    let element = build_logout_response_element(input)?;
    let doc = Document::new(element)?;
    let xml = emit_document(&doc)?;
    Ok(xml.into_bytes())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    fn fixed_instant() -> SystemTime {
        UNIX_EPOCH
            .checked_add(Duration::from_secs(1_779_798_896))
            .expect("UNIX_EPOCH + small duration fits in SystemTime")
    }

    fn minimal_input<'a>(status: LogoutStatus) -> BuildLogoutResponse<'a> {
        BuildLogoutResponse {
            id: "_resp-1",
            issue_instant: fixed_instant(),
            issuer_entity_id: "https://idp.example.com/saml",
            destination: Some("https://sp.example.com/slo"),
            in_response_to: "_req-1",
            status,
            status_message: None,
        }
    }

    fn emit_and_reparse(input: &BuildLogoutResponse<'_>) -> Document {
        let xml = build_logout_response_xml(input).expect("build");
        Document::parse(&xml).expect("re-parse")
    }

    /// Helper: extract `(top-level StatusCode Value, optional second-level
    /// StatusCode Value)` from a parsed `<samlp:Status>` subtree.
    fn extract_status_codes(doc: &Document) -> (String, Option<String>) {
        let status = doc
            .root()
            .child_element(Some(SAMLP_NS), "Status")
            .expect("Status present");
        let top = status
            .child_element(Some(SAMLP_NS), "StatusCode")
            .expect("top StatusCode");
        let top_value = top.attribute(None, "Value").expect("Value").to_owned();
        let nested = top
            .child_element(Some(SAMLP_NS), "StatusCode")
            .map(|n| n.attribute(None, "Value").expect("Value").to_owned());
        (top_value, nested)
    }

    #[test]
    fn success_status_emits_single_top_level_code() {
        let doc = emit_and_reparse(&minimal_input(LogoutStatus::Success));
        let root = doc.root();
        assert_eq!(root.qname().namespace(), Some(SAMLP_NS));
        assert_eq!(root.qname().local(), "LogoutResponse");
        assert_eq!(root.attribute(None, "ID"), Some("_resp-1"));
        assert_eq!(root.attribute(None, "Version"), Some("2.0"));
        assert_eq!(
            root.attribute(None, "IssueInstant"),
            Some("2026-05-26T12:34:56Z")
        );
        assert_eq!(root.attribute(None, "InResponseTo"), Some("_req-1"));
        assert_eq!(
            root.attribute(None, "Destination"),
            Some("https://sp.example.com/slo")
        );

        let issuer = root.child_element(Some(SAML_NS), "Issuer").unwrap();
        assert_eq!(issuer.text_content(), "https://idp.example.com/saml");

        let (top, second) = extract_status_codes(&doc);
        assert_eq!(top, "urn:oasis:names:tc:SAML:2.0:status:Success");
        assert!(second.is_none());
    }

    #[test]
    fn requester_status_emits_top_level_only() {
        let doc = emit_and_reparse(&minimal_input(LogoutStatus::Requester));
        let (top, second) = extract_status_codes(&doc);
        assert_eq!(top, "urn:oasis:names:tc:SAML:2.0:status:Requester");
        assert!(second.is_none());
    }

    #[test]
    fn responder_status_emits_top_level_only() {
        let doc = emit_and_reparse(&minimal_input(LogoutStatus::Responder));
        let (top, second) = extract_status_codes(&doc);
        assert_eq!(top, "urn:oasis:names:tc:SAML:2.0:status:Responder");
        assert!(second.is_none());
    }

    #[test]
    fn partial_logout_nests_under_responder() {
        let doc = emit_and_reparse(&minimal_input(LogoutStatus::PartialLogout));
        let (top, second) = extract_status_codes(&doc);
        assert_eq!(top, "urn:oasis:names:tc:SAML:2.0:status:Responder");
        assert_eq!(
            second.as_deref(),
            Some("urn:oasis:names:tc:SAML:2.0:status:PartialLogout")
        );
    }

    #[test]
    fn request_denied_nests_under_requester() {
        let doc = emit_and_reparse(&minimal_input(LogoutStatus::RequestDenied));
        let (top, second) = extract_status_codes(&doc);
        assert_eq!(top, "urn:oasis:names:tc:SAML:2.0:status:Requester");
        assert_eq!(
            second.as_deref(),
            Some("urn:oasis:names:tc:SAML:2.0:status:RequestDenied")
        );
    }

    #[test]
    fn status_message_emitted_when_provided() {
        let mut input = minimal_input(LogoutStatus::PartialLogout);
        input.status_message = Some("SP-B unreachable, retried 3x");

        let doc = emit_and_reparse(&input);
        let status = doc.root().child_element(Some(SAMLP_NS), "Status").unwrap();
        let msg = status
            .child_element(Some(SAMLP_NS), "StatusMessage")
            .expect("StatusMessage present");
        assert_eq!(msg.text_content(), "SP-B unreachable, retried 3x");
    }

    #[test]
    fn destination_optional() {
        let mut input = minimal_input(LogoutStatus::Success);
        input.destination = None;
        let doc = emit_and_reparse(&input);
        assert_eq!(doc.root().attribute(None, "Destination"), None);
    }

    #[test]
    fn xml_well_formed_with_all_optional_fields() {
        let input = BuildLogoutResponse {
            id: "_full-resp",
            issue_instant: fixed_instant(),
            issuer_entity_id: "https://idp.example.com/saml",
            destination: Some("https://sp.example.com/slo"),
            in_response_to: "_req-full",
            status: LogoutStatus::PartialLogout,
            status_message: Some("partial"),
        };
        let xml = build_logout_response_xml(&input).unwrap();
        let doc = Document::parse(&xml).unwrap();
        assert_eq!(doc.root().qname().local(), "LogoutResponse");
        let status = doc.root().child_element(Some(SAMLP_NS), "Status").unwrap();
        assert!(
            status
                .child_element(Some(SAMLP_NS), "StatusCode")
                .is_some()
        );
        assert!(
            status
                .child_element(Some(SAMLP_NS), "StatusMessage")
                .is_some()
        );
    }
}
