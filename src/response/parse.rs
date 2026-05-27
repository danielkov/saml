//! Parse `<samlp:Response>` + `<saml:Assertion>` XML structure.
//!
//! This module produces a typed view of the wire XML; signature verification
//! and time-window / audience / subject-confirmation checks live in
//! `crate::response::validate`. Splitting the responsibilities lets us reuse
//! the parser for the IdP-side decrypt-and-re-parse path without re-applying
//! the validation pipeline.

use std::time::SystemTime;

use crate::attribute::Attribute;
use crate::conditions::Conditions;
use crate::error::Error;
use crate::nameid::{NameId, NameIdFormat};
use crate::response::{SAML_NS, SAMLP_NS};
use crate::time::parse_xs_datetime;
use crate::xml::parse::{Document, Element, ElementId};

/// SAML 2.0 success status URI.
pub(crate) const STATUS_SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";

/// SAML 2.0 bearer SubjectConfirmation method URI.
pub(crate) const SUBJECT_CONFIRMATION_BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

/// Typed view of a parsed `<samlp:Response>` (without signature verification).
#[derive(Debug, Clone)]
pub(crate) struct ParsedResponse {
    pub destination: Option<String>,
    pub in_response_to: Option<String>,
    pub issuer: Option<String>,
    pub status_code: String,
    pub status_message: Option<String>,
    /// Either an `<saml:Assertion>` (cleartext) or `<saml:EncryptedAssertion>`.
    ///
    /// `None` is permitted at parse time so the validate layer can surface
    /// `StatusNotSuccess` (step 5 of RFC-003 §4.1) for error responses before
    /// it tries to read the assertion. Multiple assertions (an XSW vector)
    /// are still rejected at parse time.
    pub assertion: Option<AssertionWrapper>,
}

#[derive(Debug, Clone)]
pub(crate) enum AssertionWrapper {
    /// Cleartext `<saml:Assertion>` ElementId.
    Cleartext(ElementId),
    /// Encrypted `<saml:EncryptedAssertion>` ElementId.
    Encrypted(ElementId),
}

#[derive(Debug, Clone)]
pub(crate) struct ParsedAssertion {
    pub id: String,
    pub issue_instant: SystemTime,
    pub issuer: String,
    pub subject_name_id: NameId,
    pub subject_confirmations: Vec<SubjectConfirmation>,
    pub conditions: Conditions,
    pub authn_statements: Vec<ParsedAuthnStatement>,
    pub attributes: Vec<Attribute>,
}

#[derive(Debug, Clone)]
pub(crate) struct SubjectConfirmation {
    /// `@Method` URI. Bearer is `urn:oasis:names:tc:SAML:2.0:cm:bearer`.
    pub method: String,
    pub recipient: Option<String>,
    pub not_on_or_after: Option<SystemTime>,
    pub not_before: Option<SystemTime>,
    pub in_response_to: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct ParsedAuthnStatement {
    pub authn_instant: SystemTime,
    pub session_index: Option<String>,
    pub session_not_on_or_after: Option<SystemTime>,
    pub authn_context_class_ref: Option<String>,
}

// =============================================================================
// Response parser
// =============================================================================

/// Parse `<samlp:Response>` from a document. Returns the typed view + the
/// Response ElementId (for binding-layer signature verification).
pub(crate) fn parse_response(document: &Document) -> Result<(ParsedResponse, ElementId), Error> {
    let root = document.root();

    if root.qname().namespace() != Some(SAMLP_NS) || root.qname().local() != "Response" {
        return Err(Error::XmlParse(format!(
            "expected <samlp:Response> root, got {{{}}}{}",
            root.qname().namespace().unwrap_or(""),
            root.qname().local()
        )));
    }

    root.attribute(None, "ID")
        .ok_or_else(|| Error::XmlParse("Response missing ID".to_string()))?;
    let version = root
        .attribute(None, "Version")
        .ok_or_else(|| Error::XmlParse("Response missing Version".to_string()))?;
    if version != "2.0" {
        return Err(Error::XmlParse(format!(
            "unsupported SAML version: {version}"
        )));
    }
    let issue_instant_str = root
        .attribute(None, "IssueInstant")
        .ok_or_else(|| Error::XmlParse("Response missing IssueInstant".to_string()))?;
    parse_xs_datetime(issue_instant_str)?;

    let destination = root.attribute(None, "Destination").map(str::to_owned);
    let in_response_to = root.attribute(None, "InResponseTo").map(str::to_owned);

    let issuer = root
        .child_element(Some(SAML_NS), "Issuer")
        .map(|i| i.text_content().trim().to_owned());

    // ---- <samlp:Status> ----
    let status = root.child_element(Some(SAMLP_NS), "Status").ok_or_else(|| {
        Error::XmlParse("Response missing samlp:Status".to_string())
    })?;
    let status_code_elem = status
        .child_element(Some(SAMLP_NS), "StatusCode")
        .ok_or_else(|| Error::XmlParse("Status missing StatusCode".to_string()))?;
    let status_code = status_code_elem
        .attribute(None, "Value")
        .ok_or_else(|| Error::XmlParse("StatusCode missing @Value".to_string()))?
        .to_owned();
    let status_message = status
        .child_element(Some(SAMLP_NS), "StatusMessage")
        .map(|m| m.text_content().trim().to_owned());

    // ---- locate exactly-one assertion-or-encrypted-assertion ----
    let mut assertion_wrappers: Vec<AssertionWrapper> = Vec::new();
    for child in root.child_elements() {
        if child.qname().namespace() == Some(SAML_NS) {
            match child.qname().local() {
                "Assertion" => {
                    assertion_wrappers.push(AssertionWrapper::Cleartext(child.id()));
                }
                "EncryptedAssertion" => {
                    assertion_wrappers.push(AssertionWrapper::Encrypted(child.id()));
                }
                _ => {}
            }
        }
    }
    // Multiple assertions is the canonical XSW vector; reject loudly. Zero is
    // permitted at parse time so validate can surface `StatusNotSuccess` for
    // error responses ahead of any "missing assertion" complaint (RFC-003 §4.1
    // step 7 runs after the status check).
    if assertion_wrappers.len() > 1 {
        return Err(Error::XmlParse(
            "multiple assertions in response — XSW vector".to_string(),
        ));
    }
    let assertion = assertion_wrappers.pop();

    let parsed = ParsedResponse {
        destination,
        in_response_to,
        issuer,
        status_code,
        status_message,
        assertion,
    };

    Ok((parsed, root.id()))
}

// =============================================================================
// Assertion parser
// =============================================================================

/// Parse a `<saml:Assertion>` element (already located).
pub(crate) fn parse_assertion(assertion: &Element) -> Result<ParsedAssertion, Error> {
    if assertion.qname().namespace() != Some(SAML_NS) || assertion.qname().local() != "Assertion" {
        return Err(Error::XmlParse(format!(
            "expected <saml:Assertion>, got {{{}}}{}",
            assertion.qname().namespace().unwrap_or(""),
            assertion.qname().local()
        )));
    }

    let id = assertion
        .attribute(None, "ID")
        .ok_or_else(|| Error::XmlParse("Assertion missing ID".to_string()))?
        .to_owned();

    let issue_instant_str = assertion
        .attribute(None, "IssueInstant")
        .ok_or_else(|| Error::XmlParse("Assertion missing IssueInstant".to_string()))?;
    let issue_instant = parse_xs_datetime(issue_instant_str)?;

    let issuer = assertion
        .child_element(Some(SAML_NS), "Issuer")
        .ok_or_else(|| Error::XmlParse("Assertion missing Issuer".to_string()))?
        .text_content()
        .trim()
        .to_owned();

    // ---- Subject ----
    let subject = assertion
        .child_element(Some(SAML_NS), "Subject")
        .ok_or_else(|| Error::XmlParse("Assertion missing Subject".to_string()))?;
    let name_id_elem = subject
        .child_element(Some(SAML_NS), "NameID")
        .ok_or_else(|| Error::XmlParse("Subject missing NameID".to_string()))?;
    let subject_name_id = parse_name_id(name_id_elem);

    let mut subject_confirmations = Vec::new();
    for sc in subject.all_child_elements(Some(SAML_NS), "SubjectConfirmation") {
        subject_confirmations.push(parse_subject_confirmation(sc)?);
    }

    // ---- Conditions ----
    let conditions = match assertion.child_element(Some(SAML_NS), "Conditions") {
        Some(c) => parse_conditions(c)?,
        None => Conditions {
            not_before: None,
            not_on_or_after: None,
            audiences: vec![],
            one_time_use: false,
            proxy_restriction_count: None,
            proxy_restriction_audiences: vec![],
        },
    };

    // ---- AuthnStatement(s) ----
    let mut authn_statements = Vec::new();
    for stmt in assertion.all_child_elements(Some(SAML_NS), "AuthnStatement") {
        authn_statements.push(parse_authn_statement(stmt)?);
    }

    // ---- AttributeStatement (zero or more) → flatten Attributes ----
    let mut attributes = Vec::new();
    for attr_stmt in assertion.all_child_elements(Some(SAML_NS), "AttributeStatement") {
        for attr in attr_stmt.all_child_elements(Some(SAML_NS), "Attribute") {
            attributes.push(parse_attribute(attr));
        }
    }

    Ok(ParsedAssertion {
        id,
        issue_instant,
        issuer,
        subject_name_id,
        subject_confirmations,
        conditions,
        authn_statements,
        attributes,
    })
}

fn parse_name_id(elem: &Element) -> NameId {
    let value = elem.text_content().trim().to_owned();
    let format = elem
        .attribute(None, "Format")
        .map(NameIdFormat::from_uri)
        .unwrap_or(NameIdFormat::Unspecified);
    let name_qualifier = elem.attribute(None, "NameQualifier").map(str::to_owned);
    let sp_name_qualifier = elem.attribute(None, "SPNameQualifier").map(str::to_owned);
    let sp_provided_id = elem.attribute(None, "SPProvidedID").map(str::to_owned);
    NameId {
        value,
        format,
        name_qualifier,
        sp_name_qualifier,
        sp_provided_id,
    }
}

fn parse_subject_confirmation(elem: &Element) -> Result<SubjectConfirmation, Error> {
    let method = elem
        .attribute(None, "Method")
        .ok_or_else(|| Error::XmlParse("SubjectConfirmation missing Method".to_string()))?
        .to_owned();

    let data = elem.child_element(Some(SAML_NS), "SubjectConfirmationData");
    let (recipient, not_on_or_after, not_before, in_response_to) = match data {
        Some(d) => (
            d.attribute(None, "Recipient").map(str::to_owned),
            d.attribute(None, "NotOnOrAfter").map(parse_xs_datetime).transpose()?,
            d.attribute(None, "NotBefore").map(parse_xs_datetime).transpose()?,
            d.attribute(None, "InResponseTo").map(str::to_owned),
        ),
        None => (None, None, None, None),
    };

    Ok(SubjectConfirmation {
        method,
        recipient,
        not_on_or_after,
        not_before,
        in_response_to,
    })
}

fn parse_conditions(elem: &Element) -> Result<Conditions, Error> {
    let not_before = elem
        .attribute(None, "NotBefore")
        .map(parse_xs_datetime)
        .transpose()?;
    let not_on_or_after = elem
        .attribute(None, "NotOnOrAfter")
        .map(parse_xs_datetime)
        .transpose()?;

    let mut audiences: Vec<String> = Vec::new();
    for restriction in elem.all_child_elements(Some(SAML_NS), "AudienceRestriction") {
        for aud in restriction.all_child_elements(Some(SAML_NS), "Audience") {
            audiences.push(aud.text_content().trim().to_owned());
        }
    }

    let one_time_use = elem.child_element(Some(SAML_NS), "OneTimeUse").is_some();

    let (proxy_restriction_count, proxy_restriction_audiences) = match elem
        .child_element(Some(SAML_NS), "ProxyRestriction")
    {
        Some(pr) => {
            let count = pr
                .attribute(None, "Count")
                .map(|c| {
                    c.parse::<u32>().map_err(|_| {
                        Error::XmlParse(format!("ProxyRestriction/@Count not an integer: {c}"))
                    })
                })
                .transpose()?;
            let mut auds = Vec::new();
            for aud in pr.all_child_elements(Some(SAML_NS), "Audience") {
                auds.push(aud.text_content().trim().to_owned());
            }
            (count, auds)
        }
        None => (None, Vec::new()),
    };

    Ok(Conditions {
        not_before,
        not_on_or_after,
        audiences,
        one_time_use,
        proxy_restriction_count,
        proxy_restriction_audiences,
    })
}

fn parse_authn_statement(elem: &Element) -> Result<ParsedAuthnStatement, Error> {
    let authn_instant_str = elem.attribute(None, "AuthnInstant").ok_or_else(|| {
        Error::XmlParse("AuthnStatement missing AuthnInstant".to_string())
    })?;
    let authn_instant = parse_xs_datetime(authn_instant_str)?;
    let session_index = elem.attribute(None, "SessionIndex").map(str::to_owned);
    let session_not_on_or_after = elem
        .attribute(None, "SessionNotOnOrAfter")
        .map(parse_xs_datetime)
        .transpose()?;
    let authn_context_class_ref = elem
        .child_element(Some(SAML_NS), "AuthnContext")
        .and_then(|c| c.child_element(Some(SAML_NS), "AuthnContextClassRef"))
        .map(|r| r.text_content().trim().to_owned());

    Ok(ParsedAuthnStatement {
        authn_instant,
        session_index,
        session_not_on_or_after,
        authn_context_class_ref,
    })
}

fn parse_attribute(elem: &Element) -> Attribute {
    let name = elem
        .attribute(None, "Name")
        .map(str::to_owned)
        .unwrap_or_default();
    let name_format = elem.attribute(None, "NameFormat").map(str::to_owned);
    let friendly_name = elem.attribute(None, "FriendlyName").map(str::to_owned);
    let values: Vec<String> = elem
        .all_child_elements(Some(SAML_NS), "AttributeValue")
        .map(|v| v.text_content())
        .collect();
    Attribute {
        name,
        name_format,
        friendly_name,
        values,
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xml::parse::Document;
    use std::time::{Duration, UNIX_EPOCH};

    /// Build a complete Response XML with a single cleartext Assertion.
    fn sample_response_xml() -> String {
        format!(
            r##"<samlp:Response xmlns:samlp="{SAMLP_NS}" xmlns:saml="{SAML_NS}"
                                   ID="_resp1" Version="2.0"
                                   IssueInstant="2026-05-26T12:00:00Z"
                                   Destination="https://sp.example.com/acs"
                                   InResponseTo="_req1">
                  <saml:Issuer>https://idp.example.com</saml:Issuer>
                  <samlp:Status>
                    <samlp:StatusCode Value="{STATUS_SUCCESS}"/>
                  </samlp:Status>
                  <saml:Assertion ID="_a1" Version="2.0"
                                  IssueInstant="2026-05-26T12:00:01Z">
                    <saml:Issuer>https://idp.example.com</saml:Issuer>
                    <saml:Subject>
                      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@example.com</saml:NameID>
                      <saml:SubjectConfirmation Method="{SUBJECT_CONFIRMATION_BEARER}">
                        <saml:SubjectConfirmationData
                              Recipient="https://sp.example.com/acs"
                              NotOnOrAfter="2026-05-26T12:05:00Z"
                              InResponseTo="_req1"/>
                      </saml:SubjectConfirmation>
                    </saml:Subject>
                    <saml:Conditions NotBefore="2026-05-26T11:59:00Z"
                                     NotOnOrAfter="2026-05-26T12:10:00Z">
                      <saml:AudienceRestriction>
                        <saml:Audience>https://sp.example.com</saml:Audience>
                      </saml:AudienceRestriction>
                    </saml:Conditions>
                    <saml:AuthnStatement AuthnInstant="2026-05-26T11:59:30Z"
                                         SessionIndex="sess-7">
                      <saml:AuthnContext>
                        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
                      </saml:AuthnContext>
                    </saml:AuthnStatement>
                    <saml:AttributeStatement>
                      <saml:Attribute Name="urn:oid:0.9.2342.19200300.100.1.3"
                                      NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                                      FriendlyName="mail">
                        <saml:AttributeValue>alice@example.com</saml:AttributeValue>
                      </saml:Attribute>
                      <saml:Attribute Name="groups">
                        <saml:AttributeValue>admins</saml:AttributeValue>
                        <saml:AttributeValue>engineering</saml:AttributeValue>
                      </saml:Attribute>
                    </saml:AttributeStatement>
                  </saml:Assertion>
                </samlp:Response>"##
        )
    }

    #[test]
    fn parses_response_root_attributes() {
        let xml = sample_response_xml();
        let doc = Document::parse(xml.as_bytes()).expect("parse");
        let (resp, response_id) = parse_response(&doc).expect("parse_response");

        assert_eq!(resp.destination.as_deref(), Some("https://sp.example.com/acs"));
        assert_eq!(resp.in_response_to.as_deref(), Some("_req1"));
        assert_eq!(resp.issuer.as_deref(), Some("https://idp.example.com"));
        assert_eq!(resp.status_code, STATUS_SUCCESS);
        assert!(resp.status_message.is_none());

        // The response ID round-trips back through document.element().
        let resolved = doc.element(response_id).unwrap();
        assert_eq!(resolved.qname().local(), "Response");
    }

    #[test]
    fn parses_assertion_full_shape() {
        let xml = sample_response_xml();
        let doc = Document::parse(xml.as_bytes()).expect("parse");
        let (resp, _) = parse_response(&doc).expect("parse_response");

        let assertion_id = match resp.assertion {
            Some(AssertionWrapper::Cleartext(id)) => id,
            _ => panic!("expected cleartext assertion"),
        };
        let assertion_elem = doc.element(assertion_id).expect("assertion element");
        let assertion = parse_assertion(assertion_elem).expect("parse_assertion");

        assert_eq!(assertion.id, "_a1");
        assert_eq!(assertion.issuer, "https://idp.example.com");
        assert_eq!(assertion.subject_name_id.value, "alice@example.com");
        assert_eq!(assertion.subject_name_id.format, NameIdFormat::EmailAddress);

        // SubjectConfirmation
        assert_eq!(assertion.subject_confirmations.len(), 1);
        let sc = &assertion.subject_confirmations[0];
        assert_eq!(sc.method, SUBJECT_CONFIRMATION_BEARER);
        assert_eq!(sc.recipient.as_deref(), Some("https://sp.example.com/acs"));
        assert!(sc.not_on_or_after.is_some());
        assert_eq!(sc.in_response_to.as_deref(), Some("_req1"));

        // Conditions
        assert!(assertion.conditions.not_before.is_some());
        assert!(assertion.conditions.not_on_or_after.is_some());
        assert_eq!(
            assertion.conditions.audiences,
            vec!["https://sp.example.com".to_string()]
        );

        // AuthnStatement
        assert_eq!(assertion.authn_statements.len(), 1);
        let auth = &assertion.authn_statements[0];
        assert_eq!(auth.session_index.as_deref(), Some("sess-7"));
        assert_eq!(
            auth.authn_context_class_ref.as_deref(),
            Some("urn:oasis:names:tc:SAML:2.0:ac:classes:Password")
        );

        // Attributes
        assert_eq!(assertion.attributes.len(), 2);
        let mail = assertion
            .attributes
            .iter()
            .find(|a| a.name == "urn:oid:0.9.2342.19200300.100.1.3")
            .unwrap();
        assert_eq!(mail.friendly_name.as_deref(), Some("mail"));
        assert_eq!(mail.values, vec!["alice@example.com".to_string()]);
        let groups = assertion
            .attributes
            .iter()
            .find(|a| a.name == "groups")
            .unwrap();
        assert_eq!(groups.values.len(), 2);
        assert!(groups.values.contains(&"admins".to_string()));
        assert!(groups.values.contains(&"engineering".to_string()));
    }

    #[test]
    fn rejects_non_samlp_response_root() {
        let xml = format!(r##"<saml:Foo xmlns:saml="{SAML_NS}"/>"##);
        let doc = Document::parse(xml.as_bytes()).expect("parse");
        let err = parse_response(&doc).unwrap_err();
        match err {
            Error::XmlParse(msg) => assert!(msg.contains("expected <samlp:Response>"), "got: {msg}"),
            other => panic!("expected XmlParse, got {other:?}"),
        }
    }

    #[test]
    fn rejects_multi_assertion_response_xsw_vector() {
        // Two cleartext assertions inside a single Response is the canonical
        // XSW vector class — reject it at parse time.
        let xml = format!(
            r##"<samlp:Response xmlns:samlp="{SAMLP_NS}" xmlns:saml="{SAML_NS}"
                                ID="_r" Version="2.0"
                                IssueInstant="2026-05-26T12:00:00Z">
              <saml:Issuer>https://idp.example.com</saml:Issuer>
              <samlp:Status><samlp:StatusCode Value="{STATUS_SUCCESS}"/></samlp:Status>
              <saml:Assertion ID="_a1" Version="2.0" IssueInstant="2026-05-26T12:00:00Z">
                <saml:Issuer>https://idp.example.com</saml:Issuer>
                <saml:Subject><saml:NameID>x</saml:NameID></saml:Subject>
              </saml:Assertion>
              <saml:Assertion ID="_a2" Version="2.0" IssueInstant="2026-05-26T12:00:00Z">
                <saml:Issuer>https://idp.example.com</saml:Issuer>
                <saml:Subject><saml:NameID>y</saml:NameID></saml:Subject>
              </saml:Assertion>
            </samlp:Response>"##
        );
        let doc = Document::parse(xml.as_bytes()).expect("parse");
        let err = parse_response(&doc).unwrap_err();
        match err {
            Error::XmlParse(msg) => {
                assert!(msg.contains("multiple assertions"), "got: {msg}");
                assert!(msg.contains("XSW"), "got: {msg}");
            }
            other => panic!("expected XmlParse, got {other:?}"),
        }
    }

    #[test]
    fn rejects_response_with_missing_status() {
        let xml = format!(
            r##"<samlp:Response xmlns:samlp="{SAMLP_NS}" xmlns:saml="{SAML_NS}"
                                ID="_r" Version="2.0"
                                IssueInstant="2026-05-26T12:00:00Z">
              <saml:Issuer>https://idp.example.com</saml:Issuer>
              <saml:Assertion ID="_a1" Version="2.0" IssueInstant="2026-05-26T12:00:00Z">
                <saml:Issuer>https://idp.example.com</saml:Issuer>
                <saml:Subject><saml:NameID>x</saml:NameID></saml:Subject>
              </saml:Assertion>
            </samlp:Response>"##
        );
        let doc = Document::parse(xml.as_bytes()).expect("parse");
        let err = parse_response(&doc).unwrap_err();
        match err {
            Error::XmlParse(msg) => assert!(msg.contains("Status"), "got: {msg}"),
            other => panic!("expected XmlParse, got {other:?}"),
        }
    }

    #[test]
    fn parses_second_level_status_code_and_message() {
        let xml = format!(
            r##"<samlp:Response xmlns:samlp="{SAMLP_NS}" xmlns:saml="{SAML_NS}"
                                ID="_r" Version="2.0"
                                IssueInstant="2026-05-26T12:00:00Z">
              <saml:Issuer>https://idp.example.com</saml:Issuer>
              <samlp:Status>
                <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester">
                  <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:RequestDenied"/>
                </samlp:StatusCode>
                <samlp:StatusMessage>Consent declined</samlp:StatusMessage>
              </samlp:Status>
              <saml:Assertion ID="_a1" Version="2.0" IssueInstant="2026-05-26T12:00:00Z">
                <saml:Issuer>https://idp.example.com</saml:Issuer>
                <saml:Subject><saml:NameID>x</saml:NameID></saml:Subject>
              </saml:Assertion>
            </samlp:Response>"##
        );
        let doc = Document::parse(xml.as_bytes()).expect("parse");
        let (resp, _) = parse_response(&doc).expect("parse");
        assert_eq!(resp.status_code, "urn:oasis:names:tc:SAML:2.0:status:Requester");
        assert_eq!(resp.status_message.as_deref(), Some("Consent declined"));
    }

    #[test]
    fn parses_encrypted_assertion_wrapper() {
        let xml = format!(
            r##"<samlp:Response xmlns:samlp="{SAMLP_NS}" xmlns:saml="{SAML_NS}"
                                ID="_r" Version="2.0"
                                IssueInstant="2026-05-26T12:00:00Z">
              <saml:Issuer>https://idp.example.com</saml:Issuer>
              <samlp:Status><samlp:StatusCode Value="{STATUS_SUCCESS}"/></samlp:Status>
              <saml:EncryptedAssertion>
                <fake-ciphertext/>
              </saml:EncryptedAssertion>
            </samlp:Response>"##
        );
        let doc = Document::parse(xml.as_bytes()).expect("parse");
        let (resp, _) = parse_response(&doc).expect("parse");
        match resp.assertion {
            Some(AssertionWrapper::Encrypted(_)) => {}
            _ => panic!("expected Encrypted wrapper"),
        }
    }

}
