//! Parse inbound `<samlp:LogoutRequest>` per SAML 2.0 Core §3.7.1.
//!
//! Used by `ServiceProvider::consume_logout_request` /
//! `IdentityProvider::consume_logout_request` (RFC-007 §2 / §3) after the
//! binding layer has decoded the wire envelope and the XML hardening pass
//! (RFC-002 §1) has parsed the body into a `Document`.
//!
//! This module is intentionally a pure XML-to-struct translator: it does NOT
//! perform Issuer / Destination / signature / clock validation. Those are
//! caller responsibilities (RFC-007 §5.1) so the parser can be reused by both
//! SP and IdP code paths that share the same wire shape but apply different
//! policy decisions.
//!
//! `<saml:EncryptedID>` is recognized at the schema level but rejected here
//! as out-of-scope for v0.1 (see RFC-007 §9). A future revision will plug
//! `crate::xmlenc::decrypt` in at this point.

use crate::error::Error;
use crate::logout::{ParsedLogoutRequest, SAML_NS, SAMLP_NS};
use crate::nameid::{NameId, NameIdFormat};
use crate::time::parse_xs_datetime;
use crate::xml::parse::{Document, Element, ElementId};

/// Parse a `<samlp:LogoutRequest>` document into the structured view.
///
/// Returns the parsed payload alongside the root [`ElementId`] so the caller
/// can hand the same handle to `dsig::verify::verify_signature` without
/// re-walking the tree (RFC-002 §3).
pub(crate) fn parse_logout_request(
    document: &Document,
) -> Result<(ParsedLogoutRequest, ElementId), Error> {
    let root = document.root();
    if root.qname().namespace() != Some(SAMLP_NS) || root.qname().local() != "LogoutRequest" {
        return Err(Error::XmlParse(format!(
            "expected <samlp:LogoutRequest>, got <{}>",
            root.qname()
        )));
    }

    // Structural schema gate. See `crate::schema` for the rule set.
    #[cfg(feature = "xsd-validate")]
    crate::schema::validate_logout_request(root)?;

    // Version: MUST be "2.0" per Core §3.2.2.1 / §3.7.1.
    let version = root
        .attribute(None, "Version")
        .ok_or_else(|| Error::XmlParse("LogoutRequest missing Version".to_string()))?;
    if version != "2.0" {
        return Err(Error::XmlParse(format!(
            "unsupported LogoutRequest Version: {version}"
        )));
    }

    let id = root
        .attribute(None, "ID")
        .ok_or_else(|| Error::XmlParse("LogoutRequest missing ID".to_string()))?
        .to_owned();
    let issue_instant_str = root
        .attribute(None, "IssueInstant")
        .ok_or_else(|| Error::XmlParse("LogoutRequest missing IssueInstant".to_string()))?;
    let issue_instant = parse_xs_datetime(issue_instant_str)?;

    let destination = root.attribute(None, "Destination").map(str::to_owned);
    let not_on_or_after = root
        .attribute(None, "NotOnOrAfter")
        .map(parse_xs_datetime)
        .transpose()?;
    let reason = root.attribute(None, "Reason").map(str::to_owned);

    // <saml:Issuer> required.
    let issuer_el = root
        .child_element(Some(SAML_NS), "Issuer")
        .ok_or_else(|| Error::XmlParse("LogoutRequest missing <saml:Issuer>".to_string()))?;
    let issuer = issuer_el.text_content();
    if issuer.trim().is_empty() {
        return Err(Error::XmlParse(
            "LogoutRequest <saml:Issuer> is empty".to_string(),
        ));
    }

    // Subject identifier: a cleartext <saml:NameID>, or — with the `xmlenc`
    // feature — an encrypted <saml:EncryptedID>. EncryptedID is decrypted by the
    // consumer (`consume_logout_request`) *after* signature verification, where
    // the decryption key and crypto policy live and where the message is known
    // to be authentic before we apply our private key to its ciphertext. Here we
    // leave a placeholder NameID that the consumer overwrites via
    // `decrypt_encrypted_name_id`.
    //
    // BaseID is out of scope; the BaseID/NameID/EncryptedID group is an
    // xsd:choice, so a missing NameID with no EncryptedID is a hard error rather
    // than a silent BaseID fallthrough.
    let name_id = match root.child_element(Some(SAML_NS), "NameID") {
        Some(nameid_el) => parse_name_id(nameid_el),
        #[cfg(feature = "xmlenc")]
        None if root.child_element(Some(SAML_NS), "EncryptedID").is_some() => {
            NameId::new(String::new(), NameIdFormat::Unspecified)
        }
        None => {
            #[cfg(not(feature = "xmlenc"))]
            if root.child_element(Some(SAML_NS), "EncryptedID").is_some() {
                return Err(Error::XmlParse(
                    "<saml:EncryptedID> in LogoutRequest requires the `xmlenc` feature".to_string(),
                ));
            }
            return Err(Error::XmlParse(
                "LogoutRequest missing <saml:NameID>".to_string(),
            ));
        }
    };

    // <samlp:SessionIndex>* — text content, in document order. Schema allows
    // zero, so absence is not an error.
    let session_index: Vec<String> = root
        .all_child_elements(Some(SAMLP_NS), "SessionIndex")
        .map(Element::text_content)
        .collect();

    let parsed = ParsedLogoutRequest {
        id,
        issuer,
        issue_instant,
        destination,
        not_on_or_after,
        reason,
        name_id,
        session_index,
        // RelayState rides on the binding envelope, not the XML body. Caller
        // fills this in after binding decode if it received one.
        relay_state: None,
    };
    Ok((parsed, root.id()))
}

fn parse_name_id(el: &Element) -> NameId {
    let value = el.text_content();
    let format = el
        .attribute(None, "Format")
        .map_or(NameIdFormat::Unspecified, NameIdFormat::from_uri);
    let name_qualifier = el.attribute(None, "NameQualifier").map(str::to_owned);
    let sp_name_qualifier = el.attribute(None, "SPNameQualifier").map(str::to_owned);
    let sp_provided_id = el.attribute(None, "SPProvidedID").map(str::to_owned);
    NameId {
        value,
        format,
        name_qualifier,
        sp_name_qualifier,
        sp_provided_id,
    }
}

/// Decrypt a `<saml:EncryptedID>` carried directly under a
/// `<samlp:LogoutRequest>` into a cleartext [`NameId`]. Returns `Ok(None)` when
/// the request used a cleartext `<saml:NameID>` (the parser already populated
/// `name_id`, so there is nothing to do).
///
/// The consumer MUST call this only *after* the LogoutRequest signature has been
/// verified: we apply our private decryption key solely to ciphertext we have
/// already authenticated, and algorithm acceptance is gated by the peer's
/// [`PeerCryptoPolicy`] allow-lists — never by the compile-time feature alone.
/// This reuses the same xmlenc plumbing as `<saml:EncryptedAssertion>`; an
/// `EncryptedID` is just an `<xenc:EncryptedData>` wrapper whose plaintext is a
/// `<saml:NameID>` rather than an `<saml:Assertion>`.
#[cfg(feature = "xmlenc")]
pub(crate) fn decrypt_encrypted_name_id(
    document: &Document,
    decryption_keys: &[&crate::crypto::keypair::KeyPair],
    policy: &crate::dsig::algorithms::PeerCryptoPolicy,
) -> Result<Option<NameId>, Error> {
    let root = document.root();
    let Some(encrypted_id) = root.child_element(Some(SAML_NS), "EncryptedID") else {
        return Ok(None);
    };
    if decryption_keys.is_empty() {
        return Err(Error::DecryptFailed {
            reason: "LogoutRequest carries <saml:EncryptedID> but no decryption key is configured",
        });
    }
    let decrypted = crate::xmlenc::decrypt::decrypt_encrypted_assertion(
        encrypted_id,
        decryption_keys,
        &policy.allowed_data_encryption_algorithms,
        &policy.allowed_key_transport_algorithms,
    )?;
    if decrypted.qname().namespace() != Some(SAML_NS) || decrypted.qname().local() != "NameID" {
        return Err(Error::XmlParse(
            "decrypted <saml:EncryptedID> did not contain a <saml:NameID>".to_string(),
        ));
    }
    Ok(Some(parse_name_id(&decrypted)))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    fn parse(xml: &str) -> Result<(ParsedLogoutRequest, ElementId), Error> {
        let doc = Document::parse(xml.as_bytes())?;
        parse_logout_request(&doc)
    }

    #[test]
    fn parses_well_formed_logout_request() {
        let xml = r#"<samlp:LogoutRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_req-1" Version="2.0"
            IssueInstant="2026-05-26T12:34:56Z"
            Destination="https://idp.example.com/slo"
            NotOnOrAfter="2026-05-26T12:39:56Z"
            Reason="urn:oasis:names:tc:SAML:2.0:logout:user">
            <saml:Issuer>https://sp.example.com/saml</saml:Issuer>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
                         NameQualifier="https://idp.example.com/saml"
                         SPNameQualifier="https://sp.example.com/saml">alice@example.com</saml:NameID>
            <samlp:SessionIndex>sess-1</samlp:SessionIndex>
        </samlp:LogoutRequest>"#;

        let (req, _id) = parse(xml).expect("parse");
        assert_eq!(req.id, "_req-1");
        assert_eq!(req.issuer, "https://sp.example.com/saml");
        assert_eq!(
            req.issue_instant,
            UNIX_EPOCH + Duration::from_secs(1_779_798_896)
        );
        assert_eq!(
            req.destination.as_deref(),
            Some("https://idp.example.com/slo")
        );
        assert_eq!(
            req.not_on_or_after,
            Some(UNIX_EPOCH + Duration::from_secs(1_779_798_896 + 300))
        );
        assert_eq!(
            req.reason.as_deref(),
            Some("urn:oasis:names:tc:SAML:2.0:logout:user")
        );
        assert_eq!(req.name_id.value, "alice@example.com");
        assert_eq!(req.name_id.format, NameIdFormat::EmailAddress);
        assert_eq!(
            req.name_id.name_qualifier.as_deref(),
            Some("https://idp.example.com/saml")
        );
        assert_eq!(
            req.name_id.sp_name_qualifier.as_deref(),
            Some("https://sp.example.com/saml")
        );
        assert_eq!(req.session_index, vec!["sess-1".to_string()]);
        assert!(req.relay_state.is_none());
    }

    #[test]
    fn multiple_session_indices_captured_in_order() {
        let xml = r#"<samlp:LogoutRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_r" Version="2.0" IssueInstant="2026-05-26T12:34:56Z">
            <saml:Issuer>idp</saml:Issuer>
            <saml:NameID>u</saml:NameID>
            <samlp:SessionIndex>a</samlp:SessionIndex>
            <samlp:SessionIndex>b</samlp:SessionIndex>
            <samlp:SessionIndex>c</samlp:SessionIndex>
        </samlp:LogoutRequest>"#;
        let (req, _) = parse(xml).expect("parse");
        assert_eq!(req.session_index, vec!["a", "b", "c"]);
    }

    #[test]
    fn missing_session_indices_yields_empty_vec() {
        let xml = r#"<samlp:LogoutRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_r" Version="2.0" IssueInstant="2026-05-26T12:34:56Z">
            <saml:Issuer>idp</saml:Issuer>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">u@example.com</saml:NameID>
        </samlp:LogoutRequest>"#;
        let (req, _) = parse(xml).expect("parse");
        assert!(req.session_index.is_empty());
    }

    #[test]
    fn wrong_root_element_rejected() {
        // AuthnRequest is valid SAML, just not the message we expect.
        let xml = r#"<samlp:AuthnRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            ID="_x" Version="2.0" IssueInstant="2026-05-26T12:34:56Z"/>"#;
        let err = parse(xml).unwrap_err();
        match err {
            Error::XmlParse(msg) => {
                assert!(msg.contains("LogoutRequest"), "got: {msg}");
            }
            other => panic!("expected XmlParse, got {other:?}"),
        }
    }

    #[test]
    fn missing_version_rejected() {
        let xml = r#"<samlp:LogoutRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_r" IssueInstant="2026-05-26T12:34:56Z">
            <saml:Issuer>idp</saml:Issuer>
            <saml:NameID>u</saml:NameID>
        </samlp:LogoutRequest>"#;
        let err = parse(xml).unwrap_err();
        // Schema gate fires first under default features; xsd-validate-off
        // falls through to the manual XmlParse check on Version.
        assert!(matches!(
            err,
            Error::XmlParse(_) | Error::SchemaViolation { .. }
        ));
    }

    #[test]
    fn wrong_version_rejected() {
        let xml = r#"<samlp:LogoutRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_r" Version="1.1" IssueInstant="2026-05-26T12:34:56Z">
            <saml:Issuer>idp</saml:Issuer>
            <saml:NameID>u</saml:NameID>
        </samlp:LogoutRequest>"#;
        let err = parse(xml).unwrap_err();
        match err {
            Error::XmlParse(msg) => assert!(msg.contains("Version"), "got: {msg}"),
            other => panic!("expected XmlParse, got {other:?}"),
        }
    }

    #[test]
    fn missing_issuer_rejected() {
        let xml = r#"<samlp:LogoutRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_r" Version="2.0" IssueInstant="2026-05-26T12:34:56Z">
            <saml:NameID>u</saml:NameID>
        </samlp:LogoutRequest>"#;
        let err = parse(xml).unwrap_err();
        match err {
            Error::XmlParse(msg) => assert!(msg.contains("Issuer"), "got: {msg}"),
            other => panic!("expected XmlParse, got {other:?}"),
        }
    }

    #[test]
    fn empty_issuer_rejected() {
        let xml = r#"<samlp:LogoutRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_r" Version="2.0" IssueInstant="2026-05-26T12:34:56Z">
            <saml:Issuer>   </saml:Issuer>
            <saml:NameID>u</saml:NameID>
        </samlp:LogoutRequest>"#;
        let err = parse(xml).unwrap_err();
        assert!(matches!(err, Error::XmlParse(_)));
    }

    #[test]
    fn missing_name_id_rejected() {
        let xml = r#"<samlp:LogoutRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_r" Version="2.0" IssueInstant="2026-05-26T12:34:56Z">
            <saml:Issuer>idp</saml:Issuer>
        </samlp:LogoutRequest>"#;
        let err = parse(xml).unwrap_err();
        match err {
            Error::XmlParse(msg) => assert!(msg.contains("NameID"), "got: {msg}"),
            other => panic!("expected XmlParse, got {other:?}"),
        }
    }

    /// Without the `xmlenc` feature there is no way to decrypt, so an
    /// `<saml:EncryptedID>` LogoutRequest is rejected outright at parse time.
    #[cfg(not(feature = "xmlenc"))]
    #[test]
    fn encrypted_id_rejected_without_xmlenc() {
        let xml = r#"<samlp:LogoutRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_r" Version="2.0" IssueInstant="2026-05-26T12:34:56Z">
            <saml:Issuer>idp</saml:Issuer>
            <saml:EncryptedID/>
        </samlp:LogoutRequest>"#;
        let err = parse(xml).unwrap_err();
        match err {
            Error::XmlParse(msg) => assert!(msg.contains("EncryptedID"), "got: {msg}"),
            other => panic!("expected XmlParse, got {other:?}"),
        }
    }

    /// With `xmlenc`, the parser defers an `<saml:EncryptedID>`: it succeeds with
    /// a placeholder `name_id` that the consumer overwrites after verifying the
    /// signature and decrypting (see `decrypt_encrypted_name_id`).
    #[cfg(feature = "xmlenc")]
    #[test]
    fn encrypted_id_deferred_to_consumer() {
        let xml = r#"<samlp:LogoutRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_r" Version="2.0" IssueInstant="2026-05-26T12:34:56Z">
            <saml:Issuer>idp</saml:Issuer>
            <saml:EncryptedID/>
        </samlp:LogoutRequest>"#;
        let (req, _) = parse(xml).expect("EncryptedID parses to a placeholder");
        // Placeholder: empty value, awaiting decryption.
        assert_eq!(req.name_id.value, "");
        assert_eq!(req.name_id.format, NameIdFormat::Unspecified);
    }

    /// End-to-end: encrypt a `<saml:NameID>` to a recipient cert, splice it into
    /// a LogoutRequest as `<saml:EncryptedID>`, and confirm
    /// `decrypt_encrypted_name_id` recovers the cleartext NameID.
    #[cfg(feature = "xmlenc")]
    #[test]
    fn decrypt_encrypted_name_id_round_trip() {
        use crate::crypto::cert::X509Certificate;
        use crate::crypto::cert::test_vectors::{RSA_CERT_PEM, RSA_KEY_PKCS8_PEM};
        use crate::crypto::keypair::KeyPair;
        use crate::dsig::algorithms::PeerCryptoPolicy;
        use crate::xml::emit::emit_element;
        use crate::xml::parse::QName;
        use crate::xmlenc::algorithms::{DataEncryptionAlgorithm, KeyTransportAlgorithm};
        use crate::xmlenc::encrypt::encrypt_assertion;

        // The cleartext subject we expect to recover.
        let name_id = Element::build(QName::new(Some(SAML_NS.to_owned()), "NameID"))
            .with_namespace(Some("saml".to_owned()), SAML_NS)
            .with_attribute(
                QName::new(None, "Format"),
                NameIdFormat::EmailAddress.as_uri(),
            )
            .with_text("alice@example.org")
            .finish();

        // Encrypt it. `encrypt_assertion` wraps any element's <xenc:EncryptedData>
        // in a <saml:EncryptedAssertion>; we lift that EncryptedData into a
        // <saml:EncryptedID> instead, which is the only structural difference.
        let cert = X509Certificate::from_pem(RSA_CERT_PEM).unwrap();
        let mut encrypted_id = encrypt_assertion(
            &name_id,
            &cert,
            DataEncryptionAlgorithm::Aes256Gcm,
            KeyTransportAlgorithm::RsaOaep,
        )
        .expect("encrypt");
        // `encrypt_assertion` wraps the <xenc:EncryptedData> in a
        // <saml:EncryptedAssertion>; the only structural difference from an
        // <saml:EncryptedID> is the wrapper's local name. Rename it in place so
        // the wrapper keeps every namespace declaration the payload needs.
        encrypted_id.qname.local = "EncryptedID".to_string();

        let xml = format!(
            r#"<samlp:LogoutRequest
                xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_r" Version="2.0" IssueInstant="2026-05-26T12:34:56Z">
                <saml:Issuer>https://sp.example.com</saml:Issuer>
                {}
            </samlp:LogoutRequest>"#,
            emit_element(&encrypted_id).unwrap()
        );

        let doc = Document::parse(xml.as_bytes()).expect("parse");
        let (req, _) = parse_logout_request(&doc).expect("parse defers EncryptedID");
        assert_eq!(req.name_id.value, "", "placeholder before decryption");

        let kp = KeyPair::from_pkcs8_pem(RSA_KEY_PKCS8_PEM).unwrap();
        let policy = PeerCryptoPolicy::strong_defaults();
        let decrypted = decrypt_encrypted_name_id(&doc, &[&kp], &policy)
            .expect("decrypt ok")
            .expect("EncryptedID present");
        assert_eq!(decrypted.value, "alice@example.org");
        assert_eq!(decrypted.format, NameIdFormat::EmailAddress);
    }

    /// A cleartext NameID request yields `Ok(None)` — nothing to decrypt.
    #[cfg(feature = "xmlenc")]
    #[test]
    fn decrypt_encrypted_name_id_noop_for_cleartext() {
        use crate::crypto::cert::test_vectors::RSA_KEY_PKCS8_PEM;
        use crate::crypto::keypair::KeyPair;
        use crate::dsig::algorithms::PeerCryptoPolicy;

        let xml = r#"<samlp:LogoutRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_r" Version="2.0" IssueInstant="2026-05-26T12:34:56Z">
            <saml:Issuer>idp</saml:Issuer>
            <saml:NameID>u@example.com</saml:NameID>
        </samlp:LogoutRequest>"#;
        let doc = Document::parse(xml.as_bytes()).unwrap();
        let kp = KeyPair::from_pkcs8_pem(RSA_KEY_PKCS8_PEM).unwrap();
        let policy = PeerCryptoPolicy::strong_defaults();
        let got = decrypt_encrypted_name_id(&doc, &[&kp], &policy).unwrap();
        assert!(got.is_none());
    }

    /// EncryptedID present but no decryption key configured is a clear error,
    /// not a silent placeholder leak.
    #[cfg(feature = "xmlenc")]
    #[test]
    fn decrypt_encrypted_name_id_requires_key() {
        use crate::dsig::algorithms::PeerCryptoPolicy;

        let xml = r#"<samlp:LogoutRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_r" Version="2.0" IssueInstant="2026-05-26T12:34:56Z">
            <saml:Issuer>idp</saml:Issuer>
            <saml:EncryptedID/>
        </samlp:LogoutRequest>"#;
        let doc = Document::parse(xml.as_bytes()).unwrap();
        let policy = PeerCryptoPolicy::strong_defaults();
        let err = decrypt_encrypted_name_id(&doc, &[], &policy).unwrap_err();
        assert!(matches!(err, Error::DecryptFailed { .. }));
    }

    #[test]
    fn returns_element_id_pointing_at_root() {
        let xml = r#"<samlp:LogoutRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_r" Version="2.0" IssueInstant="2026-05-26T12:34:56Z">
            <saml:Issuer>idp</saml:Issuer>
            <saml:NameID>u</saml:NameID>
        </samlp:LogoutRequest>"#;
        let doc = Document::parse(xml.as_bytes()).unwrap();
        let (_req, eid) = parse_logout_request(&doc).unwrap();
        assert_eq!(eid, doc.root().id());
    }

    #[test]
    fn nameid_format_defaults_to_unspecified_when_attribute_absent() {
        let xml = r#"<samlp:LogoutRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_r" Version="2.0" IssueInstant="2026-05-26T12:34:56Z">
            <saml:Issuer>idp</saml:Issuer>
            <saml:NameID>bare-value</saml:NameID>
        </samlp:LogoutRequest>"#;
        let (req, _) = parse(xml).unwrap();
        assert_eq!(req.name_id.format, NameIdFormat::Unspecified);
        assert_eq!(req.name_id.value, "bare-value");
    }
}
