//! The final identity payload extracted from a verified SAML assertion.
//!
//! See `docs/rfcs/RFC-003-service-provider.md` §4.

use std::time::SystemTime;

use crate::attribute::Attribute;
use crate::nameid::{NameId, NameIdFormat};

/// What the SP gets back from `consume_response` after all signature, audience,
/// subject-confirmation, and time-window checks pass. The caller dedupes on
/// `assertion_id` for replay defense and uses `name_id` + `session_index`
/// to construct an application session.
#[derive(Debug, Clone)]
pub struct Identity {
    pub name_id: NameId,
    pub session_index: Option<String>,
    pub authn_instant: SystemTime,
    pub session_not_on_or_after: Option<SystemTime>,
    pub authn_context_class_ref: Option<String>,
    pub attributes: Vec<Attribute>,
    /// For replay defense — dedupe on this until `not_on_or_after`.
    pub assertion_id: String,
    pub not_on_or_after: SystemTime,
    /// Cert that verified the assertion signature. For key-rotation logging.
    pub verifying_cert_fingerprint: [u8; 32],
    /// `<saml:OneTimeUse>` was present in `<saml:Conditions>` (SAML 2.0 Core
    /// §2.5.1.5). When `true` the relying party MUST consume the assertion
    /// only once — i.e. it MUST refuse a second presentation of the same
    /// assertion regardless of `not_on_or_after`. The library does not
    /// enforce this directive itself; the caller is responsible for plugging
    /// in a replay cache (dedupe by `assertion_id`) and rejecting repeats
    /// until at least `not_on_or_after`. Note that single-use is *stricter*
    /// than ordinary expiry-bounded replay defense: even within the validity
    /// window the assertion is good for exactly one consumption.
    pub is_one_time_use: bool,
}

impl Identity {
    /// Return the first non-empty value of an attribute whose `Name` or
    /// `FriendlyName` exactly matches one of the requested claim names,
    /// ignoring ASCII case.
    ///
    /// URI-valued names are not matched by their final path component: callers
    /// must list every trusted short name or URI explicitly. This avoids
    /// treating an unrelated attribute such as `https://example.test/email` as
    /// the conventional `email` claim.
    pub fn attribute(&self, requested_names: &[&str]) -> Option<&str> {
        self.attributes.iter().find_map(|attribute| {
            let matches = attribute_matches(attribute, requested_names);
            matches
                .then(|| {
                    attribute
                        .values
                        .iter()
                        .map(|value| value.trim())
                        .find(|value| !value.is_empty())
                })
                .flatten()
        })
    }

    /// Resolve a syntactically valid email address from an email-format NameID
    /// or an explicitly allow-listed conventional email attribute.
    ///
    /// This validates only the address syntax. It does not prove mailbox
    /// ownership or make an IdP's claim authoritative for account linking;
    /// applications must still apply their configured issuer and domain policy.
    pub fn email(&self) -> Option<&str> {
        let name_id = self.name_id.value.trim();
        if self.name_id.format == NameIdFormat::EmailAddress
            && email_address::EmailAddress::is_valid(name_id)
        {
            return Some(name_id);
        }

        const EMAIL_CLAIMS: &[&str] = &[
            "mail",
            "email",
            "emailaddress",
            "urn:oid:0.9.2342.19200300.100.1.3",
            "urn:oid:1.2.840.113549.1.9.1",
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
        ];
        self.attributes
            .iter()
            .filter(|attribute| attribute_matches(attribute, EMAIL_CLAIMS))
            .flat_map(|attribute| attribute.values.iter())
            .map(|value| value.trim())
            .find(|value| email_address::EmailAddress::is_valid(value))
    }

    /// Resolve a conventional display-name attribute.
    pub fn display_name(&self) -> Option<&str> {
        self.attribute(&[
            "name",
            "displayname",
            "cn",
            "urn:oid:2.16.840.1.113730.3.1.241",
            "urn:oid:2.5.4.3",
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
        ])
    }
}

fn attribute_matches(attribute: &Attribute, requested_names: &[&str]) -> bool {
    requested_names.iter().any(|requested| {
        attribute.name.eq_ignore_ascii_case(requested)
            || attribute
                .friendly_name
                .as_deref()
                .is_some_and(|friendly_name| friendly_name.eq_ignore_ascii_case(requested))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nameid::NameIdFormat;
    use std::time::Duration;

    #[test]
    fn identity_constructs_with_all_fields() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let id = Identity {
            name_id: NameId::email("alice@example.com"),
            session_index: Some("session-7".to_owned()),
            authn_instant: now,
            session_not_on_or_after: Some(now + Duration::from_hours(1)),
            authn_context_class_ref: Some(
                "urn:oasis:names:tc:SAML:2.0:ac:classes:Password".to_owned(),
            ),
            attributes: vec![Attribute::email("alice@example.com")],
            assertion_id: "_a1".to_owned(),
            not_on_or_after: now + Duration::from_mins(5),
            verifying_cert_fingerprint: [0u8; 32],
            is_one_time_use: false,
        };
        assert_eq!(id.assertion_id, "_a1");
        assert_eq!(id.attributes.len(), 1);
        assert_eq!(id.name_id.format, NameIdFormat::EmailAddress);
        assert!(!id.is_one_time_use);
    }

    #[test]
    fn identity_is_clone_and_debug() {
        let id = Identity {
            name_id: NameId::new("u", NameIdFormat::Transient),
            session_index: None,
            authn_instant: SystemTime::UNIX_EPOCH,
            session_not_on_or_after: None,
            authn_context_class_ref: None,
            attributes: vec![],
            assertion_id: "_x".to_owned(),
            not_on_or_after: SystemTime::UNIX_EPOCH,
            verifying_cert_fingerprint: [1u8; 32],
            is_one_time_use: true,
        };
        let cloned = id.clone();
        assert_eq!(cloned.assertion_id, id.assertion_id);
        assert_eq!(
            cloned.verifying_cert_fingerprint,
            id.verifying_cert_fingerprint
        );
        assert_eq!(cloned.is_one_time_use, id.is_one_time_use);
        // Debug compiles + emits something non-empty.
        let _s = format!("{cloned:?}");
    }

    #[test]
    fn conventional_identity_claims_are_resolved() {
        let mut id = Identity {
            name_id: NameId::new("opaque-subject", NameIdFormat::Persistent),
            session_index: None,
            authn_instant: SystemTime::UNIX_EPOCH,
            session_not_on_or_after: None,
            authn_context_class_ref: None,
            attributes: vec![
                Attribute {
                    name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
                        .to_owned(),
                    name_format: None,
                    friendly_name: None,
                    values: vec!["  alice@example.com  ".to_owned()],
                },
                Attribute::display_name("Alice Example"),
            ],
            assertion_id: "_claims".to_owned(),
            not_on_or_after: SystemTime::UNIX_EPOCH,
            verifying_cert_fingerprint: [0; 32],
            is_one_time_use: false,
        };

        assert_eq!(id.email(), Some("alice@example.com"));
        assert_eq!(id.display_name(), Some("Alice Example"));

        id.name_id = NameId::email("name-id@example.com");
        assert_eq!(id.email(), Some("name-id@example.com"));
        assert!(id.attribute(&["notemail"]).is_none());
    }

    #[test]
    fn opaque_name_id_containing_at_sign_is_not_an_email() {
        let id = Identity {
            name_id: NameId::new("opaque@tenant", NameIdFormat::Persistent),
            session_index: None,
            authn_instant: SystemTime::UNIX_EPOCH,
            session_not_on_or_after: None,
            authn_context_class_ref: None,
            attributes: vec![],
            assertion_id: "_opaque-name-id".to_owned(),
            not_on_or_after: SystemTime::UNIX_EPOCH,
            verifying_cert_fingerprint: [0; 32],
            is_one_time_use: false,
        };

        assert!(id.email().is_none());
    }

    #[test]
    fn deceptive_uri_suffix_does_not_match_conventional_claim() {
        let id = Identity {
            name_id: NameId::new("opaque-subject", NameIdFormat::Persistent),
            session_index: None,
            authn_instant: SystemTime::UNIX_EPOCH,
            session_not_on_or_after: None,
            authn_context_class_ref: None,
            attributes: vec![Attribute::single(
                "https://attacker.example/claims/email",
                "victim@example.com",
            )],
            assertion_id: "_deceptive-claim".to_owned(),
            not_on_or_after: SystemTime::UNIX_EPOCH,
            verifying_cert_fingerprint: [0; 32],
            is_one_time_use: false,
        };

        assert!(id.attribute(&["email"]).is_none());
        assert!(id.email().is_none());
    }

    #[test]
    fn malformed_email_claim_is_skipped() {
        let id = Identity {
            name_id: NameId::new("opaque-subject", NameIdFormat::Persistent),
            session_index: None,
            authn_instant: SystemTime::UNIX_EPOCH,
            session_not_on_or_after: None,
            authn_context_class_ref: None,
            attributes: vec![Attribute::single("mail", "not-an-email")],
            assertion_id: "_malformed-email".to_owned(),
            not_on_or_after: SystemTime::UNIX_EPOCH,
            verifying_cert_fingerprint: [0; 32],
            is_one_time_use: false,
        };

        assert!(id.email().is_none());
    }
}
