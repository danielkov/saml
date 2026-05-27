//! The final identity payload extracted from a verified SAML assertion.
//!
//! See `docs/rfcs/RFC-003-service-provider.md` §4.

use std::time::SystemTime;

use crate::attribute::Attribute;
use crate::nameid::NameId;

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
            session_not_on_or_after: Some(now + Duration::from_secs(3600)),
            authn_context_class_ref: Some(
                "urn:oasis:names:tc:SAML:2.0:ac:classes:Password".to_owned(),
            ),
            attributes: vec![Attribute::email("alice@example.com")],
            assertion_id: "_a1".to_owned(),
            not_on_or_after: now + Duration::from_secs(300),
            verifying_cert_fingerprint: [0u8; 32],
        };
        assert_eq!(id.assertion_id, "_a1");
        assert_eq!(id.attributes.len(), 1);
        assert_eq!(id.name_id.format, NameIdFormat::EmailAddress);
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
        };
        let cloned = id.clone();
        assert_eq!(cloned.assertion_id, id.assertion_id);
        assert_eq!(cloned.verifying_cert_fingerprint, id.verifying_cert_fingerprint);
        // Debug compiles + emits something non-empty.
        let _s = format!("{cloned:?}");
    }
}
