//! The final identity payload extracted from a verified SAML assertion.
//!
//! See `docs/rfcs/RFC-003-service-provider.md` §4.

use std::time::SystemTime;

use crate::attribute::Attribute;
use crate::nameid::NameId;

/// What the SP gets back from `consume_response` after all signature, audience,
/// subject-confirmation, and time-window checks pass. The caller dedupes on
/// [`assertion_id`](Self::assertion_id) for replay defense and uses
/// [`name_id`](Self::name_id) + [`session_index`](Self::session_index) to
/// construct an application session.
///
/// # Read-only by construction
///
/// Every field is private and exposed through an accessor. This is not
/// ceremony: [`Proxy::relay_to_downstream`](crate::Proxy::relay_to_downstream)
/// mints signed assertions from an `Identity`, so a mutable one is a signing
/// oracle. A caller could otherwise authenticate as themselves once, rewrite
/// the subject, attributes, authentication context or timestamps on the
/// resulting value, and have the proxy sign the rewritten claims — the
/// private witness would still hold, because it attests that *some* payload
/// was validated, not that these values are that payload.
///
/// Mutation does not compile:
///
/// ```compile_fail
/// # use saml::Identity;
/// fn escalate(identity: &mut Identity) {
///     identity.name_id = saml::NameId::email("admin@example.com");
/// }
/// ```
///
/// Neither does rewriting the attributes:
///
/// ```compile_fail
/// # use saml::Identity;
/// fn grant(identity: &mut Identity) {
///     identity.attributes = vec![saml::Attribute::single("role", "admin")];
/// }
/// ```
///
/// Nor is one constructible from whole cloth:
///
/// ```compile_fail
/// # use saml::Identity;
/// let forged = Identity {
///     name_id: saml::NameId::email("admin@example.com"),
///     session_index: None,
///     authn_instant: std::time::SystemTime::UNIX_EPOCH,
///     session_not_on_or_after: None,
///     subject_confirmation_not_on_or_after: std::time::SystemTime::UNIX_EPOCH,
///     authn_context_class_ref: None,
///     attributes: vec![],
///     assertion_id: "_forged".to_owned(),
///     not_on_or_after: std::time::SystemTime::UNIX_EPOCH,
///     verifying_cert_fingerprint: [0u8; 32],
///     is_one_time_use: false,
/// };
/// ```
#[derive(Debug, Clone)]
pub struct Identity {
    pub(crate) name_id: NameId,
    pub(crate) session_index: Option<String>,
    pub(crate) authn_instant: SystemTime,
    pub(crate) session_not_on_or_after: Option<SystemTime>,
    /// Expiry of the specific SubjectConfirmation that authorized this
    /// presentation. May be earlier than Conditions or session expiry.
    pub(crate) subject_confirmation_not_on_or_after: SystemTime,
    pub(crate) authn_context_class_ref: Option<String>,
    pub(crate) attributes: Vec<Attribute>,
    /// For replay defense, retain this ID until `not_on_or_after` plus the
    /// clock skew used for response validation. If the time calculation
    /// fails, reject the assertion.
    pub(crate) assertion_id: String,
    pub(crate) not_on_or_after: SystemTime,
    /// Cert that verified the assertion signature. For key-rotation logging.
    pub(crate) verifying_cert_fingerprint: [u8; 32],
    /// `<saml:OneTimeUse>` was present in `<saml:Conditions>` (SAML 2.0 Core
    /// §2.5.1.5). When `true` the relying party MUST consume the assertion
    /// only once — i.e. it MUST refuse a second presentation of the same
    /// assertion regardless of `not_on_or_after`.
    /// [`ServiceProvider::consume_response`](crate::ServiceProvider::consume_response)
    /// enforces this through the supplied replay cache and fails closed when
    /// none is enabled, returning
    /// `OneTimeUseUnenforceable`. Note that single-use is *stricter* than
    /// ordinary expiry-bounded replay defense: even within the validity window
    /// the assertion is good for exactly one consumption.
    pub(crate) is_one_time_use: bool,
    /// Witness that this value came out of the SP response validator.
    ///
    /// Private, so `Identity` cannot be constructed outside this crate. It is
    /// the evidence that a signed, audience-checked, time-window-checked
    /// assertion was actually seen — and downstream consumers, notably
    /// [`Proxy::relay_to_downstream`](crate::Proxy::relay_to_downstream),
    /// mint signed assertions from it. Were it forgeable, a caller could
    /// hand the proxy an arbitrary subject and get a signed assertion for
    /// them without any upstream authentication having occurred.
    #[expect(
        dead_code,
        reason = "never read: its purpose is to deny struct-literal construction \
                  outside this crate, so an Identity can only come from response \
                  validation. Reading it would prove nothing a type already does."
    )]
    validated: ValidatedUpstream,
}

/// Zero-sized proof that an [`Identity`] came from response validation.
#[derive(Debug, Clone)]
struct ValidatedUpstream;

impl Identity {
    /// Construct an `Identity`. Crate-internal: only the response validator
    /// may vouch for one.
    #[expect(
        clippy::too_many_arguments,
        reason = "mirrors the field list one-for-one; grouping them into a                   builder would add a second way to assemble an Identity,                   which is what the private witness exists to prevent"
    )]
    pub(crate) fn new(
        name_id: NameId,
        session_index: Option<String>,
        authn_instant: SystemTime,
        session_not_on_or_after: Option<SystemTime>,
        subject_confirmation_not_on_or_after: SystemTime,
        authn_context_class_ref: Option<String>,
        attributes: Vec<Attribute>,
        assertion_id: String,
        not_on_or_after: SystemTime,
        verifying_cert_fingerprint: [u8; 32],
        is_one_time_use: bool,
    ) -> Self {
        Self {
            name_id,
            session_index,
            authn_instant,
            session_not_on_or_after,
            subject_confirmation_not_on_or_after,
            authn_context_class_ref,
            attributes,
            assertion_id,
            not_on_or_after,
            verifying_cert_fingerprint,
            is_one_time_use,
            validated: ValidatedUpstream,
        }
    }

    /// Subject of the validated assertion.
    #[must_use]
    pub fn name_id(&self) -> &NameId {
        &self.name_id
    }

    /// `<saml:AuthnStatement>/@SessionIndex`, when present.
    #[must_use]
    pub fn session_index(&self) -> Option<&str> {
        self.session_index.as_deref()
    }

    /// When the subject authenticated at the asserting party.
    #[must_use]
    pub fn authn_instant(&self) -> SystemTime {
        self.authn_instant
    }

    /// `<saml:AuthnStatement>/@SessionNotOnOrAfter`, when present.
    #[must_use]
    pub fn session_not_on_or_after(&self) -> Option<SystemTime> {
        self.session_not_on_or_after
    }

    /// Expiry of the bearer/Holder-of-Key confirmation actually selected by
    /// validation.
    #[must_use]
    pub fn subject_confirmation_not_on_or_after(&self) -> SystemTime {
        self.subject_confirmation_not_on_or_after
    }

    /// The authentication context class the asserting party reported.
    #[must_use]
    pub fn authn_context_class_ref(&self) -> Option<&str> {
        self.authn_context_class_ref.as_deref()
    }

    /// Attributes carried by the assertion.
    #[must_use]
    pub fn attributes(&self) -> &[Attribute] {
        &self.attributes
    }

    /// `<saml:Assertion>/@ID` — dedupe on this for replay defense.
    #[must_use]
    pub fn assertion_id(&self) -> &str {
        &self.assertion_id
    }

    /// Upper bound of the assertion's validity window.
    #[must_use]
    pub fn not_on_or_after(&self) -> SystemTime {
        self.not_on_or_after
    }

    /// SHA-256 fingerprint of the certificate that verified the signature.
    #[must_use]
    pub fn verifying_cert_fingerprint(&self) -> [u8; 32] {
        self.verifying_cert_fingerprint
    }

    /// Whether `<saml:OneTimeUse>` was present. See the field documentation
    /// for the caller's obligation.
    #[must_use]
    pub fn is_one_time_use(&self) -> bool {
        self.is_one_time_use
    }
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
            subject_confirmation_not_on_or_after: now + Duration::from_mins(5),
            authn_context_class_ref: Some(
                "urn:oasis:names:tc:SAML:2.0:ac:classes:Password".to_owned(),
            ),
            attributes: vec![Attribute::email("alice@example.com")],
            assertion_id: "_a1".to_owned(),
            not_on_or_after: now + Duration::from_mins(5),
            verifying_cert_fingerprint: [0u8; 32],
            is_one_time_use: false,
            validated: ValidatedUpstream,
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
            subject_confirmation_not_on_or_after: SystemTime::UNIX_EPOCH,
            authn_context_class_ref: None,
            attributes: vec![],
            assertion_id: "_x".to_owned(),
            not_on_or_after: SystemTime::UNIX_EPOCH,
            verifying_cert_fingerprint: [1u8; 32],
            is_one_time_use: true,
            validated: ValidatedUpstream,
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
}
