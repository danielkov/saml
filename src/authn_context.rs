//! `<saml:AuthnContext>` / `<samlp:RequestedAuthnContext>` types.
//!
//! Used both inbound (the AuthnStatement's actual class ref) and outbound
//! (a request-side hint that the SP requires a particular authentication
//! strength, e.g. MFA). Non-downgrade is enforced in response validation
//! (RFC-003 §4.1 step 17, RFC-005 §7); this module is just the type surface.

/// `<samlp:RequestedAuthnContext Comparison>` — how the IdP's actual
/// `AuthnContextClassRef` is compared against the requested set.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AuthnContextComparison {
    /// Default. Returned context must match one of the requested class refs
    /// exactly.
    Exact,
    /// Returned context must be at least as strong as the weakest requested.
    Minimum,
    /// Returned context must be no stronger than the strongest requested.
    Maximum,
    /// Returned context must be strictly stronger than every requested.
    Better,
}

/// Standard `<saml:AuthnContextClassRef>` URIs from
/// [SAML 2.0 Authentication Context]. Unrecognized URIs become `Custom`.
///
/// Note on `MultiFactorAuth`: SAML 2.0 does not define a single canonical
/// "MFA" class ref — the spec ships a catalogue of specific contexts. The
/// URI used here, `urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactorAuthentication`,
/// is what real-world IdPs (Okta, Azure AD, Auth0) advertise when they want
/// to signal a generic multi-factor result. Vendors emitting the more
/// specific `MobileTwoFactorContract`, `SecondFactorIGTKey`, etc., land in
/// `Custom`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AuthnContextClassRef {
    Password,
    PasswordProtectedTransport,
    TlsClient,
    Smartcard,
    SmartcardPki,
    Kerberos,
    PreviousSession,
    Unspecified,
    /// Generic multi-factor authentication. See type-level note above.
    MultiFactorAuth,
    TimeSyncToken,
    Custom(String),
}

impl AuthnContextClassRef {
    /// URI for this class ref.
    pub fn as_uri(&self) -> &str {
        match self {
            AuthnContextClassRef::Password => "urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
            AuthnContextClassRef::PasswordProtectedTransport => {
                "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
            }
            AuthnContextClassRef::TlsClient => "urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient",
            AuthnContextClassRef::Smartcard => "urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard",
            AuthnContextClassRef::SmartcardPki => {
                "urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI"
            }
            AuthnContextClassRef::Kerberos => "urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos",
            AuthnContextClassRef::PreviousSession => {
                "urn:oasis:names:tc:SAML:2.0:ac:classes:PreviousSession"
            }
            AuthnContextClassRef::Unspecified => {
                "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified"
            }
            AuthnContextClassRef::MultiFactorAuth => {
                "urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactorAuthentication"
            }
            AuthnContextClassRef::TimeSyncToken => {
                "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken"
            }
            AuthnContextClassRef::Custom(s) => s.as_str(),
        }
    }

    /// Parse a URI into the corresponding variant. Unrecognized URIs become
    /// `Custom`.
    pub fn from_uri(uri: &str) -> Self {
        match uri {
            "urn:oasis:names:tc:SAML:2.0:ac:classes:Password" => AuthnContextClassRef::Password,
            "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport" => {
                AuthnContextClassRef::PasswordProtectedTransport
            }
            "urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient" => AuthnContextClassRef::TlsClient,
            "urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard" => AuthnContextClassRef::Smartcard,
            "urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI" => {
                AuthnContextClassRef::SmartcardPki
            }
            "urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos" => AuthnContextClassRef::Kerberos,
            "urn:oasis:names:tc:SAML:2.0:ac:classes:PreviousSession" => {
                AuthnContextClassRef::PreviousSession
            }
            "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified" => {
                AuthnContextClassRef::Unspecified
            }
            "urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactorAuthentication" => {
                AuthnContextClassRef::MultiFactorAuth
            }
            "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken" => {
                AuthnContextClassRef::TimeSyncToken
            }
            other => AuthnContextClassRef::Custom(other.to_string()),
        }
    }
}

/// `<samlp:RequestedAuthnContext>` request hint, attached to an AuthnRequest
/// and re-attached to a `LoginTracker` so the response-side validator can
/// enforce non-downgrade.
///
/// SAML 2.0 also allows `<AuthnContextDeclRef>` in addition to
/// `<AuthnContextClassRef>`; declaration refs are out of scope for v0.1 per
/// RFC-001 §12.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RequestedAuthnContext {
    pub class_refs: Vec<AuthnContextClassRef>,
    pub comparison: AuthnContextComparison,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_known_class_refs() {
        for cr in [
            AuthnContextClassRef::Password,
            AuthnContextClassRef::PasswordProtectedTransport,
            AuthnContextClassRef::TlsClient,
            AuthnContextClassRef::Smartcard,
            AuthnContextClassRef::SmartcardPki,
            AuthnContextClassRef::Kerberos,
            AuthnContextClassRef::PreviousSession,
            AuthnContextClassRef::Unspecified,
            AuthnContextClassRef::MultiFactorAuth,
            AuthnContextClassRef::TimeSyncToken,
        ] {
            let uri = cr.as_uri().to_string();
            assert_eq!(AuthnContextClassRef::from_uri(&uri), cr);
        }
    }

    #[test]
    fn mfa_uri_is_well_known() {
        assert_eq!(
            AuthnContextClassRef::MultiFactorAuth.as_uri(),
            "urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactorAuthentication"
        );
    }

    #[test]
    fn unrecognized_uri_becomes_custom() {
        let uri = "urn:example:com:custom:strong-auth";
        let v = AuthnContextClassRef::from_uri(uri);
        assert_eq!(v, AuthnContextClassRef::Custom(uri.to_string()));
        assert_eq!(v.as_uri(), uri);
    }

    #[test]
    fn requested_authn_context_holds_multiple_class_refs() {
        let r = RequestedAuthnContext {
            class_refs: vec![
                AuthnContextClassRef::PasswordProtectedTransport,
                AuthnContextClassRef::MultiFactorAuth,
            ],
            comparison: AuthnContextComparison::Minimum,
        };
        assert_eq!(r.class_refs.len(), 2);
        assert_eq!(r.comparison, AuthnContextComparison::Minimum);
    }

    #[test]
    fn comparison_variants_distinct() {
        assert_ne!(AuthnContextComparison::Exact, AuthnContextComparison::Minimum);
        assert_ne!(AuthnContextComparison::Maximum, AuthnContextComparison::Better);
    }

    #[test]
    fn serde_round_trip_compiles() {
        fn assert_serde<T: serde::Serialize + serde::de::DeserializeOwned>() {}
        assert_serde::<AuthnContextClassRef>();
        assert_serde::<AuthnContextComparison>();
        assert_serde::<RequestedAuthnContext>();
    }
}
