//! SAML 2.0 `<saml:NameID>` representation.
//!
//! `NameIdFormat` enumerates the standard URI formats from
//! [saml-core-2.0-os] §8.3 and falls back to `Custom(String)` for the long
//! tail of non-standard formats some IdPs emit.

/// Standard `<saml:NameID>` Format URIs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum NameIdFormat {
    Unspecified,
    EmailAddress,
    X509SubjectName,
    WindowsDomainQualifiedName,
    Kerberos,
    Entity,
    Persistent,
    Transient,
    Custom(String),
}

impl NameIdFormat {
    /// URI string for this format, per saml-core-2.0-os §8.3.
    pub fn as_uri(&self) -> &str {
        match self {
            NameIdFormat::Unspecified => "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
            NameIdFormat::EmailAddress => "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            NameIdFormat::X509SubjectName => {
                "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName"
            }
            NameIdFormat::WindowsDomainQualifiedName => {
                "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName"
            }
            NameIdFormat::Kerberos => "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos",
            NameIdFormat::Entity => "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
            NameIdFormat::Persistent => "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
            NameIdFormat::Transient => "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
            NameIdFormat::Custom(s) => s.as_str(),
        }
    }

    /// Parse a URI into the corresponding variant. Unrecognized URIs become
    /// `Custom`. Never fails; SAML deployments routinely invent formats.
    pub fn from_uri(uri: &str) -> Self {
        match uri {
            "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" => NameIdFormat::Unspecified,
            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" => NameIdFormat::EmailAddress,
            "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName" => {
                NameIdFormat::X509SubjectName
            }
            "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName" => {
                NameIdFormat::WindowsDomainQualifiedName
            }
            "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos" => NameIdFormat::Kerberos,
            "urn:oasis:names:tc:SAML:2.0:nameid-format:entity" => NameIdFormat::Entity,
            "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" => NameIdFormat::Persistent,
            "urn:oasis:names:tc:SAML:2.0:nameid-format:transient" => NameIdFormat::Transient,
            other => NameIdFormat::Custom(other.to_string()),
        }
    }
}

/// `<saml:NameID>` element value plus its qualifying attributes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NameId {
    pub value: String,
    pub format: NameIdFormat,
    pub name_qualifier: Option<String>,
    pub sp_name_qualifier: Option<String>,
    pub sp_provided_id: Option<String>,
}

impl NameId {
    /// Bare constructor — value + format, no qualifiers.
    pub fn new(value: impl Into<String>, format: NameIdFormat) -> Self {
        Self {
            value: value.into(),
            format,
            name_qualifier: None,
            sp_name_qualifier: None,
            sp_provided_id: None,
        }
    }

    /// `EmailAddress`-format NameID. Caller is responsible for the value being
    /// a syntactically valid email.
    pub fn email(value: impl Into<String>) -> Self {
        Self::new(value, NameIdFormat::EmailAddress)
    }

    /// `Persistent`-format NameID scoped to the given SP entity ID. Setting
    /// `SPNameQualifier` is the SAML mechanism that prevents downstream SPs
    /// from correlating users across audiences. RFC-004 §3.1 calls this out
    /// as a required privacy property for persistent IDs.
    pub fn persistent_for_sp(
        value: impl Into<String>,
        sp_entity_id: impl Into<String>,
    ) -> Self {
        Self {
            value: value.into(),
            format: NameIdFormat::Persistent,
            name_qualifier: None,
            sp_name_qualifier: Some(sp_entity_id.into()),
            sp_provided_id: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_known_formats() {
        for fmt in [
            NameIdFormat::Unspecified,
            NameIdFormat::EmailAddress,
            NameIdFormat::X509SubjectName,
            NameIdFormat::WindowsDomainQualifiedName,
            NameIdFormat::Kerberos,
            NameIdFormat::Entity,
            NameIdFormat::Persistent,
            NameIdFormat::Transient,
        ] {
            let uri = fmt.as_uri().to_string();
            let parsed = NameIdFormat::from_uri(&uri);
            assert_eq!(parsed, fmt, "round-trip failed for {uri}");
        }
    }

    #[test]
    fn unrecognized_uri_becomes_custom() {
        let custom = "urn:example:com:custom:nameid";
        let v = NameIdFormat::from_uri(custom);
        assert_eq!(v, NameIdFormat::Custom(custom.into()));
        assert_eq!(v.as_uri(), custom);
    }

    #[test]
    fn email_constructor() {
        let n = NameId::email("alice@example.com");
        assert_eq!(n.format, NameIdFormat::EmailAddress);
        assert_eq!(n.value, "alice@example.com");
        assert!(n.sp_name_qualifier.is_none());
    }

    #[test]
    fn persistent_for_sp_sets_sp_qualifier() {
        let n = NameId::persistent_for_sp("opaque-user-id", "https://sp.example.com");
        assert_eq!(n.format, NameIdFormat::Persistent);
        assert_eq!(n.sp_name_qualifier.as_deref(), Some("https://sp.example.com"));
        assert!(n.name_qualifier.is_none());
    }

    #[test]
    fn new_leaves_qualifiers_unset() {
        let n = NameId::new("xyz", NameIdFormat::Transient);
        assert!(n.name_qualifier.is_none());
        assert!(n.sp_name_qualifier.is_none());
        assert!(n.sp_provided_id.is_none());
    }

    #[test]
    fn serde_round_trip_compiles() {
        // The library does not promise a specific serde format, but the
        // derives must compile so callers can persist a `LoginTracker` that
        // carries a `NameIdFormat`. This test pins that contract.
        fn assert_serde<T: serde::Serialize + serde::de::DeserializeOwned>() {}
        assert_serde::<NameIdFormat>();
        assert_serde::<NameId>();
    }
}
