//! SAML 2.0 `<saml:Attribute>` representation.
//!
//! Attributes are name/value pairs an IdP attaches to an Assertion. The
//! `NameFormat` field is a URI describing how `Name` is to be interpreted;
//! the three values defined by the spec are exported as the constants
//! [`NAME_FORMAT_UNSPECIFIED`], [`NAME_FORMAT_URI`], [`NAME_FORMAT_BASIC`].

/// `<saml:Attribute NameFormat>` value: opaque to the schema.
pub const NAME_FORMAT_UNSPECIFIED: &str =
    "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified";

/// `<saml:Attribute NameFormat>` value: `Name` is a URI.
pub const NAME_FORMAT_URI: &str = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";

/// `<saml:Attribute NameFormat>` value: `Name` follows the SAML 1.1 BASIC
/// profile (a short token, no embedded namespace).
pub const NAME_FORMAT_BASIC: &str = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic";

/// A parsed or to-be-emitted `<saml:Attribute>`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Attribute {
    pub name: String,
    /// `NameFormat` URI, e.g. [`NAME_FORMAT_BASIC`]. `None` means the wire
    /// element carried no `NameFormat` attribute.
    pub name_format: Option<String>,
    pub friendly_name: Option<String>,
    pub values: Vec<String>,
}

impl Attribute {
    /// Multi-valued attribute with no `FriendlyName` and no `NameFormat`.
    pub fn new(name: impl Into<String>, values: Vec<String>) -> Self {
        Self {
            name: name.into(),
            name_format: None,
            friendly_name: None,
            values,
        }
    }

    /// Single-valued convenience constructor.
    pub fn single(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self::new(name, vec![value.into()])
    }

    /// `mail` (RFC 4519 / `urn:oid:0.9.2342.19200300.100.1.3`) attribute.
    pub fn email(value: impl Into<String>) -> Self {
        Self {
            name: "urn:oid:0.9.2342.19200300.100.1.3".to_string(),
            name_format: Some(NAME_FORMAT_URI.to_string()),
            friendly_name: Some("mail".to_string()),
            values: vec![value.into()],
        }
    }

    /// `displayName` (`urn:oid:2.16.840.1.113730.3.1.241`) attribute.
    pub fn display_name(value: impl Into<String>) -> Self {
        Self {
            name: "urn:oid:2.16.840.1.113730.3.1.241".to_string(),
            name_format: Some(NAME_FORMAT_URI.to_string()),
            friendly_name: Some("displayName".to_string()),
            values: vec![value.into()],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_carries_values() {
        let a = Attribute::new("groups", vec!["admins".into(), "engineering".into()]);
        assert_eq!(a.name, "groups");
        assert_eq!(a.values.len(), 2);
        assert!(a.name_format.is_none());
        assert!(a.friendly_name.is_none());
    }

    #[test]
    fn single_wraps_one_value() {
        let a = Attribute::single("dept", "platform");
        assert_eq!(a.values, vec!["platform".to_string()]);
    }

    #[test]
    fn email_constructor_uses_canonical_oid() {
        let a = Attribute::email("alice@example.com");
        assert_eq!(a.name, "urn:oid:0.9.2342.19200300.100.1.3");
        assert_eq!(a.name_format.as_deref(), Some(NAME_FORMAT_URI));
        assert_eq!(a.friendly_name.as_deref(), Some("mail"));
        assert_eq!(a.values, vec!["alice@example.com".to_string()]);
    }

    #[test]
    fn display_name_constructor_uses_canonical_oid() {
        let a = Attribute::display_name("Alice Anderson");
        assert_eq!(a.name, "urn:oid:2.16.840.1.113730.3.1.241");
        assert_eq!(a.friendly_name.as_deref(), Some("displayName"));
        assert_eq!(a.values, vec!["Alice Anderson".to_string()]);
    }

    #[test]
    fn name_format_constants_match_spec() {
        assert_eq!(
            NAME_FORMAT_UNSPECIFIED,
            "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"
        );
        assert_eq!(
            NAME_FORMAT_URI,
            "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
        );
        assert_eq!(
            NAME_FORMAT_BASIC,
            "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
        );
    }

    #[test]
    fn serde_round_trip_compiles() {
        fn assert_serde<T: serde::Serialize + serde::de::DeserializeOwned>() {}
        assert_serde::<Attribute>();
    }
}
