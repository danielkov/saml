//! SAML 2.0 metadata parse + emit.
//!
//! See `docs/rfcs/RFC-006-metadata.md`.

pub mod emit_idp;
pub mod emit_sp;
pub mod parse;

// ── Extended metadata fields (RFC-006 §6.3) ──────────────────────────────

/// Optional `<md:Organization>` + `<md:ContactPerson>` payload, accepted by
/// the SP / IdP metadata-emit paths via their `metadata_xml_with_extras`
/// methods (Wave 6) and by the standalone `emit_*_metadata` functions in
/// `metadata::emit_sp` / `metadata::emit_idp`.
///
/// Both fields are optional / may be empty — passing the default value is
/// equivalent to emitting no extras at all.
#[derive(Debug, Clone, Default)]
pub struct MetadataExtras {
    pub organization: Option<MetadataOrganization>,
    pub contacts: Vec<MetadataContact>,
}

/// `<md:Organization>` payload. Per the SAML 2.0 metadata schema each of the
/// three nested elements (`<md:OrganizationName>`, `<md:OrganizationDisplayName>`,
/// `<md:OrganizationURL>`) carries an `xml:lang` attribute identifying the
/// language of the human-readable text. RFC 5646 (BCP 47) language tags such
/// as `"en"` or `"en-US"` are the conventional values.
#[derive(Debug, Clone)]
pub struct MetadataOrganization {
    pub name: String,
    pub display_name: String,
    pub url: String,
    /// RFC 5646 language tag (e.g. `"en"`, `"en-US"`).
    pub language: String,
}

/// `<md:ContactPerson>/@contactType` discriminant per the SAML 2.0 metadata
/// schema (`technical`, `support`, `administrative`, `billing`, `other`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataContactType {
    Technical,
    Support,
    Administrative,
    Billing,
    Other,
}

impl MetadataContactType {
    /// Lower-case wire string used as the value of the `contactType` attribute.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Technical => "technical",
            Self::Support => "support",
            Self::Administrative => "administrative",
            Self::Billing => "billing",
            Self::Other => "other",
        }
    }
}

/// `<md:ContactPerson>` payload. Each contained list emits one child element
/// per entry (`<md:EmailAddress>` / `<md:TelephoneNumber>`).
#[derive(Debug, Clone)]
pub struct MetadataContact {
    pub contact_type: MetadataContactType,
    pub given_name: Option<String>,
    pub surname: Option<String>,
    pub email_addresses: Vec<String>,
    pub telephone_numbers: Vec<String>,
    pub company: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contact_type_as_str_matches_schema_tokens() {
        assert_eq!(MetadataContactType::Technical.as_str(), "technical");
        assert_eq!(MetadataContactType::Support.as_str(), "support");
        assert_eq!(
            MetadataContactType::Administrative.as_str(),
            "administrative"
        );
        assert_eq!(MetadataContactType::Billing.as_str(), "billing");
        assert_eq!(MetadataContactType::Other.as_str(), "other");
    }

    #[test]
    fn extras_default_is_empty() {
        let e = MetadataExtras::default();
        assert!(e.organization.is_none());
        assert!(e.contacts.is_empty());
    }
}
