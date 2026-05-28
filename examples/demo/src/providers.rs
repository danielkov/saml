//! Static per-IdP configuration loaded from `config/providers.toml`.
//!
//! Each `[[provider]]` block describes one IdP we know how to drive through
//! the standard Web Browser SSO profile. The set of attribute lookup keys is
//! the only thing that varies by vendor; everything else (signing, the ACS
//! path, the SP entityID) is shared across the seven hosted/local IdPs in
//! this demo.

use std::collections::BTreeMap;

use saml::NameIdFormat;
use serde::Deserialize;

/// Wire layout for `providers.toml`. Wraps a flat list of `[[provider]]`
/// tables so callers can deserialize the whole file in one go.
#[derive(Debug, Clone, Deserialize)]
pub struct ProvidersFile {
    #[serde(default)]
    pub provider: Vec<ProviderConfig>,
}

/// Typed configuration for one IdP entry.
///
/// `id` is the slug used in URLs (`/login/<id>`) and as the `RelayState`
/// value, and must be unique. `metadata_url` is fetched at startup. The
/// `attribute_keys` block lists, per logical field (email/displayName/etc.),
/// the ordered list of attribute names to try when rendering the dashboard;
/// the first hit wins, so put the most-specific vendor URI first and the
/// generic short name last.
#[derive(Debug, Clone, Deserialize)]
pub struct ProviderConfig {
    pub id: String,
    pub label: String,
    pub metadata_url: String,
    /// Hex accent color used in the brand mark + the login card border.
    pub accent_color: String,
    /// Single character or short glyph rendered inside the brand mark on
    /// the provider card (e.g. `K` for Keycloak, `Z` for Zitadel).
    pub brand_initial: String,
    /// Which NameID format to request on the AuthnRequest. Mirrors what the
    /// IdP's IDPSSODescriptor advertises so we don't ask for a shape it
    /// won't return.
    #[serde(default, deserialize_with = "deserialize_name_id_format")]
    pub requested_name_id_format: Option<NameIdFormat>,
    /// If true, the demo will treat a NameID format of `emailAddress` as a
    /// valid fallback for the email field on the dashboard. Asgardeo uses
    /// `emailAddress` but populates the Subject with a `userid` opaque
    /// string rather than an email, so we leave it off there.
    #[serde(default = "default_use_name_id_as_email_fallback")]
    pub use_name_id_as_email_fallback: bool,
    #[serde(default)]
    pub attribute_keys: AttributeKeys,
    /// Optional list of human-readable notes shown on the provider card.
    /// Currently unused at runtime; the field is here so the README and
    /// providers.toml stay in sync.
    #[serde(default)]
    #[allow(
        dead_code,
        reason = "Reserved for future use; serde tolerates the field on disk"
    )]
    pub notes: Vec<String>,
}

/// Ordered attribute-name lookup tables for the dashboard. All fields are
/// case-sensitive and exact-matched against `Attribute::name` (and falling
/// back to `friendly_name`) on the verified `Identity`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AttributeKeys {
    #[serde(default)]
    pub email: Vec<String>,
    #[serde(default)]
    pub display_name: Vec<String>,
    #[serde(default)]
    pub given_name: Vec<String>,
    #[serde(default)]
    pub surname: Vec<String>,
    #[serde(default)]
    pub department: Vec<String>,
}

fn default_use_name_id_as_email_fallback() -> bool {
    true
}

fn deserialize_name_id_format<'de, D>(d: D) -> Result<Option<NameIdFormat>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw: Option<String> = Option::deserialize(d)?;
    match raw.as_deref() {
        None | Some("") => Ok(None),
        Some("EmailAddress") => Ok(Some(NameIdFormat::EmailAddress)),
        Some("Persistent") => Ok(Some(NameIdFormat::Persistent)),
        Some("Transient") => Ok(Some(NameIdFormat::Transient)),
        Some("Unspecified") => Ok(Some(NameIdFormat::Unspecified)),
        Some(other) => Err(serde::de::Error::custom(format!(
            "unknown requested_name_id_format `{other}` (expected EmailAddress | Persistent | Transient | Unspecified)"
        ))),
    }
}

impl ProvidersFile {
    /// Parse a TOML buffer. Surfaces serde errors directly so the operator
    /// can see exactly which `[[provider]]` block failed to validate.
    pub fn from_toml(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }

    /// Allow operator overrides through environment variables of the form
    /// `SAML_DEMO_PROVIDER_<UPPER_ID>_METADATA_URL`. Useful for pointing the
    /// demo at a local Keycloak (or a private Zitadel) without editing the
    /// committed providers.toml.
    pub fn apply_env_overrides(&mut self) {
        for p in &mut self.provider {
            let key = format!(
                "SAML_DEMO_PROVIDER_{}_METADATA_URL",
                p.id.to_uppercase().replace('-', "_")
            );
            if let Ok(v) = std::env::var(&key)
                && !v.is_empty()
            {
                tracing::info!(provider = %p.id, env = %key, "overriding metadata_url via env");
                p.metadata_url = v;
            }
        }
    }
}

/// Indexed view of provider configs, keyed by `id`. Cheap to clone (each
/// entry is a `ProviderConfig` clone) and lets the ACS handler resolve a
/// provider in O(1) from the RelayState slug.
#[derive(Debug, Clone, Default)]
pub struct ProviderIndex {
    pub by_id: BTreeMap<String, ProviderConfig>,
}

impl ProviderIndex {
    pub fn build(file: &ProvidersFile) -> Result<Self, String> {
        let mut by_id: BTreeMap<String, ProviderConfig> = BTreeMap::new();
        for p in &file.provider {
            if by_id.insert(p.id.clone(), p.clone()).is_some() {
                return Err(format!("duplicate provider id `{}` in providers.toml", p.id));
            }
        }
        Ok(Self { by_id })
    }

    pub fn get(&self, id: &str) -> Option<&ProviderConfig> {
        self.by_id.get(id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &ProviderConfig> {
        self.by_id.values()
    }

    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_two_provider_blocks() {
        let toml_src = r##"
[[provider]]
id = "keycloak"
label = "Keycloak"
metadata_url = "http://localhost:8080/realms/saml-demo/protocol/saml/descriptor"
accent_color = "#cd0000"
brand_initial = "K"
requested_name_id_format = "EmailAddress"
attribute_keys.email = ["mail"]
attribute_keys.display_name = ["displayName"]

[[provider]]
id = "zitadel"
label = "Zitadel"
metadata_url = "https://saml-demo.us1.zitadel.cloud/saml/v2/metadata"
accent_color = "#5469d4"
brand_initial = "Z"
requested_name_id_format = "Persistent"
use_name_id_as_email_fallback = false
attribute_keys.email = ["Email", "mail"]
attribute_keys.display_name = ["FullName", "displayName"]
"##;
        let file = ProvidersFile::from_toml(toml_src).expect("parses");
        assert_eq!(file.provider.len(), 2);
        let idx = ProviderIndex::build(&file).expect("indexes");
        let z = idx.get("zitadel").expect("zitadel present");
        assert_eq!(z.requested_name_id_format, Some(NameIdFormat::Persistent));
        assert!(!z.use_name_id_as_email_fallback);
        assert_eq!(z.attribute_keys.email, vec!["Email", "mail"]);
    }

    #[test]
    fn duplicate_id_rejected() {
        let toml_src = r##"
[[provider]]
id = "dup"
label = "A"
metadata_url = "http://a"
accent_color = "#000"
brand_initial = "A"

[[provider]]
id = "dup"
label = "B"
metadata_url = "http://b"
accent_color = "#000"
brand_initial = "B"
"##;
        let file = ProvidersFile::from_toml(toml_src).expect("parses");
        let err = ProviderIndex::build(&file).expect_err("duplicate id should reject");
        assert!(err.contains("duplicate provider id"), "{err}");
    }

    #[test]
    fn unknown_name_id_format_errors() {
        let toml_src = r##"
[[provider]]
id = "x"
label = "X"
metadata_url = "http://x"
accent_color = "#000"
brand_initial = "X"
requested_name_id_format = "MoonBase"
"##;
        let err = ProvidersFile::from_toml(toml_src).expect_err("rejects bad format");
        assert!(err.to_string().contains("MoonBase"), "{err}");
    }
}
