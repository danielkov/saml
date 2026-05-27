//! `<md:EntityDescriptor>` and `<md:EntitiesDescriptor>` parsing, plus the
//! atomic verify-then-parse helpers per RFC-006 §3 and §5.
//!
//! Shared low-level helpers (`parse_endpoint`, `parse_key_descriptors`,
//! `parse_optional_duration`, etc.) live here as `pub(crate)` items because
//! both `descriptor::idp` and `descriptor::sp` consume them. Centralizing the
//! XML walks means the `<md:KeyDescriptor>` cert-use partitioning rule
//! (RFC-006 §4) and the xs:duration grammar live in exactly one place.

use std::time::{Duration, SystemTime};

use crate::crypto::cert::X509Certificate;
use crate::descriptor::idp::IdpDescriptor;
use crate::descriptor::sp::SpDescriptor;
use crate::dsig::algorithms::SignatureAlgorithm;
use crate::dsig::verify::verify_signature;
use crate::error::Error;
use crate::nameid::NameIdFormat;
use crate::time::parse_xs_datetime;
use crate::xml::parse::{Document, Element, Node};

// =============================================================================
// Namespace constants
// =============================================================================

pub(crate) const MD_NS: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
pub(crate) const DS_NS: &str = "http://www.w3.org/2000/09/xmldsig#";

// =============================================================================
// Federation aggregate type
// =============================================================================

/// Parsed `<md:EntitiesDescriptor>` (or a single `<md:EntityDescriptor>`
/// promoted to an aggregate with one entry, for caller convenience).
pub struct EntitiesDescriptor {
    pub name: Option<String>,
    pub valid_until: Option<SystemTime>,
    pub entities: Vec<MetadataEntry>,
}

/// One entry in a federation aggregate.
pub enum MetadataEntry {
    Idp(IdpDescriptor),
    Sp(SpDescriptor),
    /// Some entities advertise both roles (Shibboleth proxies, for example).
    Dual(IdpDescriptor, SpDescriptor),
    /// AuthnAuthority, AttributeAuthority, PDP, etc. — out of scope for v0.1.
    Other,
}

impl EntitiesDescriptor {
    /// Parse a federation aggregate or a single-entity metadata document.
    pub fn from_metadata_xml(xml: &[u8]) -> Result<Self, Error> {
        let doc = Document::parse(xml)?;
        Self::from_root_element(doc.root())
    }

    fn from_root_element(root: &Element) -> Result<Self, Error> {
        if !is_md_element(root, "EntitiesDescriptor") {
            // Promote a single EntityDescriptor into a one-entry aggregate.
            if is_md_element(root, "EntityDescriptor") {
                let entry = parse_entity_descriptor(root)?;
                return Ok(Self {
                    name: None,
                    valid_until: parse_optional_xs_datetime(root, "validUntil")?,
                    entities: vec![entry],
                });
            }
            return Err(Error::InvalidConfiguration {
                reason: "root is not <md:EntityDescriptor> or <md:EntitiesDescriptor>",
            });
        }

        let name = root.attribute(None, "Name").map(str::to_owned);
        let valid_until = parse_optional_xs_datetime(root, "validUntil")?;

        let mut entities = Vec::new();
        collect_entities(root, &mut entities)?;

        Ok(Self {
            name,
            valid_until,
            entities,
        })
    }

    /// Find an IdP entity by entity ID.
    pub fn find_idp(&self, entity_id: &str) -> Option<&IdpDescriptor> {
        for entry in &self.entities {
            match entry {
                MetadataEntry::Idp(idp) if idp.entity_id == entity_id => return Some(idp),
                MetadataEntry::Dual(idp, _) if idp.entity_id == entity_id => return Some(idp),
                _ => {}
            }
        }
        None
    }

    /// Find an SP entity by entity ID.
    pub fn find_sp(&self, entity_id: &str) -> Option<&SpDescriptor> {
        for entry in &self.entities {
            match entry {
                MetadataEntry::Sp(sp) if sp.entity_id == entity_id => return Some(sp),
                MetadataEntry::Dual(_, sp) if sp.entity_id == entity_id => return Some(sp),
                _ => {}
            }
        }
        None
    }

    /// Iterate over all IdP descriptors (including the IdP half of Dual entries).
    pub fn iter_idps(&self) -> impl Iterator<Item = &IdpDescriptor> {
        self.entities.iter().filter_map(|e| match e {
            MetadataEntry::Idp(idp) => Some(idp),
            MetadataEntry::Dual(idp, _) => Some(idp),
            _ => None,
        })
    }

    /// Iterate over all SP descriptors (including the SP half of Dual entries).
    pub fn iter_sps(&self) -> impl Iterator<Item = &SpDescriptor> {
        self.entities.iter().filter_map(|e| match e {
            MetadataEntry::Sp(sp) => Some(sp),
            MetadataEntry::Dual(_, sp) => Some(sp),
            _ => None,
        })
    }
}

/// Recursively flatten nested `<md:EntitiesDescriptor>` blocks (RFC-006 §3).
fn collect_entities(
    entities_descriptor: &Element,
    out: &mut Vec<MetadataEntry>,
) -> Result<(), Error> {
    for child in entities_descriptor.children() {
        let Node::Element(elem) = child else { continue };
        if is_md_element(elem, "EntityDescriptor") {
            out.push(parse_entity_descriptor(elem)?);
        } else if is_md_element(elem, "EntitiesDescriptor") {
            collect_entities(elem, out)?;
        }
        // Other md:* extensions (RoleDescriptor, etc.) are ignored.
    }
    Ok(())
}

fn parse_entity_descriptor(entity: &Element) -> Result<MetadataEntry, Error> {
    let has_idp = entity.child_element(Some(MD_NS), "IDPSSODescriptor").is_some();
    let has_sp = entity.child_element(Some(MD_NS), "SPSSODescriptor").is_some();

    match (has_idp, has_sp) {
        (true, true) => {
            let idp = IdpDescriptor::from_entity_descriptor_element(entity)?;
            let sp = SpDescriptor::from_entity_descriptor_element(entity)?;
            Ok(MetadataEntry::Dual(idp, sp))
        }
        (true, false) => Ok(MetadataEntry::Idp(
            IdpDescriptor::from_entity_descriptor_element(entity)?,
        )),
        (false, true) => Ok(MetadataEntry::Sp(
            SpDescriptor::from_entity_descriptor_element(entity)?,
        )),
        (false, false) => Ok(MetadataEntry::Other),
    }
}

// =============================================================================
// Metadata signature verification & verify-then-parse helpers
// =============================================================================

/// Inputs for `verify_metadata_signature`. Bundled into a struct so callers
/// don't accidentally swap the cert / XML arguments.
pub struct VerifyMetadata<'a> {
    pub metadata_xml: &'a [u8],
    pub trusted_signing_cert: &'a X509Certificate,
}

/// Verify the enveloped XML-DSig on a metadata document.
///
/// The signed element MUST be the document root (the top-level
/// `<md:EntityDescriptor>` or `<md:EntitiesDescriptor>`). Any other arrangement
/// — for example, a signature whose `Reference URI` points at a descendant
/// while the attacker wraps the document in an outer envelope — is rejected
/// here. This is the structural XSW defense documented in RFC-002 §3.2 applied
/// at the metadata layer.
pub fn verify_metadata_signature(input: VerifyMetadata<'_>) -> Result<(), Error> {
    let doc = Document::parse(input.metadata_xml)?;
    verify_metadata_signature_on_document(&doc, input.trusted_signing_cert)
}

fn verify_metadata_signature_on_document(
    doc: &Document,
    trusted_signing_cert: &X509Certificate,
) -> Result<(), Error> {
    let signature_elem = doc
        .root()
        .child_element(Some(DS_NS), "Signature")
        .ok_or(Error::SignatureMissing)?;
    let verified = verify_signature(
        doc,
        signature_elem,
        &[trusted_signing_cert.clone()],
        SignatureAlgorithm::DEFAULTS,
    )?;
    if verified.signed_element != doc.root().id() {
        return Err(Error::SignatureVerification {
            reason: "metadata signature does not cover the document root",
        });
    }
    Ok(())
}

/// Verify the XML-DSig signature on a federation metadata document, then parse
/// it. Per RFC-006 §5, the verify-then-parse ordering is enforced atomically
/// here so attacker-supplied XML is never parsed into a usable descriptor
/// before the signature check runs.
pub fn parse_signed_entities_descriptor(
    metadata_xml: &[u8],
    trusted_signing_cert: &X509Certificate,
) -> Result<EntitiesDescriptor, Error> {
    let doc = Document::parse(metadata_xml)?;
    verify_metadata_signature_on_document(&doc, trusted_signing_cert)?;
    EntitiesDescriptor::from_root_element(doc.root())
}

/// Verify-then-parse helper for a single-entity IdP metadata document.
pub fn parse_signed_idp_descriptor(
    metadata_xml: &[u8],
    trusted_signing_cert: &X509Certificate,
) -> Result<IdpDescriptor, Error> {
    let doc = Document::parse(metadata_xml)?;
    verify_metadata_signature_on_document(&doc, trusted_signing_cert)?;
    let entity = find_entity_descriptor(doc.root(), |e| {
        e.child_element(Some(MD_NS), "IDPSSODescriptor").is_some()
    })
    .ok_or(Error::InvalidConfiguration {
        reason: "metadata does not contain an IdP entity",
    })?;
    IdpDescriptor::from_entity_descriptor_element(entity)
}

/// Verify-then-parse helper for a single-entity SP metadata document.
pub fn parse_signed_sp_descriptor(
    metadata_xml: &[u8],
    trusted_signing_cert: &X509Certificate,
) -> Result<SpDescriptor, Error> {
    let doc = Document::parse(metadata_xml)?;
    verify_metadata_signature_on_document(&doc, trusted_signing_cert)?;
    let entity = find_entity_descriptor(doc.root(), |e| {
        e.child_element(Some(MD_NS), "SPSSODescriptor").is_some()
    })
    .ok_or(Error::InvalidConfiguration {
        reason: "metadata does not contain an SP entity",
    })?;
    SpDescriptor::from_entity_descriptor_element(entity)
}

// =============================================================================
// Shared parsing helpers (consumed by descriptor::idp and descriptor::sp)
// =============================================================================

pub(crate) fn is_md_element(element: &Element, local: &str) -> bool {
    element.qname().local() == local && element.qname().namespace() == Some(MD_NS)
}

/// Locate an `<md:EntityDescriptor>` in `root` (which may itself be one or be
/// an `<md:EntitiesDescriptor>` aggregate) that satisfies `pred`.
///
/// For aggregates the search is in document order, flattening any nested
/// `<md:EntitiesDescriptor>` blocks (RFC-006 §3).
pub(crate) fn find_entity_descriptor<'a, F>(root: &'a Element, pred: F) -> Option<&'a Element>
where
    F: Fn(&Element) -> bool + Copy,
{
    if is_md_element(root, "EntityDescriptor") {
        if pred(root) {
            return Some(root);
        }
        return None;
    }
    if is_md_element(root, "EntitiesDescriptor") {
        for child in root.children() {
            let Node::Element(elem) = child else { continue };
            if is_md_element(elem, "EntityDescriptor") {
                if pred(elem) {
                    return Some(elem);
                }
            } else if is_md_element(elem, "EntitiesDescriptor") {
                if let Some(found) = find_entity_descriptor(elem, pred) {
                    return Some(found);
                }
            }
        }
    }
    None
}

/// Parse a `Binding=` / `Location=` / `index=` / `isDefault=` SAML endpoint.
pub(crate) fn parse_endpoint(element: &Element) -> Result<crate::binding::Endpoint, Error> {
    let binding_uri = element
        .attribute(None, "Binding")
        .ok_or(Error::InvalidConfiguration {
            reason: "endpoint missing Binding",
        })?;
    let binding = crate::binding::Binding::from_uri(binding_uri)?;
    let location = element
        .attribute(None, "Location")
        .ok_or(Error::InvalidConfiguration {
            reason: "endpoint missing Location",
        })?
        .to_owned();
    let index = match element.attribute(None, "index") {
        Some(s) => Some(s.parse::<u16>().map_err(|_| Error::InvalidConfiguration {
            reason: "endpoint index is not a u16",
        })?),
        None => None,
    };
    let is_default = parse_optional_bool_value(element.attribute(None, "isDefault"))?.unwrap_or(false);
    Ok(crate::binding::Endpoint {
        url: location,
        binding,
        index,
        is_default,
    })
}

/// Partition `<md:KeyDescriptor>` children into `(signing_certs,
/// encryption_certs)` per RFC-006 §4. A `KeyDescriptor` with no `use`
/// attribute lands in *both* lists.
pub(crate) fn parse_key_descriptors(
    role_descriptor: &Element,
) -> Result<(Vec<X509Certificate>, Vec<X509Certificate>), Error> {
    let mut signing = Vec::new();
    let mut encryption = Vec::new();

    for kd in role_descriptor.all_child_elements(Some(MD_NS), "KeyDescriptor") {
        let use_attr = kd.attribute(None, "use");
        let goes_to_signing = use_attr == Some("signing") || use_attr.is_none();
        let goes_to_encryption = use_attr == Some("encryption") || use_attr.is_none();

        // Reject explicit but unrecognized `use` values to surface metadata
        // typos rather than silently dropping the cert from both lists.
        if let Some(value) = use_attr {
            if value != "signing" && value != "encryption" {
                return Err(Error::InvalidConfiguration {
                    reason: "KeyDescriptor use attribute must be signing or encryption",
                });
            }
        }

        let key_info = kd
            .child_element(Some(DS_NS), "KeyInfo")
            .ok_or(Error::InvalidConfiguration {
                reason: "KeyDescriptor missing KeyInfo",
            })?;

        for x509_data in key_info.all_child_elements(Some(DS_NS), "X509Data") {
            for cert_elem in x509_data.all_child_elements(Some(DS_NS), "X509Certificate") {
                let b64 = cert_elem.text_content();
                let cert = X509Certificate::from_base64_x509(&b64)?;
                if goes_to_signing {
                    signing.push(cert.clone());
                }
                if goes_to_encryption {
                    encryption.push(cert);
                }
            }
        }
    }

    Ok((signing, encryption))
}

/// Collect every `<md:NameIDFormat>` child of a role descriptor and map each
/// to a [`NameIdFormat`]. Whitespace-only entries are dropped silently — the
/// SAML schema permits them but they carry no information.
pub(crate) fn parse_name_id_formats(role_descriptor: &Element) -> Vec<NameIdFormat> {
    let mut out = Vec::new();
    for child in role_descriptor.all_child_elements(Some(MD_NS), "NameIDFormat") {
        let uri = child.text_content();
        let trimmed = uri.trim();
        if !trimmed.is_empty() {
            out.push(NameIdFormat::from_uri(trimmed));
        }
    }
    out
}

/// Parse a `validUntil` (xs:dateTime) attribute on `element` if present.
pub(crate) fn parse_optional_xs_datetime(
    element: &Element,
    attr: &str,
) -> Result<Option<SystemTime>, Error> {
    match element.attribute(None, attr) {
        Some(s) => Ok(Some(parse_xs_datetime(s)?)),
        None => Ok(None),
    }
}

/// Parse a `cacheDuration` (xs:duration) attribute on `element` if present.
pub(crate) fn parse_optional_duration(
    element: &Element,
    attr: &str,
) -> Result<Option<Duration>, Error> {
    match element.attribute(None, attr) {
        Some(s) => Ok(Some(parse_xs_duration(s)?)),
        None => Ok(None),
    }
}

/// Parse a `WantAuthnRequestsSigned` / `AuthnRequestsSigned` /
/// `WantAssertionsSigned` style boolean attribute on `element`.
pub(crate) fn parse_optional_bool(element: &Element, attr: &str) -> Result<Option<bool>, Error> {
    parse_optional_bool_value(element.attribute(None, attr))
}

fn parse_optional_bool_value(value: Option<&str>) -> Result<Option<bool>, Error> {
    match value {
        None => Ok(None),
        // xs:boolean lexical space.
        Some("true") | Some("1") => Ok(Some(true)),
        Some("false") | Some("0") => Ok(Some(false)),
        Some(_) => Err(Error::InvalidConfiguration {
            reason: "invalid xs:boolean attribute",
        }),
    }
}

/// Parse an xs:duration of the common subset supported by this crate.
///
/// Accepted grammar (state-machine; no regex dependency):
///
/// ```text
/// P [ <digits> D ] [ T [ <digits> H ] [ <digits> M ] [ <digits> S ] ]
/// ```
///
/// Anything else (`Y` / `M` for years/months, negative durations, fractional
/// digits, or whitespace) is rejected with
/// `Error::InvalidConfiguration { reason: "unsupported xs:duration" }`.
pub(crate) fn parse_xs_duration(s: &str) -> Result<Duration, Error> {
    let unsupported = || Error::InvalidConfiguration {
        reason: "unsupported xs:duration",
    };

    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes[0] != b'P' {
        return Err(unsupported());
    }
    // We require at least one component (P alone, PT alone are invalid).
    if bytes.len() < 3 {
        return Err(unsupported());
    }

    // Phase tracking: 0 = before T (D allowed), 1 = after T (H, M, S allowed).
    // Within each phase we require designators in canonical order: D, then T,
    // then H, M, S. A repeated or out-of-order designator is an error.
    #[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
    enum Slot {
        Days,
        Hours,
        Minutes,
        Seconds,
    }

    let mut i = 1usize;
    let mut after_t = false;
    let mut last_slot: Option<Slot> = None;
    let mut days: u64 = 0;
    let mut hours: u64 = 0;
    let mut minutes: u64 = 0;
    let mut seconds: u64 = 0;
    let mut saw_any = false;

    while i < bytes.len() {
        let b = bytes[i];
        if b == b'T' {
            if after_t {
                return Err(unsupported());
            }
            after_t = true;
            i += 1;
            // After T we require at least one designator.
            if i >= bytes.len() {
                return Err(unsupported());
            }
            continue;
        }
        if !b.is_ascii_digit() {
            return Err(unsupported());
        }
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i >= bytes.len() {
            return Err(unsupported());
        }
        let designator = bytes[i];
        let value: u64 = std::str::from_utf8(&bytes[start..i])
            .map_err(|_| unsupported())?
            .parse::<u64>()
            .map_err(|_| unsupported())?;

        let (slot, target) = match (after_t, designator) {
            // Years / months are not fixed-length; rejected.
            (false, b'Y') | (false, b'M') => return Err(unsupported()),
            (false, b'D') => (Slot::Days, &mut days),
            (true, b'H') => (Slot::Hours, &mut hours),
            (true, b'M') => (Slot::Minutes, &mut minutes),
            (true, b'S') => (Slot::Seconds, &mut seconds),
            _ => return Err(unsupported()),
        };

        // Designators must appear at most once, and in canonical order.
        if let Some(prev) = last_slot {
            if slot <= prev {
                return Err(unsupported());
            }
        }
        last_slot = Some(slot);
        *target = value;
        saw_any = true;
        i += 1;
    }

    if !saw_any {
        return Err(unsupported());
    }

    // Compose into total seconds. None of the supported components can
    // realistically overflow u64 seconds for sane SAML metadata.
    let total_secs = days
        .checked_mul(86_400)
        .and_then(|d| d.checked_add(hours.checked_mul(3600)?))
        .and_then(|d| d.checked_add(minutes.checked_mul(60)?))
        .and_then(|d| d.checked_add(seconds))
        .ok_or_else(unsupported)?;

    Ok(Duration::from_secs(total_secs))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::{Binding, SsoResponseBinding};
    use crate::crypto::cert::X509Certificate;
    use crate::crypto::cert::test_vectors::{RSA_CERT_PEM, RSA_KEY_PKCS8_PEM};
    use crate::crypto::keypair::KeyPair;
    use crate::dsig::algorithms::{C14nAlgorithm, DigestAlgorithm, SignatureAlgorithm};
    use crate::dsig::c14n::canonicalize;
    use crate::dsig::reference::ancestor_chain;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;

    fn rsa_cert_b64() -> String {
        X509Certificate::from_pem(RSA_CERT_PEM)
            .unwrap()
            .to_base64_x509()
    }

    fn rsa_cert() -> X509Certificate {
        X509Certificate::from_pem(RSA_CERT_PEM).unwrap()
    }

    // ---- xs:duration ----

    #[test]
    fn duration_pt1h() {
        assert_eq!(parse_xs_duration("PT1H").unwrap(), Duration::from_secs(3600));
    }

    #[test]
    fn duration_pt15m() {
        assert_eq!(
            parse_xs_duration("PT15M").unwrap(),
            Duration::from_secs(15 * 60)
        );
    }

    #[test]
    fn duration_p1d() {
        assert_eq!(parse_xs_duration("P1D").unwrap(), Duration::from_secs(86_400));
    }

    #[test]
    fn duration_pt3600s() {
        assert_eq!(
            parse_xs_duration("PT3600S").unwrap(),
            Duration::from_secs(3600)
        );
    }

    #[test]
    fn duration_compound_hms() {
        assert_eq!(
            parse_xs_duration("PT1H30M15S").unwrap(),
            Duration::from_secs(3600 + 30 * 60 + 15)
        );
    }

    #[test]
    fn duration_p1d_pt1h() {
        assert_eq!(
            parse_xs_duration("P1DT1H").unwrap(),
            Duration::from_secs(86_400 + 3600)
        );
    }

    #[test]
    fn duration_rejects_years() {
        assert!(matches!(
            parse_xs_duration("P1Y"),
            Err(Error::InvalidConfiguration { .. })
        ));
    }

    #[test]
    fn duration_rejects_months() {
        assert!(matches!(
            parse_xs_duration("P1M"),
            Err(Error::InvalidConfiguration { .. })
        ));
    }

    #[test]
    fn duration_rejects_negative() {
        assert!(matches!(
            parse_xs_duration("-PT1H"),
            Err(Error::InvalidConfiguration { .. })
        ));
    }

    #[test]
    fn duration_rejects_empty_payload() {
        assert!(matches!(
            parse_xs_duration("P"),
            Err(Error::InvalidConfiguration { .. })
        ));
        assert!(matches!(
            parse_xs_duration("PT"),
            Err(Error::InvalidConfiguration { .. })
        ));
    }

    #[test]
    fn duration_rejects_repeated_designator() {
        assert!(matches!(
            parse_xs_duration("PT1H1H"),
            Err(Error::InvalidConfiguration { .. })
        ));
    }

    // ---- EntitiesDescriptor ----

    fn idp_entity_xml(entity_id: &str) -> String {
        format!(
            r#"<md:EntityDescriptor entityID="{eid}">
              <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                <md:KeyDescriptor use="signing">
                  <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
                </md:KeyDescriptor>
                <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                        Location="https://idp.example.com/sso"/>
              </md:IDPSSODescriptor>
            </md:EntityDescriptor>"#,
            eid = entity_id,
            cert = rsa_cert_b64()
        )
    }

    fn sp_entity_xml(entity_id: &str) -> String {
        format!(
            r#"<md:EntityDescriptor entityID="{eid}">
              <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"
                                  AuthnRequestsSigned="true"
                                  WantAssertionsSigned="true">
                <md:AssertionConsumerService index="0" isDefault="true"
                    Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                    Location="https://sp.example.com/acs"/>
                <md:SingleLogoutService
                    Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                    Location="https://sp.example.com/slo"/>
              </md:SPSSODescriptor>
            </md:EntityDescriptor>"#,
            eid = entity_id
        )
    }

    fn dual_entity_xml(entity_id: &str) -> String {
        format!(
            r#"<md:EntityDescriptor entityID="{eid}">
              <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                <md:KeyDescriptor use="signing">
                  <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
                </md:KeyDescriptor>
                <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                        Location="https://entity.example.com/sso"/>
              </md:IDPSSODescriptor>
              <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                <md:AssertionConsumerService index="0" isDefault="true"
                    Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                    Location="https://entity.example.com/acs"/>
              </md:SPSSODescriptor>
            </md:EntityDescriptor>"#,
            eid = entity_id,
            cert = rsa_cert_b64()
        )
    }

    #[test]
    fn aggregate_with_mixed_children() {
        let xml = format!(
            r#"<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                                       xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                                       Name="urn:example:federation">
                {idp}
                {sp}
              </md:EntitiesDescriptor>"#,
            idp = idp_entity_xml("https://idp.example.com/saml"),
            sp = sp_entity_xml("https://sp.example.com/saml")
        );
        let fed = EntitiesDescriptor::from_metadata_xml(xml.as_bytes()).expect("parse ok");
        assert_eq!(fed.name.as_deref(), Some("urn:example:federation"));
        assert_eq!(fed.entities.len(), 2);
        assert!(matches!(fed.entities[0], MetadataEntry::Idp(_)));
        assert!(matches!(fed.entities[1], MetadataEntry::Sp(_)));

        assert!(fed.find_idp("https://idp.example.com/saml").is_some());
        assert!(fed.find_sp("https://sp.example.com/saml").is_some());
        assert!(fed.find_idp("does-not-exist").is_none());
        assert_eq!(fed.iter_idps().count(), 1);
        assert_eq!(fed.iter_sps().count(), 1);
    }

    #[test]
    fn aggregate_flattens_nested_entities_descriptor() {
        let xml = format!(
            r#"<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                                       xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                {idp_outer}
                <md:EntitiesDescriptor>
                  {idp_inner}
                </md:EntitiesDescriptor>
              </md:EntitiesDescriptor>"#,
            idp_outer = idp_entity_xml("https://idp.outer.example.com/saml"),
            idp_inner = idp_entity_xml("https://idp.inner.example.com/saml")
        );
        let fed = EntitiesDescriptor::from_metadata_xml(xml.as_bytes()).unwrap();
        assert_eq!(fed.entities.len(), 2);
        assert!(fed.find_idp("https://idp.outer.example.com/saml").is_some());
        assert!(fed.find_idp("https://idp.inner.example.com/saml").is_some());
    }

    #[test]
    fn dual_role_entity_classified_as_dual() {
        let xml = format!(
            r#"<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                                       xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                {dual}
              </md:EntitiesDescriptor>"#,
            dual = dual_entity_xml("https://shib.example.com/saml")
        );
        let fed = EntitiesDescriptor::from_metadata_xml(xml.as_bytes()).unwrap();
        assert_eq!(fed.entities.len(), 1);
        assert!(matches!(fed.entities[0], MetadataEntry::Dual(_, _)));
        let idp = fed.find_idp("https://shib.example.com/saml").unwrap();
        let sp = fed.find_sp("https://shib.example.com/saml").unwrap();
        assert_eq!(idp.entity_id, sp.entity_id);
        assert_eq!(idp.sso_endpoints.len(), 1);
        assert_eq!(sp.assertion_consumer_services.len(), 1);
    }

    #[test]
    fn unknown_role_descriptor_becomes_other_variant() {
        let xml = r#"<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
                <md:EntityDescriptor entityID="https://aa.example.com/saml">
                  <!-- An entity without IDP/SP role descriptors, e.g. an AttributeAuthority. -->
                  <md:AttributeAuthorityDescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/>
                </md:EntityDescriptor>
              </md:EntitiesDescriptor>"#;
        let fed = EntitiesDescriptor::from_metadata_xml(xml.as_bytes()).unwrap();
        assert_eq!(fed.entities.len(), 1);
        assert!(matches!(fed.entities[0], MetadataEntry::Other));
    }

    #[test]
    fn single_entity_descriptor_root_is_promoted_to_aggregate() {
        let xml = format!(
            r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                                     entityID="https://idp.example.com/saml">
              <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                <md:KeyDescriptor use="signing">
                  <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
                </md:KeyDescriptor>
                <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                        Location="https://idp.example.com/sso"/>
              </md:IDPSSODescriptor>
            </md:EntityDescriptor>"#,
            cert = rsa_cert_b64()
        );
        let fed = EntitiesDescriptor::from_metadata_xml(xml.as_bytes()).unwrap();
        assert_eq!(fed.entities.len(), 1);
        assert!(matches!(fed.entities[0], MetadataEntry::Idp(_)));
    }

    // ---- Endpoint helpers ----

    #[test]
    fn parse_endpoint_handles_index_and_default() {
        let xml = r#"<md:Wrapper xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
            <md:E Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                  Location="https://x/acs" index="3" isDefault="true"/>
            </md:Wrapper>"#;
        let doc = Document::parse(xml.as_bytes()).unwrap();
        let e = doc
            .root()
            .child_element(Some(MD_NS), "E")
            .unwrap();
        let parsed = parse_endpoint(e).unwrap();
        assert_eq!(parsed.binding, Binding::HttpPost);
        assert_eq!(parsed.url, "https://x/acs");
        assert_eq!(parsed.index, Some(3));
        assert!(parsed.is_default);
    }

    // ---- Signed metadata ----

    /// Sign a metadata document the same way `crate::dsig::verify` tests do.
    fn sign_metadata(target_id: &str, body_xml: &str) -> (String, X509Certificate) {
        let kp = KeyPair::from_pkcs8_pem(RSA_KEY_PKCS8_PEM).unwrap();
        let cert = rsa_cert();
        let c14n_alg = C14nAlgorithm::ExclusiveCanonical;
        let sig_alg = SignatureAlgorithm::RsaSha256;

        let stage_1_xml = format!(
            r##"<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="{target_id}">{body_xml}</md:EntitiesDescriptor>"##
        );
        let stage_1_doc = Document::parse(stage_1_xml.as_bytes()).unwrap();
        let chain_1 = ancestor_chain(&stage_1_doc, stage_1_doc.root().id()).unwrap();
        let canonical_root =
            canonicalize(&stage_1_doc, stage_1_doc.root(), &chain_1, c14n_alg, &[]).unwrap();
        let reference_digest = DigestAlgorithm::Sha256.digest(&canonical_root);
        let digest_b64 = BASE64_STANDARD.encode(&reference_digest);

        let signed_info_inner = format!(
            r##"<ds:CanonicalizationMethod Algorithm="{c14n}"/><ds:SignatureMethod Algorithm="{sig}"/><ds:Reference URI="#{id}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="{c14n}"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference>"##,
            c14n = c14n_alg.uri(),
            sig = sig_alg.uri(),
            id = target_id,
            digest = digest_b64,
        );
        let signed_info_xml = format!(
            r##"<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{}</ds:SignedInfo>"##,
            signed_info_inner
        );
        let signed_info_doc = Document::parse(signed_info_xml.as_bytes()).unwrap();
        let si_chain = ancestor_chain(&signed_info_doc, signed_info_doc.root().id()).unwrap();
        let si_canonical = canonicalize(
            &signed_info_doc,
            signed_info_doc.root(),
            &si_chain,
            c14n_alg,
            &[],
        )
        .unwrap();
        let sig_bytes = kp.sign(sig_alg, &si_canonical).unwrap();
        let sig_b64 = BASE64_STANDARD.encode(&sig_bytes);

        let cert_b64 = cert.to_base64_x509();
        let final_xml = format!(
            r##"<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="{target_id}">{body}<ds:Signature><ds:SignedInfo>{si_inner}</ds:SignedInfo><ds:SignatureValue>{sig}</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature></md:EntitiesDescriptor>"##,
            target_id = target_id,
            body = body_xml,
            si_inner = signed_info_inner,
            sig = sig_b64,
            cert = cert_b64,
        );
        (final_xml, cert)
    }

    #[test]
    fn verify_metadata_signature_happy_path() {
        let body = idp_entity_xml("https://idp.example.com/saml");
        let (xml, cert) = sign_metadata("md-1", &body);
        verify_metadata_signature(VerifyMetadata {
            metadata_xml: xml.as_bytes(),
            trusted_signing_cert: &cert,
        })
        .expect("signature verifies");
    }

    #[test]
    fn verify_metadata_signature_missing_signature() {
        let xml = format!(
            r#"<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                                       xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                {idp}
              </md:EntitiesDescriptor>"#,
            idp = idp_entity_xml("https://idp.example.com/saml")
        );
        let cert = rsa_cert();
        let err = verify_metadata_signature(VerifyMetadata {
            metadata_xml: xml.as_bytes(),
            trusted_signing_cert: &cert,
        })
        .unwrap_err();
        assert!(matches!(err, Error::SignatureMissing));
    }

    #[test]
    fn parse_signed_entities_descriptor_round_trip() {
        let body = idp_entity_xml("https://idp.example.com/saml");
        let (xml, cert) = sign_metadata("md-1", &body);
        let fed = parse_signed_entities_descriptor(xml.as_bytes(), &cert).unwrap();
        assert_eq!(fed.entities.len(), 1);
        assert!(fed.find_idp("https://idp.example.com/saml").is_some());
    }

    #[test]
    fn parse_signed_idp_descriptor_via_aggregate() {
        let body = idp_entity_xml("https://idp.example.com/saml");
        let (xml, cert) = sign_metadata("md-1", &body);
        let idp = parse_signed_idp_descriptor(xml.as_bytes(), &cert).unwrap();
        assert_eq!(idp.entity_id, "https://idp.example.com/saml");
        let _ = SsoResponseBinding::HttpPost; // import sanity
    }

    #[test]
    fn parse_signed_sp_descriptor_via_aggregate() {
        let body = sp_entity_xml("https://sp.example.com/saml");
        let (xml, cert) = sign_metadata("md-1", &body);
        let sp = parse_signed_sp_descriptor(xml.as_bytes(), &cert).unwrap();
        assert_eq!(sp.entity_id, "https://sp.example.com/saml");
    }
}
