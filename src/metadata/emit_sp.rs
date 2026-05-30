//! Emit `<md:EntityDescriptor>` containing `<md:SPSSODescriptor>` for an SP
//! role — RFC-006 §6.1.
//!
//! The public surface is [`emit_sp_metadata`], a standalone function taking
//! the precise inputs RFC-006 §6.1 says are emitted (collected in
//! [`SpMetadataInputs`]) plus an optional XML-DSig signer tuple. Wave 6
//! wraps this into the `ServiceProvider::metadata_xml(_with_extras)` role
//! methods declared in RFC-006 §6.

use crate::binding::{Endpoint, SsoResponseEndpoint};
use crate::crypto::cert::X509Certificate;
use crate::crypto::keypair::KeyPair;
use crate::dsig::algorithms::{C14nAlgorithm, DigestAlgorithm, SignatureAlgorithm};
use crate::error::Error;
use crate::nameid::NameIdFormat;
use crate::xml::emit::emit_document;
use crate::xml::parse::{Document, Element, Node, QName};
#[cfg(feature = "xmlenc")]
use crate::xmlenc::algorithms::DataEncryptionAlgorithm;

use super::{MetadataContact, MetadataExtras, MetadataOrganization};

/// SAML 2.0 metadata namespace URI.
pub(super) const MD_NS: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
/// XML Signature namespace URI.
pub(super) const DS_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
/// `xml:lang` attribute namespace.
const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";
/// SAML 2.0 protocol enumeration constant (single value per spec).
pub(super) const SAML2_PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";

/// Caller-supplied SP metadata fields. Mirrors the inputs RFC-003 says
/// `ServiceProviderConfig` holds and what RFC-006 §6.1 says are emitted.
pub struct SpMetadataInputs<'a> {
    pub entity_id: &'a str,
    pub acs: &'a [SsoResponseEndpoint],
    pub slo: &'a [Endpoint],
    pub name_id_formats: &'a [NameIdFormat],
    pub signing_cert: Option<&'a X509Certificate>,
    #[cfg(feature = "xmlenc")]
    pub encryption_cert: Option<&'a X509Certificate>,
    #[cfg(feature = "xmlenc")]
    pub encryption_algorithms: &'a [DataEncryptionAlgorithm],
    pub authn_requests_signed: bool,
    pub want_assertions_signed: bool,
    pub valid_until: Option<std::time::SystemTime>,
    pub cache_duration: Option<std::time::Duration>,
    pub extras: Option<&'a MetadataExtras>,
}

/// Sign + emit the SP `<md:EntityDescriptor>` XML.
///
/// When `signer` is `Some((key, sig, digest, c14n))` the emitted descriptor
/// carries an enveloped `<ds:Signature>` covering the EntityDescriptor
/// element via `Reference URI="#<id>"` (RFC-006 §6.4). When `None`, the
/// descriptor is emitted unsigned.
pub fn emit_sp_metadata(
    inputs: &SpMetadataInputs<'_>,
    signer: Option<(&KeyPair, SignatureAlgorithm, DigestAlgorithm, C14nAlgorithm)>,
) -> Result<String, Error> {
    let entity_descriptor_id = crate::binding::random_xml_id()?;
    let root = build_sp_entity_descriptor(inputs, &entity_descriptor_id)?;

    let final_root = if let Some((key, sig_alg, digest, c14n)) = signer {
        // The signing helper canonicalizes against a document context, so we
        // need a `Document` wrapping the unsigned tree. We then thread the
        // resulting signed element back into a fresh `Document` for the final
        // emit step — `sign_element` keeps every existing attribute (including
        // `ID`) intact so the `Reference URI="#<id>"` resolves on the verifier.
        let unsigned_doc = Document::new(root.clone())?;
        crate::dsig::sign::sign_element(
            root,
            &unsigned_doc,
            crate::dsig::sign::SignOptions {
                signing_key: key,
                sig_alg,
                digest_alg: digest,
                c14n_alg: c14n,
                inclusive_namespaces: &[],
                include_x509_cert: true,
            },
        )?
    } else {
        root
    };

    let doc = Document::new(final_root)?;
    emit_document(&doc)
}

// =============================================================================
// Builders
// =============================================================================

pub(super) fn build_sp_entity_descriptor(
    inputs: &SpMetadataInputs<'_>,
    entity_descriptor_id: &str,
) -> Result<Element, Error> {
    // ── <md:SPSSODescriptor> ─────────────────────────────────────────────
    let mut sp_descriptor = Element::build(md_qname("SPSSODescriptor"))
        .with_attribute(
            QName::new(None, "protocolSupportEnumeration"),
            SAML2_PROTOCOL,
        )
        .with_attribute(
            QName::new(None, "AuthnRequestsSigned"),
            bool_str(inputs.authn_requests_signed),
        )
        .with_attribute(
            QName::new(None, "WantAssertionsSigned"),
            bool_str(inputs.want_assertions_signed),
        );

    // KeyDescriptors (signing first, then encryption — order matches the
    // worked example in the spec and is the only ordering parsers in the
    // wild reliably tolerate).
    if let Some(cert) = inputs.signing_cert {
        sp_descriptor = sp_descriptor.with_child(Node::Element(build_signing_key_descriptor(cert)));
    }
    #[cfg(feature = "xmlenc")]
    if let Some(cert) = inputs.encryption_cert {
        sp_descriptor = sp_descriptor.with_child(Node::Element(build_encryption_key_descriptor(
            cert,
            inputs.encryption_algorithms,
        )));
    }

    // NameIDFormats.
    for fmt in inputs.name_id_formats {
        sp_descriptor = sp_descriptor.with_child(Node::Element(
            Element::build(md_qname("NameIDFormat"))
                .with_text(fmt.as_uri().to_owned())
                .finish(),
        ));
    }

    // AssertionConsumerService endpoints.
    for endpoint in inputs.acs {
        sp_descriptor = sp_descriptor.with_child(Node::Element(build_acs_endpoint(endpoint)));
    }

    // SingleLogoutService endpoints.
    for endpoint in inputs.slo {
        sp_descriptor = sp_descriptor.with_child(Node::Element(build_slo_endpoint(endpoint)));
    }

    let sp_descriptor = sp_descriptor.finish();

    // ── <md:EntityDescriptor> wrapper ────────────────────────────────────
    let mut entity_descriptor = Element::build(md_qname("EntityDescriptor"))
        .with_namespace(Some("md".to_owned()), MD_NS)
        .with_namespace(Some("ds".to_owned()), DS_NS)
        .with_attribute(QName::new(None, "entityID"), inputs.entity_id.to_owned())
        // ID attribute is required by the signing pipeline (`Reference
        // URI="#<id>"` resolution); we emit it unconditionally so signed
        // and unsigned output remain structurally identical.
        .with_attribute(QName::new(None, "ID"), entity_descriptor_id.to_owned());

    if let Some(valid_until) = inputs.valid_until {
        entity_descriptor = entity_descriptor.with_attribute(
            QName::new(None, "validUntil"),
            crate::time::format_xs_datetime(valid_until)?,
        );
    }
    if let Some(cache_duration) = inputs.cache_duration {
        entity_descriptor = entity_descriptor.with_attribute(
            QName::new(None, "cacheDuration"),
            format_cache_duration(cache_duration),
        );
    }

    entity_descriptor = entity_descriptor.with_child(Node::Element(sp_descriptor));

    if let Some(extras) = inputs.extras {
        entity_descriptor = append_extras(entity_descriptor, extras);
    }

    Ok(entity_descriptor.finish())
}

// =============================================================================
// Shared helpers (re-used by `emit_idp`)
// =============================================================================

/// `xs:duration` in the simple "seconds-only" form `PT<n>S`. SAML deployments
/// universally produce / accept this shape; we deliberately do not emit weeks
/// or months because their xs:duration semantics are date-dependent and
/// surprise downstream parsers.
pub(super) fn format_cache_duration(d: std::time::Duration) -> String {
    format!("PT{}S", d.as_secs())
}

pub(super) fn bool_str(b: bool) -> &'static str {
    if b { "true" } else { "false" }
}

pub(super) fn md_qname(local: &str) -> QName {
    QName::new(Some(MD_NS.to_owned()), local)
}

fn ds_qname(local: &str) -> QName {
    QName::new(Some(DS_NS.to_owned()), local)
}

pub(super) fn build_signing_key_descriptor(cert: &X509Certificate) -> Element {
    Element::build(md_qname("KeyDescriptor"))
        .with_attribute(QName::new(None, "use"), "signing")
        .with_child(Node::Element(build_key_info_x509(cert)))
        .finish()
}

#[cfg(feature = "xmlenc")]
pub(super) fn build_encryption_key_descriptor(
    cert: &X509Certificate,
    encryption_algorithms: &[DataEncryptionAlgorithm],
) -> Element {
    let mut builder = Element::build(md_qname("KeyDescriptor"))
        .with_attribute(QName::new(None, "use"), "encryption")
        .with_child(Node::Element(build_key_info_x509(cert)));

    for alg in encryption_algorithms {
        builder = builder.with_child(Node::Element(
            Element::build(md_qname("EncryptionMethod"))
                .with_attribute(QName::new(None, "Algorithm"), alg.uri())
                .finish(),
        ));
    }
    builder.finish()
}

fn build_key_info_x509(cert: &X509Certificate) -> Element {
    let x509_cert = Element::build(ds_qname("X509Certificate"))
        .with_text(cert.to_base64_x509())
        .finish();
    let x509_data = Element::build(ds_qname("X509Data"))
        .with_child(Node::Element(x509_cert))
        .finish();
    Element::build(ds_qname("KeyInfo"))
        .with_child(Node::Element(x509_data))
        .finish()
}

fn build_acs_endpoint(endpoint: &SsoResponseEndpoint) -> Element {
    let mut builder = Element::build(md_qname("AssertionConsumerService"))
        .with_attribute(QName::new(None, "Binding"), endpoint.binding.uri())
        .with_attribute(QName::new(None, "Location"), endpoint.url.clone());
    if let Some(index) = endpoint.index {
        builder = builder.with_attribute(QName::new(None, "index"), index.to_string());
    }
    if endpoint.is_default {
        builder = builder.with_attribute(QName::new(None, "isDefault"), "true");
    }
    builder.finish()
}

fn build_slo_endpoint(endpoint: &Endpoint) -> Element {
    // `<md:SingleLogoutService>` per the schema only carries `Binding` /
    // `Location` (+ optional `ResponseLocation`); the `index` / `isDefault`
    // attributes are exclusive to indexed endpoints (ACS / ARS / AttrCS),
    // not SLO. We deliberately do not emit them here even when the
    // input `Endpoint` carries them — they would be schema-invalid.
    Element::build(md_qname("SingleLogoutService"))
        .with_attribute(QName::new(None, "Binding"), endpoint.binding.uri())
        .with_attribute(QName::new(None, "Location"), endpoint.url.clone())
        .finish()
}

/// Append `<md:Organization>` (if present) and any `<md:ContactPerson>`
/// entries from `extras` onto the EntityDescriptor builder. Per the SAML 2.0
/// metadata schema, `<md:Organization>` precedes `<md:ContactPerson>` and
/// both follow the role descriptors.
pub(super) fn append_extras(
    mut entity_descriptor: crate::xml::emit::ElementBuilder,
    extras: &MetadataExtras,
) -> crate::xml::emit::ElementBuilder {
    if let Some(org) = &extras.organization {
        entity_descriptor = entity_descriptor.with_child(Node::Element(build_organization(org)));
    }
    for contact in &extras.contacts {
        entity_descriptor =
            entity_descriptor.with_child(Node::Element(build_contact_person(contact)));
    }
    entity_descriptor
}

fn build_organization(org: &MetadataOrganization) -> Element {
    let lang_attr = QName::new(Some(XML_NS.to_owned()), "lang");

    let name = Element::build(md_qname("OrganizationName"))
        .with_attribute(lang_attr.clone(), org.language.clone())
        .with_text(org.name.clone())
        .finish();
    let display_name = Element::build(md_qname("OrganizationDisplayName"))
        .with_attribute(lang_attr.clone(), org.language.clone())
        .with_text(org.display_name.clone())
        .finish();
    let url = Element::build(md_qname("OrganizationURL"))
        .with_attribute(lang_attr, org.language.clone())
        .with_text(org.url.clone())
        .finish();

    Element::build(md_qname("Organization"))
        // The `xml:` prefix is intrinsic (XML Namespaces 1.0 §3) — the
        // emitter resolves `xml:lang` to the reserved `xml` prefix without
        // a per-element declaration.
        .with_child(Node::Element(name))
        .with_child(Node::Element(display_name))
        .with_child(Node::Element(url))
        .finish()
}

fn build_contact_person(contact: &MetadataContact) -> Element {
    let mut builder = Element::build(md_qname("ContactPerson")).with_attribute(
        QName::new(None, "contactType"),
        contact.contact_type.as_str(),
    );

    if let Some(company) = &contact.company {
        builder = builder.with_child(Node::Element(
            Element::build(md_qname("Company"))
                .with_text(company.clone())
                .finish(),
        ));
    }
    if let Some(given_name) = &contact.given_name {
        builder = builder.with_child(Node::Element(
            Element::build(md_qname("GivenName"))
                .with_text(given_name.clone())
                .finish(),
        ));
    }
    if let Some(surname) = &contact.surname {
        builder = builder.with_child(Node::Element(
            Element::build(md_qname("SurName"))
                .with_text(surname.clone())
                .finish(),
        ));
    }
    for email in &contact.email_addresses {
        builder = builder.with_child(Node::Element(
            Element::build(md_qname("EmailAddress"))
                .with_text(email.clone())
                .finish(),
        ));
    }
    for phone in &contact.telephone_numbers {
        builder = builder.with_child(Node::Element(
            Element::build(md_qname("TelephoneNumber"))
                .with_text(phone.clone())
                .finish(),
        ));
    }
    builder.finish()
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[cfg(feature = "xmlenc")]
mod tests {
    use super::*;
    use crate::binding::{Binding, Endpoint, SsoResponseEndpoint};
    use crate::crypto::cert::X509Certificate;
    use crate::crypto::cert::test_vectors::{RSA_CERT_PEM, RSA_KEY_PKCS8_PEM};
    use crate::dsig::algorithms::{C14nAlgorithm, DigestAlgorithm, SignatureAlgorithm};
    use crate::metadata::{
        MetadataContact, MetadataContactType, MetadataExtras, MetadataOrganization,
    };
    use crate::xml::parse::Document;
    use std::time::{Duration, SystemTime};

    fn rsa_cert() -> X509Certificate {
        X509Certificate::from_pem(RSA_CERT_PEM).unwrap()
    }

    fn signing_keypair() -> KeyPair {
        KeyPair::from_pkcs8_pem(RSA_KEY_PKCS8_PEM)
            .unwrap()
            .with_certificate(rsa_cert())
    }

    fn baseline_inputs<'a>(
        cert: &'a X509Certificate,
        acs: &'a [SsoResponseEndpoint],
        slo: &'a [Endpoint],
        formats: &'a [NameIdFormat],
        algos: &'a [DataEncryptionAlgorithm],
    ) -> SpMetadataInputs<'a> {
        SpMetadataInputs {
            entity_id: "https://sp.example.com/saml",
            acs,
            slo,
            name_id_formats: formats,
            signing_cert: Some(cert),
            encryption_cert: Some(cert),
            encryption_algorithms: algos,
            authn_requests_signed: true,
            want_assertions_signed: true,
            valid_until: None,
            cache_duration: None,
            extras: None,
        }
    }

    #[test]
    fn emits_well_formed_entity_descriptor_with_expected_shape() {
        let cert = rsa_cert();
        let acs = [SsoResponseEndpoint::post(
            "https://sp.example.com/acs/post",
            0,
            true,
        )];
        let slo = [Endpoint::redirect("https://sp.example.com/slo", 0, false)];
        let formats = [NameIdFormat::EmailAddress, NameIdFormat::Persistent];
        let algos = [
            DataEncryptionAlgorithm::Aes256Gcm,
            DataEncryptionAlgorithm::Aes128Gcm,
        ];
        let inputs = baseline_inputs(&cert, &acs, &slo, &formats, &algos);

        let xml = emit_sp_metadata(&inputs, None).expect("emit");

        // Parses as well-formed XML, root has the right name + entityID.
        let doc = Document::parse(xml.as_bytes()).expect("re-parse");
        let root = doc.root();
        assert_eq!(root.qname().namespace(), Some(MD_NS));
        assert_eq!(root.qname().local(), "EntityDescriptor");
        assert_eq!(
            root.attribute(None, "entityID"),
            Some("https://sp.example.com/saml")
        );
        let id_attr = root.attribute(None, "ID").expect("ID attribute");
        assert!(id_attr.starts_with('_'), "ID = {id_attr}");

        // SPSSODescriptor present with the correct enumeration + signing flags.
        let sp_desc = root
            .child_element(Some(MD_NS), "SPSSODescriptor")
            .expect("SPSSODescriptor present");
        assert_eq!(
            sp_desc.attribute(None, "protocolSupportEnumeration"),
            Some(SAML2_PROTOCOL)
        );
        assert_eq!(sp_desc.attribute(None, "AuthnRequestsSigned"), Some("true"));
        assert_eq!(
            sp_desc.attribute(None, "WantAssertionsSigned"),
            Some("true")
        );

        // KeyDescriptors: one signing, one encryption (with EncryptionMethods).
        let key_descriptors: Vec<_> = sp_desc
            .all_child_elements(Some(MD_NS), "KeyDescriptor")
            .collect();
        assert_eq!(key_descriptors.len(), 2);
        assert_eq!(key_descriptors[0].attribute(None, "use"), Some("signing"));
        assert_eq!(
            key_descriptors[1].attribute(None, "use"),
            Some("encryption")
        );
        // EncryptionMethods appear under the encryption KeyDescriptor.
        let enc_methods: Vec<_> = key_descriptors[1]
            .all_child_elements(Some(MD_NS), "EncryptionMethod")
            .collect();
        assert_eq!(enc_methods.len(), 2);
        assert_eq!(
            enc_methods[0].attribute(None, "Algorithm"),
            Some(DataEncryptionAlgorithm::Aes256Gcm.uri())
        );
        assert_eq!(
            enc_methods[1].attribute(None, "Algorithm"),
            Some(DataEncryptionAlgorithm::Aes128Gcm.uri())
        );

        // NameIDFormats — both URIs present, in input order.
        let name_id_formats: Vec<_> = sp_desc
            .all_child_elements(Some(MD_NS), "NameIDFormat")
            .map(Element::text_content)
            .collect();
        assert_eq!(
            name_id_formats,
            vec![
                NameIdFormat::EmailAddress.as_uri().to_owned(),
                NameIdFormat::Persistent.as_uri().to_owned(),
            ]
        );

        // ACS + SLO endpoints carry the right binding URIs.
        let acs_elements: Vec<_> = sp_desc
            .all_child_elements(Some(MD_NS), "AssertionConsumerService")
            .collect();
        assert_eq!(acs_elements.len(), 1);
        assert_eq!(
            acs_elements[0].attribute(None, "Binding"),
            Some(Binding::HttpPost.uri())
        );
        assert_eq!(
            acs_elements[0].attribute(None, "Location"),
            Some("https://sp.example.com/acs/post")
        );
        assert_eq!(acs_elements[0].attribute(None, "index"), Some("0"));
        assert_eq!(acs_elements[0].attribute(None, "isDefault"), Some("true"));

        let slo_elements: Vec<_> = sp_desc
            .all_child_elements(Some(MD_NS), "SingleLogoutService")
            .collect();
        assert_eq!(slo_elements.len(), 1);
        assert_eq!(
            slo_elements[0].attribute(None, "Binding"),
            Some(Binding::HttpRedirect.uri())
        );
        assert_eq!(
            slo_elements[0].attribute(None, "Location"),
            Some("https://sp.example.com/slo")
        );
    }

    #[test]
    fn multiple_acs_endpoints_emit_index_and_is_default() {
        let cert = rsa_cert();
        let acs = [
            SsoResponseEndpoint::post("https://sp.example.com/acs/post", 0, true),
            SsoResponseEndpoint::artifact("https://sp.example.com/acs/art", 1, false),
            SsoResponseEndpoint::post("https://sp.example.com/acs/extra", 2, false),
        ];
        let formats = [NameIdFormat::Transient];
        let algos: [DataEncryptionAlgorithm; 0] = [];
        let inputs = baseline_inputs(&cert, &acs, &[], &formats, &algos);

        let xml = emit_sp_metadata(&inputs, None).unwrap();
        let doc = Document::parse(xml.as_bytes()).unwrap();
        let sp_desc = doc
            .root()
            .child_element(Some(MD_NS), "SPSSODescriptor")
            .unwrap();
        let acs_elements: Vec<_> = sp_desc
            .all_child_elements(Some(MD_NS), "AssertionConsumerService")
            .collect();
        assert_eq!(acs_elements.len(), 3);

        // index attribute is emitted for every entry.
        assert_eq!(acs_elements[0].attribute(None, "index"), Some("0"));
        assert_eq!(acs_elements[1].attribute(None, "index"), Some("1"));
        assert_eq!(acs_elements[2].attribute(None, "index"), Some("2"));

        // isDefault only on the default ACS — non-defaults omit the attribute
        // (per SAML 2.0 metadata schema, default value is `false`).
        assert_eq!(acs_elements[0].attribute(None, "isDefault"), Some("true"));
        assert_eq!(acs_elements[1].attribute(None, "isDefault"), None);
        assert_eq!(acs_elements[2].attribute(None, "isDefault"), None);

        // Bindings: POST / Artifact / POST.
        assert_eq!(
            acs_elements[0].attribute(None, "Binding"),
            Some(Binding::HttpPost.uri())
        );
        assert_eq!(
            acs_elements[1].attribute(None, "Binding"),
            Some(Binding::HttpArtifact.uri())
        );
        assert_eq!(
            acs_elements[2].attribute(None, "Binding"),
            Some(Binding::HttpPost.uri())
        );
    }

    #[test]
    fn valid_until_and_cache_duration_emit_attributes() {
        let cert = rsa_cert();
        let acs = [SsoResponseEndpoint::post(
            "https://sp.example.com/acs",
            0,
            true,
        )];
        let formats = [NameIdFormat::Persistent];
        let algos: [DataEncryptionAlgorithm; 0] = [];
        let mut inputs = baseline_inputs(&cert, &acs, &[], &formats, &algos);
        let valid_until = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000_000); // 2033-05-18T03:33:20Z
        inputs.valid_until = Some(valid_until);
        inputs.cache_duration = Some(Duration::from_hours(1));

        let xml = emit_sp_metadata(&inputs, None).unwrap();
        let doc = Document::parse(xml.as_bytes()).unwrap();
        let root = doc.root();

        // validUntil round-trips through xs:dateTime: parse it back with the
        // same helper used by the metadata-parse path.
        let vu = root.attribute(None, "validUntil").expect("validUntil");
        let parsed = crate::time::parse_xs_datetime(vu).expect("parse");
        assert_eq!(parsed, valid_until);

        // cacheDuration is the simple `PT<n>S` form.
        assert_eq!(root.attribute(None, "cacheDuration"), Some("PT3600S"));
    }

    #[test]
    fn extras_emit_organization_and_contact_person() {
        let cert = rsa_cert();
        let acs = [SsoResponseEndpoint::post(
            "https://sp.example.com/acs",
            0,
            true,
        )];
        let formats = [NameIdFormat::EmailAddress];
        let algos: [DataEncryptionAlgorithm; 0] = [];
        let extras = MetadataExtras {
            organization: Some(MetadataOrganization {
                name: "Example Corp".into(),
                display_name: "Example Corporation".into(),
                url: "https://example.com".into(),
                language: "en".into(),
            }),
            contacts: vec![MetadataContact {
                contact_type: MetadataContactType::Technical,
                given_name: Some("Alex".into()),
                surname: Some("Operator".into()),
                email_addresses: vec!["sso-admin@example.com".into()],
                telephone_numbers: vec!["+15551234567".into()],
                company: Some("Example Corp".into()),
            }],
        };
        let mut inputs = baseline_inputs(&cert, &acs, &[], &formats, &algos);
        inputs.extras = Some(&extras);

        let xml = emit_sp_metadata(&inputs, None).unwrap();
        let doc = Document::parse(xml.as_bytes()).unwrap();
        let root = doc.root();

        // <md:Organization>
        let org = root
            .child_element(Some(MD_NS), "Organization")
            .expect("Organization");
        let name = org
            .child_element(Some(MD_NS), "OrganizationName")
            .expect("OrganizationName");
        assert_eq!(name.text_content(), "Example Corp");
        assert_eq!(name.attribute(Some(XML_NS), "lang"), Some("en"));
        let display = org
            .child_element(Some(MD_NS), "OrganizationDisplayName")
            .expect("OrganizationDisplayName");
        assert_eq!(display.text_content(), "Example Corporation");
        let url = org
            .child_element(Some(MD_NS), "OrganizationURL")
            .expect("OrganizationURL");
        assert_eq!(url.text_content(), "https://example.com");

        // <md:ContactPerson>
        let contact = root
            .child_element(Some(MD_NS), "ContactPerson")
            .expect("ContactPerson");
        assert_eq!(contact.attribute(None, "contactType"), Some("technical"));
        assert_eq!(
            contact
                .child_element(Some(MD_NS), "Company")
                .map(Element::text_content),
            Some("Example Corp".to_owned())
        );
        assert_eq!(
            contact
                .child_element(Some(MD_NS), "GivenName")
                .map(Element::text_content),
            Some("Alex".to_owned())
        );
        assert_eq!(
            contact
                .child_element(Some(MD_NS), "SurName")
                .map(Element::text_content),
            Some("Operator".to_owned())
        );
        assert_eq!(
            contact
                .child_element(Some(MD_NS), "EmailAddress")
                .map(Element::text_content),
            Some("sso-admin@example.com".to_owned())
        );
        assert_eq!(
            contact
                .child_element(Some(MD_NS), "TelephoneNumber")
                .map(Element::text_content),
            Some("+15551234567".to_owned())
        );
    }

    #[test]
    fn signed_metadata_carries_ds_signature_as_first_child() {
        let cert = rsa_cert();
        let acs = [SsoResponseEndpoint::post(
            "https://sp.example.com/acs",
            0,
            true,
        )];
        let formats = [NameIdFormat::EmailAddress];
        let algos: [DataEncryptionAlgorithm; 0] = [];
        let inputs = baseline_inputs(&cert, &acs, &[], &formats, &algos);
        let kp = signing_keypair();
        let xml = emit_sp_metadata(
            &inputs,
            Some((
                &kp,
                SignatureAlgorithm::RsaSha256,
                DigestAlgorithm::Sha256,
                C14nAlgorithm::ExclusiveCanonical,
            )),
        )
        .unwrap();

        let doc = Document::parse(xml.as_bytes()).unwrap();
        let root = doc.root();
        // EntityDescriptor has no Issuer; signature must be the first child.
        let children: Vec<_> = root.child_elements().collect();
        assert!(!children.is_empty());
        assert_eq!(children[0].qname().namespace(), Some(DS_NS));
        assert_eq!(children[0].qname().local(), "Signature");

        // Reference URI inside the signature equals "#<EntityDescriptor/@ID>".
        let id_attr = root.attribute(None, "ID").expect("ID");
        let expected_uri = format!("#{id_attr}");
        let signed_info = children[0]
            .child_element(Some(DS_NS), "SignedInfo")
            .unwrap();
        let reference = signed_info.child_element(Some(DS_NS), "Reference").unwrap();
        assert_eq!(
            reference.attribute(None, "URI"),
            Some(expected_uri.as_str())
        );

        // SPSSODescriptor still present (signing must not eat children).
        assert!(root.child_element(Some(MD_NS), "SPSSODescriptor").is_some());
    }

    #[test]
    fn unsigned_metadata_has_no_ds_signature_child() {
        let cert = rsa_cert();
        let acs = [SsoResponseEndpoint::post(
            "https://sp.example.com/acs",
            0,
            true,
        )];
        let formats = [NameIdFormat::Persistent];
        let algos: [DataEncryptionAlgorithm; 0] = [];
        let inputs = baseline_inputs(&cert, &acs, &[], &formats, &algos);
        let xml = emit_sp_metadata(&inputs, None).unwrap();
        let doc = Document::parse(xml.as_bytes()).unwrap();
        assert!(doc.root().child_element(Some(DS_NS), "Signature").is_none());
    }

    #[test]
    fn omits_key_descriptors_when_certs_absent() {
        let acs = [SsoResponseEndpoint::post(
            "https://sp.example.com/acs",
            0,
            true,
        )];
        let formats = [NameIdFormat::Transient];
        let algos: [DataEncryptionAlgorithm; 0] = [];
        // No certs — the SP may not sign AuthnRequests and may not accept
        // encrypted assertions. We still emit a structurally valid SP
        // descriptor without any KeyDescriptor children.
        let inputs = SpMetadataInputs {
            entity_id: "https://sp.example.com/saml",
            acs: &acs,
            slo: &[],
            name_id_formats: &formats,
            signing_cert: None,
            encryption_cert: None,
            encryption_algorithms: &algos,
            authn_requests_signed: false,
            want_assertions_signed: false,
            valid_until: None,
            cache_duration: None,
            extras: None,
        };

        let xml = emit_sp_metadata(&inputs, None).unwrap();
        let doc = Document::parse(xml.as_bytes()).unwrap();
        let sp_desc = doc
            .root()
            .child_element(Some(MD_NS), "SPSSODescriptor")
            .unwrap();
        assert_eq!(
            sp_desc
                .all_child_elements(Some(MD_NS), "KeyDescriptor")
                .count(),
            0
        );
        assert_eq!(
            sp_desc.attribute(None, "AuthnRequestsSigned"),
            Some("false")
        );
        assert_eq!(
            sp_desc.attribute(None, "WantAssertionsSigned"),
            Some("false")
        );
    }
}
