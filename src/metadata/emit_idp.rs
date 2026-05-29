//! Emit `<md:EntityDescriptor>` containing `<md:IDPSSODescriptor>` for an IdP
//! role — RFC-006 §6.2.
//!
//! The public surface is [`emit_idp_metadata`], a standalone function taking
//! the precise inputs RFC-006 §6.2 says are emitted (collected in
//! [`IdpMetadataInputs`]) plus an optional XML-DSig signer tuple. Wave 6
//! wraps this into the `IdentityProvider::metadata_xml(_with_extras)` role
//! methods declared in RFC-006 §6.

use crate::binding::Endpoint;
use crate::crypto::cert::X509Certificate;
use crate::crypto::keypair::KeyPair;
use crate::dsig::algorithms::{C14nAlgorithm, DigestAlgorithm, SignatureAlgorithm};
use crate::error::Error;
use crate::nameid::NameIdFormat;
use crate::xml::emit::emit_document;
use crate::xml::parse::{Document, Element, Node, QName};
#[cfg(feature = "xmlenc")]
use crate::xmlenc::algorithms::DataEncryptionAlgorithm;

use super::MetadataExtras;
#[cfg(feature = "xmlenc")]
use super::emit_sp::build_encryption_key_descriptor;
use super::emit_sp::{
    DS_NS, MD_NS, SAML2_PROTOCOL, append_extras, bool_str, build_signing_key_descriptor,
    format_cache_duration, generate_id, md_qname,
};

/// Caller-supplied IdP metadata fields. Mirrors what RFC-006 §6.2 says are
/// emitted under `<md:IDPSSODescriptor>`.
pub struct IdpMetadataInputs<'a> {
    pub entity_id: &'a str,
    pub sso: &'a [Endpoint],
    pub slo: &'a [Endpoint],
    pub artifact_resolution: &'a [Endpoint],
    pub name_id_formats: &'a [NameIdFormat],
    /// IdPs MUST publish a signing cert — Responses they emit must be
    /// signed, and SPs need the cert to verify.
    pub signing_cert: &'a X509Certificate,
    #[cfg(feature = "xmlenc")]
    pub encryption_cert: Option<&'a X509Certificate>,
    #[cfg(feature = "xmlenc")]
    pub encryption_algorithms: &'a [DataEncryptionAlgorithm],
    pub want_authn_requests_signed: bool,
    pub valid_until: Option<std::time::SystemTime>,
    pub cache_duration: Option<std::time::Duration>,
    pub extras: Option<&'a MetadataExtras>,
}

/// Sign + emit the IdP `<md:EntityDescriptor>` XML.
///
/// When `signer` is `Some((key, sig, digest, c14n))` the emitted descriptor
/// carries an enveloped `<ds:Signature>` covering the EntityDescriptor
/// element via `Reference URI="#<id>"` (RFC-006 §6.4). When `None`, the
/// descriptor is emitted unsigned.
pub fn emit_idp_metadata(
    inputs: &IdpMetadataInputs<'_>,
    signer: Option<(&KeyPair, SignatureAlgorithm, DigestAlgorithm, C14nAlgorithm)>,
) -> Result<String, Error> {
    let entity_descriptor_id = generate_id();
    let root = build_idp_entity_descriptor(inputs, &entity_descriptor_id)?;

    let final_root = if let Some((key, sig_alg, digest, c14n)) = signer {
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

fn build_idp_entity_descriptor(
    inputs: &IdpMetadataInputs<'_>,
    entity_descriptor_id: &str,
) -> Result<Element, Error> {
    // ── <md:IDPSSODescriptor> ────────────────────────────────────────────
    let mut idp_descriptor = Element::build(md_qname("IDPSSODescriptor"))
        .with_attribute(
            QName::new(None, "protocolSupportEnumeration"),
            SAML2_PROTOCOL,
        )
        .with_attribute(
            QName::new(None, "WantAuthnRequestsSigned"),
            bool_str(inputs.want_authn_requests_signed),
        );

    // KeyDescriptors.
    idp_descriptor = idp_descriptor.with_child(Node::Element(build_signing_key_descriptor(
        inputs.signing_cert,
    )));
    #[cfg(feature = "xmlenc")]
    if let Some(cert) = inputs.encryption_cert {
        idp_descriptor = idp_descriptor.with_child(Node::Element(build_encryption_key_descriptor(
            cert,
            inputs.encryption_algorithms,
        )));
    }

    // NameIDFormats.
    for fmt in inputs.name_id_formats {
        idp_descriptor = idp_descriptor.with_child(Node::Element(
            Element::build(md_qname("NameIDFormat"))
                .with_text(fmt.as_uri().to_owned())
                .finish(),
        ));
    }

    // SingleSignOnService endpoints.
    for endpoint in inputs.sso {
        idp_descriptor = idp_descriptor.with_child(Node::Element(build_sso_endpoint(endpoint)));
    }

    // SingleLogoutService endpoints.
    for endpoint in inputs.slo {
        idp_descriptor = idp_descriptor.with_child(Node::Element(build_slo_endpoint(endpoint)));
    }

    // ArtifactResolutionService endpoints (indexed; the schema requires an
    // `index` attribute on each — we emit one even if the caller forgot, to
    // keep the output schema-valid).
    for endpoint in inputs.artifact_resolution {
        idp_descriptor =
            idp_descriptor.with_child(Node::Element(build_artifact_resolution_endpoint(endpoint)));
    }

    let idp_descriptor = idp_descriptor.finish();

    // ── <md:EntityDescriptor> wrapper ────────────────────────────────────
    let mut entity_descriptor = Element::build(md_qname("EntityDescriptor"))
        .with_namespace(Some("md".to_owned()), MD_NS)
        .with_namespace(Some("ds".to_owned()), DS_NS)
        .with_attribute(QName::new(None, "entityID"), inputs.entity_id.to_owned())
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

    entity_descriptor = entity_descriptor.with_child(Node::Element(idp_descriptor));

    if let Some(extras) = inputs.extras {
        entity_descriptor = append_extras(entity_descriptor, extras);
    }

    Ok(entity_descriptor.finish())
}

fn build_sso_endpoint(endpoint: &Endpoint) -> Element {
    // `<md:SingleSignOnService>` is not indexed per schema. We deliberately
    // do not emit `index` / `isDefault` here even if the input carries them.
    Element::build(md_qname("SingleSignOnService"))
        .with_attribute(QName::new(None, "Binding"), endpoint.binding.uri())
        .with_attribute(QName::new(None, "Location"), endpoint.url.clone())
        .finish()
}

fn build_slo_endpoint(endpoint: &Endpoint) -> Element {
    // Same constraint as `<md:SingleLogoutService>` on the SP side: not
    // indexed per schema.
    Element::build(md_qname("SingleLogoutService"))
        .with_attribute(QName::new(None, "Binding"), endpoint.binding.uri())
        .with_attribute(QName::new(None, "Location"), endpoint.url.clone())
        .finish()
}

fn build_artifact_resolution_endpoint(endpoint: &Endpoint) -> Element {
    let mut builder = Element::build(md_qname("ArtifactResolutionService"))
        .with_attribute(QName::new(None, "Binding"), endpoint.binding.uri())
        .with_attribute(QName::new(None, "Location"), endpoint.url.clone());
    // Schema requires an `index` attribute on ArtifactResolutionService.
    // Fall back to `0` if the caller did not supply one.
    let index = endpoint.index.unwrap_or(0);
    builder = builder.with_attribute(QName::new(None, "index"), index.to_string());
    if endpoint.is_default {
        builder = builder.with_attribute(QName::new(None, "isDefault"), "true");
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
    use crate::binding::{Binding, Endpoint};
    use crate::crypto::cert::X509Certificate;
    use crate::crypto::cert::test_vectors::{RSA_CERT_PEM, RSA_KEY_PKCS8_PEM};
    use crate::dsig::algorithms::{C14nAlgorithm, DigestAlgorithm, SignatureAlgorithm};
    use crate::metadata::{
        MetadataContact, MetadataContactType, MetadataExtras, MetadataOrganization,
    };
    use crate::xml::parse::Document;
    use std::time::{Duration, SystemTime};

    const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";

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
        sso: &'a [Endpoint],
        slo: &'a [Endpoint],
        ars: &'a [Endpoint],
        formats: &'a [NameIdFormat],
        algos: &'a [DataEncryptionAlgorithm],
    ) -> IdpMetadataInputs<'a> {
        IdpMetadataInputs {
            entity_id: "https://idp.example.com/saml",
            sso,
            slo,
            artifact_resolution: ars,
            name_id_formats: formats,
            signing_cert: cert,
            encryption_cert: Some(cert),
            encryption_algorithms: algos,
            want_authn_requests_signed: true,
            valid_until: None,
            cache_duration: None,
            extras: None,
        }
    }

    #[test]
    fn emits_well_formed_idp_descriptor_with_expected_shape() {
        let cert = rsa_cert();
        let sso = [
            Endpoint::post("https://idp.example.com/sso/post", 0, true),
            Endpoint::redirect("https://idp.example.com/sso/redir", 1, false),
        ];
        let slo = [Endpoint::redirect("https://idp.example.com/slo", 0, false)];
        let ars = [Endpoint::soap("https://idp.example.com/ars", Some(0), true)];
        let formats = [NameIdFormat::Persistent, NameIdFormat::Transient];
        let algos = [DataEncryptionAlgorithm::Aes256Gcm];
        let inputs = baseline_inputs(&cert, &sso, &slo, &ars, &formats, &algos);

        let xml = emit_idp_metadata(&inputs, None).expect("emit");
        let doc = Document::parse(xml.as_bytes()).expect("re-parse");
        let root = doc.root();
        assert_eq!(root.qname().namespace(), Some(MD_NS));
        assert_eq!(root.qname().local(), "EntityDescriptor");
        assert_eq!(
            root.attribute(None, "entityID"),
            Some("https://idp.example.com/saml")
        );

        let idp_desc = root
            .child_element(Some(MD_NS), "IDPSSODescriptor")
            .expect("IDPSSODescriptor present");
        assert_eq!(
            idp_desc.attribute(None, "protocolSupportEnumeration"),
            Some(SAML2_PROTOCOL)
        );
        assert_eq!(
            idp_desc.attribute(None, "WantAuthnRequestsSigned"),
            Some("true")
        );

        // KeyDescriptors: one signing, one encryption.
        let key_descriptors: Vec<_> = idp_desc
            .all_child_elements(Some(MD_NS), "KeyDescriptor")
            .collect();
        assert_eq!(key_descriptors.len(), 2);
        assert_eq!(key_descriptors[0].attribute(None, "use"), Some("signing"));
        assert_eq!(
            key_descriptors[1].attribute(None, "use"),
            Some("encryption")
        );
        let enc_methods: Vec<_> = key_descriptors[1]
            .all_child_elements(Some(MD_NS), "EncryptionMethod")
            .collect();
        assert_eq!(enc_methods.len(), 1);
        assert_eq!(
            enc_methods[0].attribute(None, "Algorithm"),
            Some(DataEncryptionAlgorithm::Aes256Gcm.uri())
        );

        // NameIDFormats in input order.
        let formats: Vec<_> = idp_desc
            .all_child_elements(Some(MD_NS), "NameIDFormat")
            .map(Element::text_content)
            .collect();
        assert_eq!(
            formats,
            vec![
                NameIdFormat::Persistent.as_uri().to_owned(),
                NameIdFormat::Transient.as_uri().to_owned(),
            ]
        );

        // SSO endpoints emit Binding + Location, no index/isDefault.
        let sso_elements: Vec<_> = idp_desc
            .all_child_elements(Some(MD_NS), "SingleSignOnService")
            .collect();
        assert_eq!(sso_elements.len(), 2);
        assert_eq!(
            sso_elements[0].attribute(None, "Binding"),
            Some(Binding::HttpPost.uri())
        );
        assert_eq!(
            sso_elements[0].attribute(None, "Location"),
            Some("https://idp.example.com/sso/post")
        );
        assert_eq!(sso_elements[0].attribute(None, "index"), None);
        assert_eq!(sso_elements[0].attribute(None, "isDefault"), None);
        assert_eq!(
            sso_elements[1].attribute(None, "Binding"),
            Some(Binding::HttpRedirect.uri())
        );

        // SLO endpoint.
        let slo_elements: Vec<_> = idp_desc
            .all_child_elements(Some(MD_NS), "SingleLogoutService")
            .collect();
        assert_eq!(slo_elements.len(), 1);
        assert_eq!(
            slo_elements[0].attribute(None, "Binding"),
            Some(Binding::HttpRedirect.uri())
        );

        // ArtifactResolution endpoint carries index + isDefault.
        let ars_elements: Vec<_> = idp_desc
            .all_child_elements(Some(MD_NS), "ArtifactResolutionService")
            .collect();
        assert_eq!(ars_elements.len(), 1);
        assert_eq!(
            ars_elements[0].attribute(None, "Binding"),
            Some(Binding::Soap.uri())
        );
        assert_eq!(ars_elements[0].attribute(None, "index"), Some("0"));
        assert_eq!(ars_elements[0].attribute(None, "isDefault"), Some("true"));
    }

    #[test]
    fn valid_until_and_cache_duration_emit_attributes() {
        let cert = rsa_cert();
        let sso = [Endpoint::post("https://idp.example.com/sso", 0, true)];
        let formats = [NameIdFormat::Persistent];
        let algos: [DataEncryptionAlgorithm; 0] = [];
        let mut inputs = baseline_inputs(&cert, &sso, &[], &[], &formats, &algos);
        let valid_until = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000_000);
        inputs.valid_until = Some(valid_until);
        inputs.cache_duration = Some(Duration::from_hours(2));

        let xml = emit_idp_metadata(&inputs, None).unwrap();
        let doc = Document::parse(xml.as_bytes()).unwrap();
        let root = doc.root();
        let vu = root.attribute(None, "validUntil").expect("validUntil");
        let parsed = crate::time::parse_xs_datetime(vu).expect("parse");
        assert_eq!(parsed, valid_until);
        assert_eq!(root.attribute(None, "cacheDuration"), Some("PT7200S"));
    }

    #[test]
    fn extras_emit_organization_and_contact_person() {
        let cert = rsa_cert();
        let sso = [Endpoint::post("https://idp.example.com/sso", 0, true)];
        let formats = [NameIdFormat::Persistent];
        let algos: [DataEncryptionAlgorithm; 0] = [];
        let extras = MetadataExtras {
            organization: Some(MetadataOrganization {
                name: "Example IdP Inc".into(),
                display_name: "Example Identity Provider".into(),
                url: "https://idp.example.com".into(),
                language: "en-US".into(),
            }),
            contacts: vec![
                MetadataContact {
                    contact_type: MetadataContactType::Technical,
                    given_name: Some("Sam".into()),
                    surname: None,
                    email_addresses: vec!["ops@idp.example.com".into()],
                    telephone_numbers: vec![],
                    company: None,
                },
                MetadataContact {
                    contact_type: MetadataContactType::Support,
                    given_name: None,
                    surname: None,
                    email_addresses: vec!["help@idp.example.com".into()],
                    telephone_numbers: vec!["+15550000".into(), "+15550001".into()],
                    company: Some("Example IdP Inc".into()),
                },
            ],
        };
        let mut inputs = baseline_inputs(&cert, &sso, &[], &[], &formats, &algos);
        inputs.extras = Some(&extras);

        let xml = emit_idp_metadata(&inputs, None).unwrap();
        let doc = Document::parse(xml.as_bytes()).unwrap();
        let root = doc.root();
        let org = root
            .child_element(Some(MD_NS), "Organization")
            .expect("Organization");
        assert_eq!(
            org.child_element(Some(MD_NS), "OrganizationName")
                .map(Element::text_content),
            Some("Example IdP Inc".to_owned())
        );
        assert_eq!(
            org.child_element(Some(MD_NS), "OrganizationName")
                .and_then(|e| e.attribute(Some(XML_NS), "lang").map(str::to_owned)),
            Some("en-US".to_owned())
        );

        // Both ContactPersons emitted in input order.
        let contacts: Vec<_> = root
            .all_child_elements(Some(MD_NS), "ContactPerson")
            .collect();
        assert_eq!(contacts.len(), 2);
        assert_eq!(
            contacts[0].attribute(None, "contactType"),
            Some("technical")
        );
        assert_eq!(contacts[1].attribute(None, "contactType"), Some("support"));

        // Second contact has two phone numbers, in input order.
        let phones: Vec<_> = contacts[1]
            .all_child_elements(Some(MD_NS), "TelephoneNumber")
            .map(Element::text_content)
            .collect();
        assert_eq!(phones, vec!["+15550000".to_owned(), "+15550001".to_owned()]);
    }

    #[test]
    fn signed_metadata_carries_ds_signature_referencing_entity_descriptor_id() {
        let cert = rsa_cert();
        let sso = [Endpoint::post("https://idp.example.com/sso", 0, true)];
        let formats = [NameIdFormat::Persistent];
        let algos: [DataEncryptionAlgorithm; 0] = [];
        let inputs = baseline_inputs(&cert, &sso, &[], &[], &formats, &algos);

        let kp = signing_keypair();
        let xml = emit_idp_metadata(
            &inputs,
            Some((
                &kp,
                SignatureAlgorithm::RsaSha256,
                DigestAlgorithm::Sha256,
                C14nAlgorithm::ExclusiveCanonical,
            )),
        )
        .expect("sign + emit");

        let doc = Document::parse(xml.as_bytes()).unwrap();
        let root = doc.root();
        let id_attr = root.attribute(None, "ID").expect("ID");

        // Signature is the first child of EntityDescriptor.
        let children: Vec<_> = root.child_elements().collect();
        assert!(!children.is_empty());
        assert_eq!(children[0].qname().namespace(), Some(DS_NS));
        assert_eq!(children[0].qname().local(), "Signature");

        // Reference URI matches "#<ID>".
        let signed_info = children[0]
            .child_element(Some(DS_NS), "SignedInfo")
            .unwrap();
        let reference = signed_info.child_element(Some(DS_NS), "Reference").unwrap();
        assert_eq!(
            reference.attribute(None, "URI"),
            Some(format!("#{id_attr}").as_str())
        );

        // C14n algorithm in the SignedInfo is the one we requested.
        let c14n_method = signed_info
            .child_element(Some(DS_NS), "CanonicalizationMethod")
            .unwrap();
        assert_eq!(
            c14n_method.attribute(None, "Algorithm"),
            Some(C14nAlgorithm::ExclusiveCanonical.uri())
        );

        // IDPSSODescriptor is still present after the signature.
        assert!(
            root.child_element(Some(MD_NS), "IDPSSODescriptor")
                .is_some()
        );
    }

    #[test]
    fn omits_encryption_key_descriptor_when_cert_absent() {
        let cert = rsa_cert();
        let sso = [Endpoint::post("https://idp.example.com/sso", 0, true)];
        let formats = [NameIdFormat::Persistent];
        let algos: [DataEncryptionAlgorithm; 0] = [];
        let mut inputs = baseline_inputs(&cert, &sso, &[], &[], &formats, &algos);
        inputs.encryption_cert = None;

        let xml = emit_idp_metadata(&inputs, None).unwrap();
        let doc = Document::parse(xml.as_bytes()).unwrap();
        let idp_desc = doc
            .root()
            .child_element(Some(MD_NS), "IDPSSODescriptor")
            .unwrap();
        let kds: Vec<_> = idp_desc
            .all_child_elements(Some(MD_NS), "KeyDescriptor")
            .collect();
        assert_eq!(kds.len(), 1);
        assert_eq!(kds[0].attribute(None, "use"), Some("signing"));
    }

    #[test]
    fn want_authn_requests_signed_false_emits_false() {
        let cert = rsa_cert();
        let sso = [Endpoint::post("https://idp.example.com/sso", 0, true)];
        let formats = [NameIdFormat::Persistent];
        let algos: [DataEncryptionAlgorithm; 0] = [];
        let mut inputs = baseline_inputs(&cert, &sso, &[], &[], &formats, &algos);
        inputs.want_authn_requests_signed = false;

        let xml = emit_idp_metadata(&inputs, None).unwrap();
        let doc = Document::parse(xml.as_bytes()).unwrap();
        let idp_desc = doc
            .root()
            .child_element(Some(MD_NS), "IDPSSODescriptor")
            .unwrap();
        assert_eq!(
            idp_desc.attribute(None, "WantAuthnRequestsSigned"),
            Some("false")
        );
    }
}
