//! Emit a federation aggregate `<md:EntitiesDescriptor>` wrapping multiple
//! child `<md:EntityDescriptor>` elements — RFC-006 §3.
//!
//! This is the emit counterpart to [`EntitiesDescriptor`] parsing. It reuses
//! the single-entity builders in [`emit_idp`] / [`emit_sp`] rather than
//! duplicating the per-role XML walks; an aggregate is, structurally, just a
//! signed (or unsigned) wrapper around those same children.
//!
//! [`EntitiesDescriptor`]: crate::metadata::parse::EntitiesDescriptor
//! [`emit_idp`]: crate::metadata::emit_idp
//! [`emit_sp`]: crate::metadata::emit_sp

use crate::crypto::keypair::KeyPair;
use crate::dsig::algorithms::{C14nAlgorithm, DigestAlgorithm, SignatureAlgorithm};
use crate::error::Error;
use crate::xml::emit::emit_document;
use crate::xml::parse::{Document, Element, Node, QName};

use super::emit_idp::{IdpMetadataInputs, build_idp_entity_descriptor};
use super::emit_sp::{
    DS_NS, MD_NS, SpMetadataInputs, build_sp_entity_descriptor, format_cache_duration, generate_id,
    md_qname,
};

/// One child entity to place in the aggregate. Each variant carries the same
/// per-role inputs the single-entity emit functions take, so the aggregate
/// emitter is a thin wrapper that delegates child construction.
pub enum AggregateMember<'a> {
    /// An IdP-only `<md:EntityDescriptor>`.
    Idp(IdpMetadataInputs<'a>),
    /// An SP-only `<md:EntityDescriptor>`.
    Sp(SpMetadataInputs<'a>),
}

/// Caller-supplied aggregate fields. Mirrors the parsed
/// [`EntitiesDescriptor`](crate::metadata::parse::EntitiesDescriptor) shape.
pub struct EntitiesDescriptorInputs<'a> {
    /// Optional federation `Name` attribute (commonly a `urn:` identifier).
    pub name: Option<&'a str>,
    pub valid_until: Option<std::time::SystemTime>,
    pub cache_duration: Option<std::time::Duration>,
    pub members: &'a [AggregateMember<'a>],
}

/// Sign + emit an `<md:EntitiesDescriptor>` wrapping the given members.
///
/// When `signer` is `Some`, a single enveloped `<ds:Signature>` is added that
/// covers the **whole** `<md:EntitiesDescriptor>` element (via
/// `Reference URI="#<id>"`) — i.e. one signature over all children, the trust
/// model federations like InCommon publish. When `None`, the aggregate is
/// emitted unsigned.
pub fn emit_entities_descriptor(
    inputs: &EntitiesDescriptorInputs<'_>,
    signer: Option<(&KeyPair, SignatureAlgorithm, DigestAlgorithm, C14nAlgorithm)>,
) -> Result<String, Error> {
    let aggregate_id = generate_id();
    let root = build_entities_descriptor(inputs, &aggregate_id)?;

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

fn build_entities_descriptor(
    inputs: &EntitiesDescriptorInputs<'_>,
    aggregate_id: &str,
) -> Result<Element, Error> {
    let mut builder = Element::build(md_qname("EntitiesDescriptor"))
        .with_namespace(Some("md".to_owned()), MD_NS)
        .with_namespace(Some("ds".to_owned()), DS_NS)
        // ID is required for the enveloped-signature `Reference URI="#<id>"`
        // to resolve; emitted unconditionally so signed and unsigned output
        // are structurally identical.
        .with_attribute(QName::new(None, "ID"), aggregate_id.to_owned());

    if let Some(name) = inputs.name {
        builder = builder.with_attribute(QName::new(None, "Name"), name.to_owned());
    }
    if let Some(valid_until) = inputs.valid_until {
        builder = builder.with_attribute(
            QName::new(None, "validUntil"),
            crate::time::format_xs_datetime(valid_until)?,
        );
    }
    if let Some(cache_duration) = inputs.cache_duration {
        builder = builder.with_attribute(
            QName::new(None, "cacheDuration"),
            format_cache_duration(cache_duration),
        );
    }

    for member in inputs.members {
        // Each child gets its own `ID` (distinct from the aggregate's). The
        // wrapping signature covers them transitively via the parent
        // reference; child `ID`s are still useful so the emitted XML is a
        // valid input for the single-entity verify path if extracted.
        let child_id = generate_id();
        let child = match member {
            AggregateMember::Idp(idp) => build_idp_entity_descriptor(idp, &child_id)?,
            AggregateMember::Sp(sp) => build_sp_entity_descriptor(sp, &child_id)?,
        };
        builder = builder.with_child(Node::Element(child));
    }

    Ok(builder.finish())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[cfg(feature = "xmlenc")]
mod tests {
    use super::*;
    use crate::binding::{Endpoint, SsoResponseEndpoint};
    use crate::crypto::cert::X509Certificate;
    use crate::crypto::cert::test_vectors::{RSA_CERT_PEM, RSA_KEY_PKCS8_PEM};
    use crate::metadata::parse::{
        EntitiesDescriptor, MetadataEntry, parse_signed_entities_descriptor,
    };
    use crate::nameid::NameIdFormat;
    use crate::xmlenc::algorithms::DataEncryptionAlgorithm;

    fn rsa_cert() -> X509Certificate {
        X509Certificate::from_pem(RSA_CERT_PEM).unwrap()
    }

    fn signing_keypair() -> KeyPair {
        KeyPair::from_pkcs8_pem(RSA_KEY_PKCS8_PEM)
            .unwrap()
            .with_certificate(rsa_cert())
    }

    fn idp_member<'a>(
        cert: &'a X509Certificate,
        entity_id: &'a str,
        sso: &'a [Endpoint],
        formats: &'a [NameIdFormat],
        algos: &'a [DataEncryptionAlgorithm],
    ) -> AggregateMember<'a> {
        AggregateMember::Idp(IdpMetadataInputs {
            entity_id,
            sso,
            slo: &[],
            artifact_resolution: &[],
            name_id_formats: formats,
            signing_cert: cert,
            encryption_cert: None,
            encryption_algorithms: algos,
            want_authn_requests_signed: false,
            valid_until: None,
            cache_duration: None,
            extras: None,
        })
    }

    fn sp_member<'a>(
        cert: &'a X509Certificate,
        entity_id: &'a str,
        acs: &'a [SsoResponseEndpoint],
        formats: &'a [NameIdFormat],
        algos: &'a [DataEncryptionAlgorithm],
    ) -> AggregateMember<'a> {
        AggregateMember::Sp(SpMetadataInputs {
            entity_id,
            acs,
            slo: &[],
            name_id_formats: formats,
            signing_cert: Some(cert),
            encryption_cert: None,
            encryption_algorithms: algos,
            authn_requests_signed: false,
            want_assertions_signed: true,
            valid_until: None,
            cache_duration: None,
            extras: None,
        })
    }

    #[test]
    fn emits_aggregate_wrapping_idp_and_sp() {
        let cert = rsa_cert();
        let sso = [Endpoint::post("https://idp.example.com/sso", 0, true)];
        let acs = [SsoResponseEndpoint::post(
            "https://sp.example.com/acs",
            0,
            true,
        )];
        let formats = [NameIdFormat::Persistent];
        let algos: [DataEncryptionAlgorithm; 0] = [];
        let members = [
            idp_member(
                &cert,
                "https://idp.example.com/saml",
                &sso,
                &formats,
                &algos,
            ),
            sp_member(&cert, "https://sp.example.com/saml", &acs, &formats, &algos),
        ];
        let inputs = EntitiesDescriptorInputs {
            name: Some("urn:example:federation"),
            valid_until: None,
            cache_duration: None,
            members: &members,
        };

        let xml = emit_entities_descriptor(&inputs, None).expect("emit");
        let doc = Document::parse(xml.as_bytes()).expect("re-parse");
        let root = doc.root();
        assert_eq!(root.qname().local(), "EntitiesDescriptor");
        assert_eq!(root.attribute(None, "Name"), Some("urn:example:federation"));
        let children: Vec<_> = root
            .all_child_elements(Some(MD_NS), "EntityDescriptor")
            .collect();
        assert_eq!(children.len(), 2);
    }

    #[test]
    fn emit_then_parse_round_trip_resolves_both_entities() {
        let cert = rsa_cert();
        let sso = [Endpoint::post("https://idp.example.com/sso", 0, true)];
        let acs = [SsoResponseEndpoint::post(
            "https://sp.example.com/acs",
            0,
            true,
        )];
        let formats = [NameIdFormat::Persistent];
        let algos: [DataEncryptionAlgorithm; 0] = [];
        let members = [
            idp_member(
                &cert,
                "https://idp.example.com/saml",
                &sso,
                &formats,
                &algos,
            ),
            sp_member(&cert, "https://sp.example.com/saml", &acs, &formats, &algos),
        ];
        let inputs = EntitiesDescriptorInputs {
            name: None,
            valid_until: None,
            cache_duration: None,
            members: &members,
        };
        let xml = emit_entities_descriptor(&inputs, None).unwrap();
        let fed = EntitiesDescriptor::from_metadata_xml(xml.as_bytes()).unwrap();
        assert_eq!(fed.entities.len(), 2);
        assert!(fed.find_idp("https://idp.example.com/saml").is_some());
        assert!(fed.find_sp("https://sp.example.com/saml").is_some());
        assert!(matches!(
            fed.by_entity_id("https://idp.example.com/saml"),
            Some(MetadataEntry::Idp(_))
        ));
    }

    #[test]
    fn signed_aggregate_verifies_and_parses() {
        let cert = rsa_cert();
        let sso = [Endpoint::post("https://idp.example.com/sso", 0, true)];
        let formats = [NameIdFormat::Persistent];
        let algos: [DataEncryptionAlgorithm; 0] = [];
        let members = [idp_member(
            &cert,
            "https://idp.example.com/saml",
            &sso,
            &formats,
            &algos,
        )];
        let inputs = EntitiesDescriptorInputs {
            name: None,
            valid_until: None,
            cache_duration: None,
            members: &members,
        };
        let kp = signing_keypair();
        let xml = emit_entities_descriptor(
            &inputs,
            Some((
                &kp,
                SignatureAlgorithm::RsaSha256,
                DigestAlgorithm::Sha256,
                C14nAlgorithm::ExclusiveCanonical,
            )),
        )
        .expect("sign + emit");

        // The wrapping signature covers all children: verify-then-parse passes.
        let fed = parse_signed_entities_descriptor(xml.as_bytes(), &cert).expect("verify+parse");
        assert_eq!(fed.entities.len(), 1);
        assert!(fed.find_idp("https://idp.example.com/saml").is_some());
    }

    #[test]
    fn tampering_a_child_breaks_the_wrapper_signature() {
        let cert = rsa_cert();
        let sso = [Endpoint::post("https://idp.example.com/sso", 0, true)];
        let formats = [NameIdFormat::Persistent];
        let algos: [DataEncryptionAlgorithm; 0] = [];
        let members = [idp_member(
            &cert,
            "https://idp.example.com/saml",
            &sso,
            &formats,
            &algos,
        )];
        let inputs = EntitiesDescriptorInputs {
            name: None,
            valid_until: None,
            cache_duration: None,
            members: &members,
        };
        let kp = signing_keypair();
        let xml = emit_entities_descriptor(
            &inputs,
            Some((
                &kp,
                SignatureAlgorithm::RsaSha256,
                DigestAlgorithm::Sha256,
                C14nAlgorithm::ExclusiveCanonical,
            )),
        )
        .unwrap();

        // Flip a byte inside a child entity's Location URL. Negative control:
        // the wrapping signature must no longer verify.
        let tampered = xml.replacen(
            "https://idp.example.com/sso",
            "https://idp.evil.example/sso",
            1,
        );
        assert_ne!(tampered, xml, "tamper should have changed the document");
        match parse_signed_entities_descriptor(tampered.as_bytes(), &cert) {
            Err(Error::SignatureVerification { .. }) => {}
            Err(other) => panic!("unexpected error: {other:?}"),
            Ok(_) => panic!("tampered aggregate must not verify"),
        }
    }
}
