//! Parsed view of an IdP peer's metadata (`<md:IDPSSODescriptor>`).
//!
//! See `docs/rfcs/RFC-006-metadata.md` §2.

use std::time::{Duration, SystemTime};

use crate::binding::{Binding, Endpoint};
use crate::crypto::cert::X509Certificate;
use crate::error::Error;
use crate::nameid::NameIdFormat;
use crate::xml::parse::{Document, Element};

use crate::metadata::parse::{
    MD_NS, find_entity_descriptor, is_md_element, parse_endpoint, parse_key_descriptors,
    parse_name_id_formats, parse_optional_bool, parse_optional_duration,
    parse_optional_xs_datetime,
};

/// Parsed `<md:IDPSSODescriptor>` plus the enclosing `<md:EntityDescriptor>`'s
/// `entityID`. Field meanings track RFC-006 §2.
#[derive(Debug, Clone)]
pub struct IdpDescriptor {
    pub entity_id: String,
    pub sso_endpoints: Vec<Endpoint>,
    pub slo_endpoints: Vec<Endpoint>,
    pub artifact_resolution_endpoints: Vec<Endpoint>,
    pub signing_certs: Vec<X509Certificate>,
    pub encryption_certs: Vec<X509Certificate>,
    pub supported_name_id_formats: Vec<NameIdFormat>,
    pub want_authn_requests_signed: bool,
    pub valid_until: Option<SystemTime>,
    pub cache_duration: Option<Duration>,
}

impl IdpDescriptor {
    /// Parse IdP metadata from raw XML bytes. Accepts a single
    /// `<md:EntityDescriptor>` root or an `<md:EntitiesDescriptor>` aggregate
    /// (in which case the first entity carrying an `<md:IDPSSODescriptor>` is
    /// returned).
    pub fn from_metadata_xml(xml: &[u8]) -> Result<Self, Error> {
        let doc = Document::parse(xml)?;
        let entity =
            find_entity_descriptor(doc.root(), |e| {
                e.child_element(Some(MD_NS), "IDPSSODescriptor").is_some()
            })
            .ok_or(Error::InvalidConfiguration {
                reason: "metadata does not contain an IdP entity",
            })?;
        Self::from_entity_descriptor_element(entity)
    }

    pub(crate) fn from_entity_descriptor_element(element: &Element) -> Result<Self, Error> {
        if !is_md_element(element, "EntityDescriptor") {
            return Err(Error::InvalidConfiguration {
                reason: "expected <md:EntityDescriptor>",
            });
        }

        let entity_id = element
            .attribute(None, "entityID")
            .ok_or(Error::InvalidConfiguration {
                reason: "EntityDescriptor missing entityID",
            })?
            .to_owned();

        let idp = element
            .child_element(Some(MD_NS), "IDPSSODescriptor")
            .ok_or(Error::InvalidConfiguration {
                reason: "EntityDescriptor missing IDPSSODescriptor",
            })?;

        let want_authn_requests_signed =
            parse_optional_bool(idp, "WantAuthnRequestsSigned")?.unwrap_or(false);
        let valid_until = parse_optional_xs_datetime(idp, "validUntil")?
            .or(parse_optional_xs_datetime(element, "validUntil")?);
        let cache_duration = parse_optional_duration(idp, "cacheDuration")?
            .or(parse_optional_duration(element, "cacheDuration")?);

        let (signing_certs, encryption_certs) = parse_key_descriptors(idp)?;

        let mut sso_endpoints = Vec::new();
        for child in idp.all_child_elements(Some(MD_NS), "SingleSignOnService") {
            sso_endpoints.push(parse_endpoint(child)?);
        }

        let mut slo_endpoints = Vec::new();
        for child in idp.all_child_elements(Some(MD_NS), "SingleLogoutService") {
            slo_endpoints.push(parse_endpoint(child)?);
        }

        let mut artifact_resolution_endpoints = Vec::new();
        for child in idp.all_child_elements(Some(MD_NS), "ArtifactResolutionService") {
            artifact_resolution_endpoints.push(parse_endpoint(child)?);
        }

        let supported_name_id_formats = parse_name_id_formats(idp);

        Ok(Self {
            entity_id,
            sso_endpoints,
            slo_endpoints,
            artifact_resolution_endpoints,
            signing_certs,
            encryption_certs,
            supported_name_id_formats,
            want_authn_requests_signed,
            valid_until,
            cache_duration,
        })
    }

    /// Locate an SSO endpoint that advertises the requested binding. First
    /// match wins; metadata that advertises the same binding twice is not
    /// usefully disambiguable.
    pub fn sso_endpoint(&self, binding: Binding) -> Option<&Endpoint> {
        self.sso_endpoints.iter().find(|e| e.binding == binding)
    }

    /// Locate an SLO endpoint that advertises the requested binding.
    pub fn slo_endpoint(&self, binding: Binding) -> Option<&Endpoint> {
        self.slo_endpoints.iter().find(|e| e.binding == binding)
    }

    /// Return the first `<md:ArtifactResolutionService>` endpoint, if any.
    /// Artifact resolution is always SOAP per the SAML 2.0 spec, so there's
    /// no binding to disambiguate.
    pub fn artifact_resolution_endpoint(&self) -> Option<&Endpoint> {
        // Prefer the endpoint flagged isDefault if any.
        if let Some(d) = self.artifact_resolution_endpoints.iter().find(|e| e.is_default) {
            return Some(d);
        }
        self.artifact_resolution_endpoints.first()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::Binding;
    use crate::crypto::cert::X509Certificate;
    use crate::crypto::cert::test_vectors::RSA_CERT_PEM;

    fn rsa_cert_b64() -> String {
        X509Certificate::from_pem(RSA_CERT_PEM)
            .unwrap()
            .to_base64_x509()
    }

    fn idp_metadata_xml() -> String {
        format!(
            r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                                     entityID="https://idp.example.com/saml"
                                     validUntil="2030-01-01T00:00:00Z">
              <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"
                                   WantAuthnRequestsSigned="true"
                                   cacheDuration="PT1H">
                <md:KeyDescriptor use="signing">
                  <ds:KeyInfo>
                    <ds:X509Data>
                      <ds:X509Certificate>{cert}</ds:X509Certificate>
                    </ds:X509Data>
                  </ds:KeyInfo>
                </md:KeyDescriptor>
                <md:KeyDescriptor use="encryption">
                  <ds:KeyInfo>
                    <ds:X509Data>
                      <ds:X509Certificate>{cert}</ds:X509Certificate>
                    </ds:X509Data>
                  </ds:KeyInfo>
                </md:KeyDescriptor>
                <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
                <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
                <md:SingleSignOnService
                    Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                    Location="https://idp.example.com/sso/redirect"/>
                <md:SingleSignOnService
                    Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                    Location="https://idp.example.com/sso/post"/>
                <md:SingleLogoutService
                    Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                    Location="https://idp.example.com/slo"/>
                <md:ArtifactResolutionService
                    Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
                    Location="https://idp.example.com/ars" index="0"/>
              </md:IDPSSODescriptor>
            </md:EntityDescriptor>"#,
            cert = rsa_cert_b64()
        )
    }

    #[test]
    fn parses_idp_metadata_full_shape() {
        let xml = idp_metadata_xml();
        let idp = IdpDescriptor::from_metadata_xml(xml.as_bytes()).expect("parse ok");

        assert_eq!(idp.entity_id, "https://idp.example.com/saml");
        assert!(idp.want_authn_requests_signed);
        assert_eq!(idp.cache_duration, Some(Duration::from_hours(1)));
        assert!(idp.valid_until.is_some());

        assert_eq!(idp.sso_endpoints.len(), 2);
        assert_eq!(idp.slo_endpoints.len(), 1);
        assert_eq!(idp.artifact_resolution_endpoints.len(), 1);
        assert_eq!(idp.signing_certs.len(), 1);
        assert_eq!(idp.encryption_certs.len(), 1);
        assert_eq!(idp.supported_name_id_formats.len(), 2);
        assert_eq!(
            idp.supported_name_id_formats[0],
            NameIdFormat::EmailAddress
        );
    }

    #[test]
    fn sso_endpoint_dispatches_on_binding() {
        let idp = IdpDescriptor::from_metadata_xml(idp_metadata_xml().as_bytes()).unwrap();
        assert_eq!(
            idp.sso_endpoint(Binding::HttpRedirect).unwrap().url,
            "https://idp.example.com/sso/redirect"
        );
        assert_eq!(
            idp.sso_endpoint(Binding::HttpPost).unwrap().url,
            "https://idp.example.com/sso/post"
        );
        assert!(idp.sso_endpoint(Binding::HttpArtifact).is_none());
    }

    #[test]
    fn slo_endpoint_lookup() {
        let idp = IdpDescriptor::from_metadata_xml(idp_metadata_xml().as_bytes()).unwrap();
        assert!(idp.slo_endpoint(Binding::HttpRedirect).is_some());
        assert!(idp.slo_endpoint(Binding::HttpPost).is_none());
    }

    #[test]
    fn artifact_resolution_endpoint_lookup() {
        let idp = IdpDescriptor::from_metadata_xml(idp_metadata_xml().as_bytes()).unwrap();
        let ars = idp.artifact_resolution_endpoint().unwrap();
        assert_eq!(ars.url, "https://idp.example.com/ars");
        assert_eq!(ars.binding, Binding::Soap);
        assert_eq!(ars.index, Some(0));
    }

    #[test]
    fn no_use_attribute_key_descriptor_lands_in_both_lists() {
        let xml = format!(
            r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                                     entityID="https://idp.example.com/saml">
              <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                <md:KeyDescriptor>
                  <ds:KeyInfo>
                    <ds:X509Data>
                      <ds:X509Certificate>{cert}</ds:X509Certificate>
                    </ds:X509Data>
                  </ds:KeyInfo>
                </md:KeyDescriptor>
                <md:SingleSignOnService
                    Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                    Location="https://idp.example.com/sso/post"/>
              </md:IDPSSODescriptor>
            </md:EntityDescriptor>"#,
            cert = rsa_cert_b64()
        );
        let idp = IdpDescriptor::from_metadata_xml(xml.as_bytes()).unwrap();
        assert_eq!(idp.signing_certs.len(), 1);
        assert_eq!(idp.encryption_certs.len(), 1);
        assert_eq!(idp.signing_certs[0], idp.encryption_certs[0]);
    }

    #[test]
    fn missing_entity_id_is_rejected() {
        let xml = format!(
            r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
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
        let err = IdpDescriptor::from_metadata_xml(xml.as_bytes()).unwrap_err();
        match err {
            Error::InvalidConfiguration { reason } => {
                assert_eq!(reason, "EntityDescriptor missing entityID");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn metadata_without_idp_role_is_rejected() {
        let xml = r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     entityID="https://sp.example.com/saml">
              <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                <md:AssertionConsumerService
                    index="0"
                    Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                    Location="https://sp.example.com/acs"/>
              </md:SPSSODescriptor>
            </md:EntityDescriptor>"#;
        let err = IdpDescriptor::from_metadata_xml(xml.as_bytes()).unwrap_err();
        assert!(matches!(err, Error::InvalidConfiguration { .. }));
    }

    #[test]
    fn aggregate_root_picks_first_idp() {
        let xml = format!(
            r#"<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                                       xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <md:EntityDescriptor entityID="https://sp.example.com/saml">
                  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                    <md:AssertionConsumerService index="0"
                      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                      Location="https://sp.example.com/acs"/>
                  </md:SPSSODescriptor>
                </md:EntityDescriptor>
                <md:EntityDescriptor entityID="https://idp.example.com/saml">
                  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                    <md:KeyDescriptor use="signing">
                      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
                    </md:KeyDescriptor>
                    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                            Location="https://idp.example.com/sso"/>
                  </md:IDPSSODescriptor>
                </md:EntityDescriptor>
              </md:EntitiesDescriptor>"#,
            cert = rsa_cert_b64()
        );
        let idp = IdpDescriptor::from_metadata_xml(xml.as_bytes()).expect("parse ok");
        assert_eq!(idp.entity_id, "https://idp.example.com/saml");
        assert_eq!(idp.sso_endpoints.len(), 1);
        assert_eq!(idp.signing_certs.len(), 1);
    }

    #[test]
    fn from_entity_descriptor_element_directly() {
        let xml = idp_metadata_xml();
        let doc = Document::parse(xml.as_bytes()).unwrap();
        let idp = IdpDescriptor::from_entity_descriptor_element(doc.root()).unwrap();
        assert_eq!(idp.entity_id, "https://idp.example.com/saml");
    }
}
