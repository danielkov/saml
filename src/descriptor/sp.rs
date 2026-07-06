//! Parsed view of an SP peer's metadata (`<md:SPSSODescriptor>`).
//!
//! See `docs/rfcs/RFC-006-metadata.md` §2 and §2.1.

use std::time::{Duration, SystemTime};

use crate::binding::{Binding, Endpoint, SsoResponseEndpoint};
use crate::crypto::cert::X509Certificate;
use crate::error::Error;
use crate::nameid::NameIdFormat;
use crate::xml::parse::{Document, Element};

use crate::metadata::parse::{
    MD_NS, find_entity_descriptor, is_md_element, parse_endpoint, parse_key_descriptors,
    parse_name_id_formats, parse_optional_bool, parse_optional_duration,
    parse_optional_xs_datetime,
};

/// Parsed `<md:SPSSODescriptor>`.
///
/// The `assertion_consumer_services` field is type-narrowed to
/// `SsoResponseEndpoint` per RFC-006 §2.1: an SP that advertises an ACS over
/// Redirect or SOAP is non-conformant per SAML 2.0 Profiles §4.1.4 and
/// accepting it would let the IdP later mint a Response over a binding the SP
/// cannot validate signatures for. `from_metadata_xml` rejects such metadata
/// outright.
#[derive(Debug, Clone)]
pub struct SpDescriptor {
    pub entity_id: String,
    pub assertion_consumer_services: Vec<SsoResponseEndpoint>,
    pub single_logout_services: Vec<Endpoint>,
    pub signing_certs: Vec<X509Certificate>,
    pub encryption_certs: Vec<X509Certificate>,
    pub supported_name_id_formats: Vec<NameIdFormat>,
    pub want_assertions_signed: bool,
    pub authn_requests_signed: bool,
    pub valid_until: Option<SystemTime>,
    pub cache_duration: Option<Duration>,
    /// `<idpdisc:DiscoveryResponse>` endpoints from the role descriptor's
    /// `<md:Extensions>` — the URLs a discovery service may redirect the
    /// user agent back to for this SP. See
    /// [`validate_discovery_return_url`](crate::disco::validate_discovery_return_url).
    #[cfg(feature = "idp-disco")]
    pub discovery_response_endpoints: Vec<crate::disco::DiscoveryResponseEndpoint>,
}

impl SpDescriptor {
    /// Parse SP metadata from raw XML bytes. Accepts a single
    /// `<md:EntityDescriptor>` root or an `<md:EntitiesDescriptor>` aggregate
    /// (in which case the first entity carrying an `<md:SPSSODescriptor>` is
    /// returned).
    ///
    /// Rejects non-conformant ACS bindings per RFC-006 §2.1.
    pub fn from_metadata_xml(xml: &[u8]) -> Result<Self, Error> {
        let doc = Document::parse(xml)?;
        let entity = find_entity_descriptor(doc.root(), |e| {
            e.child_element(Some(MD_NS), "SPSSODescriptor").is_some()
        })
        .ok_or(Error::InvalidConfiguration {
            reason: "metadata does not contain an SP entity",
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

        let sp = element
            .child_element(Some(MD_NS), "SPSSODescriptor")
            .ok_or(Error::InvalidConfiguration {
                reason: "EntityDescriptor missing SPSSODescriptor",
            })?;

        let authn_requests_signed =
            parse_optional_bool(sp, "AuthnRequestsSigned")?.unwrap_or(false);
        let want_assertions_signed =
            parse_optional_bool(sp, "WantAssertionsSigned")?.unwrap_or(false);
        let valid_until = parse_optional_xs_datetime(sp, "validUntil")?
            .or(parse_optional_xs_datetime(element, "validUntil")?);
        let cache_duration = parse_optional_duration(sp, "cacheDuration")?
            .or(parse_optional_duration(element, "cacheDuration")?);

        let (signing_certs, encryption_certs) = parse_key_descriptors(sp)?;

        // RFC-006 §2.1: narrow each ACS endpoint to SsoResponseEndpoint. A
        // Redirect or SOAP ACS is silently allowed by the underlying schema
        // but is non-conformant per SAML 2.0 Profiles §4.1.4. Surface it as a
        // structured parse error so the caller cannot accept SP metadata
        // that would later let the IdP mint a Response over an illegal
        // binding.
        let mut assertion_consumer_services = Vec::new();
        for child in sp.all_child_elements(Some(MD_NS), "AssertionConsumerService") {
            let endpoint = parse_endpoint(child)?;
            let narrowed =
                SsoResponseEndpoint::try_from_endpoint(endpoint).map_err(|e| match e {
                    Error::InvalidConfiguration { .. } => Error::InvalidConfiguration {
                        reason: "SP metadata advertises ACS with non-POST/Artifact binding",
                    },
                    other => other,
                })?;
            assertion_consumer_services.push(narrowed);
        }

        let mut single_logout_services = Vec::new();
        for child in sp.all_child_elements(Some(MD_NS), "SingleLogoutService") {
            single_logout_services.push(parse_endpoint(child)?);
        }

        let supported_name_id_formats = parse_name_id_formats(sp);

        #[cfg(feature = "idp-disco")]
        let discovery_response_endpoints = crate::disco::parse_discovery_response_extensions(sp)?;

        Ok(Self {
            entity_id,
            assertion_consumer_services,
            single_logout_services,
            signing_certs,
            encryption_certs,
            supported_name_id_formats,
            want_assertions_signed,
            authn_requests_signed,
            valid_until,
            cache_duration,
            #[cfg(feature = "idp-disco")]
            discovery_response_endpoints,
        })
    }

    /// Look up an ACS endpoint by metadata-advertised `index`.
    pub fn acs_endpoint_by_index(&self, index: u16) -> Option<&SsoResponseEndpoint> {
        self.assertion_consumer_services
            .iter()
            .find(|e| e.index == Some(index))
    }

    /// Look up an ACS endpoint by exact-match URL. Used to verify that an
    /// inbound `AssertionConsumerServiceURL` on an AuthnRequest matches one
    /// advertised in metadata.
    pub fn acs_endpoint_by_url(&self, url: &str) -> Option<&SsoResponseEndpoint> {
        self.assertion_consumer_services
            .iter()
            .find(|e| e.url == url)
    }

    /// Default ACS endpoint: the entry flagged `isDefault="true"`, falling
    /// back to the first entry if none is so flagged.
    pub fn default_acs(&self) -> Option<&SsoResponseEndpoint> {
        if let Some(d) = self
            .assertion_consumer_services
            .iter()
            .find(|e| e.is_default)
        {
            return Some(d);
        }
        self.assertion_consumer_services.first()
    }

    /// SLO endpoint advertising the requested binding.
    pub fn slo_endpoint(&self, binding: Binding) -> Option<&Endpoint> {
        self.single_logout_services
            .iter()
            .find(|e| e.binding == binding)
    }

    /// First encryption cert, if any. Convenience: most SPs advertise exactly
    /// one encryption cert and callers want it for `EncryptedAssertion`
    /// decryption.
    pub fn encryption_cert(&self) -> Option<&X509Certificate> {
        self.encryption_certs.first()
    }

    /// Default `<idpdisc:DiscoveryResponse>` endpoint: the entry flagged
    /// `isDefault="true"`, falling back to the first entry if none is so
    /// flagged. Mirrors [`Self::default_acs`].
    #[cfg(feature = "idp-disco")]
    pub fn default_discovery_response(&self) -> Option<&crate::disco::DiscoveryResponseEndpoint> {
        self.discovery_response_endpoints
            .iter()
            .find(|e| e.is_default)
            .or_else(|| self.discovery_response_endpoints.first())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::{Binding, SsoResponseBinding};
    use crate::crypto::cert::X509Certificate;
    use crate::crypto::cert::test_vectors::RSA_CERT_PEM;

    fn rsa_cert_b64() -> String {
        X509Certificate::from_pem(RSA_CERT_PEM)
            .unwrap()
            .to_base64_x509()
    }

    fn sp_metadata_xml() -> String {
        format!(
            r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                                     entityID="https://sp.example.com/saml"
                                     validUntil="2030-01-01T00:00:00Z">
              <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"
                                  AuthnRequestsSigned="true"
                                  WantAssertionsSigned="true"
                                  cacheDuration="PT15M">
                <md:KeyDescriptor use="signing">
                  <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
                </md:KeyDescriptor>
                <md:KeyDescriptor use="encryption">
                  <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
                </md:KeyDescriptor>
                <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
                <md:AssertionConsumerService
                    index="0" isDefault="true"
                    Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                    Location="https://sp.example.com/acs/post"/>
                <md:AssertionConsumerService
                    index="1"
                    Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"
                    Location="https://sp.example.com/acs/artifact"/>
                <md:SingleLogoutService
                    Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                    Location="https://sp.example.com/slo"/>
              </md:SPSSODescriptor>
            </md:EntityDescriptor>"#,
            cert = rsa_cert_b64()
        )
    }

    #[test]
    fn parses_sp_metadata_full_shape() {
        let sp = SpDescriptor::from_metadata_xml(sp_metadata_xml().as_bytes()).expect("parse ok");
        assert_eq!(sp.entity_id, "https://sp.example.com/saml");
        assert!(sp.authn_requests_signed);
        assert!(sp.want_assertions_signed);
        assert_eq!(sp.cache_duration, Some(Duration::from_mins(15)));
        assert!(sp.valid_until.is_some());

        assert_eq!(sp.assertion_consumer_services.len(), 2);
        assert_eq!(
            sp.assertion_consumer_services[0].binding,
            SsoResponseBinding::HttpPost
        );
        assert_eq!(
            sp.assertion_consumer_services[1].binding,
            SsoResponseBinding::HttpArtifact
        );

        assert_eq!(sp.single_logout_services.len(), 1);
        assert_eq!(sp.signing_certs.len(), 1);
        assert_eq!(sp.encryption_certs.len(), 1);
        assert_eq!(sp.supported_name_id_formats.len(), 1);
    }

    #[test]
    fn acs_lookup_by_index_and_url_and_default() {
        let sp = SpDescriptor::from_metadata_xml(sp_metadata_xml().as_bytes()).unwrap();
        assert_eq!(
            sp.acs_endpoint_by_index(0).unwrap().url,
            "https://sp.example.com/acs/post"
        );
        assert_eq!(
            sp.acs_endpoint_by_index(1).unwrap().url,
            "https://sp.example.com/acs/artifact"
        );
        assert!(sp.acs_endpoint_by_index(2).is_none());

        assert_eq!(
            sp.acs_endpoint_by_url("https://sp.example.com/acs/post")
                .unwrap()
                .index,
            Some(0)
        );
        assert!(
            sp.acs_endpoint_by_url("https://other.example/acs")
                .is_none()
        );

        let default = sp.default_acs().unwrap();
        assert_eq!(default.url, "https://sp.example.com/acs/post");
        assert!(default.is_default);
    }

    #[test]
    fn slo_endpoint_lookup() {
        let sp = SpDescriptor::from_metadata_xml(sp_metadata_xml().as_bytes()).unwrap();
        assert!(sp.slo_endpoint(Binding::HttpRedirect).is_some());
        assert!(sp.slo_endpoint(Binding::HttpPost).is_none());
    }

    #[test]
    fn encryption_cert_accessor() {
        let sp = SpDescriptor::from_metadata_xml(sp_metadata_xml().as_bytes()).unwrap();
        let enc = sp.encryption_cert().expect("has encryption cert");
        assert_eq!(enc, &sp.encryption_certs[0]);
    }

    #[test]
    fn rejects_acs_with_redirect_binding() {
        let xml = r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                                     entityID="https://sp.example.com/saml">
              <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                <md:AssertionConsumerService
                    index="0"
                    Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                    Location="https://sp.example.com/acs"/>
              </md:SPSSODescriptor>
            </md:EntityDescriptor>"#;
        let err = SpDescriptor::from_metadata_xml(xml.as_bytes()).unwrap_err();
        match err {
            Error::InvalidConfiguration { reason } => {
                assert_eq!(
                    reason,
                    "SP metadata advertises ACS with non-POST/Artifact binding"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn rejects_acs_with_soap_binding() {
        let xml = r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                                            entityID="https://sp.example.com/saml">
              <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                <md:AssertionConsumerService
                    index="0"
                    Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
                    Location="https://sp.example.com/acs"/>
              </md:SPSSODescriptor>
            </md:EntityDescriptor>"#;
        let err = SpDescriptor::from_metadata_xml(xml.as_bytes()).unwrap_err();
        match err {
            Error::InvalidConfiguration { reason } => {
                assert_eq!(
                    reason,
                    "SP metadata advertises ACS with non-POST/Artifact binding"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn missing_sp_role_in_aggregate_is_rejected() {
        let xml = format!(
            r#"<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                                        xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
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
        let err = SpDescriptor::from_metadata_xml(xml.as_bytes()).unwrap_err();
        assert!(matches!(err, Error::InvalidConfiguration { .. }));
    }

    #[test]
    fn default_acs_falls_back_to_first_when_none_flagged() {
        let xml = r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                                            entityID="https://sp.example.com/saml">
              <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                <md:AssertionConsumerService index="0"
                    Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                    Location="https://sp.example.com/acs/a"/>
                <md:AssertionConsumerService index="1"
                    Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                    Location="https://sp.example.com/acs/b"/>
              </md:SPSSODescriptor>
            </md:EntityDescriptor>"#;
        let sp = SpDescriptor::from_metadata_xml(xml.as_bytes()).unwrap();
        let default = sp.default_acs().unwrap();
        assert_eq!(default.url, "https://sp.example.com/acs/a");
    }

    #[cfg(feature = "idp-disco")]
    #[test]
    fn parses_discovery_response_extensions() {
        use crate::disco::{DiscoveryResponseEndpoint, IDPDISC_NS};

        let xml = format!(
            r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                                    xmlns:idpdisc="{IDPDISC_NS}"
                                    entityID="https://sp.example.com/saml">
              <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                <md:Extensions>
                  <idpdisc:DiscoveryResponse Binding="{IDPDISC_NS}"
                      Location="https://sp.example.com/disco" index="0" isDefault="true"/>
                  <idpdisc:DiscoveryResponse Binding="{IDPDISC_NS}"
                      Location="https://sp.example.com/disco/alt" index="1"/>
                </md:Extensions>
                <md:AssertionConsumerService index="0"
                    Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                    Location="https://sp.example.com/acs"/>
              </md:SPSSODescriptor>
            </md:EntityDescriptor>"#
        );
        let sp = SpDescriptor::from_metadata_xml(xml.as_bytes()).expect("parse ok");
        assert_eq!(
            sp.discovery_response_endpoints,
            vec![
                DiscoveryResponseEndpoint::new("https://sp.example.com/disco", 0, true),
                DiscoveryResponseEndpoint::new("https://sp.example.com/disco/alt", 1, false),
            ]
        );
        assert_eq!(
            sp.default_discovery_response().unwrap().url,
            "https://sp.example.com/disco"
        );
    }

    #[cfg(feature = "idp-disco")]
    #[test]
    fn no_extensions_means_no_discovery_endpoints() {
        let sp = SpDescriptor::from_metadata_xml(sp_metadata_xml().as_bytes()).unwrap();
        assert!(sp.discovery_response_endpoints.is_empty());
        assert!(sp.default_discovery_response().is_none());
    }

    #[test]
    fn from_entity_descriptor_element_directly() {
        let xml = sp_metadata_xml();
        let doc = Document::parse(xml.as_bytes()).unwrap();
        let sp = SpDescriptor::from_entity_descriptor_element(doc.root()).unwrap();
        assert_eq!(sp.entity_id, "https://sp.example.com/saml");
    }
}
