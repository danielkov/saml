//! Identity Provider Discovery (`idp-disco` feature).
//!
//! SAML 2.0 specifies two cooperating mechanisms for answering "which IdP
//! does this user belong to?" before an SP can start Web-Browser SSO:
//!
//! - **Common Domain Cookie profile** (SAML 2.0 Profiles §4.3) — IdPs in a
//!   federation write the `_saml_idp` cookie in a shared *common domain*
//!   after each successful authentication; SPs read it back to learn the
//!   user's previously used IdPs. [`CommonDomainCookie`] is the value codec.
//! - **Identity Provider Discovery Service Protocol and Profile** (OASIS
//!   `sstc-saml-idp-discovery-cs-01`) — the SP redirects the user agent to a
//!   central discovery service with a handful of query parameters; the
//!   service picks an IdP (interactively or from the CDC) and redirects back
//!   with the chosen entityID. [`build_discovery_request_url`] /
//!   [`parse_discovery_response_query`] cover the SP side;
//!   [`parse_discovery_request_query`] / [`validate_discovery_return_url`] /
//!   [`build_discovery_response_url`] cover the discovery-service side.
//!
//! Consistent with the crate's stateless design, nothing here touches HTTP:
//! the caller owns cookie headers, redirects, and any UI. Every function is a
//! pure codec over strings and [`url::Url`]s.
//!
//! # Security
//!
//! The one trust decision in the protocol is the discovery service's
//! validation of the `return` URL — an unchecked value is an open redirect
//! that hands the chosen IdP hint (and the user agent) to an attacker.
//! [`validate_discovery_return_url`] therefore only accepts URLs whose
//! scheme, host, port, and path exactly match a `<idpdisc:DiscoveryResponse>`
//! endpoint registered in the SP's metadata; only the query string may
//! differ. Comparison happens on *parsed* URLs, so prefix tricks
//! (`https://sp.example.com.evil.test/…`, userinfo smuggling) don't apply.
//!
//! See `docs/rfcs/RFC-008-idp-discovery.md` for the full design discussion.

mod cdc;
mod service;

pub use cdc::{COMMON_DOMAIN_COOKIE_NAME, CommonDomainCookie};
pub use service::{
    DiscoveryRequest, ParsedDiscoveryRequest, build_discovery_request_url,
    build_discovery_response_url, parse_discovery_request_query, parse_discovery_response_query,
    validate_discovery_return_url,
};

use crate::error::Error;
use crate::metadata::parse::{MD_NS, parse_optional_bool_value};
use crate::xml::parse::Element;

/// Namespace URI of the Identity Provider Discovery Service Protocol. Doubles
/// as the value of the `Binding` attribute on `<idpdisc:DiscoveryResponse>`
/// metadata endpoints.
pub const IDPDISC_NS: &str = "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol";

/// The only `policy` URI defined by the discovery-service protocol (and the
/// implied default when the parameter is absent): return a single IdP
/// entityID in the `returnIDParam` query parameter.
pub const DISCOVERY_POLICY_SINGLE: &str =
    "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol:single";

/// Default name of the query parameter carrying the chosen IdP entityID on
/// the return redirect, used when the request carries no `returnIDParam`.
pub const DEFAULT_RETURN_ID_PARAM: &str = "entityID";

/// A `<idpdisc:DiscoveryResponse>` endpoint from SP metadata — the indexed
/// endpoint a discovery service is allowed to redirect the user agent back
/// to. Lives inside `<md:Extensions>` of the `<md:SPSSODescriptor>`; its
/// `Binding` attribute is fixed to [`IDPDISC_NS`], so only the variable
/// fields are modeled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryResponseEndpoint {
    pub url: String,
    pub index: u16,
    pub is_default: bool,
}

impl DiscoveryResponseEndpoint {
    pub fn new(url: impl Into<String>, index: u16, is_default: bool) -> Self {
        Self {
            url: url.into(),
            index,
            is_default,
        }
    }
}

/// Parse `<idpdisc:DiscoveryResponse>` endpoints out of an
/// `<md:SPSSODescriptor>`'s `<md:Extensions>` child. Absent `Extensions` (or
/// no discovery entries inside it) yields an empty list; a present entry with
/// a wrong `Binding`, missing `Location`, or missing/garbled `index` is a
/// hard parse error — a discovery service must not guess at the one field it
/// bases its redirect trust decision on.
pub(crate) fn parse_discovery_response_extensions(
    sp_descriptor: &Element,
) -> Result<Vec<DiscoveryResponseEndpoint>, Error> {
    let Some(extensions) = sp_descriptor.child_element(Some(MD_NS), "Extensions") else {
        return Ok(Vec::new());
    };

    let mut endpoints = Vec::new();
    for child in extensions.all_child_elements(Some(IDPDISC_NS), "DiscoveryResponse") {
        let binding = child
            .attribute(None, "Binding")
            .ok_or(Error::InvalidConfiguration {
                reason: "DiscoveryResponse missing Binding",
            })?;
        if binding != IDPDISC_NS {
            return Err(Error::InvalidConfiguration {
                reason: "DiscoveryResponse Binding is not the idp-discovery protocol URI",
            });
        }
        let url = child
            .attribute(None, "Location")
            .ok_or(Error::InvalidConfiguration {
                reason: "DiscoveryResponse missing Location",
            })?
            .to_owned();
        // `index` is a required attribute of md:IndexedEndpointType.
        let index = child
            .attribute(None, "index")
            .ok_or(Error::InvalidConfiguration {
                reason: "DiscoveryResponse missing index",
            })?
            .parse::<u16>()
            .map_err(|_parse_err| Error::InvalidConfiguration {
                reason: "DiscoveryResponse index is not a u16",
            })?;
        let is_default =
            parse_optional_bool_value(child.attribute(None, "isDefault"))?.unwrap_or(false);
        endpoints.push(DiscoveryResponseEndpoint {
            url,
            index,
            is_default,
        });
    }
    Ok(endpoints)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xml::parse::Document;

    fn parse_sp_role(extensions_body: &str) -> Result<Vec<DiscoveryResponseEndpoint>, Error> {
        let xml = format!(
            r#"<md:SPSSODescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                                   xmlns:idpdisc="{IDPDISC_NS}"
                                   protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                 {extensions_body}
               </md:SPSSODescriptor>"#
        );
        let doc = Document::parse(xml.as_bytes())?;
        parse_discovery_response_extensions(doc.root())
    }

    #[test]
    fn absent_extensions_yields_empty_list() {
        assert_eq!(parse_sp_role("").unwrap(), vec![]);
    }

    #[test]
    fn extensions_without_discovery_entries_yields_empty_list() {
        let got = parse_sp_role(
            r#"<md:Extensions><other:Thing xmlns:other="urn:x-other"/></md:Extensions>"#,
        )
        .unwrap();
        assert_eq!(got, vec![]);
    }

    #[test]
    fn parses_multiple_endpoints_with_index_and_default() {
        let got = parse_sp_role(&format!(
            r#"<md:Extensions>
                 <idpdisc:DiscoveryResponse Binding="{IDPDISC_NS}"
                     Location="https://sp.example.com/disco" index="0" isDefault="true"/>
                 <idpdisc:DiscoveryResponse Binding="{IDPDISC_NS}"
                     Location="https://sp.example.com/disco2" index="1"/>
               </md:Extensions>"#
        ))
        .unwrap();
        assert_eq!(
            got,
            vec![
                DiscoveryResponseEndpoint::new("https://sp.example.com/disco", 0, true),
                DiscoveryResponseEndpoint::new("https://sp.example.com/disco2", 1, false),
            ]
        );
    }

    #[test]
    fn rejects_wrong_binding() {
        let err = parse_sp_role(
            r#"<md:Extensions>
                 <idpdisc:DiscoveryResponse Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                     Location="https://sp.example.com/disco" index="0"/>
               </md:Extensions>"#,
        )
        .unwrap_err();
        assert!(matches!(err, Error::InvalidConfiguration { .. }));
    }

    #[test]
    fn rejects_missing_index() {
        let err = parse_sp_role(&format!(
            r#"<md:Extensions>
                 <idpdisc:DiscoveryResponse Binding="{IDPDISC_NS}"
                     Location="https://sp.example.com/disco"/>
               </md:Extensions>"#
        ))
        .unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidConfiguration {
                reason: "DiscoveryResponse missing index"
            }
        ));
    }
}
