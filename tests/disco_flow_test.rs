//! IdP Discovery end-to-end flow test (`idp-disco` feature).
//!
//! Drives the full discovery journey across the crate's public surface:
//! the SP emits metadata carrying `<idpdisc:DiscoveryResponse>` endpoints,
//! a discovery service parses that metadata plus an inbound discovery
//! request, validates the return URL against it, picks an IdP (from a
//! Common Domain Cookie), and redirects back; the SP consumes the response
//! and learns which IdP to start Web-Browser SSO against. Also exercises
//! the open-redirect negative path.

#![cfg(feature = "idp-disco")]

#[path = "common/mod.rs"]
mod common;

use saml::{
    CommonDomainCookie, DiscoveryRequest, DiscoveryResponseEndpoint, Error, MetadataExtras,
    SpDescriptor, build_discovery_request_url, build_discovery_response_url,
    parse_discovery_request_query, parse_discovery_response_query, validate_discovery_return_url,
};
use url::Url;

const SP_ENTITY_ID: &str = "https://sp.example.com/disco-flow";
const SP_ACS_URL: &str = "https://sp.example.com/disco-flow/acs";
const SP_DISCO_URL: &str = "https://sp.example.com/disco-flow/disco";
const DS_URL: &str = "https://ds.example-federation.org/ds";
const IDP_A: &str = "https://idp-a.example-federation.org/saml";
const IDP_B: &str = "https://idp-b.example-federation.org/saml";

/// Emit SP metadata carrying one default DiscoveryResponse endpoint and
/// re-ingest it the way a discovery service (federation registrar) would.
fn registered_sp_descriptor() -> Result<SpDescriptor, Box<dyn std::error::Error>> {
    let sp = common::make_sp(SP_ENTITY_ID, SP_ACS_URL, false)?;
    let extras = MetadataExtras {
        organization: None,
        contacts: vec![],
        discovery_response_endpoints: vec![DiscoveryResponseEndpoint::new(SP_DISCO_URL, 0, true)],
    };
    let metadata_xml = sp.metadata_xml_with_extras(false, &extras)?;
    Ok(SpDescriptor::from_metadata_xml(metadata_xml.as_bytes())?)
}

/// Emit → parse round-trip preserves the DiscoveryResponse endpoints.
#[test]
fn metadata_roundtrip_preserves_discovery_endpoints() {
    let descriptor = registered_sp_descriptor().expect("sp metadata registers");
    assert_eq!(
        descriptor.discovery_response_endpoints,
        vec![DiscoveryResponseEndpoint::new(SP_DISCO_URL, 0, true)]
    );
    assert_eq!(
        descriptor
            .default_discovery_response()
            .expect("default endpoint")
            .url,
        SP_DISCO_URL
    );
}

/// SP metadata → discovery request → DS validation → choice → SP consumption.
#[test]
fn full_discovery_round_trip() {
    let sp_descriptor = registered_sp_descriptor().expect("sp metadata registers");

    // 1. SP sends the user agent to the discovery service, threading state
    //    through the return URL's query string.
    let request_url = build_discovery_request_url(
        &Url::parse(DS_URL).expect("ds url"),
        &DiscoveryRequest {
            sp_entity_id: SP_ENTITY_ID,
            return_url: Some(&format!("{SP_DISCO_URL}?relay=abc123")),
            return_id_param: None,
            is_passive: false,
        },
    )
    .expect("request builds");

    // 2. Discovery service parses the request and validates the return URL
    //    against the SP's registered endpoints.
    let parsed =
        parse_discovery_request_query(request_url.query().unwrap_or("")).expect("request parses");
    assert_eq!(parsed.sp_entity_id, SP_ENTITY_ID);
    let return_url =
        validate_discovery_return_url(&sp_descriptor, &parsed).expect("return URL validates");
    assert_eq!(return_url.query(), Some("relay=abc123"));

    // 3. The service consults the user's Common Domain Cookie — IdP B was
    //    used most recently — and redirects back with the choice.
    let mut cdc = CommonDomainCookie::default();
    cdc.record(IDP_A);
    cdc.record(IDP_B);
    let cdc = CommonDomainCookie::parse(&cdc.to_cookie_value()).expect("cookie round-trips");
    let chosen = cdc.most_recent().expect("cookie has entries");
    assert_eq!(chosen, IDP_B);

    let response_url =
        build_discovery_response_url(&return_url, &parsed.return_id_param, Some(chosen))
            .expect("response builds");

    // 4. SP consumes the return redirect: original state intact, chosen IdP
    //    recovered. From here the SP would look up IDP_B's IdpDescriptor and
    //    call start_login.
    assert_eq!(response_url.host_str(), Some("sp.example.com"));
    assert!(
        response_url
            .query()
            .unwrap_or("")
            .starts_with("relay=abc123&")
    );
    let discovered =
        parse_discovery_response_query(response_url.query().unwrap_or(""), &parsed.return_id_param)
            .expect("response parses");
    assert_eq!(discovered.as_deref(), Some(IDP_B));
}

/// A passive request with no known IdP redirects back without a choice.
#[test]
fn passive_request_without_choice_round_trips_to_none() {
    let sp_descriptor = registered_sp_descriptor().expect("sp metadata registers");

    let request_url = build_discovery_request_url(
        &Url::parse(DS_URL).expect("ds url"),
        &DiscoveryRequest {
            sp_entity_id: SP_ENTITY_ID,
            return_url: None,
            return_id_param: None,
            is_passive: true,
        },
    )
    .expect("request builds");
    let parsed =
        parse_discovery_request_query(request_url.query().unwrap_or("")).expect("request parses");
    assert!(parsed.is_passive);

    // No `return` parameter → the metadata default endpoint is used.
    let return_url =
        validate_discovery_return_url(&sp_descriptor, &parsed).expect("default endpoint resolves");
    assert_eq!(return_url.as_str(), SP_DISCO_URL);

    // Empty CDC → no choice → redirect back bare.
    let cdc = CommonDomainCookie::parse("").expect("empty cookie parses");
    let response_url =
        build_discovery_response_url(&return_url, &parsed.return_id_param, cdc.most_recent())
            .expect("response builds");
    assert_eq!(response_url.as_str(), SP_DISCO_URL);
    let discovered =
        parse_discovery_response_query(response_url.query().unwrap_or(""), &parsed.return_id_param)
            .expect("response parses");
    assert_eq!(discovered, None);
}

/// The open-redirect gate: a return URL not registered in the SP's metadata
/// is rejected even when every other parameter is legitimate.
#[test]
fn unregistered_return_url_is_rejected() {
    let sp_descriptor = registered_sp_descriptor().expect("sp metadata registers");

    let request_url = build_discovery_request_url(
        &Url::parse(DS_URL).expect("ds url"),
        &DiscoveryRequest {
            sp_entity_id: SP_ENTITY_ID,
            return_url: Some("https://evil.example.net/disco-flow/disco"),
            return_id_param: None,
            is_passive: false,
        },
    )
    .expect("request builds");
    let parsed =
        parse_discovery_request_query(request_url.query().unwrap_or("")).expect("request parses");
    let err = validate_discovery_return_url(&sp_descriptor, &parsed)
        .expect_err("unregistered return URL must be rejected");
    assert!(matches!(err, Error::DiscoveryReturnUrlNotRegistered { .. }));
}
