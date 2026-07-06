//! Identity Provider Discovery Service Protocol and Profile
//! (OASIS `sstc-saml-idp-discovery-cs-01`).
//!
//! Redirect-based, no crypto: the SP sends the user agent to a discovery
//! service with its own entityID and a `return` URL; the service determines
//! the user's IdP (interactively, or from the Common Domain Cookie) and
//! redirects back with the chosen entityID in a query parameter.
//!
//! SP side: [`build_discovery_request_url`] → (redirect, service picks) →
//! [`parse_discovery_response_query`].
//!
//! Discovery-service side: [`parse_discovery_request_query`] →
//! [`validate_discovery_return_url`] (the open-redirect gate) →
//! [`build_discovery_response_url`].

use url::Url;
use url::form_urlencoded;

use crate::descriptor::SpDescriptor;
use crate::error::Error;

use super::{DEFAULT_RETURN_ID_PARAM, DISCOVERY_POLICY_SINGLE};

/// SP-side inputs for a discovery request redirect.
#[derive(Debug, Clone)]
pub struct DiscoveryRequest<'a> {
    /// The SP's own entityID (`entityID` parameter, mandatory).
    pub sp_entity_id: &'a str,
    /// `return` parameter. `None` lets the discovery service fall back to
    /// the default `<idpdisc:DiscoveryResponse>` endpoint registered in the
    /// SP's metadata — the safest choice when one return endpoint exists.
    pub return_url: Option<&'a str>,
    /// `returnIDParam` parameter. `None` implies
    /// [`DEFAULT_RETURN_ID_PARAM`](super::DEFAULT_RETURN_ID_PARAM).
    pub return_id_param: Option<&'a str>,
    /// `isPassive` — when true the discovery service must not interact with
    /// the user and returns without a chosen IdP if none is known.
    pub is_passive: bool,
}

/// Build the discovery-request redirect URL from the SP to the discovery
/// service. `discovery_service` is the service's endpoint URL (out-of-band
/// federation configuration); an existing query string is preserved, a
/// fragment is dropped.
///
/// The `policy` parameter is deliberately not exposed:
/// [`DISCOVERY_POLICY_SINGLE`](super::DISCOVERY_POLICY_SINGLE) is the only
/// policy the spec defines and the implied default, so emitting it would
/// only add bytes to the URL.
pub fn build_discovery_request_url(
    discovery_service: &Url,
    request: &DiscoveryRequest<'_>,
) -> Result<Url, Error> {
    if request.sp_entity_id.is_empty() {
        return Err(Error::InvalidConfiguration {
            reason: "discovery request sp_entity_id must be non-empty",
        });
    }
    if let Some(param) = request.return_id_param {
        ensure_safe_param_name(param)?;
    }

    let mut url = discovery_service.clone();
    url.set_fragment(None);
    if url.query() == Some("") {
        url.set_query(None);
    }
    {
        let mut pairs = url.query_pairs_mut();
        pairs.append_pair("entityID", request.sp_entity_id);
        if let Some(return_url) = request.return_url {
            pairs.append_pair("return", return_url);
        }
        if let Some(param) = request.return_id_param {
            pairs.append_pair("returnIDParam", param);
        }
        if request.is_passive {
            pairs.append_pair("isPassive", "true");
        }
    }
    Ok(url)
}

/// SP-side consumption of the discovery service's return redirect: extract
/// the chosen IdP entityID from the query string of the request that hit the
/// SP's `<idpdisc:DiscoveryResponse>` endpoint.
///
/// `return_id_param` must be the same value the SP put in its request (or
/// [`DEFAULT_RETURN_ID_PARAM`](super::DEFAULT_RETURN_ID_PARAM)). `Ok(None)`
/// means the service made no choice — the defined outcome of an `isPassive`
/// request when no IdP is known. A duplicated parameter is rejected rather
/// than first-match-wins, so an attacker appending a second value cannot
/// depend on parser order.
pub fn parse_discovery_response_query(
    query: &str,
    return_id_param: &str,
) -> Result<Option<String>, Error> {
    ensure_safe_param_name(return_id_param)?;
    let mut chosen: Option<String> = None;
    for (name, value) in form_urlencoded::parse(query.as_bytes()) {
        if name.as_ref() == return_id_param {
            if chosen.is_some() {
                return Err(Error::DiscoveryResponseMalformed {
                    reason: "duplicate IdP entityID parameter",
                });
            }
            chosen = Some(value.into_owned());
        }
    }
    Ok(chosen.filter(|entity_id| !entity_id.is_empty()))
}

/// Parsed view of an inbound discovery request's query string, with the
/// spec-defined defaults applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedDiscoveryRequest {
    /// Requesting SP's entityID. Use it to look up the SP's metadata before
    /// calling [`validate_discovery_return_url`].
    pub sp_entity_id: String,
    /// Raw `return` parameter, if present. Untrusted until validated.
    pub return_url: Option<String>,
    /// `returnIDParam`, defaulted to `entityID` and constrained to a safe
    /// URL-parameter token.
    pub return_id_param: String,
    /// When true, respond without user interaction (no choice → redirect
    /// back with no parameter).
    pub is_passive: bool,
}

/// Discovery-service-side parse of an inbound request query string.
///
/// Rejects: a missing/empty `entityID`, any duplicated known parameter
/// (parameter-pollution defense), a `policy` other than
/// [`DISCOVERY_POLICY_SINGLE`](super::DISCOVERY_POLICY_SINGLE), a
/// non-boolean `isPassive`, and a `returnIDParam` that is not a plain
/// `[A-Za-z0-9_.-]+` token (anything wilder is a response-URL injection
/// attempt, not a legitimate parameter name). Unknown parameters are
/// ignored.
pub fn parse_discovery_request_query(query: &str) -> Result<ParsedDiscoveryRequest, Error> {
    let mut entity_id: Option<String> = None;
    let mut return_url: Option<String> = None;
    let mut return_id_param: Option<String> = None;
    let mut policy: Option<String> = None;
    let mut is_passive: Option<String> = None;

    for (name, value) in form_urlencoded::parse(query.as_bytes()) {
        let (slot, duplicate_reason): (&mut Option<String>, &'static str) = match name.as_ref() {
            "entityID" => (&mut entity_id, "duplicate entityID parameter"),
            "return" => (&mut return_url, "duplicate return parameter"),
            "returnIDParam" => (&mut return_id_param, "duplicate returnIDParam parameter"),
            "policy" => (&mut policy, "duplicate policy parameter"),
            "isPassive" => (&mut is_passive, "duplicate isPassive parameter"),
            _ => continue,
        };
        if slot.is_some() {
            return Err(Error::DiscoveryRequestMalformed {
                reason: duplicate_reason,
            });
        }
        *slot = Some(value.into_owned());
    }

    let sp_entity_id =
        entity_id
            .filter(|id| !id.is_empty())
            .ok_or(Error::DiscoveryRequestMalformed {
                reason: "missing or empty entityID parameter",
            })?;

    if let Some(policy) = policy
        && policy != DISCOVERY_POLICY_SINGLE
    {
        return Err(Error::DiscoveryRequestMalformed {
            reason: "unsupported policy",
        });
    }

    let return_id_param = match return_id_param {
        Some(param) => {
            ensure_safe_param_name(&param)?;
            param
        }
        None => DEFAULT_RETURN_ID_PARAM.to_owned(),
    };

    // xs:boolean lexical space: true / false / 1 / 0.
    let is_passive = match is_passive.as_deref() {
        Some("true" | "1") => true,
        None | Some("false" | "0") => false,
        Some(_) => {
            return Err(Error::DiscoveryRequestMalformed {
                reason: "isPassive is not a boolean",
            });
        }
    };

    Ok(ParsedDiscoveryRequest {
        sp_entity_id,
        return_url,
        return_id_param,
        is_passive,
    })
}

/// The discovery service's trust decision: resolve the URL it may redirect
/// the user agent back to, against the requesting SP's metadata.
///
/// - No `return` parameter → the SP's default `<idpdisc:DiscoveryResponse>`
///   endpoint (the `isDefault="true"` entry, else the first).
/// - `return` present → it must match a registered endpoint on **scheme,
///   host, port, and path exactly**; only the query string may differ (the
///   spec allows the SP to thread state through extra query parameters).
///   Fragments and userinfo are rejected outright. Matching is on parsed
///   URLs, so `https://sp.example.com.evil.test/…` and
///   `https://sp.example.com@evil.test/…` never match.
///
/// The returned [`Url`] (candidate query intact) is safe to hand to
/// [`build_discovery_response_url`].
pub fn validate_discovery_return_url(
    sp: &SpDescriptor,
    request: &ParsedDiscoveryRequest,
) -> Result<Url, Error> {
    match &request.return_url {
        None => {
            let endpoint = sp
                .default_discovery_response()
                .ok_or(Error::InvalidConfiguration {
                    reason: "SP metadata advertises no DiscoveryResponse endpoint",
                })?;
            Url::parse(&endpoint.url).map_err(|_parse_err| Error::InvalidConfiguration {
                reason: "registered DiscoveryResponse Location is not a valid URL",
            })
        }
        Some(requested) => {
            let candidate =
                Url::parse(requested).map_err(|_parse_err| Error::DiscoveryRequestMalformed {
                    reason: "return is not a valid absolute URL",
                })?;
            if candidate.fragment().is_some() {
                return Err(Error::DiscoveryRequestMalformed {
                    reason: "return must not carry a fragment",
                });
            }
            if !candidate.username().is_empty() || candidate.password().is_some() {
                return Err(Error::DiscoveryRequestMalformed {
                    reason: "return must not carry userinfo",
                });
            }
            let matched = sp.discovery_response_endpoints.iter().any(|endpoint| {
                Url::parse(&endpoint.url)
                    .is_ok_and(|registered| same_endpoint(&registered, &candidate))
            });
            if matched {
                Ok(candidate)
            } else {
                Err(Error::DiscoveryReturnUrlNotRegistered {
                    return_url: requested.clone(),
                })
            }
        }
    }
}

/// Build the return redirect from the discovery service to the SP.
/// `return_url` must come from [`validate_discovery_return_url`].
///
/// `chosen_idp_entity_id = None` is the "no choice made" outcome of a
/// passive request: redirect back with no added parameter, per the protocol.
pub fn build_discovery_response_url(
    return_url: &Url,
    return_id_param: &str,
    chosen_idp_entity_id: Option<&str>,
) -> Result<Url, Error> {
    ensure_safe_param_name(return_id_param)?;
    let mut url = return_url.clone();
    url.set_fragment(None);
    if url.query() == Some("") {
        url.set_query(None);
    }
    if let Some(entity_id) = chosen_idp_entity_id {
        if entity_id.is_empty() {
            return Err(Error::InvalidConfiguration {
                reason: "chosen IdP entityID must be non-empty",
            });
        }
        url.query_pairs_mut()
            .append_pair(return_id_param, entity_id);
    }
    Ok(url)
}

/// Exact scheme / host / port / path equality; query intentionally excluded.
fn same_endpoint(registered: &Url, candidate: &Url) -> bool {
    candidate.host_str().is_some()
        && registered.scheme() == candidate.scheme()
        && registered.host_str() == candidate.host_str()
        && registered.port_or_known_default() == candidate.port_or_known_default()
        && registered.path() == candidate.path()
}

/// `returnIDParam` values are echoed into the response URL as a parameter
/// *name*; constrain them to a conservative token so they cannot smuggle
/// `=`, `&`, `#`, or percent-escapes into the redirect.
fn ensure_safe_param_name(name: &str) -> Result<(), Error> {
    let safe = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
    if safe {
        Ok(())
    } else {
        Err(Error::DiscoveryRequestMalformed {
            reason: "returnIDParam is not a safe URL parameter name",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disco::DiscoveryResponseEndpoint;

    fn sp_with_endpoints(endpoints: Vec<DiscoveryResponseEndpoint>) -> SpDescriptor {
        SpDescriptor {
            entity_id: "https://sp.example.com/saml".to_owned(),
            assertion_consumer_services: vec![],
            single_logout_services: vec![],
            signing_certs: vec![],
            encryption_certs: vec![],
            supported_name_id_formats: vec![],
            want_assertions_signed: false,
            authn_requests_signed: false,
            valid_until: None,
            cache_duration: None,
            discovery_response_endpoints: endpoints,
        }
    }

    fn parsed_request(return_url: Option<&str>) -> ParsedDiscoveryRequest {
        ParsedDiscoveryRequest {
            sp_entity_id: "https://sp.example.com/saml".to_owned(),
            return_url: return_url.map(str::to_owned),
            return_id_param: DEFAULT_RETURN_ID_PARAM.to_owned(),
            is_passive: false,
        }
    }

    // ---------- request build ----------

    #[test]
    fn build_request_url_minimal() {
        let ds = Url::parse("https://disco.example-federation.org/ds").unwrap();
        let url = build_discovery_request_url(
            &ds,
            &DiscoveryRequest {
                sp_entity_id: "https://sp.example.com/saml",
                return_url: None,
                return_id_param: None,
                is_passive: false,
            },
        )
        .unwrap();
        assert_eq!(
            url.as_str(),
            "https://disco.example-federation.org/ds?entityID=https%3A%2F%2Fsp.example.com%2Fsaml"
        );
    }

    #[test]
    fn build_request_url_full_preserves_existing_query_and_drops_fragment() {
        let ds = Url::parse("https://disco.example.org/ds?tenant=blue#frag").unwrap();
        let url = build_discovery_request_url(
            &ds,
            &DiscoveryRequest {
                sp_entity_id: "https://sp.example.com/saml",
                return_url: Some("https://sp.example.com/disco?state=abc"),
                return_id_param: Some("idp"),
                is_passive: true,
            },
        )
        .unwrap();
        assert!(url.fragment().is_none());
        let query = url.query().unwrap();
        assert!(query.starts_with("tenant=blue&entityID="), "got {query}");
        assert!(query.contains("&returnIDParam=idp"));
        assert!(query.contains("&isPassive=true"));
        assert!(query.contains("&return=https%3A%2F%2Fsp.example.com%2Fdisco%3Fstate%3Dabc"));
    }

    #[test]
    fn build_request_url_rejects_empty_entity_id_and_bad_param_name() {
        let ds = Url::parse("https://disco.example.org/ds").unwrap();
        let empty = DiscoveryRequest {
            sp_entity_id: "",
            return_url: None,
            return_id_param: None,
            is_passive: false,
        };
        build_discovery_request_url(&ds, &empty).unwrap_err();

        let bad_param = DiscoveryRequest {
            sp_entity_id: "https://sp.example.com/saml",
            return_url: None,
            return_id_param: Some("idp&admin=1"),
            is_passive: false,
        };
        assert!(matches!(
            build_discovery_request_url(&ds, &bad_param).unwrap_err(),
            Error::DiscoveryRequestMalformed { .. }
        ));
    }

    // ---------- request parse ----------

    #[test]
    fn parse_request_applies_defaults() {
        let parsed =
            parse_discovery_request_query("entityID=https%3A%2F%2Fsp.example.com%2Fsaml").unwrap();
        assert_eq!(parsed.sp_entity_id, "https://sp.example.com/saml");
        assert_eq!(parsed.return_url, None);
        assert_eq!(parsed.return_id_param, "entityID");
        assert!(!parsed.is_passive);
    }

    #[test]
    fn parse_request_roundtrips_build_output() {
        let ds = Url::parse("https://disco.example.org/ds").unwrap();
        let url = build_discovery_request_url(
            &ds,
            &DiscoveryRequest {
                sp_entity_id: "https://sp.example.com/saml",
                return_url: Some("https://sp.example.com/disco?state=abc"),
                return_id_param: Some("idp"),
                is_passive: true,
            },
        )
        .unwrap();
        let parsed = parse_discovery_request_query(url.query().unwrap()).unwrap();
        assert_eq!(parsed.sp_entity_id, "https://sp.example.com/saml");
        assert_eq!(
            parsed.return_url.as_deref(),
            Some("https://sp.example.com/disco?state=abc")
        );
        assert_eq!(parsed.return_id_param, "idp");
        assert!(parsed.is_passive);
    }

    #[test]
    fn parse_request_rejects_missing_entity_id() {
        assert!(matches!(
            parse_discovery_request_query("returnIDParam=idp").unwrap_err(),
            Error::DiscoveryRequestMalformed {
                reason: "missing or empty entityID parameter"
            }
        ));
        parse_discovery_request_query("entityID=").unwrap_err();
    }

    #[test]
    fn parse_request_rejects_duplicate_parameters() {
        let err = parse_discovery_request_query("entityID=a&entityID=b").unwrap_err();
        assert!(matches!(
            err,
            Error::DiscoveryRequestMalformed {
                reason: "duplicate entityID parameter"
            }
        ));
        parse_discovery_request_query("entityID=a&return=x&return=y").unwrap_err();
    }

    #[test]
    fn parse_request_accepts_single_policy_and_rejects_others() {
        let single = format!("entityID=a&policy={DISCOVERY_POLICY_SINGLE}");
        parse_discovery_request_query(&single).unwrap();

        let err =
            parse_discovery_request_query("entityID=a&policy=urn:x-custom:policy").unwrap_err();
        assert!(matches!(
            err,
            Error::DiscoveryRequestMalformed {
                reason: "unsupported policy"
            }
        ));
    }

    #[test]
    fn parse_request_is_passive_boolean_lexical_space() {
        for (value, expected) in [("true", true), ("1", true), ("false", false), ("0", false)] {
            let parsed =
                parse_discovery_request_query(&format!("entityID=a&isPassive={value}")).unwrap();
            assert_eq!(parsed.is_passive, expected, "isPassive={value}");
        }
        parse_discovery_request_query("entityID=a&isPassive=yes").unwrap_err();
    }

    #[test]
    fn parse_request_rejects_unsafe_return_id_param() {
        for bad in ["a=b", "a&b", "a#b", "a%3Db", "a b", ""] {
            let query = format!(
                "entityID=a&returnIDParam={}",
                form_urlencoded::byte_serialize(bad.as_bytes()).collect::<String>()
            );
            parse_discovery_request_query(&query)
                .expect_err(&format!("should reject returnIDParam={bad:?}"));
        }
    }

    // ---------- return-URL validation ----------

    #[test]
    fn validate_return_url_falls_back_to_default_endpoint() {
        let sp = sp_with_endpoints(vec![
            DiscoveryResponseEndpoint::new("https://sp.example.com/disco/alt", 1, false),
            DiscoveryResponseEndpoint::new("https://sp.example.com/disco", 0, true),
        ]);
        let url = validate_discovery_return_url(&sp, &parsed_request(None)).unwrap();
        assert_eq!(url.as_str(), "https://sp.example.com/disco");
    }

    #[test]
    fn validate_return_url_default_falls_back_to_first_when_none_flagged() {
        let sp = sp_with_endpoints(vec![
            DiscoveryResponseEndpoint::new("https://sp.example.com/disco/a", 0, false),
            DiscoveryResponseEndpoint::new("https://sp.example.com/disco/b", 1, false),
        ]);
        let url = validate_discovery_return_url(&sp, &parsed_request(None)).unwrap();
        assert_eq!(url.as_str(), "https://sp.example.com/disco/a");
    }

    #[test]
    fn validate_return_url_errors_when_no_endpoints_registered() {
        let sp = sp_with_endpoints(vec![]);
        assert!(matches!(
            validate_discovery_return_url(&sp, &parsed_request(None)).unwrap_err(),
            Error::InvalidConfiguration { .. }
        ));
        assert!(matches!(
            validate_discovery_return_url(
                &sp,
                &parsed_request(Some("https://sp.example.com/disco"))
            )
            .unwrap_err(),
            Error::DiscoveryReturnUrlNotRegistered { .. }
        ));
    }

    #[test]
    fn validate_return_url_accepts_registered_with_extra_query() {
        let sp = sp_with_endpoints(vec![DiscoveryResponseEndpoint::new(
            "https://sp.example.com/disco",
            0,
            true,
        )]);
        let url = validate_discovery_return_url(
            &sp,
            &parsed_request(Some("https://sp.example.com/disco?state=xyz&hop=2")),
        )
        .unwrap();
        assert_eq!(url.query(), Some("state=xyz&hop=2"));
    }

    #[test]
    fn validate_return_url_rejects_lookalikes() {
        let sp = sp_with_endpoints(vec![DiscoveryResponseEndpoint::new(
            "https://sp.example.com/disco",
            0,
            true,
        )]);
        let attacks = [
            // host prefix trick
            "https://sp.example.com.evil.test/disco",
            // userinfo smuggling
            "https://sp.example.com@evil.test/disco",
            // wrong scheme
            "http://sp.example.com/disco",
            // wrong port
            "https://sp.example.com:8443/disco",
            // path extension
            "https://sp.example.com/disco/../admin",
            "https://sp.example.com/disco2",
            "https://sp.example.com/disco/evil",
            // fragment
            "https://sp.example.com/disco#frag",
            // relative / garbage
            "/disco",
            "javascript:alert(1)",
        ];
        for attack in attacks {
            validate_discovery_return_url(&sp, &parsed_request(Some(attack)))
                .expect_err(&format!("must reject return={attack}"));
        }
    }

    #[test]
    fn validate_return_url_normalizes_default_port_and_host_case() {
        let sp = sp_with_endpoints(vec![DiscoveryResponseEndpoint::new(
            "https://sp.example.com/disco",
            0,
            true,
        )]);
        for ok in [
            "https://sp.example.com:443/disco",
            "https://SP.EXAMPLE.COM/disco",
        ] {
            validate_discovery_return_url(&sp, &parsed_request(Some(ok)))
                .unwrap_or_else(|err| panic!("must accept return={ok}: {err}"));
        }
    }

    // ---------- response build + parse ----------

    #[test]
    fn response_roundtrip_with_choice() {
        let return_url = Url::parse("https://sp.example.com/disco?state=abc").unwrap();
        let url = build_discovery_response_url(
            &return_url,
            "entityID",
            Some("https://idp.example-federation.org/saml"),
        )
        .unwrap();
        // Original SP state survives.
        assert!(url.query().unwrap().starts_with("state=abc&"));

        let chosen = parse_discovery_response_query(url.query().unwrap(), "entityID").unwrap();
        assert_eq!(
            chosen.as_deref(),
            Some("https://idp.example-federation.org/saml")
        );
    }

    #[test]
    fn response_without_choice_adds_no_parameter() {
        let return_url = Url::parse("https://sp.example.com/disco").unwrap();
        let url = build_discovery_response_url(&return_url, "entityID", None).unwrap();
        assert_eq!(url.as_str(), "https://sp.example.com/disco");
        assert_eq!(
            parse_discovery_response_query(url.query().unwrap_or(""), "entityID").unwrap(),
            None
        );
    }

    #[test]
    fn response_build_rejects_empty_choice_and_unsafe_param() {
        let return_url = Url::parse("https://sp.example.com/disco").unwrap();
        build_discovery_response_url(&return_url, "entityID", Some("")).unwrap_err();
        build_discovery_response_url(&return_url, "a&b", Some("x")).unwrap_err();
    }

    #[test]
    fn response_parse_rejects_duplicate_choice() {
        let err = parse_discovery_response_query("entityID=a&entityID=b", "entityID").unwrap_err();
        assert!(matches!(err, Error::DiscoveryResponseMalformed { .. }));
    }

    #[test]
    fn response_parse_ignores_unrelated_parameters() {
        let chosen =
            parse_discovery_response_query("state=abc&entityID=https%3A%2F%2Fidp", "entityID")
                .unwrap();
        assert_eq!(chosen.as_deref(), Some("https://idp"));
    }

    #[test]
    fn response_parse_treats_empty_value_as_no_choice() {
        assert_eq!(
            parse_discovery_response_query("entityID=", "entityID").unwrap(),
            None
        );
    }
}
