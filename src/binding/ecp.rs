//! Enhanced Client or Proxy (ECP) profile and the Reverse-SOAP (PAOS) binding.
//!
//! SAML 2.0 Profiles §4.2 (Enhanced Client or Proxy) + SAML 2.0 Bindings §3.3
//! (Reverse SOAP — PAOS). ECP is the non-browser SSO flow used by desktop apps
//! and federated CLI tooling: there is no user agent to follow redirects, so
//! the *client* itself shuttles the SAML messages between the SP and the IdP
//! over SOAP. This module provides the library primitives for all three roles.
//!
//! # The flow (Profiles §4.2.1)
//!
//! 1. **Client → SP**: the client requests an SP resource with
//!    `Accept: text/html, application/vnd.paos+xml` and a `PAOS:` header
//!    advertising the ECP service (see [`paos_request_headers`]).
//! 2. **SP → client**: the SP answers with a SOAP envelope whose
//!    `<soap:Header>` carries `<paos:Request>` (with `responseConsumerURL` and a
//!    `messageID`) and `<ecp:Request>` (with `<saml:Issuer>`), and whose
//!    `<soap:Body>` is a `<samlp:AuthnRequest>` with
//!    `ProtocolBinding=…:PAOS`. Built by [`SpEcp::build_authn_request`].
//! 3. **Client → IdP**: the client strips the PAOS headers, re-wraps the bare
//!    `<samlp:AuthnRequest>` in a fresh SOAP envelope ([`ClientEcp::relay_request_to_idp`]),
//!    and POSTs it to the IdP's ECP SOAP endpoint. The library does **not** own
//!    the socket — HTTP Basic / mTLS authentication to the IdP is the caller's
//!    concern.
//! 4. **IdP → client**: the IdP answers with a SOAP envelope whose
//!    `<soap:Header>` carries `<ecp:Response AssertionConsumerServiceURL="…"/>`
//!    and whose `<soap:Body>` is a signed `<samlp:Response>`. Built by
//!    [`IdpEcp::build_response`] (and consumed via [`IdpEcp::parse_authn_request`]).
//! 5. **Client → SP (PAOS POST)**: the client builds a SOAP envelope with a
//!    `<paos:Response refToMessageID="…"/>` header and the IdP's
//!    `<samlp:Response>` as the body, and POSTs it to the SP's
//!    `responseConsumerURL` ([`ClientEcp::build_paos_post`]).
//! 6. **SP**: unwraps the PAOS POST and consumes the `<samlp:Response>`
//!    normally ([`SpEcp::consume_paos_response`]).
//!
//! # CRITICAL security check (Profiles §4.2.4.2)
//!
//! Step 5 is gated by a mandatory comparison: the client MUST verify that the
//! `AssertionConsumerServiceURL` the IdP put in `<ecp:Response>` (step 4)
//! **equals** the `responseConsumerURL` the SP put in `<paos:Request>`
//! (step 2). If they differ, a malicious IdP or a man-in-the-middle is trying
//! to redirect the assertion to an attacker-controlled endpoint; the client
//! MUST NOT deliver the assertion and MUST instead send a SOAP fault to the
//! SP's `responseConsumerURL`. This module makes that failure mode
//! *unrepresentable*: [`ClientEcp::build_paos_post`] performs the comparison
//! itself and returns [`Error::EcpAcsUrlMismatch`] (carrying the
//! ready-to-POST SOAP fault) rather than ever yielding a deliverable envelope
//! when the URLs disagree. There is no code path that emits the assertion to
//! the SP without the URLs matching.
//!
//! # Feature gating
//!
//! Gated behind the `ecp` feature. ECP reuses the shared
//! [`crate::binding::soap`] envelope module (extended with header-block
//! support), the AuthnRequest build/parse machinery, and the Response
//! issue/consume paths — it does not reimplement any of them.

#![cfg(feature = "ecp")]

use crate::authn::request_build::{AcsRequest, BuildAuthnRequest, build_authn_request_element};
use crate::binding::soap::{self, SOAP_NS};
use crate::error::Error;
use crate::xml::parse::{Document, Element, Node, QName};

/// SAML protocol namespace.
const SAMLP_NS: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
/// SAML assertion namespace.
const SAML_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
/// Liberty PAOS namespace (SAML 2.0 Bindings §3.3.1).
pub const PAOS_NS: &str = "urn:liberty:paos:2003-08";
/// SAML 2.0 ECP profile namespace (Profiles §4.2).
pub const ECP_NS: &str = "urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp";

/// PAOS binding URI (SAML 2.0 Bindings §3.3): the `ProtocolBinding` the SP
/// nominates in its ECP `<samlp:AuthnRequest>` so the IdP returns the Response
/// over the reverse-SOAP channel.
pub const PAOS_BINDING: &str = "urn:oasis:names:tc:SAML:2.0:bindings:PAOS";

/// `service` attribute value on `<paos:Request>` / SOAP feature URI for the ECP
/// SSO service (Profiles §4.2.2).
const ECP_SERVICE: &str = ECP_NS;

/// SOAP `actor` for the "next" SOAP node (Profiles §4.2.2 / SOAP 1.1 §4.2.2).
const SOAP_ACTOR_NEXT: &str = "http://schemas.xmlsoap.org/soap/actor/next";

/// `PAOS:` HTTP header value the ECP client sends to the SP (step 1, Bindings
/// §3.3.4): the Liberty PAOS version plus the ECP service URI.
pub const PAOS_HEADER: &str =
    "ver=\"urn:liberty:paos:2003-08\";\"urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp\"";

/// `Accept` HTTP header value the ECP client sends to the SP (step 1).
pub const PAOS_ACCEPT: &str = "text/html, application/vnd.paos+xml";

/// `Content-Type` for a PAOS message body (Bindings §3.3.4).
pub const PAOS_CONTENT_TYPE: &str = "application/vnd.paos+xml";

/// The HTTP request headers an ECP client sends to the SP to initiate the
/// PAOS flow (step 1): `Accept` and `PAOS`. Returned as owned pairs ready to
/// drop into an [`HttpRequest`](crate::http::HttpRequest) or the caller's own
/// HTTP machinery.
#[must_use]
pub fn paos_request_headers() -> Vec<(String, String)> {
    vec![
        ("Accept".to_owned(), PAOS_ACCEPT.to_owned()),
        ("PAOS".to_owned(), PAOS_HEADER.to_owned()),
    ]
}

/// HTTP headers for a PAOS message body POST (`Content-Type:
/// application/vnd.paos+xml`). Used by the client's PAOS POST back to the SP
/// (step 5) and is also the correct `Content-Type` for the SP's ECP response
/// (step 2).
#[must_use]
pub fn paos_content_type_headers() -> Vec<(String, String)> {
    vec![("Content-Type".to_owned(), PAOS_CONTENT_TYPE.to_owned())]
}

fn paos_qname(local: &str) -> QName {
    QName::new(Some(PAOS_NS.to_owned()), local)
}

fn ecp_qname(local: &str) -> QName {
    QName::new(Some(ECP_NS.to_owned()), local)
}

fn saml_qname(local: &str) -> QName {
    QName::new(Some(SAML_NS.to_owned()), local)
}

/// `soap:mustUnderstand` / `soap:actor` attribute QNames (SOAP 1.1 §4.2). They
/// live in the SOAP envelope namespace, so the envelope's `soap:` declaration
/// resolves them on emit.
fn soap_attr(local: &str) -> QName {
    QName::new(Some(SOAP_NS.to_owned()), local)
}

// =============================================================================
// SP side
// =============================================================================

/// What the SP nominates as its ECP AssertionConsumerService and PAOS callback.
///
/// In ECP both URLs are typically the SP's single PAOS endpoint, but the spec
/// keeps them distinct: `acs_url` is the `<samlp:AuthnRequest>`'s
/// `AssertionConsumerServiceURL` (which the IdP echoes into
/// `<ecp:Response>/@AssertionConsumerServiceURL`), while `response_consumer_url`
/// is the `<paos:Request>/@responseConsumerURL` the client POSTs the assertion
/// back to. The security check in Profiles §4.2.4.2 compares these two values
/// as they round-trip through the IdP, so they are modeled separately.
pub struct SpEcpEndpoints<'a> {
    /// `<samlp:AuthnRequest>/@AssertionConsumerServiceURL`.
    pub acs_url: &'a str,
    /// `<paos:Request>/@responseConsumerURL` — where the client PAOS-POSTs the
    /// assertion (step 5).
    pub response_consumer_url: &'a str,
}

/// The SP's ECP response (step 2): the PAOS SOAP envelope carrying the
/// AuthnRequest, plus the `messageID` the SP must remember to match the
/// client's eventual `<paos:Response>/@refToMessageID` (step 6).
#[derive(Debug, Clone)]
pub struct SpAuthnRequest {
    /// The full SOAP envelope XML to return as the HTTP response body
    /// (`Content-Type: application/vnd.paos+xml`).
    pub soap_envelope: String,
    /// The `<paos:Request>/@messageID` embedded in `soap_envelope`. The SP MUST
    /// persist this (keyed to the user's nascent session) and later require the
    /// PAOS POST's `<paos:Response>/@refToMessageID` to equal it
    /// ([`SpEcp::consume_paos_response`]).
    pub message_id: String,
}

/// Inputs for [`SpEcp::build_authn_request`].
pub struct BuildEcpAuthnRequest<'a> {
    /// The SP's own entity ID (emitted as the AuthnRequest `<saml:Issuer>`).
    pub sp_entity_id: &'a str,
    /// The IdP SSO endpoint the AuthnRequest is destined for (the
    /// `Destination` attribute). The client POSTs to the IdP's ECP SOAP
    /// endpoint, which may differ; this is the logical SSO destination.
    pub idp_sso_url: &'a str,
    /// The SP's ACS / PAOS callback URLs (see [`SpEcpEndpoints`]).
    pub endpoints: SpEcpEndpoints<'a>,
    /// `<ecp:Request>/@IsPassive`, if the SP wants a passive request.
    pub is_passive: bool,
    /// `<ecp:Request>/@ProviderName`, a human-readable SP name, if set.
    pub provider_name: Option<&'a str>,
    pub issue_instant: std::time::SystemTime,
}

/// SP-side ECP primitives (Profiles §4.2 steps 2 and 6).
pub struct SpEcp;

impl SpEcp {
    /// Build the SP's ECP response (step 2): a SOAP envelope whose header
    /// carries `<paos:Request>` + `<ecp:Request>` and whose body is the
    /// `<samlp:AuthnRequest>` (with `ProtocolBinding=…:PAOS`). Returns the
    /// envelope plus the generated `messageID`.
    ///
    /// The AuthnRequest reuses the crate's AuthnRequest builder; the SP normally
    /// signs nothing here because the ECP client cannot be authenticated at the
    /// SP at this point — the trust is established later by the IdP-signed
    /// Response.
    pub fn build_authn_request(input: &BuildEcpAuthnRequest<'_>) -> Result<SpAuthnRequest, Error> {
        let message_id = super::random_xml_id()?;
        let request_id = super::random_xml_id()?;

        // <samlp:AuthnRequest …> body. ECP nominates the ACS by URL with the
        // PAOS protocol binding (Profiles §4.2.3): the IdP will return the
        // Response to the client, which delivers it to this ACS via PAOS.
        let authn = build_authn_request_element(&BuildAuthnRequest {
            id: &request_id,
            issue_instant: input.issue_instant,
            issuer_entity_id: input.sp_entity_id,
            destination: input.idp_sso_url,
            force_authn: false,
            is_passive: input.is_passive,
            acs_selection: AcsRequest::Url(input.endpoints.acs_url),
            // `SsoResponseBinding` cannot represent PAOS, so emit the
            // ProtocolBinding attribute directly below instead.
            protocol_binding: None,
            requested_name_id_format: None,
            requested_authn_context: None,
        })?;
        let authn = set_protocol_binding_paos(authn);

        // <paos:Request soap:mustUnderstand="1" soap:actor="…next"
        //               responseConsumerURL="…" messageID="…"
        //               service="…ecp"/>
        let paos_request = Element::build(paos_qname("Request"))
            .with_namespace(Some("paos".to_owned()), PAOS_NS)
            .with_attribute(soap_attr("mustUnderstand"), "1")
            .with_attribute(soap_attr("actor"), SOAP_ACTOR_NEXT)
            .with_attribute(
                QName::new(None, "responseConsumerURL"),
                input.endpoints.response_consumer_url.to_owned(),
            )
            .with_attribute(QName::new(None, "service"), ECP_SERVICE)
            .with_attribute(QName::new(None, "messageID"), message_id.clone())
            .finish();

        // <ecp:Request soap:mustUnderstand="1" soap:actor="…next"
        //              [IsPassive] [ProviderName]>
        //   <saml:Issuer>{sp}</saml:Issuer>
        // </ecp:Request>
        let issuer = Element::build(saml_qname("Issuer"))
            .with_namespace(Some("saml".to_owned()), SAML_NS)
            .with_text(input.sp_entity_id.to_owned())
            .finish();
        let mut ecp_request = Element::build(ecp_qname("Request"))
            .with_namespace(Some("ecp".to_owned()), ECP_NS)
            .with_attribute(soap_attr("mustUnderstand"), "1")
            .with_attribute(soap_attr("actor"), SOAP_ACTOR_NEXT);
        if input.is_passive {
            ecp_request = ecp_request.with_attribute(QName::new(None, "IsPassive"), "1");
        }
        if let Some(name) = input.provider_name {
            ecp_request =
                ecp_request.with_attribute(QName::new(None, "ProviderName"), name.to_owned());
        }
        let ecp_request = ecp_request.with_child(Node::Element(issuer)).finish();

        let soap_envelope = soap::wrap_with_header(vec![paos_request, ecp_request], authn)?;
        Ok(SpAuthnRequest {
            soap_envelope,
            message_id,
        })
    }

    /// Consume the client's PAOS POST (step 6): unwrap the SOAP envelope, check
    /// that `<paos:Response>/@refToMessageID` matches the `messageID` the SP
    /// issued in [`SpEcp::build_authn_request`], and return the inner
    /// `<samlp:Response>` XML bytes ready for
    /// [`ServiceProvider::consume_response`](crate::sp::ServiceProvider::consume_response).
    ///
    /// `expected_message_id` is the value the SP stashed from
    /// [`SpAuthnRequest::message_id`]. A mismatch (or a missing
    /// `<paos:Response>` header) is rejected with [`Error::EcpMessageIdMismatch`]
    /// / [`Error::EcpMissingPaosHeader`] — the SP never hands a Response with a
    /// foreign `refToMessageID` to the consume path.
    pub fn consume_paos_response(
        soap_envelope: &[u8],
        expected_message_id: &str,
    ) -> Result<Vec<u8>, Error> {
        let env = soap::unwrap_envelope(soap_envelope)?;

        // <paos:Response> carries the refToMessageID bound to the issued
        // messageID below. A duplicate block could hide a second value behind
        // the first-match read, so reject it.
        if env.header_block_count(PAOS_NS, "Response") > 1 {
            return Err(Error::EcpDuplicatePaosHeader { header: "Response" });
        }
        let paos_response = env
            .header_block(PAOS_NS, "Response")
            .ok_or(Error::EcpMissingPaosHeader { header: "Response" })?;
        let ref_to =
            paos_response
                .attribute(None, "refToMessageID")
                .ok_or(Error::EcpMissingPaosHeader {
                    header: "Response/@refToMessageID",
                })?;
        if ref_to != expected_message_id {
            return Err(Error::EcpMessageIdMismatch);
        }

        // Validate the body payload's root QName on the borrowed in-arena
        // element before re-serializing — no separate Document::parse of the
        // (large, signed) Response just to read its root tag.
        require_body_payload_qname(
            &env,
            "Response",
            "ECP PAOS POST: soap:Body payload is not samlp:Response",
        )?;
        env.body_payload_xml()
    }
}

/// Assert that the borrowed `<soap:Body>` payload's root QName is
/// `{samlp}local`, returning `err_msg` as an [`Error::XmlParse`] otherwise.
/// Inspects the element already parsed into the envelope's arena, avoiding a
/// second parse of the payload purely to read its root tag.
fn require_body_payload_qname(
    env: &soap::UnwrappedEnvelope,
    local: &str,
    err_msg: &str,
) -> Result<(), Error> {
    let payload = env.body_payload().ok_or_else(|| {
        Error::XmlParse("SOAP: soap:Body contains no payload element".to_string())
    })?;
    if payload.qname().namespace() != Some(SAMLP_NS) || payload.qname().local() != local {
        return Err(Error::XmlParse(err_msg.to_string()));
    }
    Ok(())
}

/// Set the `ProtocolBinding` attribute of an AuthnRequest element to the PAOS
/// binding URI. `build_authn_request_element` only accepts an
/// `SsoResponseBinding` (POST / Artifact), which cannot represent PAOS and is
/// called here with `protocol_binding: None`, so the ECP SP adds the single
/// attribute in place rather than emitting it from the builder.
fn set_protocol_binding_paos(mut authn: Element) -> Element {
    authn.push_attribute(QName::new(None, "ProtocolBinding"), PAOS_BINDING.to_owned());
    authn
}

// =============================================================================
// Client side
// =============================================================================

/// The SP's ECP response, parsed by the client (step 2 → step 3).
///
/// Carries the two pieces the client must round-trip through the IdP — the
/// `response_consumer_url` and `message_id` — plus the bare AuthnRequest to
/// relay. `response_consumer_url` is the anchor for the critical security check
/// in [`ClientEcp::build_paos_post`]: it is the *only* URL the client will ever
/// deliver an assertion to, regardless of what the IdP later claims.
#[derive(Debug, Clone)]
pub struct ParsedSpRequest {
    /// `<paos:Request>/@responseConsumerURL`.
    pub response_consumer_url: String,
    /// `<paos:Request>/@messageID`.
    pub message_id: String,
    /// The bare `<samlp:AuthnRequest>` XML to relay to the IdP (no SOAP, no
    /// PAOS headers).
    pub authn_request_xml: Vec<u8>,
}

/// The IdP's ECP response, parsed by the client (step 4 → step 5).
#[derive(Debug, Clone)]
pub struct ParsedIdpResponse {
    /// `<ecp:Response>/@AssertionConsumerServiceURL` — the URL the IdP asserts
    /// the assertion should be delivered to. Subject to the equality check
    /// against the SP's `responseConsumerURL` (Profiles §4.2.4.2).
    pub assertion_consumer_service_url: String,
    /// The `<samlp:Response>` XML from the IdP's SOAP body (signed).
    pub response_xml: Vec<u8>,
}

/// Client-side ECP primitives (Profiles §4.2 steps 3 and 5). These are the
/// security-critical legs: the client is the only party that sees both the SP's
/// `responseConsumerURL` and the IdP's `AssertionConsumerServiceURL`, so it is
/// the party that must enforce their equality (§4.2.4.2).
pub struct ClientEcp;

impl ClientEcp {
    /// Parse the SP's PAOS SOAP response (step 2): extract the
    /// `responseConsumerURL`, the `messageID`, and the bare `<samlp:AuthnRequest>`.
    ///
    /// Rejects an envelope whose body is not a `<samlp:AuthnRequest>`, or whose
    /// header is missing the `<paos:Request>` block or its required attributes
    /// ([`Error::EcpMissingPaosHeader`]).
    pub fn parse_sp_request(soap_envelope: &[u8]) -> Result<ParsedSpRequest, Error> {
        let env = soap::unwrap_envelope(soap_envelope)?;

        // <paos:Request> carries the responseConsumerURL — the only URL the
        // client will ever deliver an assertion to. A duplicate block could
        // smuggle a second value past the first-match read, so reject it.
        if env.header_block_count(PAOS_NS, "Request") > 1 {
            return Err(Error::EcpDuplicatePaosHeader { header: "Request" });
        }
        let paos_request = env
            .header_block(PAOS_NS, "Request")
            .ok_or(Error::EcpMissingPaosHeader { header: "Request" })?;
        let response_consumer_url = paos_request
            .attribute(None, "responseConsumerURL")
            .ok_or(Error::EcpMissingPaosHeader {
                header: "Request/@responseConsumerURL",
            })?
            .to_owned();
        let message_id = paos_request
            .attribute(None, "messageID")
            .ok_or(Error::EcpMissingPaosHeader {
                header: "Request/@messageID",
            })?
            .to_owned();

        require_body_payload_qname(
            &env,
            "AuthnRequest",
            "ECP SP response: soap:Body payload is not samlp:AuthnRequest",
        )?;
        let payload = env.body_payload_xml()?;

        Ok(ParsedSpRequest {
            response_consumer_url,
            message_id,
            authn_request_xml: payload,
        })
    }

    /// Wrap the bare `<samlp:AuthnRequest>` (recovered by [`Self::parse_sp_request`])
    /// in a fresh SOAP envelope with **no** PAOS / ECP headers, ready to POST to
    /// the IdP's ECP SOAP endpoint (step 3, Profiles §4.2.4.1).
    ///
    /// Authentication to the IdP (HTTP Basic, mTLS, …) and the POST itself are
    /// the caller's responsibility — the library does not own the socket.
    pub fn relay_request_to_idp(authn_request_xml: &[u8]) -> Result<String, Error> {
        soap::wrap(std::str::from_utf8(authn_request_xml).map_err(|_err| {
            Error::XmlParse("ECP relay: AuthnRequest XML is not UTF-8".to_string())
        })?)
    }

    /// Parse the IdP's SOAP response (step 4): extract
    /// `<ecp:Response>/@AssertionConsumerServiceURL` and the `<samlp:Response>`
    /// from the body. A `<soap:Fault>` is surfaced as [`Error::SoapFault`].
    ///
    /// This does **not** perform the §4.2.4.2 equality check or any signature
    /// verification — those happen in [`Self::build_paos_post`] and in the SP's
    /// downstream `consume_response`, respectively.
    pub fn parse_idp_response(soap_envelope: &[u8]) -> Result<ParsedIdpResponse, Error> {
        let env = soap::unwrap_envelope(soap_envelope)?;

        // <ecp:Response> carries the AssertionConsumerServiceURL checked in
        // build_paos_post (Profiles §4.2.4.2). A duplicate block could hide a
        // second URL behind the first-match read, so reject it.
        if env.header_block_count(ECP_NS, "Response") > 1 {
            return Err(Error::EcpDuplicatePaosHeader {
                header: "ecp:Response",
            });
        }
        let ecp_response =
            env.header_block(ECP_NS, "Response")
                .ok_or(Error::EcpMissingPaosHeader {
                    header: "ecp:Response",
                })?;
        let assertion_consumer_service_url = ecp_response
            .attribute(None, "AssertionConsumerServiceURL")
            .ok_or(Error::EcpMissingPaosHeader {
                header: "ecp:Response/@AssertionConsumerServiceURL",
            })?
            .to_owned();

        require_body_payload_qname(
            &env,
            "Response",
            "ECP IdP response: soap:Body payload is not samlp:Response",
        )?;
        let response_xml = env.body_payload_xml()?;

        Ok(ParsedIdpResponse {
            assertion_consumer_service_url,
            response_xml,
        })
    }

    /// Build the client's PAOS POST back to the SP (step 5), **enforcing the
    /// §4.2.4.2 security check**.
    ///
    /// This compares `sp_request.response_consumer_url` (what the SP asked for,
    /// step 2) against `idp_response.assertion_consumer_service_url` (what the
    /// IdP claims, step 4) with an exact string match. On mismatch it returns
    /// [`Error::EcpAcsUrlMismatch`] — whose payload is the
    /// ready-to-POST SOAP fault the client MUST send to the SP's
    /// `responseConsumerURL` instead — and the assertion is **never** placed in
    /// a deliverable envelope. There is no other path that constructs the PAOS
    /// POST, so an assertion cannot reach the SP when the URLs disagree.
    ///
    /// On match, returns the `<paos:Response refToMessageID="…"/>`-headed SOAP
    /// envelope carrying the IdP's `<samlp:Response>`, ready to POST to
    /// `sp_request.response_consumer_url` with
    /// `Content-Type: application/vnd.paos+xml`.
    pub fn build_paos_post(
        sp_request: &ParsedSpRequest,
        idp_response: &ParsedIdpResponse,
    ) -> Result<String, Error> {
        // Profiles §4.2.4.2: the assertion-consumer URL the IdP returned MUST
        // equal the response-consumer URL the SP supplied. Exact match. This is
        // the load-bearing line — everything after it assumes the URLs agree.
        if sp_request.response_consumer_url != idp_response.assertion_consumer_service_url {
            let fault = build_acs_mismatch_fault()?;
            return Err(Error::EcpAcsUrlMismatch {
                response_consumer_url: sp_request.response_consumer_url.clone(),
                assertion_consumer_service_url: idp_response.assertion_consumer_service_url.clone(),
                soap_fault: fault,
            });
        }

        let response_doc = Document::parse(&idp_response.response_xml)?;
        let response_elem = response_doc.root().clone();

        // <paos:Response soap:actor="…next" refToMessageID="…"/>
        let paos_response = Element::build(paos_qname("Response"))
            .with_namespace(Some("paos".to_owned()), PAOS_NS)
            .with_attribute(soap_attr("actor"), SOAP_ACTOR_NEXT)
            .with_attribute(
                QName::new(None, "refToMessageID"),
                sp_request.message_id.clone(),
            )
            .finish();

        soap::wrap_with_header(vec![paos_response], response_elem)
    }
}

/// Build the SOAP fault the client sends to the SP's `responseConsumerURL` when
/// the §4.2.4.2 ACS-URL check fails (Profiles §4.2.4.2). The fault is a plain
/// `<soap:Fault>` with a `soap:Client` code; it carries no assertion.
fn build_acs_mismatch_fault() -> Result<String, Error> {
    let faultcode = Element::build(QName::new(None, "faultcode"))
        .with_text("soap:Client")
        .finish();
    let faultstring = Element::build(QName::new(None, "faultstring"))
        .with_text(
            "ECP AssertionConsumerServiceURL does not match the SP responseConsumerURL \
             (SAML 2.0 Profiles §4.2.4.2); assertion withheld",
        )
        .finish();
    let fault = Element::build(QName::new(Some(SOAP_NS.to_owned()), "Fault"))
        .with_child(Node::Element(faultcode))
        .with_child(Node::Element(faultstring))
        .finish();
    soap::wrap_element(fault)
}

// =============================================================================
// IdP side
// =============================================================================

/// IdP-side ECP primitives (Profiles §4.2 steps 3-inbound and 4-outbound).
pub struct IdpEcp;

impl IdpEcp {
    /// Consume the SOAP-wrapped `<samlp:AuthnRequest>` the client POSTs to the
    /// IdP's ECP endpoint (step 3): unwrap the envelope and return the bare
    /// AuthnRequest XML, ready for
    /// [`IdentityProvider::consume_authn_request`](crate::idp::IdentityProvider::consume_authn_request).
    ///
    /// The client's SOAP envelope carries no PAOS headers on this leg
    /// (Profiles §4.2.4.1), so this is a plain SOAP unwrap that additionally
    /// asserts the body is an `<samlp:AuthnRequest>`.
    pub fn parse_authn_request(soap_envelope: &[u8]) -> Result<Vec<u8>, Error> {
        let body = soap::unwrap(soap_envelope)?;
        let xml = body.payload_xml()?;
        let doc = Document::parse(&xml)?;
        if doc.root().qname().namespace() != Some(SAMLP_NS)
            || doc.root().qname().local() != "AuthnRequest"
        {
            return Err(Error::XmlParse(
                "ECP IdP request: soap:Body payload is not samlp:AuthnRequest".to_string(),
            ));
        }
        Ok(xml)
    }

    /// Build the IdP's ECP response (step 4): a SOAP envelope whose header is
    /// `<ecp:Response soap:mustUnderstand="1" soap:actor="…next"
    /// AssertionConsumerServiceURL="…"/>` and whose body is `response_xml` (the
    /// signed `<samlp:Response>` the IdP minted via
    /// [`IdentityProvider::issue_response`](crate::idp::IdentityProvider::issue_response)
    /// and recovered as raw XML).
    ///
    /// `assertion_consumer_service_url` is the ACS URL the IdP resolved for the
    /// requesting SP (typically the AuthnRequest's `AssertionConsumerServiceURL`,
    /// validated against SP metadata). It is echoed verbatim into
    /// `<ecp:Response>` and is exactly the value the client checks against the
    /// SP's `responseConsumerURL` in [`ClientEcp::build_paos_post`].
    pub fn build_response(
        assertion_consumer_service_url: &str,
        response_xml: &[u8],
    ) -> Result<String, Error> {
        let response_doc = Document::parse(response_xml)?;
        let response_elem = response_doc.root().clone();
        if response_elem.qname().namespace() != Some(SAMLP_NS)
            || response_elem.qname().local() != "Response"
        {
            return Err(Error::XmlParse(
                "ECP IdP build_response: payload is not samlp:Response".to_string(),
            ));
        }

        let ecp_response = Element::build(ecp_qname("Response"))
            .with_namespace(Some("ecp".to_owned()), ECP_NS)
            .with_attribute(soap_attr("mustUnderstand"), "1")
            .with_attribute(soap_attr("actor"), SOAP_ACTOR_NEXT)
            .with_attribute(
                QName::new(None, "AssertionConsumerServiceURL"),
                assertion_consumer_service_url.to_owned(),
            )
            .finish();

        soap::wrap_with_header(vec![ecp_response], response_elem)
    }
}

/// Whether `uri` is the PAOS binding URI. ECP's `ProtocolBinding` is PAOS,
/// which is intentionally absent from the four-variant [`Binding`](crate::binding::Binding)
/// enum (and from `SsoResponseBinding`); ECP callers detect it via this helper
/// instead of string-matching the constant inline.
#[must_use]
pub fn is_paos_binding(uri: &str) -> bool {
    uri == PAOS_BINDING
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::cert::X509Certificate;
    use crate::crypto::cert::test_vectors::{RSA_CERT_PEM, RSA_KEY_PKCS8_PEM};
    use crate::crypto::keypair::KeyPair;
    use crate::dsig::algorithms::{C14nAlgorithm, DigestAlgorithm, SignatureAlgorithm};
    use crate::dsig::sign::{SignOptions, sign_element};
    use crate::xml::emit::emit_element;
    use std::time::{Duration, UNIX_EPOCH};

    const SP_ENTITY_ID: &str = "https://sp.example.com/ecp";
    const SP_ACS_URL: &str = "https://sp.example.com/ecp/acs";
    const IDP_SSO_URL: &str = "https://idp.example.com/ecp/sso";

    fn fixed_instant() -> std::time::SystemTime {
        UNIX_EPOCH
            .checked_add(Duration::from_secs(1_779_798_896))
            .expect("epoch + offset")
    }

    fn endpoints() -> SpEcpEndpoints<'static> {
        SpEcpEndpoints {
            acs_url: SP_ACS_URL,
            response_consumer_url: SP_ACS_URL,
        }
    }

    fn sp_build() -> SpAuthnRequest {
        SpEcp::build_authn_request(&BuildEcpAuthnRequest {
            sp_entity_id: SP_ENTITY_ID,
            idp_sso_url: IDP_SSO_URL,
            endpoints: endpoints(),
            is_passive: false,
            provider_name: Some("Test SP"),
            issue_instant: fixed_instant(),
        })
        .expect("build SP ECP request")
    }

    fn test_keypair() -> KeyPair {
        let kp = KeyPair::from_pkcs8_pem(RSA_KEY_PKCS8_PEM).expect("key");
        let cert = X509Certificate::from_pem(RSA_CERT_PEM).expect("cert");
        kp.with_certificate(cert)
    }

    /// Build a signed `<samlp:Response>` XML for use as the IdP body payload.
    /// Signs the whole Response element (enveloped) with the test key so the
    /// PAOS POST round-trip exercises the signing+verification machinery.
    fn signed_response_xml(in_response_to: &str, acs_url: &str) -> Vec<u8> {
        let kp = test_keypair();
        let issuer = Element::build(saml_qname("Issuer"))
            .with_text("https://idp.example.com/ecp".to_owned())
            .finish();
        let status_code = Element::build(QName::new(Some(SAMLP_NS.to_owned()), "StatusCode"))
            .with_attribute(
                QName::new(None, "Value"),
                "urn:oasis:names:tc:SAML:2.0:status:Success".to_owned(),
            )
            .finish();
        let status = Element::build(QName::new(Some(SAMLP_NS.to_owned()), "Status"))
            .with_child(Node::Element(status_code))
            .finish();
        let response = Element::build(QName::new(Some(SAMLP_NS.to_owned()), "Response"))
            .with_namespace(Some("samlp".to_owned()), SAMLP_NS)
            .with_namespace(Some("saml".to_owned()), SAML_NS)
            .with_attribute(QName::new(None, "ID"), "_ecp-response".to_owned())
            .with_attribute(QName::new(None, "Version"), "2.0")
            .with_attribute(QName::new(None, "IssueInstant"), "2026-05-26T12:34:56Z")
            .with_attribute(QName::new(None, "InResponseTo"), in_response_to.to_owned())
            .with_attribute(QName::new(None, "Destination"), acs_url.to_owned())
            .with_child(Node::Element(issuer))
            .with_child(Node::Element(status))
            .finish();
        let stash = Document::new(response).expect("stash");
        let signed = sign_element(
            stash.root().clone(),
            &stash,
            SignOptions {
                signing_key: &kp,
                sig_alg: SignatureAlgorithm::RsaSha256,
                digest_alg: DigestAlgorithm::Sha256,
                c14n_alg: C14nAlgorithm::ExclusiveCanonical,
                inclusive_namespaces: &[],
                include_x509_cert: true,
            },
        )
        .expect("sign response");
        let doc = Document::new(signed).expect("doc");
        emit_element(doc.root()).expect("emit").into_bytes()
    }

    #[test]
    fn sp_request_envelope_has_paos_and_ecp_headers_and_authn_body() {
        let built = sp_build();
        let doc = Document::parse(built.soap_envelope.as_bytes()).expect("parse envelope");
        let env = doc.root();
        assert_eq!(env.qname().namespace(), Some(SOAP_NS));
        assert_eq!(env.qname().local(), "Envelope");

        let header = env.child_element(Some(SOAP_NS), "Header").expect("header");
        let paos = header
            .child_element(Some(PAOS_NS), "Request")
            .expect("paos");
        assert_eq!(
            paos.attribute(Some(SOAP_NS), "mustUnderstand"),
            Some("1"),
            "paos:Request must carry soap:mustUnderstand"
        );
        assert_eq!(
            paos.attribute(Some(SOAP_NS), "actor"),
            Some(SOAP_ACTOR_NEXT)
        );
        assert_eq!(
            paos.attribute(None, "responseConsumerURL"),
            Some(SP_ACS_URL)
        );
        assert_eq!(paos.attribute(None, "service"), Some(ECP_NS));
        assert_eq!(
            paos.attribute(None, "messageID"),
            Some(built.message_id.as_str())
        );

        let ecp = header.child_element(Some(ECP_NS), "Request").expect("ecp");
        assert_eq!(ecp.attribute(Some(SOAP_NS), "mustUnderstand"), Some("1"));
        assert_eq!(ecp.attribute(None, "ProviderName"), Some("Test SP"));
        let ecp_issuer = ecp.child_element(Some(SAML_NS), "Issuer").expect("issuer");
        assert_eq!(ecp_issuer.text_content(), SP_ENTITY_ID);

        let body = env.child_element(Some(SOAP_NS), "Body").expect("body");
        let authn = body
            .child_element(Some(SAMLP_NS), "AuthnRequest")
            .expect("authn");
        assert_eq!(
            authn.attribute(None, "ProtocolBinding"),
            Some(PAOS_BINDING),
            "AuthnRequest ProtocolBinding must be PAOS"
        );
        assert_eq!(
            authn.attribute(None, "AssertionConsumerServiceURL"),
            Some(SP_ACS_URL)
        );
    }

    #[test]
    fn client_parses_sp_request_and_relays_bare_authn_to_idp() {
        let built = sp_build();
        let parsed = ClientEcp::parse_sp_request(built.soap_envelope.as_bytes()).expect("parse");
        assert_eq!(parsed.response_consumer_url, SP_ACS_URL);
        assert_eq!(parsed.message_id, built.message_id);

        let authn_doc = Document::parse(&parsed.authn_request_xml).expect("authn parse");
        assert_eq!(authn_doc.root().qname().local(), "AuthnRequest");

        // Relayed envelope to IdP carries NO PAOS headers.
        let to_idp = ClientEcp::relay_request_to_idp(&parsed.authn_request_xml).expect("relay");
        let idp_env = Document::parse(to_idp.as_bytes()).expect("idp env parse");
        assert!(
            idp_env
                .root()
                .child_element(Some(SOAP_NS), "Header")
                .is_none(),
            "relay to IdP must have no soap:Header"
        );
        let idp_body = idp_env
            .root()
            .child_element(Some(SOAP_NS), "Body")
            .expect("body");
        assert!(
            idp_body
                .child_element(Some(SAMLP_NS), "AuthnRequest")
                .is_some()
        );
    }

    #[test]
    fn full_three_leg_round_trip_delivers_assertion_to_sp() {
        // Step 2: SP builds the PAOS request.
        let sp = sp_build();

        // Step 3: client parses + relays to IdP.
        let parsed_sp = ClientEcp::parse_sp_request(sp.soap_envelope.as_bytes()).expect("parse sp");
        let to_idp = ClientEcp::relay_request_to_idp(&parsed_sp.authn_request_xml).expect("relay");

        // (mock IdP) unwrap the AuthnRequest, mint a signed Response, wrap it
        // with an ecp:Response header echoing the SAME ACS URL.
        let authn_xml = IdpEcp::parse_authn_request(to_idp.as_bytes()).expect("idp parse");
        let authn_doc = Document::parse(&authn_xml).expect("authn doc");
        let request_id = authn_doc
            .root()
            .attribute(None, "ID")
            .expect("authn ID")
            .to_owned();
        let response_xml = signed_response_xml(&request_id, SP_ACS_URL);
        let idp_envelope = IdpEcp::build_response(SP_ACS_URL, &response_xml).expect("idp build");

        // Step 4 → 5: client parses IdP response, runs the ACS check, builds PAOS POST.
        let parsed_idp = ClientEcp::parse_idp_response(idp_envelope.as_bytes()).expect("parse idp");
        assert_eq!(parsed_idp.assertion_consumer_service_url, SP_ACS_URL);
        let paos_post = ClientEcp::build_paos_post(&parsed_sp, &parsed_idp).expect("build paos");

        // Step 6: SP consumes the PAOS POST and recovers the inner Response.
        let inner = SpEcp::consume_paos_response(paos_post.as_bytes(), &sp.message_id)
            .expect("consume paos");
        let inner_doc = Document::parse(&inner).expect("inner doc");
        assert_eq!(inner_doc.root().qname().local(), "Response");
        assert_eq!(
            inner_doc.root().attribute(None, "ID"),
            Some("_ecp-response")
        );

        // The recovered Response still verifies against the IdP cert — the SOAP
        // wrap/unwrap preserved the enveloped signature byte-structure.
        let cert = X509Certificate::from_pem(RSA_CERT_PEM).unwrap();
        let sig = inner_doc
            .root()
            .child_element(Some(crate::dsig::reference::DS_NS), "Signature")
            .expect("signature present");
        let verified = crate::dsig::verify::verify_signature(
            &inner_doc,
            sig,
            std::slice::from_ref(&cert),
            &[SignatureAlgorithm::RsaSha256],
        )
        .expect("verify recovered response signature");
        assert_eq!(verified.signed_element, inner_doc.root().id());
    }

    #[test]
    fn acs_url_mismatch_refuses_delivery_and_yields_soap_fault() {
        // The IdP returns a DIFFERENT AssertionConsumerServiceURL than the SP's
        // responseConsumerURL. Profiles §4.2.4.2: the client MUST NOT deliver.
        let sp = sp_build();
        let parsed_sp = ClientEcp::parse_sp_request(sp.soap_envelope.as_bytes()).expect("parse sp");

        let response_xml = signed_response_xml("_anything", "https://attacker.example.com/exfil");
        let attacker_url = "https://attacker.example.com/exfil";
        let idp_envelope = IdpEcp::build_response(attacker_url, &response_xml).expect("idp build");
        let parsed_idp = ClientEcp::parse_idp_response(idp_envelope.as_bytes()).expect("parse idp");

        let err = ClientEcp::build_paos_post(&parsed_sp, &parsed_idp).unwrap_err();
        match err {
            Error::EcpAcsUrlMismatch {
                response_consumer_url,
                assertion_consumer_service_url,
                soap_fault,
            } => {
                assert_eq!(response_consumer_url, SP_ACS_URL);
                assert_eq!(assertion_consumer_service_url, attacker_url);
                // The error carries a ready-to-POST SOAP fault, and that fault
                // carries NO assertion / Response.
                let fault_doc = Document::parse(soap_fault.as_bytes()).expect("fault doc");
                let body = fault_doc
                    .root()
                    .child_element(Some(SOAP_NS), "Body")
                    .expect("body");
                assert!(
                    body.child_element(Some(SOAP_NS), "Fault").is_some(),
                    "mismatch path must produce a soap:Fault"
                );
                assert!(
                    body.child_element(Some(SAMLP_NS), "Response").is_none(),
                    "the fault envelope must NOT carry the assertion/Response"
                );
            }
            other => panic!("expected EcpAcsUrlMismatch, got {other:?}"),
        }
    }

    #[test]
    fn sp_rejects_ref_to_message_id_mismatch() {
        // A PAOS POST whose refToMessageID does not match the issued messageID
        // is rejected before the inner Response reaches the consume path.
        let sp = sp_build();
        let parsed_sp = ClientEcp::parse_sp_request(sp.soap_envelope.as_bytes()).expect("parse sp");
        let response_xml = signed_response_xml("_req", SP_ACS_URL);
        let idp_envelope = IdpEcp::build_response(SP_ACS_URL, &response_xml).expect("idp build");
        let parsed_idp = ClientEcp::parse_idp_response(idp_envelope.as_bytes()).expect("parse idp");
        let paos_post = ClientEcp::build_paos_post(&parsed_sp, &parsed_idp).expect("build paos");

        // The SP expects a DIFFERENT messageID than the one in the POST.
        let err = SpEcp::consume_paos_response(paos_post.as_bytes(), "_some-other-message-id")
            .unwrap_err();
        assert!(
            matches!(err, Error::EcpMessageIdMismatch),
            "expected EcpMessageIdMismatch, got {err:?}"
        );

        // Sanity: the correct messageID is accepted.
        SpEcp::consume_paos_response(paos_post.as_bytes(), &sp.message_id)
            .expect("matching messageID accepted");
    }

    #[test]
    fn idp_response_soap_fault_is_surfaced() {
        let fault = format!(
            r#"<soap:Envelope xmlns:soap="{SOAP_NS}"><soap:Body><soap:Fault><faultcode>soap:Server</faultcode><faultstring>auth failed</faultstring></soap:Fault></soap:Body></soap:Envelope>"#
        );
        let err = ClientEcp::parse_idp_response(fault.as_bytes()).unwrap_err();
        match err {
            Error::SoapFault { faultcode, .. } => assert_eq!(faultcode, "soap:Server"),
            other => panic!("expected SoapFault, got {other:?}"),
        }
    }

    #[test]
    fn client_rejects_sp_response_without_paos_request_header() {
        // A SOAP envelope with the AuthnRequest body but no paos:Request header.
        let authn = r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_a" Version="2.0" IssueInstant="2026-05-26T12:34:56Z"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">x</saml:Issuer></samlp:AuthnRequest>"#;
        let envelope = soap::wrap(authn).expect("wrap");
        let err = ClientEcp::parse_sp_request(envelope.as_bytes()).unwrap_err();
        match err {
            Error::EcpMissingPaosHeader { header } => assert_eq!(header, "Request"),
            other => panic!("expected EcpMissingPaosHeader, got {other:?}"),
        }
    }

    #[test]
    fn client_rejects_duplicate_paos_request_header() {
        // Two <paos:Request> blocks: the second could carry a different
        // responseConsumerURL the first-match read would never see. Reject.
        let envelope = format!(
            r#"<soap:Envelope xmlns:soap="{SOAP_NS}" xmlns:paos="{PAOS_NS}" xmlns:samlp="{SAMLP_NS}"><soap:Header><paos:Request responseConsumerURL="https://sp.example.com/acs" messageID="_m1"/><paos:Request responseConsumerURL="https://attacker.example.com/exfil" messageID="_m2"/></soap:Header><soap:Body><samlp:AuthnRequest ID="_a"/></soap:Body></soap:Envelope>"#
        );
        let err = ClientEcp::parse_sp_request(envelope.as_bytes()).unwrap_err();
        match err {
            Error::EcpDuplicatePaosHeader { header } => assert_eq!(header, "Request"),
            other => panic!("expected EcpDuplicatePaosHeader, got {other:?}"),
        }
    }

    #[test]
    fn client_rejects_duplicate_ecp_response_header() {
        // Two <ecp:Response> blocks with different AssertionConsumerServiceURLs.
        let envelope = format!(
            r#"<soap:Envelope xmlns:soap="{SOAP_NS}" xmlns:ecp="{ECP_NS}" xmlns:samlp="{SAMLP_NS}"><soap:Header><ecp:Response AssertionConsumerServiceURL="https://sp.example.com/acs"/><ecp:Response AssertionConsumerServiceURL="https://attacker.example.com/exfil"/></soap:Header><soap:Body><samlp:Response ID="_r"/></soap:Body></soap:Envelope>"#
        );
        let err = ClientEcp::parse_idp_response(envelope.as_bytes()).unwrap_err();
        match err {
            Error::EcpDuplicatePaosHeader { header } => assert_eq!(header, "ecp:Response"),
            other => panic!("expected EcpDuplicatePaosHeader, got {other:?}"),
        }
    }

    #[test]
    fn is_paos_binding_matches_only_paos() {
        assert!(is_paos_binding(PAOS_BINDING));
        assert!(!is_paos_binding(
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        ));
    }

    #[test]
    fn paos_headers_carry_spec_values() {
        let h = paos_request_headers();
        assert!(h.iter().any(|(k, v)| k == "Accept" && v == PAOS_ACCEPT));
        assert!(
            h.iter()
                .any(|(k, v)| k == "PAOS" && v.contains("urn:liberty:paos:2003-08"))
        );
        let ct = paos_content_type_headers();
        assert!(
            ct.iter()
                .any(|(k, v)| k == "Content-Type" && v == PAOS_CONTENT_TYPE)
        );
    }
}
