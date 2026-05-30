//! HTTP handlers for the IdP-side SAML flows.
//!
//! - `GET /` — landing page. Welcome banner when a session is present,
//!   "use an SP to log in" copy otherwise.
//! - `GET /metadata` — signed `<EntityDescriptor>` per
//!   [`saml::IdentityProvider::metadata_xml`].
//! - `GET | POST /saml/sso` — decode the inbound binding wire (DEFLATE+
//!   base64 over Redirect, base64 over POST), hand the XML to
//!   [`saml::IdentityProvider::consume_authn_request`], then either issue the
//!   Response immediately (session present) or redirect to the login form.
//! - `POST /login` — verify credentials, mint the session cookie, redirect
//!   to `/saml/sso/continue?request_id=…` which pulls the stashed request.
//! - `POST /saml/sso/continue` — finalize the login by issuing the
//!   Response over the SP's preferred binding.
//! - `GET | POST /saml/slo` — verify the SP's signed LogoutRequest, clear
//!   the local session, echo the LogoutResponse back.
//! - `POST /saml/artifact` (feature `artifact-binding`) — the
//!   ArtifactResolutionService: parse the SP's SOAP `<samlp:ArtifactResolve>`,
//!   one-time-consume the stashed `<samlp:Response>` keyed by the artifact,
//!   and return it wrapped in a SOAP `<samlp:ArtifactResponse>`.

use std::time::{Duration, SystemTime};

use axum::{
    extract::{Form, RawQuery, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
};
use serde::Deserialize;
use tracing::{info, warn};

use saml::{
    Attribute, AuthnContextClassRef, Binding, ConsumeAuthnRequest, ConsumeLogoutRequest,
    ConsumeLogoutResponse, DetachedSignature, Dispatch, IssueResponse, LogoutDispatch,
    LogoutOutcome, LogoutStatus, NameId, NameIdFormat, ParsedAuthnRequest, SsoResponseDispatch,
    StartLogout, WireDirection, decode_wire,
};

use crate::auth::StoredUser;
use crate::session::{self, Session};
use crate::templates::{self, LoginView};
use crate::{AppState, PendingRequest, SpEntry, extract_session_from_headers, unix_now};

// =============================================================================
// /
// =============================================================================

pub async fn handle_index(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
) -> Response {
    let banner = raw_query
        .as_deref()
        .and_then(read_msg_query_param)
        .and_then(|msg| banner_for_msg(&msg));
    let signed_in = extract_session_from_headers(&state, &headers);
    let display = signed_in.as_ref().map(|s| s.display_name.as_str());
    Html(templates::render_index(
        &state.config.idp_entity_id,
        display,
        state.sp_count(),
        banner.as_deref(),
    ))
    .into_response()
}

// =============================================================================
// /metadata
// =============================================================================

pub async fn handle_metadata(State(state): State<AppState>) -> Response {
    match state.idp.metadata_xml(true) {
        Ok(xml) => (
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/samlmetadata+xml"),
            )],
            xml,
        )
            .into_response(),
        Err(e) => {
            warn!(error = %e, "metadata_xml failed");
            error_page(StatusCode::INTERNAL_SERVER_ERROR, "metadata emit failed")
        }
    }
}

// =============================================================================
// /saml/sso (POST + Redirect)
// =============================================================================

#[derive(Debug, Deserialize)]
pub struct SsoForm {
    #[serde(rename = "SAMLRequest")]
    saml_request: String,
    #[serde(default, rename = "RelayState")]
    relay_state: Option<String>,
}

pub async fn handle_sso_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<SsoForm>,
) -> Response {
    let decoded = match decode_wire(
        form.saml_request.as_bytes(),
        Binding::HttpPost,
        WireDirection::Request,
    ) {
        Ok(d) => d,
        Err(e) => {
            warn!(error = %e, "/saml/sso POST: SAMLRequest decode failed");
            return error_page(StatusCode::BAD_REQUEST, "SAMLRequest is not valid base64");
        }
    };
    handle_sso_xml(
        &state,
        &headers,
        &decoded.xml,
        form.relay_state.as_deref(),
        Binding::HttpPost,
        None,
    )
}

pub async fn handle_sso_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
) -> Response {
    let Some(raw_query) = raw_query.filter(|q| !q.is_empty()) else {
        return error_page(
            StatusCode::BAD_REQUEST,
            "/saml/sso GET requires a query string carrying SAMLRequest",
        );
    };

    let decoded = match decode_wire(
        raw_query.as_bytes(),
        Binding::HttpRedirect,
        WireDirection::Request,
    ) {
        Ok(d) => d,
        Err(e) => {
            warn!(error = %e, "/saml/sso GET: query decode failed");
            return error_page(
                StatusCode::BAD_REQUEST,
                "could not decode SAMLRequest from query string",
            );
        }
    };

    let detached = decoded.as_detached_signature();

    handle_sso_xml(
        &state,
        &headers,
        &decoded.xml,
        decoded.relay_state.as_deref(),
        Binding::HttpRedirect,
        detached,
    )
}

fn handle_sso_xml(
    state: &AppState,
    headers: &HeaderMap,
    saml_request_xml: &[u8],
    relay_state: Option<&str>,
    binding: Binding,
    detached: Option<DetachedSignature<'_>>,
) -> Response {
    // 1. Peek the inbound Issuer so we know which SP descriptor to
    //    validate the signature against. Same trick as the demo SP uses
    //    on /saml/acs.
    let Some(issuer) = peek_issuer(saml_request_xml) else {
        warn!("/saml/sso: AuthnRequest carries no Issuer");
        return error_page(
            StatusCode::BAD_REQUEST,
            "AuthnRequest did not carry an Issuer",
        );
    };
    let Some(entry) = state.sp_by_entity_id(&issuer) else {
        warn!(issuer = %issuer, "/saml/sso: no SP configured for Issuer");
        return error_page(
            StatusCode::UNAUTHORIZED,
            &format!("AuthnRequest Issuer `{issuer}` is not registered with this IdP"),
        );
    };

    let expected_destination = format!("{}/saml/sso", state.config.idp_base_url);

    let parsed = match state.idp.consume_authn_request(ConsumeAuthnRequest {
        sp: &entry.sp,
        peer_crypto_policy: None,
        saml_request: saml_request_xml,
        binding,
        relay_state,
        detached_signature: detached,
        expected_destination: &expected_destination,
        now: SystemTime::now(),
        clock_skew: Duration::from_mins(2),
    }) {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, sp = %entry.sp.entity_id, "/saml/sso: consume_authn_request failed");
            return error_page(
                StatusCode::UNAUTHORIZED,
                &format!("AuthnRequest rejected: {e}"),
            );
        }
    };
    info!(
        sp = %entry.sp.entity_id,
        request_id = %parsed.id,
        force_authn = parsed.force_authn,
        "/saml/sso: consumed AuthnRequest",
    );

    let request_id = parsed.id.clone();
    let parsed_arc = std::sync::Arc::new(parsed);
    let pending = PendingRequest {
        parsed: parsed_arc.clone(),
        sp_entity_id: entry.sp.entity_id.clone(),
        created_at: SystemTime::now(),
    };
    if let Err(e) = state.insert_pending(request_id.clone(), pending) {
        warn!(error = %e, "/saml/sso: pending store unavailable");
        return error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "pending store unavailable",
        );
    }

    // If we already have a session and the request didn't ask for
    // ForceAuthn, skip the password prompt and mint the Response now.
    if let Some(session) = extract_session_from_headers(state, headers)
        && !parsed_arc.force_authn
    {
        return finalize_login(state, &entry, &parsed_arc, &session);
    }

    Redirect::to(&format!("/saml/sso/login?request_id={request_id}")).into_response()
}

// =============================================================================
// /login (GET + POST)
//
// The login form lives at `/saml/sso/login?request_id=...` which is just
// a thin wrapper rendering the form via a query param. POST /login
// verifies the credentials, sets the session cookie, and bounces to
// /saml/sso/continue?request_id=...
// =============================================================================

pub async fn handle_login_get(
    State(state): State<AppState>,
    RawQuery(raw_query): RawQuery,
) -> Response {
    let request_id = raw_query
        .as_deref()
        .and_then(read_request_id_query_param)
        .unwrap_or_default();
    render_login_form(&state, request_id, None)
}

#[derive(Debug, Deserialize)]
pub struct LoginForm {
    pub request_id: String,
    pub username: String,
    pub password: String,
}

pub async fn handle_login(State(state): State<AppState>, Form(form): Form<LoginForm>) -> Response {
    let LoginForm {
        request_id,
        username,
        password,
    } = form;

    let Some(user) = state.users.verify_password(&username, &password).cloned() else {
        warn!(username, request_id, "/login: credential rejected");
        return render_login_form(&state, &request_id, Some("Invalid username or password."));
    };

    // Mint the session cookie now. The follow-up `/saml/sso/continue`
    // handler reads it.
    let now_unix = unix_now();
    let session = Session {
        user_id: user.id.clone(),
        email: user.email.clone(),
        display_name: user.display_name(),
        session_index: format!("sess-{}", uuid::Uuid::new_v4()),
        authn_instant_unix: now_unix,
        issued_at_unix: now_unix,
    };
    let cookie_value = match session::encode(&session, &state.config.session_signing_key) {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "/login: session encode failed");
            return error_page(StatusCode::INTERNAL_SERVER_ERROR, "session encode failed");
        }
    };

    let mut headers = HeaderMap::new();
    match HeaderValue::from_str(&session::set_cookie_header(&cookie_value)) {
        Ok(v) => {
            headers.insert(header::SET_COOKIE, v);
        }
        Err(e) => {
            warn!(error = %e, "/login: invalid Set-Cookie value");
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not set session cookie",
            );
        }
    }
    info!(user = %user.id, "/login: session established");

    // No pending request: just land on the IdP landing page.
    if request_id.is_empty() {
        return (headers, Redirect::to("/")).into_response();
    }
    let target = format!("/saml/sso/continue?request_id={request_id}");
    (headers, Redirect::to(&target)).into_response()
}

fn render_login_form(state: &AppState, request_id: &str, banner: Option<&str>) -> Response {
    let pending = state.peek_pending(request_id).ok().flatten();
    let (sp_label, sp_entity_id, acs_url) = match pending.as_ref() {
        Some(p) => match state.sp_by_entity_id(&p.sp_entity_id) {
            Some(entry) => (
                entry.label.clone(),
                entry.sp.entity_id.clone(),
                p.parsed.assertion_consumer_service.url.clone(),
            ),
            None => (
                "(unknown SP)".to_owned(),
                p.sp_entity_id.clone(),
                p.parsed.assertion_consumer_service.url.clone(),
            ),
        },
        None => (
            "(no pending request)".to_owned(),
            String::new(),
            String::new(),
        ),
    };

    Html(templates::render_login(&LoginView {
        idp_entity_id: &state.config.idp_entity_id,
        sp_label: &sp_label,
        sp_entity_id: &sp_entity_id,
        acs_url: &acs_url,
        request_id,
        banner,
        banner_is_error: banner.is_some(),
    }))
    .into_response()
}

// =============================================================================
// /saml/sso/continue
//
// Issued after `/login`. Pulls the pending request out of the store and
// mints the Response. If the request_id is unknown (TTL expired, server
// restart, etc) we fall back to a friendly landing redirect.
// =============================================================================

#[derive(Debug, Deserialize)]
pub struct SsoContinueForm {
    pub request_id: String,
}

pub async fn handle_sso_continue_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
) -> Response {
    let request_id = raw_query
        .as_deref()
        .and_then(read_request_id_query_param)
        .map(str::to_owned)
        .unwrap_or_default();
    finalize_continue(&state, &headers, request_id)
}

pub async fn handle_sso_continue(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<SsoContinueForm>,
) -> Response {
    finalize_continue(&state, &headers, form.request_id)
}

fn finalize_continue(state: &AppState, headers: &HeaderMap, request_id: String) -> Response {
    if request_id.is_empty() {
        return error_page(
            StatusCode::BAD_REQUEST,
            "/saml/sso/continue requires request_id",
        );
    }
    let Some(session) = extract_session_from_headers(state, headers) else {
        warn!(request_id, "/saml/sso/continue: no session cookie");
        return Redirect::to(&format!("/saml/sso/login?request_id={request_id}")).into_response();
    };

    let pending = match state.take_pending(&request_id) {
        Ok(Some(p)) => p,
        Ok(None) => {
            warn!(
                request_id,
                "/saml/sso/continue: no pending request (TTL elapsed?)"
            );
            return error_page(
                StatusCode::GONE,
                "Sign-in request is no longer pending. Restart the flow from the SP.",
            );
        }
        Err(e) => {
            warn!(error = %e, "/saml/sso/continue: pending store unavailable");
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "pending store unavailable",
            );
        }
    };

    let Some(entry) = state.sp_by_entity_id(&pending.sp_entity_id) else {
        warn!(sp = %pending.sp_entity_id, "/saml/sso/continue: SP no longer registered");
        return error_page(
            StatusCode::UNAUTHORIZED,
            "The SP that opened this sign-in is no longer registered with this IdP.",
        );
    };

    finalize_login(state, &entry, &pending.parsed, &session)
}

/// Mint the success Response and dispatch it to the SP. Used both by the
/// fresh-login path (session was created just now) and the
/// already-logged-in path (session predates the inbound AuthnRequest).
fn finalize_login(
    state: &AppState,
    entry: &SpEntry,
    parsed: &ParsedAuthnRequest,
    session: &Session,
) -> Response {
    let Some(user) = state.users.get_by_id(&session.user_id).cloned() else {
        warn!(user = %session.user_id, "/saml/sso/continue: session user no longer exists");
        return error_page(
            StatusCode::UNAUTHORIZED,
            "Your account is no longer registered with this IdP.",
        );
    };

    let attributes = build_attributes(&user);
    let now = SystemTime::now();
    let authn_instant = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(session.authn_instant_unix))
        .unwrap_or(now);

    let dispatch = match state.idp.issue_response(IssueResponse {
        sp: &entry.sp,
        in_response_to: parsed,
        name_id: NameId::new(user.email.clone(), NameIdFormat::EmailAddress),
        attributes,
        authn_instant,
        session_index: session.session_index.clone(),
        session_not_on_or_after: now.checked_add(Duration::from_hours(8)),
        authn_context_class_ref: AuthnContextClassRef::PasswordProtectedTransport,
        force_encrypt_assertion: resolve_force_encrypt(&entry.sp),
        now,
        assertion_lifetime: Duration::from_mins(5),
        subject_confirmation_lifetime: Duration::from_mins(5),
        holder_of_key_cert: None,
    }) {
        Ok(d) => d,
        Err(e) => {
            warn!(error = %e, "/saml/sso/continue: issue_response failed");
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("issue_response: {e}"),
            );
        }
    };

    finalize_sso_dispatch(state, &entry.sp.entity_id, dispatch, entry.label())
}

fn build_attributes(user: &StoredUser) -> Vec<Attribute> {
    let mut attrs = vec![
        Attribute::email(user.email.clone()),
        Attribute::display_name(user.display_name()),
        Attribute::single("givenName", user.first_name.clone()),
        Attribute::single("sn", user.last_name.clone()),
    ];
    if let Some(dept) = user.department.as_deref() {
        attrs.push(Attribute::single("department", dept));
    }
    attrs
}

/// Decide whether to encrypt the assertion for this SP.
///
/// `Some(true)` forces encryption, `Some(false)` forbids it, and `None` lets
/// the IdP's `encrypt_assertions_when_possible` default decide.
///
/// Policy: when `SAML_IDP_FORCE_ENCRYPT` is truthy AND the SP advertises an
/// encryption certificate in its metadata, encrypt. If the toggle is set but
/// the SP has no encryption cert, we cannot encrypt, so fall back to `None`
/// (issue cleartext) rather than forcing a failure. When the toggle is unset
/// we defer to the IdP default (`None`).
fn resolve_force_encrypt(sp: &saml::SpDescriptor) -> Option<bool> {
    let toggle = std::env::var("SAML_IDP_FORCE_ENCRYPT")
        .is_ok_and(|v| matches!(v.trim(), "1" | "true" | "TRUE" | "yes" | "on"));
    if toggle && sp.encryption_cert().is_some() {
        Some(true)
    } else {
        None
    }
}

// =============================================================================
// /logout — IdP-self logout (clears the local IdP cookie).
//
// This does NOT initiate SP SLO. It's a hatch for the operator using the
// IdP UI directly.
// =============================================================================

pub async fn handle_logout_self(State(state): State<AppState>, _headers: HeaderMap) -> Response {
    let _ = state; // suppress unused warning under conditional features
    let mut headers = HeaderMap::new();
    match HeaderValue::from_str(&session::clear_cookie_header()) {
        Ok(v) => {
            headers.insert(header::SET_COOKIE, v);
        }
        Err(e) => {
            warn!(error = %e, "/logout: invalid clear-cookie value");
            return error_page(StatusCode::INTERNAL_SERVER_ERROR, "could not clear cookie");
        }
    }
    (headers, Redirect::to("/?msg=signed-out-locally")).into_response()
}

// =============================================================================
// /logout-everywhere — IdP-initiated SLO.
//
// For the current IdP session, build a signed `<samlp:LogoutRequest>` to a
// participating SP and dispatch it over the SP's preferred SLO binding. The
// returning `<samlp:LogoutResponse>` lands back at `/saml/slo`, where it is
// bound to the tracker stashed here and clears the session.
//
// Front-channel SLO can only carry one SP per HTTP response, and this
// example's session doesn't record which SPs the user actually rode into,
// so we target the first registered SP that advertises an SLO endpoint —
// the single-SP demo topology. A multi-SP IdP would iterate the active
// session participants, dispatching to each in turn (typically by parking
// the remaining SPs and chaining on each LogoutResponse).
// =============================================================================

pub async fn handle_logout_everywhere(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let Some(session) = extract_session_from_headers(&state, &headers) else {
        return redirect_with_cleared_cookie("/?msg=already-signed-out");
    };

    let Some(entry) = first_sp_with_slo(&state) else {
        info!("/logout-everywhere: no SP advertises an SLO endpoint; local logout only");
        return redirect_with_cleared_cookie("/?msg=signed-out-locally");
    };
    let Some(binding) = pick_slo_binding(&entry) else {
        info!(
            sp = %entry.sp.entity_id,
            "/logout-everywhere: SP advertises no usable SLO binding; local logout only",
        );
        return redirect_with_cleared_cookie("/?msg=signed-out-locally");
    };

    let name_id = NameId::new(session.email.clone(), NameIdFormat::EmailAddress);
    let dispatch = match state.idp.start_logout(
        &entry.sp,
        StartLogout {
            name_id: &name_id,
            session_index: Some(session.session_index.as_str()),
            relay_state: None,
            reason: None,
            binding,
        },
    ) {
        Ok(d) => d,
        Err(e) => {
            warn!(error = %e, sp = %entry.sp.entity_id, "/logout-everywhere: start_logout failed");
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("start_logout: {e}"),
            );
        }
    };

    let LogoutDispatch { tracker, dispatch } = dispatch;
    if let Err(e) = state.insert_logout_tracker(tracker) {
        warn!(error = %e, "/logout-everywhere: tracker store unavailable");
        return error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "logout tracker store unavailable",
        );
    }

    info!(sp = %entry.sp.entity_id, "/logout-everywhere: dispatched LogoutRequest");
    // Keep the IdP cookie until the SP confirms via LogoutResponse — clearing
    // it now would orphan the round trip if the response never lands.
    finalize_logout_dispatch(dispatch, entry.label(), /* clear_cookie */ false)
}

/// First registered SP that advertises a usable SLO endpoint, if any.
fn first_sp_with_slo(state: &AppState) -> Option<SpEntry> {
    let guard = state.by_entity_id.lock().ok()?;
    guard
        .values()
        .find(|entry| pick_slo_binding(entry).is_some())
        .cloned()
}

// =============================================================================
// /saml/slo — SP-initiated logout
//
// Inbound LogoutRequest from the SP → verify → terminate session → echo
// LogoutResponse back. POST and Redirect bindings.
// =============================================================================

#[derive(Debug, Deserialize)]
pub struct SloForm {
    #[serde(default, rename = "SAMLRequest")]
    saml_request: Option<String>,
    #[serde(default, rename = "SAMLResponse")]
    saml_response: Option<String>,
    #[serde(default, rename = "RelayState")]
    relay_state: Option<String>,
}

pub async fn handle_slo_post(State(state): State<AppState>, Form(form): Form<SloForm>) -> Response {
    match (form.saml_request.as_deref(), form.saml_response.as_deref()) {
        (Some(req), None) => handle_slo_request_post(&state, req, form.relay_state.as_deref()),
        (None, Some(resp)) => handle_slo_response(&state, resp, Binding::HttpPost),
        (Some(_), Some(_)) => error_page(
            StatusCode::BAD_REQUEST,
            "/saml/slo received both SAMLRequest and SAMLResponse",
        ),
        (None, None) => error_page(
            StatusCode::BAD_REQUEST,
            "/saml/slo requires SAMLRequest or SAMLResponse",
        ),
    }
}

pub async fn handle_slo_get(
    State(state): State<AppState>,
    RawQuery(raw_query): RawQuery,
) -> Response {
    let Some(raw_query) = raw_query.filter(|q| !q.is_empty()) else {
        return error_page(
            StatusCode::BAD_REQUEST,
            "/saml/slo GET requires a query string carrying SAMLRequest or SAMLResponse",
        );
    };

    // A returning LogoutResponse (answering an IdP-initiated request) rides
    // the `SAMLResponse=…` parameter; an inbound SP-initiated LogoutRequest
    // rides `SAMLRequest=…`.
    if query_has_param(&raw_query, "SAMLResponse") {
        let decoded = match decode_wire(
            raw_query.as_bytes(),
            Binding::HttpRedirect,
            WireDirection::Response,
        ) {
            Ok(d) => d,
            Err(e) => {
                warn!(error = %e, "/saml/slo GET: SAMLResponse decode failed");
                return error_page(
                    StatusCode::BAD_REQUEST,
                    "could not decode SAMLResponse from query string",
                );
            }
        };
        return consume_logout_response_xml(
            &state,
            &decoded.xml,
            Binding::HttpRedirect,
            decoded.as_detached_signature(),
        );
    }

    let decoded = match decode_wire(
        raw_query.as_bytes(),
        Binding::HttpRedirect,
        WireDirection::Request,
    ) {
        Ok(d) => d,
        Err(e) => {
            warn!(error = %e, "/saml/slo GET: query decode failed");
            return error_page(
                StatusCode::BAD_REQUEST,
                "could not decode SAMLRequest from query string",
            );
        }
    };

    // Peek the Issuer to find the SP entry.
    let Some(issuer) = peek_issuer(&decoded.xml) else {
        return error_page(StatusCode::BAD_REQUEST, "LogoutRequest carries no Issuer");
    };
    let Some(entry) = state.sp_by_entity_id(&issuer) else {
        return error_page(
            StatusCode::UNAUTHORIZED,
            &format!("LogoutRequest Issuer `{issuer}` is not registered"),
        );
    };

    // For Redirect-bound SLO the signature (when present) is computed over
    // the URL-encoded `SAMLRequest=…&RelayState=…&SigAlg=…` query slice,
    // never embedded in the XML. Thread it through to `consume_logout_request`
    // so the IdP role can verify it; otherwise a Redirect-bound signed
    // request would be rejected as unsigned when `logout_want_signed.requests`
    // is on.
    let slo_detached = decoded.as_detached_signature();

    let expected_destination = format!("{}/saml/slo", state.config.idp_base_url);
    let parsed = match state.idp.consume_logout_request(
        &entry.sp,
        ConsumeLogoutRequest {
            peer_crypto_policy: None,
            body: &decoded.xml,
            binding: Binding::HttpRedirect,
            detached_signature: slo_detached,
            expected_destination: &expected_destination,
            now: SystemTime::now(),
            clock_skew: Duration::from_mins(2),
        },
    ) {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "/saml/slo GET: consume_logout_request rejected");
            return error_page(
                StatusCode::UNAUTHORIZED,
                &format!("LogoutRequest rejected: {e}"),
            );
        }
    };

    // Build the response — prefer POST so the client gets the same
    // shape whichever binding was used inbound, then clear the cookie.
    let binding = pick_slo_binding(&entry).unwrap_or(Binding::HttpPost);
    let dispatch = match state.idp.build_logout_response(
        &entry.sp,
        &parsed,
        LogoutStatus::Success,
        decoded.relay_state.as_deref(),
        binding,
    ) {
        Ok(d) => d,
        Err(e) => {
            warn!(error = %e, "/saml/slo GET: build_logout_response failed");
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("build_logout_response: {e}"),
            );
        }
    };

    info!(sp = %entry.sp.entity_id, "/saml/slo GET: handled LogoutRequest");
    finalize_logout_dispatch(dispatch, entry.label(), /* clear_cookie */ true)
}

fn handle_slo_request_post(
    state: &AppState,
    saml_request_b64: &str,
    relay_state: Option<&str>,
) -> Response {
    let decoded = match decode_wire(
        saml_request_b64.as_bytes(),
        Binding::HttpPost,
        WireDirection::Request,
    ) {
        Ok(d) => d,
        Err(e) => {
            warn!(error = %e, "/saml/slo POST: SAMLRequest decode failed");
            return error_page(StatusCode::BAD_REQUEST, "SAMLRequest is not valid base64");
        }
    };
    let Some(issuer) = peek_issuer(&decoded.xml) else {
        return error_page(StatusCode::BAD_REQUEST, "LogoutRequest carries no Issuer");
    };
    let Some(entry) = state.sp_by_entity_id(&issuer) else {
        return error_page(
            StatusCode::UNAUTHORIZED,
            &format!("LogoutRequest Issuer `{issuer}` is not registered"),
        );
    };

    // Unlike the SP-side `consume_logout_request`, the IdP-side variant
    // expects the caller to have already binding-decoded the wire bytes
    // (see `crate::idp` module docs in the saml crate). `decode_wire`
    // takes care of that — pass the recovered XML through directly.
    let expected_destination = format!("{}/saml/slo", state.config.idp_base_url);
    let parsed = match state.idp.consume_logout_request(
        &entry.sp,
        ConsumeLogoutRequest {
            peer_crypto_policy: None,
            body: &decoded.xml,
            binding: Binding::HttpPost,
            // POST binding embeds the XML-DSig signature inside the XML;
            // no detached signature material to thread through.
            detached_signature: None,
            expected_destination: &expected_destination,
            now: SystemTime::now(),
            clock_skew: Duration::from_mins(2),
        },
    ) {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "/saml/slo POST: consume_logout_request rejected");
            return error_page(
                StatusCode::UNAUTHORIZED,
                &format!("LogoutRequest rejected: {e}"),
            );
        }
    };

    let binding = pick_slo_binding(&entry).unwrap_or(Binding::HttpPost);
    let dispatch = match state.idp.build_logout_response(
        &entry.sp,
        &parsed,
        LogoutStatus::Success,
        relay_state,
        binding,
    ) {
        Ok(d) => d,
        Err(e) => {
            warn!(error = %e, "/saml/slo POST: build_logout_response failed");
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("build_logout_response: {e}"),
            );
        }
    };

    info!(sp = %entry.sp.entity_id, "/saml/slo POST: handled LogoutRequest");
    finalize_logout_dispatch(dispatch, entry.label(), /* clear_cookie */ true)
}

/// POST-binding entry point for a returning `<samlp:LogoutResponse>` — the
/// SP's answer to an IdP-initiated `/logout-everywhere` request.
fn handle_slo_response(state: &AppState, saml_response_b64: &str, binding: Binding) -> Response {
    let decoded = match decode_wire(
        saml_response_b64.as_bytes(),
        Binding::HttpPost,
        WireDirection::Response,
    ) {
        Ok(d) => d,
        Err(e) => {
            warn!(error = %e, "/saml/slo POST: SAMLResponse decode failed");
            return error_page(StatusCode::BAD_REQUEST, "SAMLResponse is not valid base64");
        }
    };
    // POST binding embeds the XML-DSig signature inside the XML; no detached
    // signature material to thread through.
    consume_logout_response_xml(state, &decoded.xml, binding, None)
}

/// Bind a returning `<samlp:LogoutResponse>` to the tracker stashed when the
/// IdP-initiated request went out (`InResponseTo` → tracker), validate it via
/// the lib's `consume_logout_response`, then clear the IdP session.
fn consume_logout_response_xml(
    state: &AppState,
    xml: &[u8],
    binding: Binding,
    detached: Option<DetachedSignature<'_>>,
) -> Response {
    let Some(issuer) = peek_issuer(xml) else {
        return error_page(StatusCode::BAD_REQUEST, "LogoutResponse carries no Issuer");
    };
    let Some(entry) = state.sp_by_entity_id(&issuer) else {
        return error_page(
            StatusCode::UNAUTHORIZED,
            &format!("LogoutResponse Issuer `{issuer}` is not registered"),
        );
    };

    // The SP echoes our LogoutRequest `ID` as `InResponseTo`; that's the key
    // the tracker was stashed under in `/logout-everywhere`.
    let Some(in_response_to) = peek_in_response_to(xml) else {
        warn!("/saml/slo: LogoutResponse carries no InResponseTo; cannot bind to a tracker");
        return error_page(
            StatusCode::BAD_REQUEST,
            "LogoutResponse carries no InResponseTo",
        );
    };
    let tracker = match state.take_logout_tracker(&in_response_to) {
        Ok(Some(t)) => t,
        Ok(None) => {
            warn!(
                in_response_to,
                "/saml/slo: no pending tracker for the LogoutResponse's InResponseTo"
            );
            return error_page(
                StatusCode::GONE,
                "No pending logout matches this LogoutResponse. It may have already completed.",
            );
        }
        Err(e) => {
            warn!(error = %e, "/saml/slo: logout tracker store unavailable");
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "logout tracker store unavailable",
            );
        }
    };

    let expected_destination = format!("{}/saml/slo", state.config.idp_base_url);
    let outcome = match state.idp.consume_logout_response(
        &entry.sp,
        ConsumeLogoutResponse {
            peer_crypto_policy: None,
            body: xml,
            binding,
            detached_signature: detached,
            tracker: &tracker,
            expected_destination: &expected_destination,
            now: SystemTime::now(),
            clock_skew: Duration::from_mins(2),
        },
    ) {
        Ok(o) => o,
        Err(e) => {
            warn!(error = %e, "/saml/slo: consume_logout_response rejected the LogoutResponse");
            return error_page(
                StatusCode::UNAUTHORIZED,
                &format!("LogoutResponse rejected: {e}"),
            );
        }
    };

    match outcome {
        LogoutOutcome::Success => {
            info!(sp = %entry.sp.entity_id, "/saml/slo: IdP-init SLO succeeded; clearing session");
            redirect_with_cleared_cookie("/?msg=signed-out")
        }
        LogoutOutcome::PartialLogout { message } => {
            warn!(
                sp = %entry.sp.entity_id,
                message = message.as_deref().unwrap_or("(none)"),
                "/saml/slo: IdP-init SLO reported partial logout; clearing local session",
            );
            redirect_with_cleared_cookie("/?msg=signed-out")
        }
        LogoutOutcome::Failure { status, message } => {
            warn!(
                sp = %entry.sp.entity_id,
                status,
                message = message.as_deref().unwrap_or("(none)"),
                "/saml/slo: SP refused the LogoutRequest; clearing local session anyway",
            );
            // The SP refused, but the IdP's own session is ours to end — the
            // operator asked to sign out. Clear locally and report.
            redirect_with_cleared_cookie("/?msg=signed-out-locally")
        }
    }
}

fn pick_slo_binding(entry: &SpEntry) -> Option<Binding> {
    if entry.sp.slo_endpoint(Binding::HttpPost).is_some() {
        return Some(Binding::HttpPost);
    }
    if entry.sp.slo_endpoint(Binding::HttpRedirect).is_some() {
        return Some(Binding::HttpRedirect);
    }
    None
}

// =============================================================================
// /saml/artifact (feature-gated)
// =============================================================================

/// `POST /saml/artifact` — the IdP's `ArtifactResolutionService`.
///
/// An SP POSTs a SOAP `<samlp:ArtifactResolve>` envelope here. We:
///
/// 1. Peek the requesting SP's `<saml:Issuer>` to pick its descriptor.
/// 2. Parse + issuer-verify the resolve via the IdP role layer.
/// 3. One-time consume the stashed `<samlp:Response>` keyed by the artifact.
/// 4. Wrap it in a signed `<samlp:ArtifactResponse>` SOAP envelope and return
///    it with `Content-Type: text/xml`.
#[cfg(feature = "artifact-binding")]
pub async fn handle_artifact(State(state): State<AppState>, body: axum::body::Bytes) -> Response {
    let Some(issuer) = peek_issuer(&body) else {
        warn!("/saml/artifact: ArtifactResolve carries no Issuer");
        return error_page(
            StatusCode::BAD_REQUEST,
            "ArtifactResolve did not carry an Issuer",
        );
    };
    let Some(entry) = state.sp_by_entity_id(&issuer) else {
        warn!(issuer = %issuer, "/saml/artifact: no SP configured for Issuer");
        return error_page(
            StatusCode::UNAUTHORIZED,
            &format!("ArtifactResolve Issuer `{issuer}` is not registered with this IdP"),
        );
    };

    let resolve = match state.idp.parse_artifact_resolve(&entry.sp, &body) {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, sp = %entry.sp.entity_id, "/saml/artifact: parse_artifact_resolve failed");
            return error_page(
                StatusCode::BAD_REQUEST,
                &format!("ArtifactResolve rejected: {e}"),
            );
        }
    };

    let stashed = match state.take_artifact(&resolve.artifact) {
        Ok(Some(s)) => s,
        Ok(None) => {
            warn!(
                artifact = %resolve.artifact,
                "/saml/artifact: unknown or already-consumed artifact"
            );
            return error_page(
                StatusCode::NOT_FOUND,
                "The requested artifact is unknown or has already been resolved.",
            );
        }
        Err(e) => {
            warn!(error = %e, "/saml/artifact: artifact store unavailable");
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "artifact store unavailable",
            );
        }
    };

    // Defense in depth: the artifact was minted for one SP; refuse to hand it
    // to a different (registered) SP even though the issuer-check above passed.
    if stashed.sp_entity_id != entry.sp.entity_id {
        warn!(
            artifact = %resolve.artifact,
            minted_for = %stashed.sp_entity_id,
            resolved_by = %entry.sp.entity_id,
            "/saml/artifact: artifact resolved by a different SP than it was minted for"
        );
        return error_page(
            StatusCode::FORBIDDEN,
            "This artifact was not issued to the resolving SP.",
        );
    }

    let envelope = match state
        .idp
        .build_artifact_response(&resolve, &stashed.response_xml)
    {
        Ok(env) => env,
        Err(e) => {
            warn!(error = %e, "/saml/artifact: build_artifact_response failed");
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("build_artifact_response: {e}"),
            );
        }
    };

    info!(
        sp = %entry.sp.entity_id,
        request_id = %resolve.request_id,
        "/saml/artifact: resolved artifact, returning ArtifactResponse"
    );
    (
        [(header::CONTENT_TYPE, HeaderValue::from_static("text/xml"))],
        envelope,
    )
        .into_response()
}

// =============================================================================
// Helpers
// =============================================================================

/// 303 redirect with the session cookie cleared.
fn redirect_with_cleared_cookie(target: &str) -> Response {
    let mut headers = HeaderMap::new();
    match HeaderValue::from_str(&session::clear_cookie_header()) {
        Ok(v) => {
            headers.insert(header::SET_COOKIE, v);
        }
        Err(e) => {
            warn!(error = %e, "could not clear session cookie");
            return error_page(StatusCode::INTERNAL_SERVER_ERROR, "could not clear cookie");
        }
    }
    (headers, Redirect::to(target)).into_response()
}

fn finalize_sso_dispatch(
    state: &AppState,
    sp_entity_id: &str,
    dispatch: SsoResponseDispatch,
    sp_label: &str,
) -> Response {
    // `sp_entity_id` is only consumed by the artifact arm below.
    let _ = (state, sp_entity_id);
    match dispatch {
        SsoResponseDispatch::Post(form) => Html(templates::render_post_dispatch(
            form.action.as_str(),
            None,
            Some(form.saml_response.as_str()),
            form.relay_state.as_deref(),
            sp_label,
        ))
        .into_response(),
        #[cfg(feature = "artifact-binding")]
        SsoResponseDispatch::Artifact(redirect) => {
            finalize_artifact_dispatch(state, sp_entity_id, redirect)
        }
        #[cfg(not(feature = "artifact-binding"))]
        SsoResponseDispatch::Artifact(_) => error_page(
            StatusCode::NOT_IMPLEMENTED,
            "Artifact-binding response dispatch is not implemented in this example.",
        ),
    }
}

/// Stash the artifact's `<samlp:Response>` XML keyed by its `SAMLart` value,
/// then redirect the user-agent to the SP's ACS carrying `?SAMLart=…`. The SP
/// resolves the artifact against `/saml/artifact` over the back channel.
#[cfg(feature = "artifact-binding")]
fn finalize_artifact_dispatch(
    state: &AppState,
    sp_entity_id: &str,
    redirect: saml::ArtifactRedirect,
) -> Response {
    let entry = crate::StashedArtifact::new(redirect.response_xml, sp_entity_id.to_owned());
    if let Err(e) = state.stash_artifact(redirect.artifact.clone(), entry) {
        warn!(error = %e, "/saml/sso: artifact store unavailable");
        return error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "artifact store unavailable",
        );
    }
    info!(
        sp = %sp_entity_id,
        acs = %redirect.redirect_to,
        "/saml/sso: dispatching SSO Response over HTTP-Artifact binding",
    );
    Redirect::to(redirect.redirect_to.as_str()).into_response()
}

fn finalize_logout_dispatch(dispatch: Dispatch, sp_label: &str, clear_cookie: bool) -> Response {
    let mut headers = HeaderMap::new();
    if clear_cookie {
        match HeaderValue::from_str(&session::clear_cookie_header()) {
            Ok(v) => {
                headers.insert(header::SET_COOKIE, v);
            }
            Err(e) => {
                warn!(error = %e, "could not clear session cookie on logout dispatch");
                return error_page(StatusCode::INTERNAL_SERVER_ERROR, "could not clear cookie");
            }
        }
    }
    match dispatch {
        Dispatch::Redirect(url) => (headers, Redirect::to(url.as_str())).into_response(),
        Dispatch::Post(form) => (
            headers,
            Html(templates::render_post_dispatch(
                form.action.as_str(),
                form.saml_request.as_deref(),
                form.saml_response.as_deref(),
                form.relay_state.as_deref(),
                sp_label,
            )),
        )
            .into_response(),
    }
}

fn read_request_id_query_param(raw_query: &str) -> Option<&str> {
    for pair in raw_query.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if k == "request_id" {
            return Some(v);
        }
    }
    None
}

fn read_msg_query_param(raw_query: &str) -> Option<String> {
    for pair in raw_query.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if k == "msg" {
            return Some(
                percent_encoding::percent_decode_str(v)
                    .decode_utf8_lossy()
                    .into_owned(),
            );
        }
    }
    None
}

/// Whether a `&`-joined query string carries the named parameter.
fn query_has_param(raw_query: &str, name: &str) -> bool {
    raw_query.split('&').any(|pair| {
        let key = pair.split_once('=').map_or(pair, |(k, _)| k);
        key == name
    })
}

/// Best-effort scan for the `InResponseTo` attribute on the root
/// `<samlp:LogoutResponse>` element. Mirrors the demo SP's fixed scanner;
/// handles a leading `<?xml ... ?>` declaration.
fn peek_in_response_to(xml: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(xml).ok()?;
    let response_tag_start = s.find("Response")?;
    let tag_open = s.get(..response_tag_start)?.rfind('<')?;
    let after_open = s.get(tag_open..)?;
    let tag_end = after_open.find('>')?;
    let tag = after_open.get(..tag_end)?;

    let key = "InResponseTo=\"";
    let start = tag.find(key)?.saturating_add(key.len());
    let rest = tag.get(start..)?;
    let end = rest.find('"')?;
    rest.get(..end).map(str::to_owned)
}

fn banner_for_msg(msg: &str) -> Option<String> {
    match msg {
        "signed-out" => Some("Signed out everywhere.".to_owned()),
        "signed-out-locally" => Some("Signed out of this IdP.".to_owned()),
        "already-signed-out" => Some("You were already signed out.".to_owned()),
        _ => None,
    }
}

fn error_page(status: StatusCode, message: &str) -> Response {
    let body = templates::render_error(message);
    (status, Html(body)).into_response()
}

/// Pull the `<saml:Issuer>` element's text content out of an XML blob.
/// Mirrors the demo SP's fixed scanner; handles a leading `<?xml ... ?>`
/// declaration and namespace-prefixed / unprefixed tags.
fn peek_issuer(xml: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(xml).ok()?;
    let mut cursor = 0usize;
    while cursor < s.len() {
        let rest = s.get(cursor..)?;
        let open_off = rest.find('<')?;
        let after = rest.get(open_off.saturating_add(1)..)?;
        let close = after.find('>')?;
        let tag = after.get(..close)?;
        if tag.starts_with('?') || tag.starts_with('!') {
            cursor = cursor
                .saturating_add(open_off)
                .saturating_add(close)
                .saturating_add(2);
            continue;
        }
        let tag_name = tag.split_whitespace().next()?;
        let local = tag_name.rsplit(':').next()?;
        if local.eq_ignore_ascii_case("Issuer") {
            let value_start = cursor
                .saturating_add(open_off)
                .saturating_add(close)
                .saturating_add(2);
            let value_rest = s.get(value_start..)?;
            let value_end = value_rest.find("</")?;
            let raw = value_rest.get(..value_end)?.trim();
            if raw.is_empty() {
                return None;
            }
            return Some(raw.to_owned());
        }
        cursor = cursor
            .saturating_add(open_off)
            .saturating_add(close)
            .saturating_add(2);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peek_issuer_handles_xml_declaration() {
        let xml = b"<?xml version=\"1.0\"?>\
            <samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" \
              xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_r1\">\
              <saml:Issuer>saml-axum-demo</saml:Issuer>\
            </samlp:AuthnRequest>";
        assert_eq!(peek_issuer(xml).as_deref(), Some("saml-axum-demo"));
    }

    #[test]
    fn peek_issuer_returns_none_on_missing() {
        let xml = b"<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" \
            ID=\"_r1\"></samlp:AuthnRequest>";
        assert_eq!(peek_issuer(xml), None);
    }

    #[test]
    fn read_request_id_query_param_finds_the_value() {
        assert_eq!(read_request_id_query_param("request_id=_xyz"), Some("_xyz"));
        assert_eq!(
            read_request_id_query_param("foo=bar&request_id=_a"),
            Some("_a"),
        );
        assert_eq!(read_request_id_query_param("foo=bar"), None);
    }

    #[test]
    fn decode_wire_round_trips_unsigned_redirect() {
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD as B64;
        use flate2::Compression;
        use flate2::write::DeflateEncoder;
        use std::io::Write as _;

        let xml = b"<samlp:AuthnRequest ID=\"_r1\"/>";
        let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
        enc.write_all(xml).unwrap();
        let deflated = enc.finish().unwrap();
        let b64 = B64.encode(deflated);
        let pct: String =
            percent_encoding::utf8_percent_encode(&b64, percent_encoding::NON_ALPHANUMERIC)
                .to_string();
        let query = format!("SAMLRequest={pct}&RelayState=hello");
        let decoded = decode_wire(
            query.as_bytes(),
            Binding::HttpRedirect,
            WireDirection::Request,
        )
        .expect("decode_wire");
        assert_eq!(decoded.xml.as_slice(), xml.as_slice());
        assert_eq!(decoded.relay_state.as_deref(), Some("hello"));
        assert!(decoded.detached_signature.is_none());
        assert!(decoded.signed_query_string.is_none());
    }

    #[test]
    fn banner_for_msg_known_values() {
        assert!(banner_for_msg("signed-out").is_some());
        assert!(banner_for_msg("signed-out-locally").is_some());
        assert!(banner_for_msg("nope").is_none());
    }
}
