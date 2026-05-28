//! HTTP handlers for the IdP-side SAML flows.
//!
//! - `GET /` — landing page. Welcome banner when a session is present,
//!   "use an SP to log in" copy otherwise.
//! - `GET /metadata` — signed `<EntityDescriptor>` per
//!   [`IdentityProvider::metadata_xml`].
//! - `GET | POST /saml/sso` — decode the inbound binding wire (DEFLATE+
//!   base64 over Redirect, base64 over POST), hand the XML to
//!   [`IdentityProvider::consume_authn_request`], then either issue the
//!   Response immediately (session present) or redirect to the login form.
//! - `POST /login` — verify credentials, mint the session cookie, redirect
//!   to `/saml/sso/continue?request_id=…` which pulls the stashed request.
//! - `POST /saml/sso/continue` — finalize the login by issuing the
//!   Response over the SP's preferred binding.
//! - `GET | POST /saml/slo` — verify the SP's signed LogoutRequest, clear
//!   the local session, echo the LogoutResponse back.

use std::time::{Duration, SystemTime};

use axum::{
    extract::{Form, RawQuery, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
};
use serde::Deserialize;
use tracing::{info, warn};

use saml::{
    AuthnContextClassRef, Attribute, Binding, ConsumeAuthnRequest, ConsumeLogoutRequest,
    DetachedSignature, Dispatch, IssueResponse, LogoutStatus, NameId, NameIdFormat,
    ParsedAuthnRequest, SsoResponseDispatch, WireDirection, decode_wire,
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
        return error_page(StatusCode::INTERNAL_SERVER_ERROR, "pending store unavailable");
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
        None => ("(no pending request)".to_owned(), String::new(), String::new()),
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
        return Redirect::to(&format!("/saml/sso/login?request_id={request_id}"))
            .into_response();
    };

    let pending = match state.take_pending(&request_id) {
        Ok(Some(p)) => p,
        Ok(None) => {
            warn!(request_id, "/saml/sso/continue: no pending request (TTL elapsed?)");
            return error_page(
                StatusCode::GONE,
                "Sign-in request is no longer pending. Restart the flow from the SP.",
            );
        }
        Err(e) => {
            warn!(error = %e, "/saml/sso/continue: pending store unavailable");
            return error_page(StatusCode::INTERNAL_SERVER_ERROR, "pending store unavailable");
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
        force_encrypt_assertion: Some(false),
        now,
        assertion_lifetime: Duration::from_mins(5),
        subject_confirmation_lifetime: Duration::from_mins(5),
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

    finalize_sso_dispatch(dispatch, entry.label())
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
        (Some(req), None) => {
            handle_slo_request_post(&state, req, form.relay_state.as_deref())
        }
        (None, Some(_)) => {
            // The IdP example doesn't initiate SLO toward SPs, so a
            // SAMLResponse arriving here is unexpected. Log and 200 so
            // the SP doesn't spin.
            info!("/saml/slo POST: received unsolicited LogoutResponse; ignoring");
            redirect_with_cleared_cookie("/?msg=signed-out-locally")
        }
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

pub async fn handle_slo_get(State(state): State<AppState>, RawQuery(raw_query): RawQuery) -> Response {
    let Some(raw_query) = raw_query.filter(|q| !q.is_empty()) else {
        return error_page(
            StatusCode::BAD_REQUEST,
            "/saml/slo GET requires a query string carrying SAMLRequest",
        );
    };
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

#[cfg(feature = "artifact-binding")]
#[derive(Debug, Deserialize)]
pub struct ArtifactBody(pub Vec<u8>);

#[cfg(feature = "artifact-binding")]
pub async fn handle_artifact(
    State(_state): State<AppState>,
    body: axum::body::Bytes,
) -> Response {
    let _ = body;
    error_page(
        StatusCode::NOT_IMPLEMENTED,
        "ArtifactResolutionService is not implemented in this example. \
         The IdP role exposes parse_artifact_resolve / build_artifact_response \
         under the artifact-binding + weak-algos features.",
    )
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

fn finalize_sso_dispatch(dispatch: SsoResponseDispatch, sp_label: &str) -> Response {
    match dispatch {
        SsoResponseDispatch::Post(form) => Html(templates::render_post_dispatch(
            form.action.as_str(),
            None,
            Some(form.saml_response.as_str()),
            form.relay_state.as_deref(),
            sp_label,
        ))
        .into_response(),
        SsoResponseDispatch::Artifact(_) => error_page(
            StatusCode::NOT_IMPLEMENTED,
            "Artifact-binding response dispatch is not implemented in this example.",
        ),
    }
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
        let pct: String = percent_encoding::utf8_percent_encode(
            &b64,
            percent_encoding::NON_ALPHANUMERIC,
        )
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
