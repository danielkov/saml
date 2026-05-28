//! Tiny `{{placeholder}}` HTML templating, same shape as the SP demo.
//! Values are HTML-escaped before substitution so SP-provided strings
//! (entity IDs, ACS URLs, request IDs) can't break out into markup.

use std::collections::BTreeMap;

const LOGIN_TMPL: &str = include_str!("../static/login.html.tmpl");
const INDEX_TMPL: &str = include_str!("../static/index.html.tmpl");
const CONSENT_TMPL: &str = include_str!("../static/consent.html.tmpl");
const ERROR_TMPL: &str = include_str!("../static/error.html.tmpl");

pub struct LoginView<'a> {
    pub idp_entity_id: &'a str,
    pub sp_label: &'a str,
    pub sp_entity_id: &'a str,
    pub acs_url: &'a str,
    pub request_id: &'a str,
    pub banner: Option<&'a str>,
    pub banner_is_error: bool,
}

pub fn render_login(view: &LoginView<'_>) -> String {
    let mut vars: BTreeMap<&str, String> = BTreeMap::new();
    vars.insert("idp_entity_id", escape(view.idp_entity_id));
    vars.insert("sp_label", escape(view.sp_label));
    vars.insert("sp_entity_id", escape(view.sp_entity_id));
    vars.insert("acs_url", escape(view.acs_url));
    vars.insert("request_id", escape(view.request_id));
    vars.insert(
        "banner",
        view.banner
            .filter(|s| !s.is_empty())
            .map_or_else(String::new, |b| render_banner(b, view.banner_is_error)),
    );
    render(LOGIN_TMPL, &vars)
}

pub struct ConsentView<'a> {
    pub idp_entity_id: &'a str,
    pub sp_label: &'a str,
    pub request_id: &'a str,
    pub display_name: &'a str,
    pub email: &'a str,
    pub initial: &'a str,
}

pub fn render_consent(view: &ConsentView<'_>) -> String {
    let mut vars: BTreeMap<&str, String> = BTreeMap::new();
    vars.insert("idp_entity_id", escape(view.idp_entity_id));
    vars.insert("sp_label", escape(view.sp_label));
    vars.insert("request_id", escape(view.request_id));
    vars.insert("display_name", escape(view.display_name));
    vars.insert("email", escape(view.email));
    vars.insert("initial", escape(view.initial));
    render(CONSENT_TMPL, &vars)
}

/// Render the landing page. Either the signed-in greeting + Sign Out
/// button when a session cookie is present, or a short blurb pointing the
/// user at an SP-initiated SSO start.
pub fn render_index(
    idp_entity_id: &str,
    signed_in_as: Option<&str>,
    sp_count: usize,
    banner: Option<&str>,
) -> String {
    let mut vars: BTreeMap<&str, String> = BTreeMap::new();
    vars.insert("idp_entity_id", escape(idp_entity_id));
    vars.insert(
        "banner",
        banner
            .filter(|s| !s.is_empty())
            .map_or_else(String::new, |b| render_banner(b, false)),
    );
    let body = if let Some(name) = signed_in_as {
        format!(
            "<section class=\"hero\">\
              <span class=\"kicker\"><span class=\"dot\"></span> Session active</span>\
              <h1>Welcome, <em>{name}</em>.</h1>\
              <p class=\"lede\">Your IdP session is live. {sp_count} \
                Service Provider{plural} can ride it. Sign in from an SP \
                application; this IdP will skip the password prompt for the \
                rest of the session.</p>\
              <form method=\"post\" action=\"/logout\" style=\"display: inline-block;\">\
                <button class=\"btn btn-primary\" type=\"submit\">Sign out</button>\
              </form>\
            </section>",
            name = escape(name),
            sp_count = sp_count,
            plural = if sp_count == 1 { "" } else { "s" },
        )
    } else {
        format!(
            "<section class=\"hero\">\
              <span class=\"kicker\"><span class=\"dot\"></span> SAML 2.0 · IdP</span>\
              <h1>Standalone Rust IdP.</h1>\
              <p class=\"lede\">Built on the same <code>saml</code> crate as the \
                SP demo. {sp_count} Service Provider{plural} registered. To start a \
                flow, point an SP at <code>/saml/sso</code>; this IdP will prompt \
                for credentials and POST a signed Assertion back to the SP's ACS \
                endpoint.</p>\
            </section>",
            sp_count = sp_count,
            plural = if sp_count == 1 { "" } else { "s" },
        )
    };
    vars.insert("body", body);
    render(INDEX_TMPL, &vars)
}

pub fn render_error(message: &str) -> String {
    let mut vars: BTreeMap<&str, String> = BTreeMap::new();
    vars.insert("message", escape(message));
    render(ERROR_TMPL, &vars)
}

/// Auto-submitting `<form method="POST">` that posts the IdP's freshly
/// minted `SAMLResponse` to the SP's ACS endpoint. Mirrors the demo SP's
/// `render_post_dispatch` shape so the browser's interpretation is
/// identical on the SP side.
pub fn render_post_dispatch(
    action: &str,
    saml_request: Option<&str>,
    saml_response: Option<&str>,
    relay_state: Option<&str>,
    sp_label: &str,
) -> String {
    use std::fmt::Write as _;
    let mut hidden = String::new();
    if let Some(v) = saml_request {
        let _ = write!(
            &mut hidden,
            "<input type=\"hidden\" name=\"SAMLRequest\" value=\"{}\">",
            escape(v),
        );
    }
    if let Some(v) = saml_response {
        let _ = write!(
            &mut hidden,
            "<input type=\"hidden\" name=\"SAMLResponse\" value=\"{}\">",
            escape(v),
        );
    }
    if let Some(v) = relay_state {
        let _ = write!(
            &mut hidden,
            "<input type=\"hidden\" name=\"RelayState\" value=\"{}\">",
            escape(v),
        );
    }
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Redirecting…</title>\
<link rel=\"stylesheet\" href=\"/static/style.css\"></head>\
<body><main class=\"shell\"><header class=\"brand\"><div class=\"mark\">R</div>\
<div class=\"name\">saml-idp-example <span>· redirecting</span></div></header>\
<section class=\"hero\"><span class=\"kicker\"><span class=\"dot\"></span> \
Posting to SP</span><h1>Forwarding to <em>{label}</em>…</h1>\
<p class=\"lede\">Your browser is auto-submitting the SAMLResponse. \
If this page is still here in a moment, JavaScript is disabled — \
press the button below.</p></section>\
<form id=\"f\" method=\"post\" action=\"{action}\">{hidden}\
<noscript><button class=\"btn btn-primary\" type=\"submit\">Continue</button></noscript>\
</form>\
<script>document.getElementById('f').submit();</script>\
</main></body></html>",
        action = escape(action),
        label = escape(sp_label),
    )
}

fn render_banner(text: &str, is_error: bool) -> String {
    let class = if is_error { "banner error" } else { "banner" };
    format!(
        "<aside class=\"{class}\" role=\"status\">{}</aside>",
        escape(text),
    )
}

fn render(template: &str, vars: &BTreeMap<&str, String>) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        if let Some(before) = rest.get(..start) {
            out.push_str(before);
        }
        let after_open = rest.get(start.saturating_add(2)..).unwrap_or("");
        if let Some(end) = after_open.find("}}") {
            let key = after_open.get(..end).unwrap_or("").trim();
            if let Some(value) = vars.get(key) {
                out.push_str(value);
            } else {
                out.push_str("{{");
                out.push_str(key);
                out.push_str("}}");
            }
            rest = after_open.get(end.saturating_add(2)..).unwrap_or("");
        } else {
            out.push_str("{{");
            out.push_str(after_open);
            rest = "";
            break;
        }
    }
    out.push_str(rest);
    out
}

fn escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_substitutes_known_keys() {
        let mut vars: BTreeMap<&str, String> = BTreeMap::new();
        vars.insert("name", "Alice".to_owned());
        assert_eq!(render("Hello, {{name}}!", &vars), "Hello, Alice!");
    }

    #[test]
    fn escape_handles_html_specials() {
        assert_eq!(escape("a<b>&c\"d'"), "a&lt;b&gt;&amp;c&quot;d&#39;");
    }

    #[test]
    fn login_view_substitutes_sp_metadata() {
        let html = render_login(&LoginView {
            idp_entity_id: "http://idp.local",
            sp_label: "Saml Axum Demo",
            sp_entity_id: "saml-axum-demo",
            acs_url: "http://localhost:3000/saml/acs",
            request_id: "_req-42",
            banner: Some("bad credentials"),
            banner_is_error: true,
        });
        assert!(html.contains("Saml Axum Demo"));
        assert!(html.contains("saml-axum-demo"));
        assert!(html.contains("_req-42"));
        assert!(html.contains("name=\"username\""));
        assert!(html.contains("name=\"password\""));
        assert!(html.contains("banner error"));
        assert!(html.contains("bad credentials"));
    }

    #[test]
    fn consent_view_renders_user_card() {
        let html = render_consent(&ConsentView {
            idp_entity_id: "idp",
            sp_label: "App",
            request_id: "_x",
            display_name: "Alice Anderson",
            email: "alice@example.com",
            initial: "A",
        });
        assert!(html.contains("Alice Anderson"));
        assert!(html.contains("alice@example.com"));
        assert!(html.contains("_x"));
    }

    #[test]
    fn index_signed_out_mentions_sp_count() {
        let html = render_index("idp", None, 2, None);
        assert!(html.contains("2 Service Providers"));
    }

    #[test]
    fn index_signed_in_renders_logout_form() {
        let html = render_index("idp", Some("Alice"), 1, Some("hi"));
        assert!(html.contains("Welcome, "));
        assert!(html.contains("Alice"));
        assert!(html.contains("action=\"/logout\""));
        assert!(html.contains("hi"));
    }

    #[test]
    fn post_dispatch_includes_response_and_relay_state() {
        let html = render_post_dispatch(
            "http://sp/acs",
            None,
            Some("PHNhbWxw"),
            Some("rust-idp"),
            "Saml Demo",
        );
        assert!(html.contains("action=\"http://sp/acs\""));
        assert!(html.contains("name=\"SAMLResponse\""));
        assert!(html.contains("PHNhbWxw"));
        assert!(html.contains("rust-idp"));
    }
}
