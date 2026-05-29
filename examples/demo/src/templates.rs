//! Tiny mustache-ish HTML templating: load the raw template at compile time
//! via `include_str!`, then `{{key}}`-substitute placeholders. No external
//! template engine - this is glue for an example, not a CMS.
//!
//! All values are HTML-escaped before substitution so attribute payloads
//! from the IdP can't break out into the surrounding markup.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::providers::ProviderConfig;

const INDEX_TMPL: &str = include_str!("../static/index.html.tmpl");
const DASHBOARD_TMPL: &str = include_str!("../static/dashboard.html.tmpl");

/// Render the landing page with one card per provider. Each card links to
/// `/login/<provider_id>` and is colour-themed with the provider's accent.
///
/// `banner` is an optional one-line notice rendered above the provider
/// grid — used to surface the outcome of the logout flow (signed-out,
/// signed-out-locally, etc.).
pub fn render_index(
    sp_entity_id: &str,
    providers: &[&ProviderConfig],
    banner: Option<&str>,
) -> String {
    let mut vars: BTreeMap<&str, String> = BTreeMap::new();
    vars.insert("sp_entity_id", escape(sp_entity_id));
    vars.insert("provider_count", providers.len().to_string());
    vars.insert("provider_cards", render_provider_cards(providers));
    vars.insert(
        "banner",
        banner.map_or_else(String::new, |text| {
            format!(
                "<aside class=\"banner\" role=\"status\">{}</aside>",
                escape(text),
            )
        }),
    );
    render(INDEX_TMPL, &vars)
}

fn render_provider_cards(providers: &[&ProviderConfig]) -> String {
    if providers.is_empty() {
        return r#"<p class="lede">No providers configured. Check <code>config/providers.toml</code>.</p>"#
            .to_owned();
    }
    let mut out = String::new();
    for p in providers {
        let _ = write!(
            &mut out,
            "<div class=\"provider-slot\" style=\"--provider-accent: {accent};\">\
               <a class=\"provider-card\" href=\"/login/{id}\">\
                 <div class=\"provider-mark\">{initial}</div>\
                 <div class=\"provider-body\">\
                   <div class=\"provider-label\">{label}</div>\
                   <div class=\"provider-meta\"><code>{id}</code></div>\
                 </div>\
                 <div class=\"provider-arrow\">&rarr;</div>\
               </a>\
               {notes}\
             </div>",
            id = escape(&p.id),
            accent = escape(&p.accent_color),
            initial = escape(&p.brand_initial),
            label = escape(&p.label),
            notes = render_provider_notes(&p.notes),
        );
    }
    out
}

fn render_provider_notes(notes: &[String]) -> String {
    if notes.is_empty() {
        return String::new();
    }
    let mut items = String::new();
    for note in notes {
        let _ = write!(&mut items, "<li>{}</li>", escape(note));
    }
    format!(
        "<details class=\"provider-notes\">\
           <summary>Notes</summary>\
           <ul>{items}</ul>\
         </details>",
    )
}

/// One row in the attribute table.
pub struct AttributeRow<'a> {
    pub name: &'a str,
    pub friendly_name: Option<&'a str>,
    pub values: &'a [String],
}

pub struct DashboardView<'a> {
    pub display_name: &'a str,
    pub email: &'a str,
    pub initial: &'a str,
    pub name_id_value: &'a str,
    pub name_id_format: &'a str,
    pub name_id_format_short: &'a str,
    pub session_index: &'a str,
    pub authn_instant: &'a str,
    pub sp_entity_id: &'a str,
    pub idp_entity_id: &'a str,
    pub provider_id: &'a str,
    pub provider_label: &'a str,
    pub provider_accent: &'a str,
    /// True if the IdP advertises a `<SingleLogoutService>` endpoint, so the
    /// dashboard can label the Sign out button as a real SLO action rather
    /// than a local-only clear.
    pub supports_slo: bool,
    pub attributes: &'a [AttributeRow<'a>],
}

pub fn render_dashboard(view: &DashboardView<'_>) -> String {
    let mut vars: BTreeMap<&str, String> = BTreeMap::new();
    vars.insert("display_name", escape(view.display_name));
    vars.insert("email", escape(view.email));
    vars.insert("initial", escape(view.initial));
    vars.insert("name_id_value", escape(view.name_id_value));
    vars.insert("name_id_format", escape(view.name_id_format));
    vars.insert("name_id_format_short", escape(view.name_id_format_short));
    vars.insert("session_index", escape(view.session_index));
    vars.insert("authn_instant", escape(view.authn_instant));
    vars.insert("sp_entity_id", escape(view.sp_entity_id));
    vars.insert("idp_entity_id", escape(view.idp_entity_id));
    vars.insert("provider_id", escape(view.provider_id));
    vars.insert("provider_label", escape(view.provider_label));
    vars.insert("provider_accent", escape(view.provider_accent));
    vars.insert("attribute_count", view.attributes.len().to_string());
    vars.insert("attribute_rows", render_attribute_rows(view.attributes));
    let (logout_label, logout_hint) = if view.supports_slo {
        (
            format!("Sign out of {}", view.provider_label),
            format!(
                "Posts a signed SAML <code>LogoutRequest</code> to {} so the IdP session ends too.",
                escape(view.provider_label),
            ),
        )
    } else {
        (
            "Sign out (local only)".to_owned(),
            format!(
                "{} does not advertise a SingleLogoutService endpoint, so only the SP-side session cookie is cleared.",
                escape(view.provider_label),
            ),
        )
    };
    vars.insert("logout_label", escape(&logout_label));
    vars.insert("logout_hint", logout_hint);
    render(DASHBOARD_TMPL, &vars)
}

/// Build the auto-submitting HTML form for the HTTP-POST AuthnRequest
/// dispatch. SAML 2.0 Bindings §3.5.4 requires a top-level `SAMLRequest`
/// (or `SAMLResponse`) field plus an optional `RelayState` field. We
/// render the form with `<noscript>` fallback per the binding's
/// recommendations.
pub fn render_post_dispatch(
    action: &str,
    saml_request: Option<&str>,
    saml_response: Option<&str>,
    relay_state: Option<&str>,
    provider_label: &str,
) -> String {
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
<body><main class=\"shell\"><header class=\"brand\"><div class=\"mark\">S</div>\
<div class=\"name\">saml-demo <span>· redirecting</span></div></header>\
<section class=\"hero\"><span class=\"kicker\"><span class=\"dot\"></span> \
Posting to IdP</span><h1>Forwarding to <em>{label}</em>…</h1>\
<p class=\"lede\">Your browser is auto-submitting the AuthnRequest. \
If this page is still here in a moment, JavaScript is disabled — \
press the button below.</p></section>\
<form id=\"f\" method=\"post\" action=\"{action}\">{hidden}\
<noscript><button class=\"btn btn-primary\" type=\"submit\">Continue</button></noscript>\
</form>\
<script>document.getElementById('f').submit();</script>\
</main></body></html>",
        action = escape(action),
        label = escape(provider_label),
    )
}

fn render_attribute_rows(rows: &[AttributeRow<'_>]) -> String {
    if rows.is_empty() {
        return "<tr><td colspan=\"2\" style=\"color: var(--text-soft);\">\
                  No attributes asserted.\
                </td></tr>"
            .to_owned();
    }
    let mut out = String::new();
    for row in rows {
        let name_html = match row.friendly_name {
            Some(friendly) if !friendly.is_empty() => format!(
                "<div>{friendly}</div>\
                 <div style=\"font-size: 11px; color: var(--text-soft); margin-top: 2px;\">{full}</div>",
                friendly = escape(friendly),
                full = escape(row.name),
            ),
            _ => escape(row.name),
        };

        let mut values_html = String::new();
        if row.values.is_empty() {
            values_html.push_str("<em style=\"color: var(--text-soft);\">(no values)</em>");
        } else {
            for v in row.values {
                let _ = write!(&mut values_html, "<code>{}</code>", escape(v));
            }
        }

        let _ = write!(
            &mut out,
            "<tr><td class=\"name\">{name_html}</td>\
             <td class=\"values\">{values_html}</td></tr>",
        );
    }
    out
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
    use crate::providers::AttributeKeys;
    use saml::NameIdFormat;

    fn p(id: &str, accent: &str, label: &str) -> ProviderConfig {
        ProviderConfig {
            id: id.to_owned(),
            label: label.to_owned(),
            metadata_url: "http://example".to_owned(),
            sso_url_override: None,
            idp_entity_id_override: None,
            slo_url_override: None,
            extra_signing_cert_paths: vec![],
            prefer_slo_binding: None,
            accent_color: accent.to_owned(),
            brand_initial: "X".to_owned(),
            requested_name_id_format: Some(NameIdFormat::EmailAddress),
            use_name_id_as_email_fallback: true,
            attribute_keys: AttributeKeys::default(),
            notes: vec![],
        }
    }

    #[test]
    fn render_substitutes_known_keys() {
        let mut vars: BTreeMap<&str, String> = BTreeMap::new();
        vars.insert("name", "Alice".to_owned());
        assert_eq!(render("Hello, {{name}}!", &vars), "Hello, Alice!");
    }

    #[test]
    fn render_preserves_unmatched_keys() {
        let vars: BTreeMap<&str, String> = BTreeMap::new();
        assert_eq!(render("Hello, {{name}}!", &vars), "Hello, {{name}}!");
    }

    #[test]
    fn escape_handles_html_specials() {
        assert_eq!(escape("a<b>&c\"d'"), "a&lt;b&gt;&amp;c&quot;d&#39;");
    }

    #[test]
    fn render_index_emits_one_card_per_provider() {
        let kc = p("keycloak", "#cd0000", "Keycloak");
        let z = p("zitadel", "#5469d4", "Zitadel");
        let html = render_index("saml-axum-demo", &[&kc, &z], None);
        assert!(html.contains("/login/keycloak"));
        assert!(html.contains("/login/zitadel"));
        assert!(html.contains("#cd0000"));
        assert!(html.contains("#5469d4"));
        assert!(html.contains("saml-axum-demo"));
    }

    #[test]
    fn render_index_skips_notes_block_when_provider_has_no_notes() {
        let kc = p("keycloak", "#cd0000", "Keycloak");
        let html = render_index("saml-axum-demo", &[&kc], None);
        assert!(
            !html.contains("provider-notes"),
            "no <details> rendered when notes is empty"
        );
    }

    #[test]
    fn render_index_renders_notes_in_details_block() {
        let mut z = p("zitadel", "#5469d4", "Zitadel");
        z.notes = vec![
            "SLO works but only with persistent NameID".to_owned(),
            "Reuses AssertionID on retry".to_owned(),
        ];
        let html = render_index("saml-axum-demo", &[&z], None);
        assert!(html.contains("<details class=\"provider-notes\""));
        assert!(html.contains("<summary>Notes</summary>"));
        assert!(html.contains("SLO works but only with persistent NameID"));
        assert!(html.contains("Reuses AssertionID on retry"));
    }

    #[test]
    fn render_index_escapes_notes_content() {
        let mut z = p("zitadel", "#5469d4", "Zitadel");
        z.notes = vec!["<script>x</script>".to_owned()];
        let html = render_index("saml-axum-demo", &[&z], None);
        assert!(!html.contains("<script>x</script>"));
        assert!(html.contains("&lt;script&gt;x&lt;/script&gt;"));
    }

    #[test]
    fn render_dashboard_renders_attribute_rows() {
        let values = vec!["alice@saml-demo.local".to_owned()];
        let attrs = vec![AttributeRow {
            name: "Email",
            friendly_name: None,
            values: &values,
        }];
        let view = DashboardView {
            display_name: "Alice Anderson",
            email: "alice@saml-demo.local",
            initial: "A",
            name_id_value: "12345",
            name_id_format: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
            name_id_format_short: "persistent",
            session_index: "abc",
            authn_instant: "2026-05-28T12:00:00Z",
            sp_entity_id: "saml-axum-demo",
            idp_entity_id: "https://idp/example",
            provider_id: "keycloak",
            provider_label: "Keycloak",
            provider_accent: "#cd0000",
            supports_slo: true,
            attributes: &attrs,
        };
        let html = render_dashboard(&view);
        assert!(html.contains("Alice Anderson"));
        assert!(html.contains("alice@saml-demo.local"));
        assert!(html.contains("Keycloak"));
    }

    #[test]
    fn render_post_dispatch_includes_action_and_request() {
        let html = render_post_dispatch(
            "https://idp.example.com/sso",
            Some("PHNhbWxwOg=="),
            None,
            Some("rs-1"),
            "Keycloak",
        );
        assert!(html.contains("action=\"https://idp.example.com/sso\""));
        assert!(html.contains("name=\"SAMLRequest\""));
        assert!(html.contains("PHNhbWxwOg=="));
        assert!(html.contains("name=\"RelayState\""));
        assert!(html.contains("Keycloak"));
    }
}
