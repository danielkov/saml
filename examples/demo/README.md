# saml-demo — multi-IdP Axum SP

One Axum-based Service Provider, seven Identity Providers behind one
`/saml/acs` endpoint. Replaces the seven per-IdP example crates we used
to ship.

## Providers

| Slug         | Label       | Where it runs                       | Accent     |
| ------------ | ----------- | ----------------------------------- | ---------- |
| `keycloak`   | Keycloak    | local · `examples/idps/` docker-compose | `#cd0000` |
| `authentik`  | Authentik   | local · `examples/idps/`            | `#fd4b2d` |
| `fusionauth` | FusionAuth  | local · `examples/idps/`            | `#f6843a` |
| `zitadel`    | Zitadel     | cloud · `*.zitadel.cloud`           | `#5469d4` |
| `auth0`      | Auth0       | cloud · `*.auth0.com`               | `#eb5424` |
| `descope`    | Descope     | cloud · `api.descope.com`           | `#5b3bff` |
| `asgardeo`   | Asgardeo    | cloud · `api.asgardeo.io`           | `#ff7300` |

Per-provider quirks (NameID format, attribute-name URIs, brand colour /
glyph) live in [`config/providers.toml`](./config/providers.toml). The
ACS handler resolves the inbound Response's `Issuer` back to a provider
entry, asserts that the `RelayState` slug matches, then validates the
assertion against that provider's IdP descriptor.

## Layout

```
examples/demo/
├── Cargo.toml
├── README.md
├── .env.example                # Committed template; copy to `.env`.
├── config/
│   └── providers.toml          # All 7 ProviderConfigs.
├── keys/
│   ├── sp.crt                  # Self-signed RSA-2048, CN=saml-axum-demo.
│   └── sp.key                  # PKCS#8 private key (test only).
├── src/
│   ├── lib.rs                  # AppConfig / AppState / handlers.
│   ├── main.rs                 # Tiny shell.
│   ├── providers.rs            # TOML → typed ProviderConfig + index.
│   ├── session.rs              # HMAC-SHA256 signed JSON session cookie.
│   └── templates.rs            # {{placeholder}} substitution.
├── static/
│   ├── style.css
│   ├── index.html.tmpl         # Landing with 7 provider cards.
│   └── dashboard.html.tmpl     # Per-session identity dashboard.
└── tests/
    └── e2e_smoke.rs            # Programmatic smoke tests, one per provider.
```

## Quickstart

```sh
# 1. (optional) tweak local overrides:
cp examples/demo/.env.example examples/demo/.env

# 2. Bring up the three local IdPs (Keycloak / Authentik / FusionAuth):
docker compose -f examples/idps/docker-compose.yml up -d
# Wait ~60s for everything to migrate + apply blueprints/realm/kickstart.

# 3. Run the SP:
cargo run -p saml-demo

# 4. Visit http://localhost:3000 and pick an IdP.
```

The cloud IdPs (Zitadel, Auth0, Descope, Asgardeo) are pinned to send
Responses to `http://localhost:3000/saml/acs` with SP entityID
`saml-axum-demo`; they work out of the box without docker. If a
cloud IdP's metadata endpoint is unreachable at startup, the SP logs a
warning and skips it — the other providers still work.

## Architecture

- **One SP**, with one entity ID (`saml-axum-demo`), one ACS
  (`/saml/acs`), one SLO endpoint (`/saml/slo`). The SP signs every
  outbound AuthnRequest with the bundled keypair.
- **Provider resolution.** At startup the SP fetches every IdP's
  metadata in parallel. The resulting `IdpDescriptor` is indexed both by
  the `providers.toml` slug (for `/login/:provider_id`) and by the
  IdP's `entity_id` (for ACS Issuer → provider routing).
- **Cross-provider replay defense.** `/login/:provider_id` stamps the
  slug into `RelayState`. The ACS handler re-derives the provider from
  the Issuer and rejects the Response if the RelayState slug doesn't
  match.
- **Per-provider attribute mapping.** The dashboard reads the
  per-provider `attribute_keys` block from `providers.toml` to find
  email / display_name / etc., walking the ordered key list and taking
  the first hit.
- **Persistent NameID providers.** Zitadel and Asgardeo set
  `use_name_id_as_email_fallback = false` so the Subject (an opaque
  persistent id) doesn't accidentally get rendered as an email.

## Configuration

| Variable                                | Default                                                              |
| --------------------------------------- | -------------------------------------------------------------------- |
| `SAML_DEMO_PORT`                        | `3000`                                                               |
| `SAML_DEMO_BASE_URL`                    | `http://localhost:3000`                                              |
| `SAML_DEMO_SP_ENTITY_ID`                | `saml-axum-demo`                                                     |
| `SAML_DEMO_PROVIDERS_TOML`              | `config/providers.toml` (relative to CWD; baked-in copy as fallback) |
| `SAML_DEMO_PROVIDER_<ID>_METADATA_URL`  | Per-provider override of `metadata_url` from providers.toml          |
| `RUST_LOG`                              | `info,tower_http=info`                                               |

## Smoke tests

```sh
cargo test -p saml-demo --lib            # unit tests
cargo test -p saml-demo --test e2e_smoke # end-to-end smoke per provider
```

The e2e tests skip (don't fail) any provider whose `SAML_DEMO_E2E_*`
env vars aren't set, so they're safe to run in CI without provisioned
credentials.
