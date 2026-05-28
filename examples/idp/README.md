# saml-idp-example — standalone Rust SAML 2.0 IdP

A working Identity Provider built on the same `saml` crate as
`examples/demo`. Paired with the demo SP, this closes the
SP↔IdP loop end-to-end: both halves of the Web Browser SSO + SLO
profile handled by one crate, against itself, programmatically.

## Quickstart

```sh
# Optional: tweak local overrides.
cp examples/idp/.env.example examples/idp/.env

# Boot the IdP on :3001.
cargo run -p saml-idp-example

# In another shell, boot the demo SP on :3000.
cargo run -p saml-demo

# Open the SP landing page; click the "Rust IdP" card.
open http://localhost:3000
```

The demo SP's `providers.toml` already lists `rust-idp` as the 8th
provider, pointing at `http://localhost:3001/metadata`. If the IdP
isn't running when the SP starts, the SP logs a warning and skips
it — the other seven providers (Keycloak, Authentik, FusionAuth,
Zitadel, Auth0, Descope, Asgardeo) keep working.

## Layout

```
examples/idp/
├── Cargo.toml
├── README.md
├── .env.example                   # Committed; copy to `.env`.
├── config/
│   ├── users.toml                 # Seed users + cleartext passwords.
│   └── sps.toml                   # Known SPs + metadata URLs.
├── keys/
│   ├── idp.crt                    # Self-signed RSA-2048, test only.
│   └── idp.key                    # PKCS#8 private key (test only).
├── src/
│   ├── main.rs                    # Tokio entry point.
│   ├── lib.rs                     # AppConfig, AppState, IdP wiring.
│   ├── auth.rs                    # Local user store + argon2id verify.
│   ├── session.rs                 # HMAC-SHA256 signed session cookie.
│   ├── templates.rs               # `{{placeholder}}` substitution.
│   └── sso.rs                     # SAML handlers.
├── static/
│   ├── style.css                  # Rust-orange theme.
│   ├── login.html.tmpl            # Username + password form.
│   ├── index.html.tmpl            # Landing page.
│   ├── consent.html.tmpl          # Optional consent screen.
│   └── error.html.tmpl
└── tests/
    └── e2e_loop.rs                # SP ↔ IdP round-trip, gated.
```

## Endpoints

| Method     | Path                  | Purpose                                                                                                                                                                                                |
| ---------- | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `GET`      | `/healthz`            | Liveness check (`200 OK`).                                                                                                                                                                             |
| `GET`      | `/`                   | Landing page. Shows the signed-in user when a session cookie is present, else a "use an SP to log in" blurb.                                                                                          |
| `GET`      | `/metadata`           | Signed `<EntityDescriptor>` via `IdentityProvider::metadata_xml(true)`.                                                                                                                                |
| `GET,POST` | `/saml/sso`           | Consume `<samlp:AuthnRequest>` (DEFLATE+base64 on Redirect, base64 on POST). If a session cookie is present, mint the Response immediately; else stash the parsed request and redirect to login.       |
| `GET`      | `/saml/sso/login`     | Render the username + password form for a given `request_id`.                                                                                                                                          |
| `POST`     | `/login`              | Verify credentials via argon2, set the session cookie, redirect to `/saml/sso/continue?request_id=…`.                                                                                                  |
| `GET,POST` | `/saml/sso/continue`  | Pull the stashed AuthnRequest, mint the signed Assertion, return a 200 auto-submit form posting `SAMLResponse` to the SP's ACS.                                                                        |
| `POST`     | `/logout`             | IdP-self logout: clears the local IdP cookie. Does NOT initiate SP SLO.                                                                                                                                |
| `GET,POST` | `/saml/slo`           | SP-initiated SLO. Verify the SP's signed `<samlp:LogoutRequest>`, clear the session, echo `<samlp:LogoutResponse>` back over the SP's preferred binding.                                                |
| `POST`     | `/saml/artifact`      | Feature-gated (`artifact-binding`). Currently returns 501 — the saml crate exposes `parse_artifact_resolve` / `build_artifact_response` but this example doesn't ship a working artifact store.        |

## Configuration

| Variable                                | Default                              |
| --------------------------------------- | ------------------------------------ |
| `SAML_IDP_PORT`                         | `3001`                               |
| `SAML_IDP_BASE_URL`                     | `http://localhost:3001`              |
| `SAML_IDP_ENTITY_ID`                    | `http://localhost:3001/saml/idp`     |
| `SAML_IDP_USERS_TOML`                   | `config/users.toml` (then baked-in)  |
| `SAML_IDP_SPS_TOML`                     | `config/sps.toml` (then baked-in)    |
| `SAML_IDP_SP_<UPPER_ENTITY_ID>_METADATA_URL` | Per-SP metadata override        |
| `RUST_LOG`                              | `info,tower_http=info`               |

## Seed users

The `config/users.toml` ships two test accounts. Passwords are hashed
with argon2id at startup; the cleartext from disk is discarded.

| Username                | Password   | Display name      |
| ----------------------- | ---------- | ----------------- |
| `alice@saml-demo.local` | `password` | Alice Anderson    |
| `bob@saml-demo.local`   | `password` | Bob Builder       |

Either the local id (`alice`, `bob`) or the email works.

## Closed-loop end-to-end test

```sh
SAML_DEMO_E2E_RUST_IDP=1 cargo test -p saml-idp-example --test e2e_loop -- --nocapture
```

Boots both halves on free ports and drives the full flow:

1. `GET {sp}/login/rust-idp` → 303 to IdP `/saml/sso?SAMLRequest=…`.
2. Follow → IdP redirects to the login form with the parsed request stashed.
3. POST `/login` with seed creds → session cookie set, redirect to `/saml/sso/continue`.
4. Follow → IdP returns 200 auto-submit form posting `SAMLResponse` to SP.
5. POST to SP's `/saml/acs` → 303 to `/dashboard`.
6. `GET /dashboard` → confirms identity rendered with the rust-idp accent.
7. POST `/logout` → SP signs a `LogoutRequest`, posts it to the IdP.
8. IdP verifies the signature, clears the IdP session, echoes a
   `LogoutResponse` back.
9. Re-attempting `/login/rust-idp` re-renders the password form — proof
   that the IdP session was actually terminated by the SLO call.

## Known sharp edges

- **IdP-side `consume_logout_request` does not accept a detached
  Redirect-binding signature.** The saml crate's IdP role hardcodes
  `detached: None` when verifying inbound LogoutRequest signatures,
  so a signed Redirect-bound `<samlp:LogoutRequest>` cannot pass
  `logout_want_signed.requests = true`. The demo's `providers.toml`
  works around this by pinning `prefer_slo_binding = "POST"` on the
  rust-idp entry; POST-bound LogoutRequests verify normally via
  enveloped XML-DSig.
- **No artifact binding.** The `artifact-binding` feature flag wires
  a stub `/saml/artifact` route, but no actual artifact store is
  implemented. The saml crate exposes `IdentityProvider::parse_artifact_resolve`
  and `build_artifact_response` for callers who want to add one.
- **No encrypted assertions.** `IdpAssertionSigning::sign_assertions = true`
  but `encrypt_assertions_when_possible = false`. The SP advertises an
  encryption cert in its metadata, so flipping `force_encrypt_assertion = Some(true)`
  in `sso::finalize_login` would exercise the xmlenc path.
- **No proxy chain.** This is a leaf IdP; SLO chain propagation
  (RFC-007 §5.1) is out of scope.
