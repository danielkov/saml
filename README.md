# saml

[![CI](https://github.com/danielkov/saml/actions/workflows/ci.yml/badge.svg)](https://github.com/danielkov/saml/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/danielkov/saml/branch/main/graph/badge.svg)](https://codecov.io/gh/danielkov/saml)
[![crates.io](https://img.shields.io/crates/v/saml.svg)](https://crates.io/crates/saml)
[![docs.rs](https://img.shields.io/docsrs/saml)](https://docs.rs/saml)

Stateless, async-native SAML 2.0 toolkit with no libxml2 / xmlsec C build chain.

`saml` implements the SAML 2.0 protocol — Service Provider, Identity Provider, and proxy composition — in pure Rust. XML, XML-DSig, XML-Canonicalization, and XML-Encryption are reimplemented on top of `quick-xml` and the RustCrypto stack; there is no `libxml2`, `libxmlsec1`, `libxslt`, `libclang`, or `openssl` dependency. The HTTP backchannel is bring-your-own via the [`HttpClient`] trait (with an optional `reqwest` adapter).

## Status

Pre-release: **v0.0.1-alpha**. The protocol surface described below is implemented and exercised against an interop corpus drawn from Okta, Microsoft Entra ID, Auth0, Google Workspace, OneLogin, Keycloak, ADFS, and Shibboleth fixtures. APIs and on-disk fixtures should be considered subject to change until v1.0. No claim of "production ready" or "battle-tested" is made yet.

## Why this vs. samael

| Dimension | `saml` | `samael` |
| --- | --- | --- |
| Native deps for SAML protocol | None — Rust-only XML / DSig / C14N / XML-Enc | libxml2 + libxmlsec1 + libxslt + libclang + libtool + libiconv |
| HTTP backchannel | Bring-your-own via `HttpClient`; optional `reqwest-client` feature | Bundled |
| Cross-compile (musl, distroless, arm64, wasm) | Clean on any `rustc` target for the protocol layer | Requires native libs on every target |
| `cargo audit` coverage | Full for the protocol layer | Splits across `cargo audit` + OS packages |
| Stateless API | Yes — caller owns clock, persistence, replay store | Mixed |
| Role split | `ServiceProvider` / `IdentityProvider` / `SpDescriptor` / `IdpDescriptor` as distinct types | Closer to one type per role |
| Proxy first-class | Yes — `Proxy` + stateless `ProxyContext` codec | Compose `sp` + `idp` manually |
| Weak-algorithm quarantine | `weak-algos` feature, off by default | RSA-PKCS1-v1.5 ships by default |
| XSW resistance | Structural: duplicate IDs rejected at parse, `VerifiedSignature` is the only path to validated payload | Inherits xmlsec; configurable |

See [`docs/rfcs/RFC-001-architecture.md`](docs/rfcs/RFC-001-architecture.md) §11 for the full comparison.

## Feature flags

| Flag | Default | Purpose |
| --- | --- | --- |
| `reqwest-client` | yes | Optional `ReqwestClient` adapter for the `HttpClient` trait. |
| `rsa-sha` | yes | RSA-SHA256 / 384 / 512 signature algorithms. |
| `ecdsa-sha` | yes | ECDSA-SHA256 / 384 / 512 signature algorithms (P-256, P-384). |
| `xmlenc` | yes | XML Encryption (`EncryptedAssertion`, `EncryptedID`, AES-CBC / AES-GCM, RSA-OAEP). |
| `slo` | yes | Single Logout (Redirect / POST, with optional back-channel SOAP). |
| `metadata-emit` | yes | `metadata_xml` / `metadata_xml_with_extras` for SP and IdP, plus federation `EntitiesDescriptor` aggregate emit. |
| `xsd-validate` | yes | Structural XSD-style schema validation of inbound messages before any crypto runs. Opt out for permissive interop with borderline-conformant IdPs. |
| `artifact-binding` | no | HTTP-Artifact binding (SOAP `ArtifactResolve`) + `BackchannelClient`. Requires `weak-algos` for the SHA-1 SourceID. |
| `idp-disco` | no | IdP Discovery: Common Domain Cookie codec + discovery service protocol (request/response, return-URL validation) + `<idpdisc:DiscoveryResponse>` metadata. No extra dependencies. |
| `ecp` | no | ECP / PAOS profile (Enhanced Client or Proxy) for non-browser clients. Reuses the `binding::soap` envelope; no extra dependencies. |
| `weak-algos` | no | SHA-1 digest, RSA-PKCS1-v1.5 key transport, DSA-SHA1. Off by default; opt in only for legacy peer interop. |

The protocol layer compiles for any target `rustc` supports, including `wasm32-unknown-unknown` with `default-features = false`.

## Install

```sh
cargo add saml
```

Minimal build, opt out of the bundled `reqwest` HTTP client:

```sh
cargo add saml --no-default-features --features rsa-sha,ecdsa-sha,xmlenc,slo,metadata-emit,xsd-validate
```

## Quick example — Service Provider

```rust
use std::time::{Duration, SystemTime};
use saml::{
    Binding, ConsumeResponse, Dispatch, IdpDescriptor, KeyPair, NameIdFormat,
    PeerCryptoPolicy, ServiceProvider, ServiceProviderConfig, SpWantSigned,
    SsoResponseBinding, SsoResponseEndpoint, StartLogin,
};

let sp = ServiceProvider::new(ServiceProviderConfig {
    entity_id: "https://app.example.com/saml".into(),
    acs: vec![SsoResponseEndpoint::post(
        "https://app.example.com/saml/acs", 0, true,
    )],
    name_id_formats: vec![NameIdFormat::EmailAddress],
    signing_key: Some(KeyPair::from_pkcs8_pem(sp_priv)?),
    sign_authn_requests: true,
    want_signed: SpWantSigned { response: false, assertions: true },
    allow_unsolicited: false,
    default_peer_crypto_policy: PeerCryptoPolicy::strong_defaults(),
    // ... see lib.rs / RFC-003 for the full field list
    ..unreachable!()
})?;

let idp = IdpDescriptor::from_metadata_xml(idp_metadata_xml)?;

let start = sp.start_login(&idp, StartLogin {
    relay_state: None,
    binding: Binding::HttpRedirect,
    force_authn: false,
    is_passive: false,
    requested_name_id_format: None,
    requested_authn_context: None,
    acs_index: None,
    acs_url: None,
    response_binding: None,
})?;
match start.dispatch {
    Dispatch::Redirect(url) => { /* 302 the user agent */ }
    Dispatch::Post(form)    => { /* render the auto-submit form */ }
}

let identity = sp.consume_response(ConsumeResponse {
    idp: &idp,
    peer_crypto_policy: None,
    saml_response,
    binding: SsoResponseBinding::HttpPost,
    relay_state: None,
    tracker: Some(&tracker),
    expected_destination: "https://app.example.com/saml/acs",
    now: SystemTime::now(),
    clock_skew: Duration::from_secs(60),
})?;
```

The full SP, IdP, and proxy quickstarts live in [`src/lib.rs`](src/lib.rs) crate-level docs (visible on docs.rs).

## End-to-end multi-IdP demo

A runnable Axum SP wired up to seven IdPs (Keycloak, Authentik, FusionAuth locally; Zitadel, Auth0, Descope, Asgardeo in the cloud) behind one `/saml/acs` lives under [`examples/demo/`](examples/demo/). See [`examples/demo/README.md`](examples/demo/README.md) for the setup steps, and [`examples/idps/`](examples/idps/) for the merged docker-compose stack for the three local IdPs.

A standalone Rust IdP built on top of `saml::IdentityProvider` lives at [`examples/idp/`](examples/idp/) — pair it with the Axum SP in `examples/demo/` to exercise the SP and IdP sides of the crate against each other without any third-party software in the loop.

Known per-IdP quirks observed during the demo build (Zitadel SLO no-op, Asgardeo URL validator, Descope free-tier no-SLO, FusionAuth signing/SLO overrides) are documented in [`docs/interop.md`](docs/interop.md).

## Replay protection

SAML 2.0 Core §2.5.1.5 forbids re-consuming the same assertion within its validity window. The library exposes a `ReplayCache` trait and an in-memory default; pass an instance into `ConsumeResponse::replay_cache` to enable the check.

```rust
use saml::{ConsumeResponse, InMemoryReplayCache};

let replay_cache = InMemoryReplayCache::default();

let identity = sp.consume_response(ConsumeResponse {
    // ...
    replay_cache: Some(&replay_cache),
})?;
```

The cache is consulted AFTER signature verification and all other spec checks succeed, so forged or malformed responses never pollute the store. A duplicate `assertion_id` within the validity window surfaces as `Error::AssertionReplay`. Passing `None` keeps existing behavior — no check is performed, and the caller is responsible for deduping `Identity::assertion_id` against its own store.

For multi-instance deployments, implement `ReplayCache` against a shared backend (Redis, memcached, a SQL table with a unique constraint on `(id, expires_at)`) so a replay caught by one process is rejected by every process.

## Implementation status

Implemented:

- Web-Browser-SSO profile (HTTP-Redirect, HTTP-POST) — SP and IdP sides.
- Single Logout (`slo` feature) — Redirect and POST bindings, signed in both directions.
- HTTP-Artifact binding (`artifact-binding` feature) — `ArtifactResolve` / `ArtifactResponse` over SOAP, with a first-class `BackchannelClient` (signs the resolve, verifies the response) built on a shared, binding-agnostic `binding::soap` envelope module.
- ECP / PAOS profile (`ecp` feature) — Enhanced Client or Proxy for non-browser clients: SP, client, and IdP primitives over the Reverse-SOAP (PAOS) binding, including the spec §4.2.4.2 `AssertionConsumerServiceURL` anti-redirect check.
- Holder-of-Key subject confirmation — SP-side match of the caller-supplied presenter TLS certificate against the assertion's `<ds:KeyInfo>` (`SubjectPublicKeyInfo`, constant-time) plus IdP-side issuance; opt-in, with bearer remaining the default.
- XML-Encryption (`xmlenc` feature) — `EncryptedAssertion`, `EncryptedID`, AES-128/256-CBC, AES-128/256-GCM, RSA-OAEP-MGF1-SHA1/256/384/512 key transport.
- XML-DSig — Exclusive and Inclusive C14N (with and without comments), enveloped-signature transform; multi-Reference signatures rejected by default; transform whitelist enforced.
- Metadata parse and emit (`metadata-emit` feature) for single `EntityDescriptor`s and federation `EntitiesDescriptor` aggregates — signed-aggregate verification, an `entityID` index, and bounded streaming for large (InCommon / eduGAIN-scale) aggregates.
- Identity proxy composition with stateless `ProxyContext`, opaque-handle Redirect codec, NameID transforms, and attribute release policies.
- IdP Discovery (`idp-disco` feature) — Common Domain Cookie profile (`_saml_idp` codec) and the Identity Provider Discovery Service Protocol (SP and discovery-service sides, with metadata-backed return-URL validation).
- Pluggable signature verification via the `SignatureVerifier` trait (for HSM- or KMS-backed keys).

Out of scope for v0.1 (see [`docs/rfcs/RFC-001-architecture.md`](docs/rfcs/RFC-001-architecture.md) §12):

- SAML 1.x compatibility.
- Attribute Query profile.
- Name Identifier Management profile.
- Metadata signing-key rotation policy (the library exposes the primitives; policy is the caller's).
- Asynchronous front-channel SLO chain orchestration across N downstream SPs.
- `RetrievalMethod`, `AgreementMethod` (DH / ECDH) inside `KeyInfo`.

## Security posture

- **XSW resistance is structural.** Duplicate `ID` attributes are rejected at parse time; the `Reference URI` resolves to a unique `ElementId`; validated payload extraction is bound to the `VerifiedSignature` handle, not to a name lookup. There is no API path that returns a "validated" payload distinct from the signed payload. See [`docs/rfcs/RFC-002-xml-crypto-core.md`](docs/rfcs/RFC-002-xml-crypto-core.md) §3.
- **Weak algorithms are feature-gated.** SHA-1, RSA-PKCS1-v1.5 key transport, and DSA-SHA1 are unavailable unless `weak-algos` is enabled — the dependency is visible in `cargo tree`. Even when compiled in, the per-peer `PeerCryptoPolicy` allow-list still gates acceptance at validation time.
- **Hard-fail defaults** for signature validity, audience restriction, ACS URL allow-listing, NameID scoping, destination matching, and the XML-DSig transform whitelist (XSLT, XPath, and base64 transforms are rejected).
- **Caller-owned clock.** Every method that compares against `xs:dateTime` values takes `now: SystemTime` and `clock_skew: Duration` explicitly. Multi-instance deployments avoid drift surprises; tests pass deterministic timestamps.
- **Replay protection is pluggable.** `ConsumeResponse::replay_cache` accepts an `Option<&dyn ReplayCache>`. The default `InMemoryReplayCache` covers single-process deployments; multi-instance setups implement the trait against Redis or a SQL store. When `None`, no replay check runs and the caller is expected to dedupe `Identity::assertion_id` against their own store. See [Replay protection](#replay-protection) below.
- **DTD, internal entities, and processing instructions are rejected** at parse time, eliminating the XXE / billion-laughs class.
- **Detached query-string signatures** (HTTP-Redirect binding) go through a distinct verification entry point with the same `allowed_algorithms` discipline as XML-DSig.
- **`unsafe_code` is forbidden** at the crate root.

See [`docs/rfcs/RFC-002-xml-crypto-core.md`](docs/rfcs/RFC-002-xml-crypto-core.md) for the full crypto-layer threat model and [`docs/rfcs/RFC-001-architecture.md`](docs/rfcs/RFC-001-architecture.md) §2 for the operational principles.

## Fuzzing

The `fuzz/` workspace member ships three `cargo-fuzz` harnesses that exercise the bytes-from-the-wire boundaries of the crate:

| Target | What it drives | Why it matters |
| --- | --- | --- |
| `fuzz_xml_parse` | The DOM-ish XML parser (`xml::parse::Document::parse`) | Every inbound SAML message — Response, AuthnRequest, LogoutRequest, metadata — funnels through this code path before any signature or schema check runs. |
| `fuzz_c14n` | The parser plus the XML-C14N / Exclusive-C14N canonicalizer (one of the four variants is selected from the first input byte). | C14N output is what the signature is computed against; a divergence between signer and verifier here is a signature-bypass primitive. The fuzzer hammers the canonicalizer with adversarial well-formed inputs. |
| `fuzz_base64_response` | `ServiceProvider::consume_response` end-to-end (base64 → XML parse → schema check → DSig verify → assertion-level spec checks) against a fixed test SP / IdP fixture. | Mirrors a hostile peer posting bytes to `/acs`. The fuzzer can't break RSA-SHA256, but it shakes out crashes, infinite loops, and quadratic blowups in the path *before* the signature check rejects the response. |

A small seed corpus per target lives under `fuzz/corpus/<target>/`, populated from fixtures borrowed from `tests/corpus/ruby-saml/` and `tests/corpus/python3-saml/` so each fuzzer starts from real-shaped input rather than random bytes.

### Running

```sh
# One-time setup
cargo install cargo-fuzz
rustup toolchain install nightly   # libfuzzer requires nightly + sanitizers

# Build all harnesses (no execution)
cargo +nightly fuzz build

# Run one harness until you Ctrl-C it
cargo +nightly fuzz run fuzz_xml_parse
cargo +nightly fuzz run fuzz_c14n
cargo +nightly fuzz run fuzz_base64_response

# Time-bounded smoke run (libfuzzer -runs is iterations, -max_total_time is seconds)
cargo +nightly fuzz run fuzz_xml_parse -- -max_total_time=60
```

Reproducing a crash:

```sh
# libfuzzer drops crash inputs into fuzz/artifacts/<target>/.
cargo +nightly fuzz run fuzz_xml_parse fuzz/artifacts/fuzz_xml_parse/crash-<hash>
```

The harnesses reach into `pub mod __fuzz` in `src/lib.rs`, which is gated on `#[cfg(fuzzing)]` and therefore invisible to regular `cargo build` / `cargo doc` / downstream callers — it exists solely to give the fuzz targets thin shims into otherwise `pub(crate)` parser + canonicalizer entry points.

## Documentation

- [`docs/rfcs/RFC-001-architecture.md`](docs/rfcs/RFC-001-architecture.md) — Design principles, role model, scope statement.
- [`docs/rfcs/RFC-002-xml-crypto-core.md`](docs/rfcs/RFC-002-xml-crypto-core.md) — XML / DSig / C14N / XML-Enc layer.
- [`docs/rfcs/RFC-003-service-provider.md`](docs/rfcs/RFC-003-service-provider.md) — `ServiceProvider` API.
- [`docs/rfcs/RFC-004-identity-provider.md`](docs/rfcs/RFC-004-identity-provider.md) — `IdentityProvider` API.
- [`docs/rfcs/RFC-005-proxy-composition.md`](docs/rfcs/RFC-005-proxy-composition.md) — Proxy composition and `ProxyContext`.
- [`docs/rfcs/RFC-006-metadata.md`](docs/rfcs/RFC-006-metadata.md) — Metadata parse and emit.
- [`docs/rfcs/RFC-007-single-logout.md`](docs/rfcs/RFC-007-single-logout.md) — Single Logout.
- [`docs/rfcs/RFC-008-idp-discovery.md`](docs/rfcs/RFC-008-idp-discovery.md) — IdP Discovery (Common Domain Cookie + discovery service protocol).

## Minimum Supported Rust Version

The MSRV is **Rust 1.91.0** — the crate uses `Duration::from_mins` and `Duration::from_hours`, both stabilized in 1.91. CI runs the full test matrix against `stable`, `beta`, and `1.91.0`. Bumping the MSRV is treated as a minor-version change and called out in the release notes.

## License

Licensed under either of

- Apache License, Version 2.0
- MIT License

at your option.
