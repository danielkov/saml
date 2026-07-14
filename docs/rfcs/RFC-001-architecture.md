# RFC-001: saml v0.1.0 — Architecture and Principles

**Status**: Draft
**Date**: 2026-05-26

## Summary

`saml` is a Rust crate for the SAML 2.0 protocol, covering the Service Provider (SP) role, the Identity Provider (IdP) role, and their composition as an identity proxy. The **SAML protocol implementation** (XML, XML-DSig, XML-C14N, XML-Enc, crypto primitives) is written in Rust without a libxml2 or libxmlsec C build chain. The HTTP backchannel client is bring-your-own, mirroring `arctic-oauth`'s pattern; the optional `reqwest-client` feature inherits whatever transitive dependencies the caller's `reqwest` configuration brings (including, by default, native TLS). The crate is stateless by design, async-runtime-agnostic, and ships comprehensive Web-Browser-SSO + Single Logout + XML-Encryption support from v0.1.0.

It is not a port of arctic-js. SAML is not OAuth — the OAuth2 tokens model, scopes, refresh, and grant types do not apply. What this crate inherits from `arctic-oauth` is operational philosophy: caller owns persistence, caller owns the clock, library does mechanics correctly with security-critical defaults that cannot be silently weakened.

---

## 1. Motivation

The Rust SAML ecosystem has one significant entry, `samael`, which depends on libxml2 + libxmlsec1 + libxslt + libclang + openssl + pkg-config + libtool for its `xmlsec` feature. This dependency stack makes cross-compilation, distroless container builds, musl static linking, and WASM targets effectively impractical. It also introduces C-level CVE surface that the Rust caller cannot audit through `cargo audit`. Its own README describes the project as "a work in progress."

Meanwhile, enterprise Rust services routinely need SAML 2.0 for federated SSO. The protocol is mature, the wire format is stable, and the algorithms required for v0.1 (RSA-SHA256, ECDSA-SHA256, exc-c14n, AES-GCM) all have first-class pure-Rust implementations on crates.io. The build-toolchain pain in the existing options is no longer justified.

This crate fills that gap with the following positioning:

> A stateless, async-native SAML 2.0 toolkit with no libxml2/xmlsec C build chain. SP role, IdP role, and proxy composition with explicit security defaults. The SAML protocol mechanics are implemented in Rust; the HTTP backchannel client is bring-your-own (the optional `reqwest-client` feature inherits reqwest's transitive deps, including native TLS unless reqwest itself is configured for `rustls-tls`).

---

## 2. Design Principles

The crate inherits five operational principles from `arctic-oauth`:

1. **Stateless.** The library generates AuthnRequest IDs and assertion IDs, validates timestamps against caller-supplied `now`, and exposes assertion IDs for caller-side replay defense. It holds no session store, no metadata cache, and no clock.
2. **BYO HTTP.** The two SAML paths that require backchannel HTTP (artifact resolution and metadata refresh) go through an `HttpClient` trait identical in shape to `arctic-oauth::HttpClient`. Web-Browser-SSO and SLO redirect/POST bindings need no HTTP client at all — they return URLs and form bodies for the caller to dispatch.
3. **Type-honest API.** Active roles (`ServiceProvider`, `IdentityProvider`) are distinct types from parsed-metadata descriptors (`SpDescriptor`, `IdpDescriptor`). Bindings are enums; algorithms are enums; cert-use values are enums. Stringly-typed configuration is avoided.
4. **Minimal surface.** Every public function exists because the protocol requires it. Convenience wrappers, builder DSLs, and runtime-dispatch type erasure are absent.
5. **Bring-your-own verification policy** where the spec admits multiple valid choices (clock skew tolerance, metadata refresh cadence, replay window). **Hard-fail** where the spec does not (signature validity, audience restriction, ACS URL allow-listing, NameID scoping).

Two principles are specific to SAML's threat model:

6. **XML-Signature-Wrapping (XSW) resistance is a structural property, not an optional check.** The Reference URI inside `<ds:Signature>` MUST resolve to the same element whose contents the library subsequently exposes to the caller as the validated payload. There is no API path that returns a "validated" payload distinct from the signed payload.
7. **Algorithm agility with weak-algorithm quarantine.** SHA-1 digests, RSA-PKCS1-v1.5 key transport, and DSA signatures are implemented but gated behind a `weak-algos` feature that is off by default. Real-world legacy IdPs sometimes still require these; making the dependency explicit at compile time documents the trade-off in `cargo tree`.

---

## 3. Role model

SAML has two roles, SP and IdP, plus their composition as a proxy. The crate models this with four types:

| Type | Purpose | Owns crypto material? |
| --- | --- | --- |
| `ServiceProvider` | Active SP role. Builds AuthnRequests, consumes Responses. | Yes — SP signing + decryption keypairs. |
| `IdentityProvider` | Active IdP role. Consumes AuthnRequests, issues Responses. | Yes — IdP signing + optional decryption keypairs. |
| `SpDescriptor` | Parsed view of some other entity acting as an SP. Used by `IdentityProvider`. | No — only certificates. |
| `IdpDescriptor` | Parsed view of some other entity acting as an IdP. Used by `ServiceProvider`. | No — only certificates. |

Proxy = `ServiceProvider` (toward upstream) + `IdentityProvider` (toward downstream) + `Proxy::new(&sp, &idp, codec)` orchestration helper carrying a stateless `ProxyContext`. See RFC-005.

This split prevents two common bug classes:

- Using a parsed-metadata descriptor where an active role is required (compile error).
- Using the wrong key for the wrong direction (each role's config holds its own keypair fields).

---

## 4. Crate layout

```
saml/
  Cargo.toml
  src/
    lib.rs                  # Re-exports, feature flags
    error.rs                # Error enum
    http.rs                 # HttpClient trait + reqwest impl
    time.rs                 # xs:dateTime parse/emit

    sp.rs                   # ServiceProvider role (RFC-003)
    idp.rs                  # IdentityProvider role (RFC-004)
    proxy.rs                # Proxy composition + ProxyContext (RFC-005)

    descriptor/
      mod.rs
      idp.rs                # IdpDescriptor (from IDPSSODescriptor XML)
      sp.rs                 # SpDescriptor (from SPSSODescriptor XML)

    metadata/               # RFC-006
      mod.rs
      parse.rs              # EntityDescriptor + EntitiesDescriptor
      emit_sp.rs
      emit_idp.rs

    binding/
      mod.rs                # Binding enum, Dispatch enum
      redirect.rs           # HTTP-Redirect (DEFLATE + base64 + detached sig)
      post.rs               # HTTP-POST (base64 + embedded sig)
      artifact.rs           # ArtifactResolve over SOAP

    authn/
      mod.rs
      request_build.rs      # AuthnRequest emit (SP-side)
      request_parse.rs      # AuthnRequest parse (IdP-side)
      request_validate.rs   # AuthnRequest validate (IdP-side)

    response/
      mod.rs
      parse.rs              # Response + Assertion XML -> typed
      validate.rs           # Sig + conditions + subject confirmation
      issue.rs              # Response + Assertion XML emit (IdP-side)
      identity.rs           # Final Identity struct returned to caller

    logout/                 # RFC-007
      mod.rs
      request_build.rs
      request_parse.rs
      response_build.rs
      response_parse.rs

    disco/                  # RFC-008 (idp-disco feature)
      mod.rs                # <idpdisc:DiscoveryResponse> metadata + constants
      cdc.rs                # Common Domain Cookie codec
      service.rs            # discovery service protocol codecs

    xml/                    # RFC-002
      mod.rs
      parse.rs              # quick-xml-based DOM-ish parser
      emit.rs               # canonical-friendly serializer

    dsig/                   # RFC-002
      mod.rs
      c14n.rs               # Exclusive + Inclusive C14N
      verify.rs             # XML-DSig signature verification
      sign.rs               # XML-DSig signature creation
      reference.rs          # Reference URI resolution + transform whitelist
      algorithms.rs         # SignatureAlgorithm, DigestAlgorithm

    xmlenc/                 # RFC-002
      mod.rs
      decrypt.rs            # Encrypted Assertion -> cleartext Assertion
      encrypt.rs            # Cleartext Assertion -> EncryptedAssertion
      algorithms.rs         # DataEncryption + KeyTransport algorithms

    crypto/
      mod.rs
      keypair.rs            # KeyPair (signing + decryption)
      cert.rs               # X509 cert wrapper
      verifier.rs           # SignatureVerifier trait + default impls

    nameid.rs
    attribute.rs
    conditions.rs
    authn_context.rs

  tests/
    common/
      mod.rs
      fixtures.rs           # Captured Okta/Azure/Auth0/Keycloak XML
      mock_http_client.rs
    sp_flow_test.rs
    idp_flow_test.rs
    proxy_flow_test.rs
    interop_okta_test.rs
    interop_azure_ad_test.rs
    interop_auth0_test.rs
    interop_google_workspace_test.rs
    interop_onelogin_test.rs
    interop_keycloak_test.rs
    interop_adfs_test.rs

  docs/
    rfcs/
      RFC-001-architecture.md
      RFC-002-xml-crypto-core.md
      RFC-003-service-provider.md
      RFC-004-identity-provider.md
      RFC-005-proxy-composition.md
      RFC-006-metadata.md
      RFC-007-single-logout.md
      RFC-008-idp-discovery.md
```

---

## 5. Dependencies

```toml
[dependencies]
quick-xml = "0.36"                   # Streaming XML parse + emit
flate2 = { version = "1", default-features = false, features = ["rust_backend"] }
base64 = "0.22"
rsa = "0.9"                          # RSA verify/sign + RSA-OAEP key transport
ecdsa = "0.16"
p256 = { version = "0.13", features = ["ecdsa"] }
p384 = { version = "0.13", features = ["ecdsa"] }
sha1 = { version = "0.10", optional = true }  # behind weak-algos
sha2 = "0.10"
rand = "0.9"
x509-cert = "0.2"
spki = "0.7"
const-oid = "0.9"
aes = "0.8"
cbc = "0.1"
aes-gcm = "0.10"
thiserror = "2"
http = "1"
url = "2"
reqwest = { version = "0.12", features = ["json"], optional = true }

[features]
default = ["rsa-sha", "ecdsa-sha", "xmlenc", "slo", "metadata-emit", "xsd-validate"]
reqwest-client = ["dep:reqwest"]
rsa-sha = []
ecdsa-sha = []
xmlenc = []
slo = []
metadata-emit = []
artifact-binding = []
weak-algos = ["dep:sha1"]            # SHA-1 verify, RSA-1.5 key transport, DSA

[dev-dependencies]
tokio = { version = "1", features = ["full"] }
proptest = "1"
hex = "0.4"
```

CI runs the full root-crate feature matrix on Linux under stable, beta, and the
declared MSRV, plus default-feature workspace smoke tests on macOS and Windows.
Feature-specific jobs target `-p saml` so examples and fuzz workspace members
cannot silently re-enable default features through Cargo feature unification.

---

## 6. HttpClient trait

Identical shape to `arctic-oauth::HttpClient`:

```rust
pub trait HttpClient: Send + Sync + Sized {
    fn send(
        &self,
        request: HttpRequest,
    ) -> impl Future<Output = Result<HttpResponse, Box<dyn std::error::Error + Send + Sync>>> + Send;
}

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub method: http::Method,
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}
```

Only used for artifact resolution (SOAP POST), backchannel SLO (SOAP POST), and explicit metadata-fetch helpers. Web-Browser-SSO and SLO redirect/POST bindings never call this trait — they return `Dispatch::Redirect(Url)` or `Dispatch::Post(PostForm)` for the caller's HTTP framework to dispatch.

---

## 7. Error type

Single `Error` enum, mirroring `arctic-oauth::Error` in style — every distinct validation rule has its own variant so callers can branch and log specifically.

```rust
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    // --- XML / wire format ---
    #[error("XML parse error: {0}")]
    XmlParse(String),
    #[error("XML emit error: {0}")]
    XmlEmit(String),
    #[error("Base64 decode failed")]
    Base64Decode,
    #[error("DEFLATE decode failed")]
    Inflate,

    // --- Signature / crypto ---
    #[error("XML signature verification failed: {reason}")]
    SignatureVerification { reason: &'static str },
    #[error("XML signature missing where required")]
    SignatureMissing,
    #[error("Disallowed signature algorithm: {alg}")]
    DisallowedAlgorithm { alg: String },
    #[error("Disallowed transform: {transform}")]
    DisallowedTransform { transform: String },
    #[error("Signature Reference URI does not resolve to a recognized element")]
    ReferenceResolution,
    #[error("X.509 parse failed")]
    X509Parse,
    #[error("XML-Enc decrypt failed: {reason}")]
    DecryptFailed { reason: &'static str },

    // --- SAML protocol ---
    #[error("Issuer mismatch: expected {expected}, got {got:?}")]
    IssuerMismatch { expected: String, got: Option<String> },
    #[error("Destination mismatch")]
    DestinationMismatch,
    #[error("InResponseTo mismatch")]
    InResponseToMismatch,
    #[error("Audience restriction not satisfied")]
    AudienceMismatch,
    #[error("Assertion not yet valid (NotBefore in future)")]
    NotYetValid,
    #[error("Assertion expired (NotOnOrAfter passed)")]
    Expired,
    #[error("SubjectConfirmation Recipient mismatch")]
    RecipientMismatch,
    #[error("Status not Success: {code}")]
    StatusNotSuccess { code: String, message: Option<String> },
    #[error("Unsolicited Response received but allow_unsolicited is false")]
    UnsolicitedNotAllowed,
    #[error("Requested AuthnContextClassRef not satisfied")]
    AuthnContextDowngrade,

    // --- Trust / metadata ---
    #[error("Unknown peer entity: {entity_id}")]
    UnknownEntity { entity_id: String },
    #[error("AssertionConsumerServiceURL not registered for SP {entity_id}")]
    UnregisteredAcs { entity_id: String },
    #[error("No signing cert found in peer metadata")]
    NoPeerSigningCert,
    #[error("Peer does not advertise the requested binding: {binding:?}")]
    UnsupportedByPeer { binding: Binding },
    #[error("AuthnRequest/@ProtocolBinding is not legal for SSO Response: {requested:?}")]
    IllegalResponseBinding { requested: Binding },

    // --- Configuration ---
    #[error("Invalid configuration: {reason}")]
    InvalidConfiguration { reason: &'static str },

    // --- Transport ---
    #[error("HTTP request failed: {0}")]
    Http(#[from] Box<dyn std::error::Error + Send + Sync>),
}
```

---

## 8. Clock policy

The library has no clock. Every method that requires the current time takes a `now: SystemTime` parameter, plus a `clock_skew: Duration` parameter when comparing to peer-supplied `xs:dateTime` values.

This matches `arctic-oauth`'s posture (the only `SystemTime::now()` call in that crate is inside `OAuth2Tokens::new` to record `received_at`). Tests can pass deterministic timestamps; multi-instance deployments avoid drift surprises.

---

## 9. Testing strategy

Three tiers:

1. **Unit tests inside each module** (`#[cfg(test)] mod tests`) — XML parse round-trips, focused C14N known answers and regressions, signature/encryption round-trips, AuthnRequest builder output structure, and error-path coverage. The C14N suite includes four external Merlin/xmlsec Exclusive-C14N known answers with pinned provenance.
2. **Cross-role flow tests** (`tests/sp_flow_test.rs`, `tests/idp_flow_test.rs`, `tests/proxy_flow_test.rs`) — SP and IdP from the same process exchange real XML, validating end-to-end behavior under controlled conditions.
3. **Interop and security corpus tests** (`tests/corpus_runner.rs`, `tests/strong_security_corpus.rs`) — MIT-licensed fixtures imported from ruby-saml and python3-saml, including real AD FS RSA-SHA256/384/512 signatures, plus strong-algorithm in-process attack mutations with exact failure assertions.

One focused C14N `proptest` generates flat elements with bounded attribute maps
and text, then checks source-order independence and idempotence under Inclusive
and Exclusive C14N. Three `cargo-fuzz` targets exercise XML parsing, C14N, and
the end-to-end base64 Response consume path. The corpus runner records borrowed
fixture licenses; the external C14N fixtures additionally pin their exact
xmlsec source commit and transformation.

---

## 10. Interop corpus

The checked-in interop inputs are borrowed test fixtures, not claimed production
captures. Their source licenses are retained under `tests/corpus/`; the suite's
currently exercised provider/library shapes are:

| Source / shape | Notes |
| --- | --- |
| AD FS | Always-on RSA-SHA256/384/512 positives, a namespace variant, and RSA-SHA1 compatibility under `weak-algos`. |
| ruby-saml / python3-saml | Positive and negative Response shapes covering signatures, encryption, schema errors, audience/time checks, and XSW mutations. |
| OpenSAML / SimpleSAMLphp-shaped fixtures | Additional namespace, serialization, and signed-response interoperability cases from the imported corpora. |
| In-process Rust SP ↔ IdP | Fresh RSA-SHA256/SHA-256 baseline with exact digest-tamper, unresolved-reference, and duplicate-ID failures. |

---

## 11. USP vs `samael`

| Dimension | `saml` (this crate) | `samael` |
| --- | --- | --- |
| SAML protocol native deps | None — Rust-only XML / DSig / C14N / XML-Enc | libxml2 + libxmlsec1 + libxslt + libclang + libtool + libiconv |
| HTTP backchannel | Bring-your-own via `HttpClient` trait; `reqwest-client` feature optional and follows reqwest's transitive deps | Bundled |
| Cross-compile (protocol layer) | Clean for any target with `rustc` support | Painful; native libs required on every target |
| Cross-compile (with default HTTP) | Depends on the caller's `reqwest` configuration (`rustls-tls` recommended for musl/alpine/wasm) | Same native-deps barrier as the protocol layer |
| Container image | `FROM rust:alpine` works when the HTTP feature is disabled or `reqwest` is configured for `rustls-tls` | Needs `apk add libxml2-dev libxslt-dev xmlsec1-dev openssl-dev ...` |
| CVE audit surface | `cargo audit` covers the protocol layer fully; HTTP-client surface follows the caller's choice | Splits across `cargo audit` + OS package manager |
| Stateless API | Yes — caller owns clock, persistence, replay | Mixed |
| Type-honest role split | Yes — `ServiceProvider` / `IdentityProvider` / `SpDescriptor` / `IdpDescriptor` distinct | Closer to one type per role |
| Proxy first-class | Yes — `Proxy` + stateless `ProxyContext` codec, plus opaque-handle codec for Redirect binding | Compose `sp` + `idp` manually |
| Hard-fail security defaults | Yes — ACS allow-list, AuthnContext non-downgrade, scoped NameID, transform whitelist, duplicate-ID rejection at parse | Inherits xmlsec defaults |
| Weak-algos quarantine | `weak-algos` feature, off by default | RSA-1.5 ships by default |
| XSW resistance as structural property | Yes — duplicate IDs rejected at parse; Reference URI → unique `ElementId`; validated payload bound to that ID | Inherits xmlsec; configurable |

---

## 12. Out-of-scope for v0.1.0

Explicit non-goals so the scope statement stays honest:

(ECP/PAOS, Holder-of-Key subject confirmation, and IdP Discovery were on this
list originally and have since been implemented behind the `ecp`, default, and
`idp-disco` features respectively — see RFC-008 for discovery.)

- SAML 1.x compatibility. SAML 2.0 only.
- Attribute Query profile.
- Name Identifier Management profile.
- Metadata signing-key rotation policy. The library exposes primitives (`cert.not_after()`, `signing_certs()`); operational policy is the caller's.
- Long-lived session registry for SLO chain propagation. The library exposes inbound/outbound LogoutRequest/LogoutResponse primitives; the chain loop lives in the caller.
- Asynchronous front-channel SLO chain orchestration (sequential redirects to N downstream SPs).
- Manifest references / `RetrievalMethod` / `AgreementMethod` (DH/ECDH) in `KeyInfo`.

---

## 13. Resolved design decisions

1. **No `async-trait`.** Rust edition 2024 supports `fn send(...) -> impl Future + Send` natively. Matches `arctic-oauth` posture.
2. **No blocking API.** Async-only on backchannel paths. Sync where there's no I/O. Wrap with `tokio::runtime::Runtime::block_on` at the call site if blocking is needed.
3. **`&impl HttpClient` on backchannel methods.** Caller wraps in `Arc` if shared ownership is needed.
4. **One feature flag per protocol capability** (`slo`, `xmlenc`, `artifact-binding`, `metadata-emit`), one per algorithm family (`rsa-sha`, `ecdsa-sha`, `weak-algos`). No per-vendor feature flags — SAML is one-size-fits-all and vendor presets are constructors, not features.
5. **`quick-xml` over `xmltree` / `roxmltree`.** Streaming parse + emit, no allocation per element, easier to wire into c14n's canonical-ordering requirements.
6. **Pure-Rust `flate2` backend** (`rust_backend` feature, `miniz_oxide`). No zlib FFI.
7. **Strings are `String` in public types.** Internal hot paths may use `&[u8]` zero-copy where the borrow is local. No `Cow<str>` proliferation across the public API.

---

## 14. Implementation order

| Phase | Deliverable |
| --- | --- |
| 1 | `error.rs`, `http.rs`, `time.rs`, `xml/parse.rs` — primitives |
| 2 | `dsig/c14n.rs`, `dsig/algorithms.rs`, `crypto/cert.rs`, `crypto/keypair.rs` |
| 3 | `dsig/verify.rs` + Reference URI resolution + transform whitelist (RFC-002 critical path) |
| 4 | `dsig/sign.rs` (outbound) |
| 5 | `xmlenc/decrypt.rs` + `xmlenc/encrypt.rs` |
| 6 | `metadata/parse.rs` + `descriptor/{idp,sp}.rs` |
| 7 | `binding/{redirect,post}.rs` |
| 8 | `authn/request_{build,parse,validate}.rs` |
| 9 | `response/{parse,validate,issue,identity}.rs` |
| 10 | `sp.rs` + `idp.rs` (active roles) |
| 11 | `metadata/emit_{sp,idp}.rs` |
| 12 | `logout/*` + `binding/artifact.rs` |
| 13 | `proxy.rs` + `ProxyContext` |
| 14 | Test harness + interop corpus |
| 15 | `lib.rs` re-exports + docs |
