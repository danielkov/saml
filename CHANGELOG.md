# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **Breaking:** `Identity`'s fields are now private, exposed through accessors.
  They were public and `Identity` is what `Proxy::relay_to_downstream` mints a
  signed downstream assertion from, so a caller could authenticate once,
  rewrite the subject, attributes, authentication context or timestamps on the
  resulting value, and have the proxy sign the rewritten claims. The private
  witness attests that *some* payload was validated, not that these values are
  that payload.
- **Breaking:** the proxy relay token is split in two. `ProxyContextPayload` is
  the transparent wire form a `ProxyContextCodec` serializes; `ProxyContext` is
  an opaque type with no public constructor, no public fields and no
  `Deserialize` impl, obtainable only from the new `Proxy::decode_context`,
  which authenticates the blob through the configured codec first.
  `relay_to_downstream` now accepts only the latter. Previously a caller could
  construct or deserialize a context naming any registered SP and ACS and pair
  it with a genuine identity.
- `Proxy::relay_to_downstream` verifies the assertion can be issued at all
  before running the caller-supplied attribute-release and NameID-transform
  callbacks. Those callbacks may write to a pseudonym store or an audit log,
  and issuance failures previously let both run first. The preflight and the
  assertion builder now share one function, so it covers every timestamp
  issuance computes — including `Conditions/@NotBefore = now - 1 minute`,
  which underflows at the epoch, and the `xs:dateTime` formatting, which
  rejects pre-epoch and non-representable instants.
- **Breaking:** `Proxy::context_codec` is removed and
  `ProxyContextCodec::encode` takes a `SealingGrant` instead of a
  `ProxyContextPayload`. A caller could otherwise build a payload naming any
  registered SP and ACS, seal it, and pass the blob to `decode_context` for a
  genuine attestation. Removing the accessor alone was insufficient:
  `Aes256GcmCodec` is public and the caller supplies its key, so a second
  instance over the same key is trivial. `SealingGrant` has no public
  constructor, so only `bounce_to_upstream` can seal.

  This closes the API route, not the underlying one — whoever holds the AEAD
  key can reimplement the documented wire format and mint blobs without this
  crate. Use `OpaqueHandleCodec` where the application's own key material is
  in scope.
- **Breaking:** `ProxyContextStore::put` takes a `SealingGrant` instead of a
  `ProxyContextPayload`. The caller constructs the store, so a `put` accepting
  a bare payload was a sealing oracle needing no key at all: insert an invented
  context under a chosen handle, then present that handle to `decode_context`.
  Its documented contract now also states that implementations must honour
  `ttl` and make `take` atomic and one-shot.
- **Breaking:** `Proxy::relay_to_downstream` takes a single `UpstreamFlow`
  instead of a separate `ProxyContext` and `Identity`, obtained from the new
  `Proxy::consume_upstream_response`. Both values were individually attested
  but nothing tied them together — `Identity` records no issuer, tracker or
  request ID — so a caller could pair identity B with context A and have the
  proxy sign an assertion authenticating B's subject into A's transaction, with
  every individual check passing. `consume_upstream_response` authenticates the
  relay token and validates the Response against *that* context's tracker in
  one step, so the pairing is no longer the caller's to choose.
- `Proxy::bounce_to_upstream` records the downstream SP's requested
  AuthnContext and NameIDPolicy in the context unconditionally. The
  `propagate_authn_context` / `propagate_name_id_policy` flags govern only what
  the upstream IdP is asked for; folding them into the stored context erased
  the downstream requirement, so `propagate_authn_context: false` made relay
  skip non-downgrade enforcement entirely.
- `Proxy::relay_to_downstream` selects the AuthnContext class the response will
  advertise *before* enforcing non-downgrade, and evaluates that class. It
  previously validated the upstream class and could then emit a different one:
  with `passthrough_authn_context: false`, an upstream MFA identity satisfied a
  downstream `Exact(MultiFactorAuth)` request and the signed assertion
  advertised PasswordProtectedTransport.
- **Breaking:** an ordered `AuthnContext` comparison (`minimum` / `maximum` /
  `better`) whose requested set contains any unrankable class now returns
  `NotComparable` instead of deciding on the rankable remainder. Nothing places
  a vendor-defined class in the standard hierarchy, so `Better([Custom,
  Password])` reporting `Satisfied` for an MFA actual answered a question the
  caller never asked.
- `OpaqueHandleCodec` rejects a `handle_byte_len` below 16 bytes. The handle is
  a bearer credential that travels in a URL, and `0` produced an empty handle
  shared by every caller.

### Added

- `Proxy::decode_context`.
- `Identity` accessors: `name_id`, `session_index`, `authn_instant`,
  `session_not_on_or_after`, `authn_context_class_ref`, `attributes`,
  `assertion_id`, `not_on_or_after`, `verifying_cert_fingerprint`,
  `is_one_time_use`.

## [0.0.1-alpha.2] - 2026-08-08

### Fixed

- Preserve each SAML `AudienceRestriction` as a separate group. Validation now
  applies OR within each group and AND across groups, as required by SAML Core
  §2.5.1.4. This prevents an assertion from passing when the service provider
  satisfies only one of multiple restrictions.

### Changed

- **Breaking:** replace `Conditions::audiences: Vec<String>` with
  `Conditions::audience_restrictions: Vec<Vec<String>>`. The flat field could
  not represent the grouping required for correct audience validation.

[0.0.1-alpha.2]: https://github.com/danielkov/saml/releases/tag/v0.0.1-alpha.2

## [0.0.1-alpha.1] - 2026-05-29

### Added

- `ReplayMode::{All, OneTimeUseOnly, Off}` opt-out on `ConsumeResponse` and
  `ConsumeArtifactResponse`. Default `All` matches existing behavior; spec-
  conformant minimum is `OneTimeUseOnly`. Caller opt-out via `Off`.
- `IdentityProvider::consume_authn_request_wire`,
  `consume_logout_request_wire`, and `consume_logout_response_wire` — wire-
  level helpers that decode the form body and dispatch in one call, matching
  the symmetry the SP side already had.
- Crate metadata for crates.io (`repository`, `homepage`, `documentation`,
  `readme`, `keywords`, `categories`).
- `LICENSE-MIT`, `LICENSE-APACHE`, `SECURITY.md`, `CHANGELOG.md`,
  `docs/interop.md`.
- `scripts/coverage.sh` (cargo-llvm-cov HTML report helper) and
  `examples/idps/fusionauth/regen_cert.sh` (rotate the FA IdP signing
  keypair).
- Demo landing renders per-provider notes on each provider card.

### Changed

- Rustdoc intra-doc links to private items rewritten as plain backticks so
  `cargo doc -D warnings` is clean.

[0.0.1-alpha.1]: https://github.com/danielkov/saml/releases/tag/v0.0.1-alpha.1

## [0.0.1-alpha.0] - 2026-05-28

### Added

- Service Provider role: parse and validate `Response` messages
  (`ServiceProvider::consume_response`) with structural XSW resistance, audience
  / destination / ACS-URL checks, and pluggable replay protection.
- Identity Provider role: parse `AuthnRequest`, issue signed `Response`
  messages, and emit IdP metadata.
- Proxy composition: stateless `Proxy` + opaque-handle `ProxyContext` codec
  bridging an upstream IdP to one or more downstream SPs.
- XML-DSig sign and verify for `AuthnRequest`, `Response`, `LogoutRequest`,
  `LogoutResponse`, and metadata. Exclusive and Inclusive C14N (with and
  without comments); enveloped-signature transform; transform allow-list
  rejecting XSLT, XPath, and base64.
- HTTP-Redirect binding (DEFLATE + base64 + URL-encoded query, detached
  query-string signature) and HTTP-POST binding (base64-wrapped, embedded
  XML-DSig).
- Single Logout (`slo` feature) — Redirect and POST bindings, signed in both
  directions.
- Metadata emit (`metadata-emit` feature) for SP and IdP descriptors,
  including signed-aggregate verification on the consume side.
- HTTP-Artifact binding (`artifact-binding` feature) — `ArtifactResolve` /
  `ArtifactResponse` over SOAP. Requires `weak-algos` for the SHA-1 SourceID.
- XSD-style structural schema validation of inbound SAML messages
  (`xsd-validate` feature, on by default).
- Distinct `ServiceProvider` / `IdentityProvider` / `SpDescriptor` /
  `IdpDescriptor` types — role boundary is enforced by the type system.
- `ReplayCache` trait + `InMemoryReplayCache` default for assertion-ID
  deduplication; checked after signature verification.
- XML Encryption (`xmlenc` feature) — `EncryptedAssertion`, `EncryptedID`,
  AES-128 / 256 CBC and GCM, RSA-OAEP-MGF1-SHA1 / 256 / 384 / 512 key
  transport.
- `weak-algos` feature flag quarantining SHA-1, RSA-PKCS1-v1.5 key transport,
  and DSA-SHA1; off by default.
- `PeerCryptoPolicy` per-peer allow-list gating accepted signature, digest,
  data-encryption, and key-transport algorithms at validation time.
- Bring-your-own backchannel via the `HttpClient` trait, with an optional
  `ReqwestClient` adapter behind the `reqwest-client` feature.
- Standalone Rust IdP in `examples/idp` paired with a multi-IdP Axum SP demo
  in `examples/demo` for a closed-loop integration test.
- `cargo-fuzz` workspace member with three harnesses
  (`fuzz_xml_parse`, `fuzz_c14n`, `fuzz_base64_response`) seeded from the
  real-IdP interop corpus.

### Notes

Pre-alpha; breaking changes expected in `0.0.x`. Public API not yet stable.
MSRV is Rust 1.91.0. The protocol layer is `#![forbid(unsafe_code)]`.

[0.0.1-alpha.0]: https://github.com/danielkov/saml/releases/tag/v0.0.1-alpha.0
