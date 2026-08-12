# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **Breaking:** a type `0x0004` artifact now carries the issuing IdP's
  `<md:ArtifactResolutionService>` index in bytes 2..4, as SAML 2.0 Bindings
  §3.6.4 requires. Issuance previously wrote the *service provider's* ACS
  index and consumption ignored the field entirely, always resolving against
  the default/first ARS. Any IdP advertising more than one ARS was misrouted.
  `ServiceProvider::consume_response_artifact` now decodes the index and
  selects that exact endpoint, refusing an index the IdP does not advertise.

- **Breaking:** `binding::artifact::build_artifact_resolve` returns an
  `ArtifactResolveEnvelope` carrying both the SOAP envelope and the
  `ArtifactResolve/@ID`, and `parse_artifact_response` takes that ID and
  requires the response's `@InResponseTo` to match. The pair previously
  discarded the generated ID and checked nothing, so callers of the manual
  low-level exchange had no way to correlate a response at all.
- **Breaking:** IdP metadata emission rejects an `ArtifactResolutionService`
  with no `index`, or two sharing one, instead of emitting `index="0"`.
  Publishing metadata that names an endpoint the operator never chose, or the
  same index twice, is the same defect as accepting it. Both the standalone and
  aggregate emitters share the validated builder.
- `BackchannelClient::resolve_artifact` now requires the
  `ArtifactResponse/@InResponseTo` to match the `ArtifactResolve/@ID` it sent.
  It previously accepted any otherwise-valid `ArtifactResponse`, so a
  substituted or replayed one could not be distinguished from the real answer.
- `<md:ArtifactResolutionService>` endpoints are now selected by exact `index`
  **and** `Binding::Soap`. Selection previously accepted any binding and then
  SOAP-posted to it, which contradicted the SOAP-only enforcement on the
  receiving side.
- **Breaking:** an `ArtifactResolutionService` with no `index`, or two sharing
  one, is now rejected when parsing metadata and when constructing an
  `IdentityProvider`. `index` is REQUIRED on an `IndexedEndpoint` and is what
  the artifact carries; a missing one left the endpoint unaddressable and a
  duplicate made routing depend on parse order.

### Added

- `binding::artifact::parse_artifact` and `ParsedArtifact`, exposing the
  endpoint index and `SourceID` of a type `0x0004` artifact.
- `IdpDescriptor::artifact_resolution_endpoint_by_index`.
- `Error::InvalidArtifact`, `Error::UnknownArtifactEndpointIndex` and
  `Error::AmbiguousArtifactEndpointIndex`.

### Security

- `IdentityProvider::build_artifact_response` now refuses an
  `ArtifactResolveRequest` that did not come from
  `IdentityProvider::parse_artifact_resolve`. The low-level
  `binding::artifact::parse_artifact_resolve` is public and applies none of the
  role-layer checks — configured certificates, issuer-vs-`IDPSSODescriptor`,
  the SOAP endpoint, `@Destination` — so a caller could previously parse
  unsigned XML and have it answered as though it had been authenticated.

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
