# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
