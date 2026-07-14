# Security Policy

## Reporting a Vulnerability

Please report suspected security vulnerabilities by email to
**daniel@speakeasy.com**. Use the subject line `[saml] security report`.

Do **not** open a public GitHub issue, pull request, or discussion thread for
security-sensitive reports — the crate's threat model includes hostile peers
on the SAML wire, and a public report tips them off before downstream callers
can update.

A report ideally includes:

- The affected crate version (or commit hash).
- A minimal reproduction — SAML message bytes, fixture metadata, the call site
  triggering the issue, and the observed vs. expected behavior.
- Your assessment of impact (e.g. signature bypass, XSW, replay, panic /
  denial-of-service on the host process, parser crash).
- Any constraints on disclosure timing (see below).

You will receive an acknowledgement within 72 hours.

## Supported Versions

While the crate is pre-alpha, only the most recent `0.0.1-alpha.x` release
line receives security fixes. Older `0.0.1-alpha.N-1` releases are not
patched — upgrade to the latest `0.0.1-alpha.*` to pick up the fix.

| Version | Supported |
| --- | --- |
| `0.0.1-alpha.x` (latest) | yes |
| anything older | no |

Once the crate reaches `0.1.0`, this table will be revised to follow the
standard "current minor + previous minor" policy.

## Threat Model

The crate is designed to defend the SP / IdP / proxy roles against a hostile
SAML peer on the wire. The following classes are explicitly in scope:

- **XML Signature Wrapping (XSW)** — duplicate `ID` attributes are rejected at
  parse time; the `Reference URI` resolves to a unique `ElementId`; validated
  payload extraction is bound to the `VerifiedSignature` handle, not to a
  name lookup. There is no API path that returns a "validated" payload
  distinct from the signed payload.
- **Replay** — `ConsumeResponse::replay_cache` exposes a `ReplayCache` trait
  with an in-memory default. Assertion `ID` deduplication is performed after
  signature verification so malformed payloads cannot pollute the store.
- **Weak-crypto downgrade** — SHA-1 crypto, RSA-PKCS1-v1.5 key transport, and
  DSA-SHA1 are gated behind the `weak-algos` Cargo feature, off by default.
  Independent per-peer `PeerCryptoPolicy` allow-lists still gate signature,
  XML-DSig reference digests, key transport, and RSA-OAEP digests even when
  `weak-algos` is compiled in. Both modern `rsa-oaep` with an explicit SHA-1
  `DigestMethod` and legacy `rsa-oaep-mgf1p` require a SHA-1 OAEP policy opt-in.
- **Signature wrapping via transforms** — the XML-DSig `Transform` allow-list
  rejects XSLT, XPath, and base64 transforms. Multi-`Reference` signatures
  are rejected by default.
- **XXE / billion-laughs / DTD injection** — DTDs, internal entities, and
  processing instructions are rejected at parse time.
- **Schema-shape exploits** — inbound messages pass through an internal
  XSD-style structural validator (`xsd-validate` feature, on by default)
  before any crypto operation runs.
- **Clock-skew abuse** — `NotBefore` / `NotOnOrAfter` checks take an explicit
  `now: SystemTime` and `clock_skew: Duration`. No method silently reads the
  wall clock.
- **HTTP-Redirect detached signatures** — verified via a distinct entry
  point with the same signature-algorithm policy discipline as XML-DSig.

The following are **out of scope** — protect against them at a higher layer:

- **Denial-of-service against the host process.** The parser rejects DTDs and
  bounds nesting depth, but a caller that accepts arbitrarily large request
  bodies still needs its own size limit.
- **Side-channel timing leaks.** Constant-time comparison is used where it
  matters for signature / MAC equality (`subtle`), but rustc / LLVM may still
  emit data-dependent branches. The crate is not engineered against an
  attacker who can run code on the same physical host as the SP.
- **Key compromise.** Once a private key leaks, the crate cannot help —
  rotate the key, re-issue metadata, and revoke trust at the relying party.
  Pluggable `SignatureVerifier` allows HSM- or KMS-backed keys; that's the
  right tool for high-value deployments.
- **Transport security beyond rustls.** The optional `reqwest-client`
  feature uses rustls; bring-your-own `HttpClient` implementations are the
  caller's responsibility. SOAP back-channel TLS pinning, mTLS, and CA
  selection are not in scope for this crate.
- **Identity provider correctness.** If the IdP issues an assertion for the
  wrong subject, no SP-side check can detect it.

## Known Advisories

The dependency audit (`cargo audit` / `cargo deny`) carries one accepted,
documented advisory:

- **RUSTSEC-2023-0071 — `rsa` "Marvin Attack" timing sidechannel.** The
  pure-Rust `rsa` crate's RSA private-key operations are not fully
  constant-time. No fixed release exists: the mitigation is partial and
  unreleased in the in-progress `rsa` 0.10 line (tracked at RustCrypto/RSA#390),
  and even that is described upstream as a "stop the bleeding" fix that does not
  completely close the channel. Pure-Rust RSA has no maintained alternative that
  avoids a C/asm backend, which would defeat this crate's no-C-build-chain
  premise.

  **Exposure here is limited by default.** The practically-exploitable PKCS#1
  v1.5 decryption padding-oracle vector is gated behind the `weak-algos` feature
  and refused by default — only RSA-OAEP key transport is accepted, so the
  classic Bleichenbacher/Marvin oracle is not reachable in a default build.
  SP-side signature *verification* uses no private key and is unaffected. The
  residual is generic non-constant-time modular-exponentiation timing on the
  RSA-OAEP `xmlenc` decryption and RSA signing paths — the same ecosystem-wide
  limitation noted under "Side-channel timing leaks" above, hard to exploit over
  a network.

  Operators who enable `weak-algos` (re-enabling RSA-1.5 key transport) take on
  the full Marvin exposure and should weigh that against their threat model.

  The advisory is recorded in `deny.toml` and the `cargo audit` CI step; it will
  be dropped once `rsa` ships a constant-time stable release.

## Disclosure Timeline

Standard timeline is **90 days** from receipt of the report to public
disclosure, regardless of fix availability. We aim to publish a fixed
release well within that window.

If you need a faster disclosure (for example, evidence of active
exploitation), say so in the initial report — we will accelerate. If you
need a slower disclosure for coordinated multi-party fixes, say so as well
and we will negotiate a date.

After a fixed release is published, the CHANGELOG entry will reference the
issue (with a CVE identifier if assigned) and credit the reporter unless
they prefer to remain anonymous.
