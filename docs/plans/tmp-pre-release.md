# Pre-release ship list

Flat list of things that need to ship before `saml` is meaningfully
released. No tiers. Each item is either a real interop bug, a verification
gap that makes a current claim performative, or a process step that has
to happen to get bits onto crates.io.

> **Status (2026-05-29).** Done: 1 (was already implemented), 2, 6, 7, 10,
> 11. Repo CI is green. Toolchain pinned via `mise.toml` (rust 1.95.0 +
> cargo-fuzz). Remaining: 3, 4, 5 (IdP-example e2e), 8, 9 (live external
> IdPs), 12, 13 (publish + tag — held for explicit go-ahead).

## Code gaps

1. **Inclusive C14N.** ✅ DONE — already fully implemented (`src/dsig/c14n.rs`,
   `C14nAlgorithm::InclusiveCanonical{,WithComments}`) with W3C example +
   Keycloak regression tests. Plan item was stale.

2. **Encrypted NameID.** ✅ DONE — standalone `EncryptedID` now decrypted on
   `<LogoutRequest>` (SP + IdP `consume_logout_request`) and assertion
   `<Subject>` (response validation), after signature verification, gated by
   `PeerCryptoPolicy`. Reuses the EncryptedAssertion xmlenc plumbing.

3. **Encrypted assertions actually exercised in Rust IdP e2e.** ⬜ TODO —
   still `force_encrypt_assertion: Some(false)` in `examples/idp/src/sso.rs`.
   Path is wired, never runs. Needs the demo SP to advertise an encryption
   cert + the e2e loop to drive the encrypted path.

4. **Artifact binding in Rust IdP.** ⬜ TODO — `/saml/artifact` still returns
   501 (`examples/idp/src/sso.rs`). Library code + `tests/artifact_flow_test.rs`
   exist; the example needs an artifact store + SP-side resolve to prove e2e.

5. **IdP-initiated SLO in Rust IdP.** ⬜ TODO — only SP-init is wired.
   Real-world IdPs trigger SLO from their dashboard.

## Verification

6. **`cargo-fuzz` real runtime.** ✅ DONE — 30 min/target on Apple silicon,
   zero crashes: `fuzz_xml_parse` 18.0M runs, `fuzz_c14n` 19.4M runs.
   **Finding:** `fuzz_base64_response` was silently broken — its
   `#[cfg(fuzzing)]` harness didn't compile after `ReplayMode` added a
   `replay_mode` field to `ConsumeResponse`, so it had spent zero CPU. Fixed,
   re-running for the full 30 min, and added a CI `fuzz-build` job so a stale
   target fails CI instead of going unnoticed.

7. **`xmlsec1` cross-check on emitted metadata signature.** ✅ DONE —
   `tests/xmlsec_interop.rs`: `xmlsec1 --verify` accepts our IdP + SP metadata
   signatures, with a tamper negative-control so it can't pass vacuously. CI
   installs `xmlsec1` and runs it.

8. **Live import of our metadata into Keycloak or Shibboleth as IdP /
   SP descriptor.** ⬜ TODO — needs a live consumer (docker available; not
   yet run). Round-trip via a real consumer, not just our own parser.

9. **Auth0 / Asgardeo / Descope end-to-end re-run** ⬜ TODO — needs external
   accounts. Demo last verified before `ReplayMode` + `consume_*_wire`
   helpers landed.

## Release ceremony

10. **Git remote.** ✅ DONE — public repo `danielkov/saml` created, `origin`
    added, `main` pushed. Cargo.toml `repository` / `homepage` URLs resolve.

11. **`cargo publish --dry-run -p saml`** ✅ DONE — passes on current `HEAD`
    (packages + verifies the tarball; 324 files, 714 KiB compressed). Note:
    `tests/corpus/` is bundled since `tests/` isn't in Cargo.toml `exclude` —
    optional download-size trim.

12. **`cargo publish -p saml`** ⬜ TODO — held for explicit go-ahead
    (irreversible).

13. **Push `v0.0.1-alpha.1` tag** ⬜ TODO — after 12.
