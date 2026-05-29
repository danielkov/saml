# Pre-release ship list

Flat list of things that need to ship before `saml` is meaningfully
released. No tiers. Each item is either a real interop bug, a verification
gap that makes a current claim performative, or a process step that has
to happen to get bits onto crates.io.

> **Status (2026-05-29).** Done: 1 (already implemented), 2, 3, 4, 5, 6, 7, 8,
> 9, 10, 11. Repo CI is green. Toolchain pinned via `mise.toml` (rust 1.95.0 +
> cargo-fuzz). Remaining: 12, 13 (publish + tag — held for explicit go-ahead).

## Code gaps

1. **Inclusive C14N.** ✅ DONE — already fully implemented (`src/dsig/c14n.rs`,
   `C14nAlgorithm::InclusiveCanonical{,WithComments}`) with W3C example +
   Keycloak regression tests. Plan item was stale.

2. **Encrypted NameID.** ✅ DONE — standalone `EncryptedID` now decrypted on
   `<LogoutRequest>` (SP + IdP `consume_logout_request`) and assertion
   `<Subject>` (response validation), after signature verification, gated by
   `PeerCryptoPolicy`. Reuses the EncryptedAssertion xmlenc plumbing.

3. **Encrypted assertions actually exercised in Rust IdP e2e.** ✅ DONE — IdP
   encrypts the assertion when the SP advertises an encryption cert (env-gated
   `SAML_IDP_FORCE_ENCRYPT`); `tests/encrypted_assertion_flow_test.rs` proves
   IdP-encrypt → SP-decrypt in-process (asserts the wire carries
   `<saml:EncryptedAssertion>` and no cleartext NameID).

4. **Artifact binding in Rust IdP.** ✅ DONE — `handle_artifact` now serves the
   SOAP ArtifactResolve → signed ArtifactResponse round trip with a bounded,
   one-time-consume `ArtifactStore` + cross-SP reuse defense;
   `examples/idp/tests/artifact_binding.rs` exercises it through the real axum
   handler (under `--features artifact-binding`).

5. **IdP-initiated SLO in Rust IdP.** ✅ DONE — `POST /logout-everywhere`
   builds a signed `<samlp:LogoutRequest>` to a participating SP and consumes
   the returning `<samlp:LogoutResponse>`, clearing the IdP session;
   `examples/idp/tests/idp_initiated_slo.rs` proves the loop (single-SP demo
   topology; multi-SP fan-out documented as out of scope).

## Verification

6. **`cargo-fuzz` real runtime.** ✅ DONE — 30 min/target on Apple silicon,
   zero crashes: `fuzz_xml_parse` 18.0M runs, `fuzz_c14n` 19.4M runs,
   `fuzz_base64_response` 28.0M runs. **Finding:** `fuzz_base64_response` was
   silently broken — its `#[cfg(fuzzing)]` harness didn't compile after
   `ReplayMode` added a `replay_mode` field to `ConsumeResponse`, so it had
   spent zero CPU. Fixed, re-ran the full 30 min, and added a CI `fuzz-build`
   job so a stale target fails CI instead of going unnoticed.

7. **`xmlsec1` cross-check on emitted metadata signature.** ✅ DONE —
   `tests/xmlsec_interop.rs`: `xmlsec1 --verify` accepts our IdP + SP metadata
   signatures, with a tamper negative-control so it can't pass vacuously. CI
   installs `xmlsec1` and runs it.

8. **Live import of our metadata into Keycloak or Shibboleth as IdP /
   SP descriptor.** ✅ DONE — Keycloak 26 (docker) accepts our emitted SP
   metadata as a SAML client and our IdP metadata as an identity provider; all
   four admin-API calls returned 2xx with no rejected/warned fields. Procedure
   + gated driver in `examples/idps/KEYCLOAK_INTEROP.md` / `keycloak_interop.sh`.

9. **Auth0 / Asgardeo / Descope end-to-end re-run.** ✅ DONE — re-ran the live
   demo SSO via the browser: **Auth0 ✅** and **Asgardeo ✅** complete the full
   Web-Browser-SSO round trip post-Tier-2 (assertion verified, identity +
   attributes extracted). **Descope ✅** — full round trip completed via
   Descope's Google login: SP dashboard reached, assertion verified, NameID +
   4 attributes extracted. The `E068003` seen at first was a
   test-environment artifact: the same browser was logged into the **Descope
   admin console**, and those session cookies, carried into the SSO endpoint,
   triggered the failure. Proven by isolating the variables: signed-no-session
   AND unsigned-no-session both reach the login page; signed AND unsigned both
   fail `E068003` when the console session is present. No code change needed —
   request signing was never the cause. Zitadel not re-tested.

## Release ceremony

10. **Git remote.** ✅ DONE — public repo `danielkov/saml` created, `origin`
    added, `main` pushed. Cargo.toml `repository` / `homepage` URLs resolve.

11. **`cargo publish --dry-run -p saml`** ✅ DONE — passes on current `HEAD`
    (packages + verifies the tarball). Also trimmed the package by excluding
    third-party `tests/corpus/` fixtures: 324 → 87 files, 714 → 356 KiB
    compressed.

12. **`cargo publish -p saml`** ⬜ TODO — held for explicit go-ahead
    (irreversible).

13. **Push `v0.0.1-alpha.1` tag** ⬜ TODO — after 12.
