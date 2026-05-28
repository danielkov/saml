# Pre-release ship list

Flat list of things that need to ship before `saml` is meaningfully
released. No tiers. Each item is either a real interop bug, a verification
gap that makes a current claim performative, or a process step that has
to happen to get bits onto crates.io.

## Code gaps

1. **Inclusive C14N.** Some peers reject our signatures. Not exotic —
   ADFS variants, older Shibboleth configs. Real interop gap.

2. **Encrypted NameID.** `EncryptedAssertion` done, but standalone
   `EncryptedID` on `<Subject>` / `<LogoutRequest>` isn't. Same xmlenc
   plumbing reused.

3. **Encrypted assertions actually exercised in Rust IdP e2e.** Currently
   `force_encrypt_assertion: false` in `examples/idp/`. Path is wired,
   never runs.

4. **Artifact binding in Rust IdP.** `/saml/artifact` returns 501 stub.
   Library code exists; example doesn't prove it works end-to-end.

5. **IdP-initiated SLO in Rust IdP.** Only SP-init is wired. Real-world
   IdPs trigger SLO from their dashboard.

## Verification

6. **`cargo-fuzz` real runtime.** Three harnesses (`fuzz_xml_parse`,
   `fuzz_c14n`, `fuzz_base64_response`), none with recorded runs.
   Shipping with "we have fuzzers" is performative until real CPU has
   been spent. Target: at minimum 30 min per target on commodity
   hardware, record findings.

7. **`xmlsec1` cross-check on emitted metadata signature.** Reference
   verifier most enterprise stacks defer to. If `xmlsec1 --verify`
   accepts our output, that's a much stronger interop claim than our own
   round-trip. Integration test already sketched in ROADMAP.

8. **Live import of our metadata into Keycloak or Shibboleth as IdP /
   SP descriptor.** Round-trip via a real consumer, not just our own
   parser.

9. **Auth0 / Asgardeo / Descope end-to-end re-run** post-Tier-2
   changes. Demo last verified before `ReplayMode` + `consume_*_wire`
   helpers landed.

## Release ceremony

10. **Git remote.** `git remote add origin <url>` then `git push -u
    origin main`. Today the Cargo.toml `repository` / `homepage`
    URLs point at a GitHub URL that may not exist.

11. **`cargo publish --dry-run -p saml` on the post-version-bump
    state.** Last run was in the T1 worktree before the version bump;
    re-run on current `HEAD` (currently `9abf617`).

12. **`cargo publish -p saml`** for real to crates.io.

13. **Push `v0.0.1-alpha.1` tag** so the CHANGELOG link target exists.
