# Roadmap

Forward-looking work not yet on `main`. Items are grouped by target
release. Each section has a **Motivation** (why), a **Sketch** (rough
implementation path), a **Complexity** estimate (Small / Medium /
Large), and a **Target release**.

Order is by target release ascending: `0.0.2-alpha` first, then
`0.1.0`, then `1.0`.

---

## Coverage report — CI integration of `cargo-llvm-cov`

**Motivation.** We have no public coverage signal today. A coverage
badge in the README sets expectations for contributors, surfaces
regressions in PRs, and makes the gaps in the test suite legible
without having to clone and run anything locally.

**Sketch.** Add a GitHub Actions job that runs `cargo llvm-cov
--workspace --lcov --output-path lcov.info`, uploads to Codecov (or
Coveralls), and emits a badge. Local-dev invocation goes through
`scripts/coverage.sh` (see below) which runs `cargo llvm-cov
--workspace --html` and prints the report path on success — same
underlying tool, just HTML for humans.

**Complexity.** Small.

**Target release.** `0.0.2-alpha`.

---

## Live `xmlsec1` cross-check on metadata signing

**Motivation.** Today the metadata-signing tests round-trip through
our own verifier plus `xmllint --c14n`. `xmlsec1 --verify` is the
reference XML-DSig verifier most enterprise SAML stacks (Shibboleth,
SimpleSAMLphp, mod_auth_mellon) build on. Cross-checking against it
catches interop bugs our self-consistent tests can't.

**Sketch.** Add a `tests/xmlsec_interop.rs` integration test gated on
`xmlsec1` being on `PATH`. For each signed-metadata fixture we already
produce, shell out to `xmlsec1 --verify --enabled-key-data x509`. Wire
a corresponding CI step that installs the `xmlsec1` Debian package
before running the test. No vendored binary needed.

**Complexity.** Small.

**Target release.** `0.0.2-alpha`.

---

## Replay cache opt-out

**Motivation.** `ReplayCache` rejects every assertion ID it has seen
before. For load-balanced deployments backed by an external store, or
for embedders who want their own dedup layer, the in-memory default is
the wrong tool. A typed opt-out makes the trade-off explicit instead
of forcing embedders to wrap the SP in glue code.

**Sketch.** Add `pub enum ReplayMode { All, OneTimeUseOnly, Off }` to
`src/replay.rs` and route SP/IdP config through it: `All` is current
behaviour, `OneTimeUseOnly` only enforces dedup when
`<OneTimeUse>` appears in the assertion's `<Conditions>`, `Off`
disables the cache entirely. Document the security implication of
`Off` in rustdoc and the README security section.

**Complexity.** Small.

**Target release.** `0.0.2-alpha`.

---

## Inclusive C14N

**Motivation.** We emit exclusive c14n only
(`http://www.w3.org/2001/10/xml-exc-c14n#`). Some ADFS configurations
and older SAML stacks require inclusive c14n
(`http://www.w3.org/TR/2001/REC-xml-c14n-20010315`). Without it we
can't sign assertions those peers will accept, which blocks interop
with a non-trivial slice of the install base.

**Sketch.** Extend `src/dsig/c14n.rs` with an inclusive variant
alongside the existing exclusive implementation: inclusive c14n keeps
inherited namespace declarations and `xml:*` attributes from ancestor
scope rather than pruning them. Plumb a `C14nAlgorithm` enum through
`SignOptions` / `VerifyOptions` and the `<CanonicalizationMethod>`
element in `<SignedInfo>`. Add fixtures from the XML-DSig interop
suite.

**Complexity.** Medium.

**Target release.** `0.1.0`.

---

## Encrypted NameID

**Motivation.** `EncryptedAssertion` is implemented, but standalone
`<EncryptedID>` on `<Subject>`, `<NameIDPolicy>`, and
`<LogoutRequest>` is not. It's less common than encrypting the whole
assertion, but it's in the SAML 2.0 core spec and some deployments
that don't otherwise encrypt assertions still expect encrypted
NameIDs in SLO flows.

**Sketch.** The xmlenc plumbing under `src/xmlenc/` already handles
`<EncryptedData>` / `<EncryptedKey>` for assertions; reuse it. Add an
`EncryptedNameId` variant alongside `NameId` in `src/nameid.rs`, wire
encrypt/decrypt through the existing key-resolver trait, and update
the `<Subject>` / `<NameIDPolicy>` / `<LogoutRequest>` parsers and
emitters to round-trip both forms.

**Complexity.** Small (existing xmlenc plumbing is reusable).

**Target release.** `0.1.0`.

---

## Federation aggregator support

**Motivation.** Academic (`.edu`) and government (`.gov`) federations
like InCommon and eduGAIN publish metadata as a single signed
`<EntitiesDescriptor>` containing hundreds or thousands of
`<EntityDescriptor>` children. Today we only parse and emit single
entities, which locks us out of those deployments entirely.

**Sketch.** Add `EntitiesDescriptor` parsing/emit to
`src/metadata/`, extend the verifier to validate a single signature
over the wrapping element (covering all children), and add an index
keyed by `entityID` so callers don't have to scan linearly. Stream
parsing matters here — InCommon's aggregate is ~50 MB — so the parser
should yield entities lazily rather than building the full tree in
memory.

**Complexity.** Medium.

**Target release.** `0.1.0`.

---

## Rust IdP example v2

**Motivation.** `examples/idp/` proves the IdP-facing API works for
the common case, but several features still ship without an
end-to-end demonstration. Filling those gaps tightens the
documentation story and gives us real test coverage of features that
are currently only exercised by unit tests.

**Sketch.** Extend `examples/idp/` to cover (a) encrypted assertions
by flipping `force_encrypt_assertion: true` and wiring the SP-side
cert, (b) artifact binding by implementing `/saml/artifact` instead
of returning 501, and (c) IdP-initiated SLO by adding an admin
endpoint that the example IdP can hit to terminate a session and fan
out `<LogoutRequest>` to all bound SPs. No new spec surface — this is
strictly about exercising existing crate features end-to-end.

**Complexity.** Medium.

**Target release.** `0.1.0`.

---

## HoK / SOAP / ECP bindings

**Motivation.** Three less-common SAML profiles we currently don't
support. Holder-of-Key (HoK) binds the assertion to a client TLS
cert; SOAP is the back-channel binding for artifact resolution
(currently stubbed); Enhanced Client/Proxy (ECP) is the non-browser
flow used by desktop apps and some federated CLI tooling. Each one
unlocks a specific deployment niche; together they round out the
SAML 2.0 binding matrix to spec-complete.

**Sketch.** Likely three separate releases. SOAP first since the
artifact stub already has the call sites: flesh out
`/saml/artifact` server-side and add an HTTP client for
`ArtifactResolve` / `ArtifactResponse`. HoK adds a TLS-cert binding
to `<SubjectConfirmation>`. ECP adds the SOAP envelope + PAOS
binding on top of the existing assertion machinery.

**Complexity.** Large each.

**Target release.** `1.0`.
