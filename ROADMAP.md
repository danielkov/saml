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

## HoK / SOAP / ECP bindings

**Motivation.** Three less-common SAML profiles we currently don't
support. Holder-of-Key (HoK) binds the assertion to a client TLS
cert; SOAP is the back-channel binding for artifact resolution
(the library has the `ArtifactResolve` / `ArtifactResponse` pieces and
the `examples/idp/` artifact endpoint exercises them, but there is no
first-class back-channel HTTP client yet); Enhanced Client/Proxy (ECP)
is the non-browser flow used by desktop apps and some federated CLI
tooling. Each one unlocks a specific deployment niche; together they
round out the SAML 2.0 binding matrix to spec-complete.

**Sketch.** Likely three separate releases. SOAP first: add a
first-class back-channel HTTP client for `ArtifactResolve` /
`ArtifactResponse` on top of the existing artifact machinery. HoK adds
a TLS-cert binding to `<SubjectConfirmation>`. ECP adds the SOAP
envelope + PAOS binding on top of the existing assertion machinery.

**Complexity.** Large each.

**Target release.** `1.0`.
