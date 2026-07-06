# Releasing `saml`

Releases are tag-driven with a human approval gate. Pushing a `v*.*.*` tag
runs `.github/workflows/release.yml`:

1. **Verify** — the tag must equal the `[package]` version in `Cargo.toml`,
   then `cargo publish --dry-run --all-features` packages and builds the
   exact tarball that would ship.
2. **Approve** — the `publish` job is bound to the `crates-io` GitHub
   environment with a required reviewer; the run pauses until a maintainer
   approves it in the Actions UI. Review the dry-run output first.
3. **Publish** — the job exchanges its GitHub OIDC identity for a
   short-lived crates.io token (Trusted Publishing) and runs
   `cargo publish --all-features`. No long-lived registry token is stored in
   the repo.

`workflow_dispatch` runs the verify/dry-run half only — use it to rehearse a
release for any tag name without publishing.

## Cutting a release

```sh
# 1. Bump [package] version in Cargo.toml, update README/release notes,
#    commit to main via the normal review flow.
# 2. Tag the release commit and push the tag:
git tag v0.1.0
git push origin v0.1.0
# 3. Watch the Release workflow; review the dry-run job's output.
# 4. Approve the `crates-io` deployment in the GitHub Actions UI.
```

Version conventions: pre-1.0, breaking API changes bump the minor version;
an MSRV bump is treated as a minor-version change and called out in the
release notes (see README).

## Bootstrap status

Both one-time prerequisites are **done**:

- `saml v0.0.1-alpha.0` was published to crates.io manually on 2026-05-28,
  claiming the crate name (Trusted Publishing can only be configured for an
  existing crate).
- Trusted Publishing (repo `danielkov/saml`, workflow `release.yml`,
  environment `crates-io`) and the `crates-io` GitHub environment (required
  reviewer, deployments restricted to `v*` tags) were configured on
  2026-07-06.

`v0.0.1-alpha.0` predates the tag-driven flow and has no git tag; the next
release (`v0.0.1-alpha.1`, version already in `Cargo.toml`) is the first to
go through it end to end.
