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

## One-time setup (bootstrap)

Trusted Publishing can only be configured for a crate that already exists on
crates.io, so the **first-ever publish is manual**:

1. `cargo publish --all-features` locally with a crates.io API token
   (`cargo login`). This ships `v0.0.1-alpha.1` and claims the crate name.
2. On crates.io: *saml → Settings → Trusted Publishing → Add* with
   repository owner `danielkov`, repository `saml`, workflow `release.yml`,
   environment `crates-io`.
3. On GitHub: *Settings → Environments → New environment* named `crates-io`;
   add a **required reviewer** (the maintainer) and, optionally, restrict
   deployment branches/tags to `v*`.
4. Push the matching `v0.0.1-alpha.1` tag so the release point is recorded.
   The verify job runs and passes; **reject** the paused `crates-io`
   deployment for this one run — the version is already on crates.io, so
   there is nothing to publish and approving it would just fail.

After bootstrap, every release is: bump version → merge → push tag →
approve.
