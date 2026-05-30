#!/usr/bin/env bash
# Generate an HTML coverage report for the workspace via cargo-llvm-cov.
#
# Requires `cargo install cargo-llvm-cov` and the `llvm-tools-preview`
# rustup component. CI uses the same underlying tool with --lcov for
# upload; this script is the local-dev entry point.

set -euo pipefail

if ! command -v cargo-llvm-cov >/dev/null 2>&1; then
  echo "cargo-llvm-cov not found. Install with:" >&2
  echo "  cargo install cargo-llvm-cov" >&2
  echo "  rustup component add llvm-tools-preview" >&2
  echo "or, to match the pinned toolchain:" >&2
  echo "  mise install" >&2
  exit 1
fi

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

cargo llvm-cov --workspace --html

report="$repo_root/target/llvm-cov/html/index.html"
echo
echo "Coverage report: $report"
