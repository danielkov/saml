//! Fuzz `saml::xml::parse::Document::parse` via the `__fuzz` re-export shim.
//!
//! Exercises the attacker-controlled bytes-to-DOM boundary: arbitrary XML
//! (well-formed or malformed) is funneled through the same parser used by
//! `ServiceProvider::consume_response` and `IdentityProvider::consume_authn_request`.
//! Any panic, abort, or sanitizer trip is a real bug — the parser is required
//! to surface failures as `Error::XmlParse`.

#![cfg_attr(fuzzing, no_main)]

#[cfg(fuzzing)]
use libfuzzer_sys::fuzz_target;

#[cfg(fuzzing)]
fuzz_target!(|data: &[u8]| {
    let _ = saml::__fuzz::parse_document(data);
});

// When this binary is built outside `cargo fuzz` (e.g. `cargo check --all`
// from the workspace root) we still need a real `main` so the linker is
// happy. The body is unreachable in practice — `cargo fuzz build` always
// sets `--cfg fuzzing` and takes the `#![no_main]` branch above.
#[cfg(not(fuzzing))]
fn main() {}
