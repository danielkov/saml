//! Fuzz `saml::dsig::c14n::canonicalize` over a parsed `Document`.
//!
//! The first input byte selects one of the four canonicalization variants;
//! the remainder is fed to the XML parser. On a successful parse we drive
//! the canonicalizer over the document root with an empty inclusive-prefix
//! list — this is the same combination used by Reference resolution when
//! the signed element is the document root and no `<ec:InclusiveNamespaces>`
//! transform appears in the chain.
//!
//! Canonicalization is a pure function of the parsed DOM and is required to
//! return `Ok(_)` or `Err(Error::*)`; panics or aborts on adversarial
//! well-formed inputs are bugs.

#![cfg_attr(fuzzing, no_main)]

#[cfg(fuzzing)]
use libfuzzer_sys::fuzz_target;
#[cfg(fuzzing)]
use saml::dsig::algorithms::C14nAlgorithm;

#[cfg(fuzzing)]
fuzz_target!(|data: &[u8]| {
    let Some((selector, rest)) = data.split_first() else {
        return;
    };
    let algorithm = match selector % 4 {
        0 => C14nAlgorithm::ExclusiveCanonical,
        1 => C14nAlgorithm::ExclusiveCanonicalWithComments,
        2 => C14nAlgorithm::InclusiveCanonical,
        _ => C14nAlgorithm::InclusiveCanonicalWithComments,
    };
    let _ = saml::__fuzz::canonicalize_root(rest, algorithm);
});

#[cfg(not(fuzzing))]
fn main() {}
