//! Real-provider response corpus runner.
//!
//! Pulls SAML `<samlp:Response>` fixtures from the upstream ruby-saml and
//! python3-saml test suites (vendored under `tests/corpus/`) and runs them
//! through `ServiceProvider::consume_response`. Tests two equivalence
//! classes:
//!
//! - **Positive fixtures** — well-formed signed responses captured from real
//!   IdPs (ADFS, OpenSAML, etc.) or synthesized by upstream test rigs. Must
//!   parse + verify cleanly and yield an `Identity`.
//! - **Negative fixtures** — XSW attack vectors, missing-signature payloads,
//!   expired assertions, audience mismatches, XXE attempts. Must return an
//!   `Err(_)`. Any acceptance is a CVE.
//!
//! See `tests/corpus/LICENSE.ruby-saml` and `tests/corpus/LICENSE.python3-saml`
//! for upstream attribution. Both source corpora are MIT-licensed.
//!
//! Some fixtures use weak algorithms (RSA-SHA1) or DEFLATE base64-wrapped
//! payloads — see per-fixture flags below. Strong-algorithm fixtures run in
//! every build; legacy SHA-1 compatibility fixtures are gated individually on
//! `weak-algos`.

#[path = "common/mod.rs"]
mod common;

use std::io::Read as _;
use std::time::{Duration, SystemTime};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

#[cfg(all(feature = "xmlenc", feature = "weak-algos"))]
use saml::OaepDigest;
use saml::binding::SsoResponseBinding;
use saml::binding::{Endpoint, SsoResponseEndpoint};
use saml::crypto::cert::X509Certificate;
#[cfg(feature = "xmlenc")]
use saml::crypto::keypair::KeyPair;
use saml::descriptor::IdpDescriptor;
#[cfg(feature = "weak-algos")]
use saml::dsig::algorithms::C14nAlgorithm;
use saml::dsig::algorithms::{DigestAlgorithm, PeerCryptoPolicy, SignatureAlgorithm};
use saml::error::Error;
use saml::nameid::NameIdFormat;
use saml::replay::ReplayMode;
use saml::sp::{
    ConsumeResponse, LoginTracker, ServiceProvider, ServiceProviderConfig, SpWantSigned,
};
use saml::time::parse_xs_datetime;

// =============================================================================
// Fixture descriptor
// =============================================================================

#[derive(Debug, Clone, Copy)]
enum Expected {
    /// `consume_response` must return Ok(Identity).
    Ok,
    /// `consume_response` must reject. Setup failures and algorithm-policy
    /// short-circuits do not count as security-test passes.
    Reject,
    /// The imported fixture cannot reach SAML validation because its embedded
    /// test certificate is intentionally malformed. This is a documented
    /// corpus limitation, not a security rejection.
    UnsupportedFixture(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FixtureEncoding {
    Xml,
    Base64Xml,
    Base64Deflate,
}

#[derive(Debug, Clone, Copy)]
enum CryptoProfile {
    Strong,
    Legacy,
}

#[derive(Debug, Clone, Copy)]
enum AssertionSignature {
    Optional,
    Required,
}

#[derive(Debug, Clone, Copy)]
struct Fixture {
    /// Path relative to `tests/corpus/`.
    path: &'static str,
    /// Encoding applied to the vendored fixture file.
    encoding: FixtureEncoding,
    expected: Expected,
    /// Permit RSA-SHA1 / SHA-1 digest. Required for old ADFS captures.
    crypto_profile: CryptoProfile,
    /// Short label for the test fn name.
    label: &'static str,
    /// Require the Assertion to carry a valid signature. Used by explicit
    /// missing-signature negatives; most corpus captures are signed already.
    assertion_signature: AssertionSignature,
    /// Evaluation time in seconds after the captured IssueInstant.
    now_offset_secs: u64,
    /// Optional explicit Audience (SP entity_id) when the Audience is inside
    /// an EncryptedAssertion and therefore not visible in the cleartext.
    sp_entity_id_override: Option<&'static str>,
    /// Optional explicit IdP signing cert (PEM path under tests/corpus/) when
    /// the cert is embedded inside an EncryptedAssertion. The python3-saml
    /// idp.crt covers every python3-saml encrypted fixture in the corpus.
    idp_cert_pem_path: Option<&'static str>,
    /// Optional SP decryption key (PKCS#1 PEM, "RSA PRIVATE KEY") path under
    /// tests/corpus/. Required to consume EncryptedAssertion payloads.
    sp_decryption_key_pkcs1_pem_path: Option<&'static str>,
    /// Optional Destination override. When the fixture's Destination is a
    /// placeholder like `{recipient}` (ruby-saml's templated fixtures) we
    /// need a real ACS URL so the SP-side Destination check has something to
    /// compare against.
    acs_url_override: Option<&'static str>,
}

impl Fixture {
    const fn pos(path: &'static str, label: &'static str) -> Self {
        Self {
            path,
            encoding: FixtureEncoding::Xml,
            expected: Expected::Ok,
            crypto_profile: CryptoProfile::Legacy,
            label,
            assertion_signature: AssertionSignature::Optional,
            now_offset_secs: 1,
            sp_entity_id_override: None,
            idp_cert_pem_path: None,
            sp_decryption_key_pkcs1_pem_path: None,
            acs_url_override: None,
        }
    }

    const fn neg(path: &'static str, label: &'static str) -> Self {
        Self {
            path,
            encoding: FixtureEncoding::Xml,
            expected: Expected::Reject,
            crypto_profile: CryptoProfile::Legacy,
            label,
            assertion_signature: AssertionSignature::Optional,
            now_offset_secs: 1,
            sp_entity_id_override: None,
            idp_cert_pem_path: None,
            sp_decryption_key_pkcs1_pem_path: None,
            acs_url_override: None,
        }
    }

    const fn b64(mut self) -> Self {
        self.encoding = FixtureEncoding::Base64Xml;
        self
    }

    const fn deflated(mut self) -> Self {
        self.encoding = FixtureEncoding::Base64Deflate;
        self
    }

    const fn strong(mut self) -> Self {
        self.crypto_profile = CryptoProfile::Strong;
        self
    }

    #[cfg(feature = "xmlenc")]
    const fn with_audience(mut self, audience: &'static str) -> Self {
        self.sp_entity_id_override = Some(audience);
        self
    }

    const fn with_idp_cert(mut self, path: &'static str) -> Self {
        self.idp_cert_pem_path = Some(path);
        self
    }

    const fn require_assertion_signature(mut self) -> Self {
        self.assertion_signature = AssertionSignature::Required;
        self
    }

    const fn at_issue_offset(mut self, seconds: u64) -> Self {
        self.now_offset_secs = seconds;
        self
    }

    const fn unsupported(mut self, reason: &'static str) -> Self {
        self.expected = Expected::UnsupportedFixture(reason);
        self
    }

    #[cfg(feature = "xmlenc")]
    const fn with_decryption_key(mut self, path: &'static str) -> Self {
        self.sp_decryption_key_pkcs1_pem_path = Some(path);
        self
    }

    #[cfg(feature = "xmlenc")]
    const fn with_acs(mut self, url: &'static str) -> Self {
        self.acs_url_override = Some(url);
        self
    }
}

// =============================================================================
// Corpus manifest
// =============================================================================

// Path to the python3-saml IdP signing certificate. Encrypted fixtures need it
// because KeyInfo is hidden; unsigned negatives need a syntactically valid
// descriptor even though no signature verification consumes the key.
const PY3_IDP_CERT: &str = "python3-saml/certs/idp.crt";
// Matching SP decryption key (PKCS#1 PEM, "RSA PRIVATE KEY") shipped with
// python3-saml's test corpus.
#[cfg(feature = "xmlenc")]
const PY3_SP_KEY: &str = "python3-saml/certs/sp.key";
// A syntactically valid ruby-saml test cert for unsigned fixture setup.
const RUBY_TEST_CERT: &str = "ruby-saml/certificates/ruby-saml.crt";

const FIXTURES: &[Fixture] = &[
    // ---- Positive: ADFS captures (real Microsoft IdP) ----
    Fixture::pos(
        "ruby-saml/responses/adfs_response_sha256.xml",
        "adfs_sha256",
    )
    .strong(),
    Fixture::pos(
        "ruby-saml/responses/adfs_response_sha384.xml",
        "adfs_sha384",
    )
    .strong(),
    Fixture::pos(
        "ruby-saml/responses/adfs_response_sha512.xml",
        "adfs_sha512",
    )
    .strong(),
    Fixture::pos("ruby-saml/responses/adfs_response_sha1.xml", "adfs_sha1"),
    // ---- Negative: XSW attack vectors ----
    Fixture::neg(
        "ruby-saml/responses/response_wrapped.xml.base64",
        "xsw_wrapped",
    )
    .b64(),
    Fixture::neg(
        "ruby-saml/responses/response_assertion_wrapped.xml.base64",
        "xsw_assertion_wrapped",
    )
    .b64()
    // Upstream embeds certificate1, whose certificate-signature OID is the
    // intentionally malformed `0.0`. x509-cert rejects it before SAML runs.
    .unsupported("X509 DER: X509Parse"),
    Fixture::neg(
        "ruby-saml/responses/response_node_text_attack.xml.base64",
        "node_text_attack_1",
    )
    .b64()
    // This attack injects XML nodes into X509Certificate text, so there is no
    // parseable trust anchor with which to exercise signature verification.
    .unsupported("X509 first=Base64Decode"),
    Fixture::neg(
        "ruby-saml/responses/response_node_text_attack2.xml.base64",
        "node_text_attack_2",
    )
    .b64(),
    Fixture::neg(
        "ruby-saml/responses/response_node_text_attack3.xml.base64",
        "node_text_attack_3",
    )
    .b64(),
    // ---- Negative: XXE (DOCTYPE injection) ----
    Fixture::neg("ruby-saml/responses/attackxee.xml", "xxe"),
    // ---- Negative: missing signature namespace ----
    Fixture::neg("ruby-saml/responses/no_signature_ns.xml", "no_signature_ns"),
    Fixture::neg(
        "ruby-saml/responses/response_unsigned_xml_base64",
        "unsigned",
    )
    .b64()
    .deflated()
    .with_idp_cert(RUBY_TEST_CERT)
    .require_assertion_signature(),
    // ---- python3-saml: encrypted + expired + audience ----
    Fixture::neg(
        "python3-saml/responses/expired_response.xml.base64",
        "expired",
    )
    .b64()
    .with_idp_cert(PY3_IDP_CERT)
    .at_issue_offset(3_600),
    Fixture::neg(
        "python3-saml/responses/no_audience.xml.base64",
        "no_audience",
    )
    .b64()
    .with_idp_cert(PY3_IDP_CERT),
    // Real provider fixture signed at both the Response and Assertion levels.
    // This covers source-prefix preservation and the enveloped-signature rule
    // that removes only the enclosing signature while retaining a separately
    // signed descendant.
    Fixture::pos(
        "python3-saml/responses/double_signed_response.xml.base64",
        "double_signed",
    )
    .b64(),
    // ---- Positive: python3-saml single-target signed responses ----
    // Response root signed only (Assertion unsigned). Exercises legacy
    // RSA-SHA1 SignedInfo canonicalization under explicit compatibility
    // policy without requiring an Assertion signature.
    Fixture::pos(
        "python3-saml/responses/signed_message_response.xml.base64",
        "signed_message_response",
    )
    .b64(),
    // Assertion-only signed (Response root unsigned). Identical trust shape to
    // ruby-saml's response_with_signed_assertion.xml.base64.
    Fixture::pos(
        "python3-saml/responses/signed_assertion_response.xml.base64",
        "signed_assertion_response",
    )
    .b64(),
    // ---- Positive: python3-saml EncryptedAssertion fixtures (xmlenc) ----
    // python3-saml encrypted-assertion fixture whose decrypted
    // SubjectConfirmationData OMITS the Recipient attribute. SAML Web SSO
    // Profile §4.1.4.2 REQUIRES bearer SubjectConfirmationData to include
    // Recipient. saml correctly rejects; this fixture serves as a positive
    // test of SP strictness against a non-spec-compliant IdP emit.
    #[cfg(feature = "xmlenc")]
    Fixture::neg(
        "python3-saml/responses/signed_encrypted_assertion.xml.base64",
        "py3_encrypted_missing_recipient",
    )
    .b64()
    .with_idp_cert(PY3_IDP_CERT)
    .with_decryption_key(PY3_SP_KEY)
    .with_audience("http://stuff.com/endpoints/metadata.php")
    .with_acs("http://stuff.com/endpoints/endpoints/acs.php"),
    // python3-saml encrypted fixture with inconsistent Issuer: outer
    // Response carries one issuer, the decrypted inner Assertion carries a
    // different one. SAML Core §2.7.3.2 forbids the mismatch. saml
    // correctly rejects; positive test of SP strictness.
    #[cfg(feature = "xmlenc")]
    Fixture::neg(
        "python3-saml/responses/double_signed_encrypted_assertion.xml.base64",
        "py3_encrypted_issuer_mismatch",
    )
    .b64()
    .with_idp_cert(PY3_IDP_CERT)
    .with_decryption_key(PY3_SP_KEY)
    .with_audience("http://stuff.com/endpoints/metadata.php")
    .with_acs("https://pitbulk.no-ip.org/newonelogin/demo1/index.php?acs"),
    // ---- Positive: ruby-saml structural variants ----
    // xmlns:ds declared on the Response root rather than inside
    // <ds:Signature>. Canonicalization must resolve the inherited prefix and
    // reproduce the signer's bytes.
    Fixture::pos(
        "ruby-saml/responses/response_with_ds_namespace_at_the_root.xml.base64",
        "ds_namespace_at_root",
    )
    .b64(),
    // Alternate signed-assertion shape (variant 2). Same security
    // properties as response_with_signed_assertion.xml.base64; differs in
    // attribute ordering / whitespace around the signed block.
    Fixture::pos(
        "ruby-saml/responses/response_with_signed_assertion_2.xml.base64",
        "signed_assertion_2",
    )
    .b64(),
    // ---- Negative: explicit no-signature assertion ----
    // Same shape as a real Response but with the <ds:Signature> element
    // deleted from the assertion. Distinct from the existing `unsigned`
    // fixture, which is a deflate-compressed payload.
    Fixture::neg(
        "python3-saml/responses/invalids/no_signature.xml.base64",
        "no_signature_explicit",
    )
    .b64()
    .with_idp_cert(PY3_IDP_CERT)
    .require_assertion_signature(),
    // Multi-assertion response (python3-saml's `multiple_assertions.xml.base64`
    // — note: the upstream filename omits "signed", but the fixture does
    // contain multiple signed Assertions inside one Response). Per
    // RFC-003 §4.1 step 7 / SAML Core §3.4.1.3, an SP processing a Response
    // must reject when more than one Assertion is present (the inner
    // <Assertion> is signed but XSW becomes trivial otherwise).
    Fixture::neg(
        "python3-saml/responses/invalids/multiple_assertions.xml.base64",
        "multiple_assertions",
    )
    .b64()
    // This fixture reuses ruby-saml's malformed-OID certificate1. The
    // always-on strong duplicate-ID XSW case covers the defense independently.
    .unsupported("X509 DER: X509Parse"),
    // Empty Destination attribute (Destination=""). RFC-003 §4.1 step 4 and
    // SAML Core §3.2.2.1 require Destination to match the SP's ACS URL when
    // present — an empty string cannot match a real URL.
    Fixture::neg(
        "python3-saml/responses/invalids/empty_destination.xml.base64",
        "empty_destination",
    )
    .b64(),
    // ---- Negative: additional XSW / signature-bypass vectors ----
    // ruby-saml: two signed Assertions in one Response — XSW variant.
    Fixture::neg(
        "ruby-saml/responses/invalids/multiple_signed.xml.base64",
        "ruby_multiple_signed",
    )
    .b64(),
    // ruby-saml: signature references a different element than the
    // <Assertion> the SP would process (signed-element confusion).
    Fixture::neg(
        "ruby-saml/responses/invalids/response_invalid_signed_element.xml.base64",
        "ruby_invalid_signed_element",
    )
    .b64(),
    // ruby-saml: attacker concealed an additional <Assertion> inside the
    // tree alongside a legitimately signed one (concealed-XSW).
    Fixture::neg(
        "ruby-saml/responses/invalids/response_with_concealed_signed_assertion.xml",
        "ruby_concealed_signed_assertion",
    ),
    // ruby-saml: two copies of the same signed <Assertion> in one Response
    // (doubled-XSW).
    Fixture::neg(
        "ruby-saml/responses/invalids/response_with_doubled_signed_assertion.xml",
        "ruby_doubled_signed_assertion",
    ),
    // python3-saml: classic signature-wrapping attack — signed element
    // moved to <StatusDetail>, attacker payload hoisted into <Assertion>.
    Fixture::neg(
        "python3-saml/responses/invalids/signature_wrapping_attack.xml.base64",
        "py3_sig_wrap_attack",
    )
    .b64(),
    // python3-saml: variant of the above that ships the original signed
    // Response embedded inside a wrapper <ns0:Response>.
    Fixture::neg(
        "python3-saml/responses/invalids/signature_wrapping_attack2.xml.base64",
        "py3_sig_wrap_attack2",
    )
    .b64(),
    // python3-saml: bad ds:Reference — the signature digest doesn't cover
    // the element the SP would process.
    Fixture::neg(
        "python3-saml/responses/invalids/bad_reference.xml.base64",
        "py3_bad_reference",
    )
    .b64(),
    // ---- Negative: synthetic Somorovsky XSW patterns ----
    // Three XSW attack patterns from Somorovsky et al. "On Breaking SAML:
    // Be Whoever You Want to Be" (USENIX Security 2012) that were not
    // already exercised by the upstream ruby-saml / python3-saml corpora.
    // Each is synthesized from python3-saml/responses/invalids/
    // bad_reference.xml.base64 with the structural mutation called out in
    // the paper. saml MUST reject all three.
    //
    // Pattern 5: Wrapped Original Assertion in
    // samlp:Response/ds:Signature/ds:Object. The signed Assertion (with
    // its own enveloped <ds:Signature>) is hidden inside <ds:Object>
    // appended to the Response-level signature. The visible Assertion
    // sibling of <samlp:Status> is an attacker-controlled unsigned
    // Assertion.
    Fixture::neg(
        "synthetic/xsw_pattern_5_assertion_in_signature_object.xml.base64",
        "xsw_pattern_5_assertion_in_signature_object",
    )
    .b64(),
    // Pattern 6: Substituted Subject under signed Assertion. The signed
    // Assertion element is kept intact except for the NameID text, which
    // is rewritten to an attacker-controlled value. Tests that saml
    // rejects via digest mismatch (Subject is covered by the assertion
    // signature) rather than honoring a textually altered identity.
    Fixture::neg(
        "synthetic/xsw_pattern_6_substituted_subject.xml.base64",
        "xsw_pattern_6_substituted_subject",
    )
    .b64(),
    // Pattern 8: Namespace Injection / xmlns redefinition. The signed
    // Assertion is hidden inside a <wrap:Decoy> element that redeclares
    // xmlns:saml to a bogus namespace, so the signed `saml:Assertion`
    // resolves to a different namespace URI than the visible attacker
    // Assertion sibling. Tests that saml's element lookup is
    // namespace-aware and that c14n preserves the namespace binding the
    // signer intended.
    Fixture::neg(
        "synthetic/xsw_pattern_8_namespace_injection.xml.base64",
        "xsw_pattern_8_namespace_injection",
    )
    .b64(),
    // ADFS assertion signed with RSA-SHA256/SHA-256 and the XML-DSig
    // namespace supplied as the default namespace on Signature. Keep this
    // always-on: it catches namespace/c14n regressions without weak-algos.
    Fixture::pos(
        "ruby-saml/responses/adfs_response_xmlns.xml",
        "adfs_response_xmlns",
    )
    .strong(),
];

// =============================================================================
// Permissive crypto policy for corpus fixtures (includes weak algos).
// =============================================================================

#[cfg(feature = "weak-algos")]
fn permissive_policy() -> PeerCryptoPolicy {
    let mut allowed = SignatureAlgorithm::DEFAULTS.to_vec();
    allowed.push(SignatureAlgorithm::RsaSha1);
    let mut allowed_digests = DigestAlgorithm::DEFAULTS.to_vec();
    allowed_digests.push(DigestAlgorithm::Sha1);
    #[cfg(feature = "xmlenc")]
    let mut allowed_oaep_digests = OaepDigest::DEFAULTS.to_vec();
    #[cfg(feature = "xmlenc")]
    allowed_oaep_digests.push(OaepDigest::Sha1);
    PeerCryptoPolicy {
        allowed_signature_algorithms: allowed,
        allowed_digest_algorithms: allowed_digests,
        allowed_c14n_algorithms: vec![
            C14nAlgorithm::ExclusiveCanonical,
            C14nAlgorithm::ExclusiveCanonicalWithComments,
            C14nAlgorithm::InclusiveCanonical,
            C14nAlgorithm::InclusiveCanonicalWithComments,
        ],
        #[cfg(feature = "xmlenc")]
        allowed_data_encryption_algorithms: vec![
            saml::xmlenc::algorithms::DataEncryptionAlgorithm::Aes128Gcm,
            saml::xmlenc::algorithms::DataEncryptionAlgorithm::Aes256Gcm,
            saml::xmlenc::algorithms::DataEncryptionAlgorithm::Aes128Cbc,
            saml::xmlenc::algorithms::DataEncryptionAlgorithm::Aes256Cbc,
        ],
        #[cfg(feature = "xmlenc")]
        allowed_key_transport_algorithms: vec![
            saml::xmlenc::algorithms::KeyTransportAlgorithm::RsaOaep,
            saml::xmlenc::algorithms::KeyTransportAlgorithm::RsaOaepMgf1Sha1,
            saml::xmlenc::algorithms::KeyTransportAlgorithm::RsaPkcs1V15,
        ],
        #[cfg(feature = "xmlenc")]
        allowed_oaep_digest_algorithms: allowed_oaep_digests,
    }
}

// =============================================================================
// Per-fixture metadata extraction (minimal, regex-y because we just need
// the few attributes/elements needed to build an SP+IdP config)
// =============================================================================

struct Extracted {
    issuer: String,
    audience: Option<String>,
    destination: Option<String>,
    in_response_to: Option<String>,
    issue_instant: SystemTime,
    /// `None` when the response carries no cleartext <X509Certificate> (e.g.
    /// the cert is inside an EncryptedAssertion). Callers must provide an
    /// `idp_cert_pem_path` on the Fixture in that case.
    cert: Option<X509Certificate>,
}

fn extract(xml: &[u8]) -> Result<Extracted, String> {
    let s = std::str::from_utf8(xml).map_err(|e| format!("utf8: {e}"))?;

    let issuer =
        first_element_text(s, "Issuer").ok_or_else(|| "missing <Issuer> text".to_string())?;
    let audience = first_element_text(s, "Audience");
    let destination = first_attribute(s, "Destination");
    let in_response_to = first_attribute(s, "InResponseTo");

    let issue_instant_raw = first_attribute(s, "IssueInstant")
        .ok_or_else(|| "missing IssueInstant attr".to_string())?;
    let issue_instant = parse_xs_datetime(&issue_instant_raw)
        .map_err(|e| format!("parse IssueInstant {issue_instant_raw}: {e:?}"))?;

    // First <ds:X509Certificate> in the document. Two shapes exist in the
    // wild:
    //   (a) `<X509Certificate>{base64 DER}</X509Certificate>` (spec-standard)
    //   (b) `<X509Certificate>{base64 of full PEM}</X509Certificate>`
    //       (some legacy ADFS captures wrap PEM in another base64 layer)
    // Try (a) first; if X509 parse fails, decode one more layer and try
    // again as PEM. When the cert is missing entirely (encrypted assertion
    // / unsigned response), return `cert: None` and let the runner decide.
    let cert = if let Some(cert_b64) = first_element_text(s, "X509Certificate") {
        let cert_b64_clean: String = cert_b64.chars().filter(|c| !c.is_whitespace()).collect();
        let parsed = match X509Certificate::from_base64_x509(&cert_b64_clean) {
            Ok(c) => c,
            Err(first_err) => {
                // Maybe the element wraps PEM in another base64 layer.
                let inner = BASE64
                    .decode(cert_b64_clean.as_bytes())
                    .map_err(|e| format!("X509 first={first_err:?} b64 outer: {e:?}"))?;
                if inner.starts_with(b"-----BEGIN") {
                    X509Certificate::from_pem(&inner).map_err(|e| format!("X509 PEM: {e:?}"))?
                } else {
                    X509Certificate::from_der(&inner).map_err(|e| format!("X509 DER: {e:?}"))?
                }
            }
        };
        Some(parsed)
    } else {
        None
    };

    Ok(Extracted {
        issuer,
        audience,
        destination,
        in_response_to,
        issue_instant,
        cert,
    })
}

/// Find first occurrence of `<*:local>text</*:local>` and return the inner text.
/// Permissive: ignores namespace prefix on the tag.
fn first_element_text(s: &str, local: &str) -> Option<String> {
    // Match either `<local>` or `<NS:local>` then capture inner text up to `</...local>`.
    let needle_a = format!(":{local}>");
    let needle_b = format!("<{local}>");
    let pos = s
        .match_indices(&needle_a)
        .map(|(i, _)| i.saturating_add(needle_a.len()))
        .next()
        .or_else(|| {
            s.match_indices(&needle_b)
                .map(|(i, _)| i.saturating_add(needle_b.len()))
                .next()
        })?;
    let close = format!("{local}>");
    let rest = s.get(pos..)?;
    let end = rest.find("</")?;
    let inner = rest.get(..end)?;
    // Sanity: the close tag should reference `local` (we matched `</`).
    let after_end = rest.get(end..)?;
    if !after_end.contains(&close) {
        return None;
    }
    Some(inner.trim().to_string())
}

/// Find the first occurrence of `name="value"` on any element.
fn first_attribute(s: &str, name: &str) -> Option<String> {
    // Both quote styles are legal XML. ADFS captures in ruby-saml use both,
    // so limiting this test-runner helper to double quotes silently skipped
    // otherwise-valid interop fixtures.
    for quote in ['"', '\''] {
        let needle = format!(" {name}={quote}");
        let Some(start) = s
            .find(&needle)
            .map(|offset| offset.saturating_add(needle.len()))
        else {
            continue;
        };
        let rest = s.get(start..)?;
        let end = rest.find(quote)?;
        return Some(rest.get(..end)?.to_string());
    }
    None
}

// =============================================================================
// Per-fixture runner
// =============================================================================

/// Resolve a path on the Fixture against the corpus root.
fn corpus_path(rel: &str) -> String {
    format!("{}/tests/corpus/{}", env!("CARGO_MANIFEST_DIR"), rel)
}

/// Run one fixture through the SP `consume_response` path. Returns the
/// recovered `Identity` on success; on failure, returns a string that wraps
/// either a setup error (I/O, base64, XML extract) or saml's own
/// `Err(_)` from `consume_response`. The caller (inside a `#[test]` fn)
/// decides whether that outcome matches the fixture's expectation.
fn run_fixture(fx: &Fixture) -> Result<saml::response::Identity, String> {
    let abs_path = corpus_path(fx.path);
    let raw = std::fs::read(&abs_path).map_err(|e| format!("read {abs_path}: {e}"))?;
    let mut xml = match fx.encoding {
        FixtureEncoding::Xml => raw,
        FixtureEncoding::Base64Xml | FixtureEncoding::Base64Deflate => {
            let s = std::str::from_utf8(&raw).map_err(|e| format!("utf8 wrap: {e}"))?;
            let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
            BASE64
                .decode(clean.as_bytes())
                .map_err(|e| format!("b64 wrap decode: {e}"))?
        }
    };
    if fx.encoding == FixtureEncoding::Base64Deflate {
        let mut decoder = flate2::read::DeflateDecoder::new(xml.as_slice());
        let mut inflated = Vec::new();
        decoder
            .read_to_end(&mut inflated)
            .map_err(|e| format!("raw DEFLATE decode: {e}"))?;
        xml = inflated;
    }

    let meta = extract(&xml).map_err(|e| format!("extract: {e}"))?;

    // Resolve the trusted IdP signing cert. Prefer the fixture's per-fixture
    // override (used when the cert lives inside an EncryptedAssertion);
    // otherwise use whatever was embedded in cleartext <ds:KeyInfo>.
    let idp_cert = match (fx.idp_cert_pem_path, meta.cert.clone()) {
        (Some(rel), _) => {
            let pem =
                std::fs::read(corpus_path(rel)).map_err(|e| format!("read idp cert {rel}: {e}"))?;
            X509Certificate::from_pem(&pem).map_err(|e| format!("idp cert PEM {rel}: {e:?}"))?
        }
        (None, Some(c)) => c,
        (None, None) => {
            return Err(
                "no cleartext <X509Certificate> and no idp_cert_pem_path override".to_string(),
            );
        }
    };

    let acs_url = fx
        .acs_url_override
        .map(str::to_owned)
        .or_else(|| meta.destination.clone())
        .unwrap_or_else(|| "https://sp.example.com/acs".to_string());

    let audience = fx
        .sp_entity_id_override
        .map(str::to_owned)
        .or_else(|| meta.audience.clone())
        .unwrap_or_else(|| "https://sp.example.com/metadata".to_string());

    let policy = match fx.crypto_profile {
        CryptoProfile::Strong => PeerCryptoPolicy::strong_defaults(),
        CryptoProfile::Legacy => {
            #[cfg(feature = "weak-algos")]
            {
                permissive_policy()
            }
            #[cfg(not(feature = "weak-algos"))]
            {
                return Err(format!(
                    "fixture {} requires the weak-algos feature",
                    fx.path
                ));
            }
        }
    };

    let idp = IdpDescriptor {
        entity_id: meta.issuer.clone(),
        sso_endpoints: vec![Endpoint::post("https://example.invalid/sso", 0, true)],
        slo_endpoints: vec![],
        artifact_resolution_endpoints: vec![],
        signing_certs: vec![idp_cert],
        encryption_certs: vec![],
        supported_name_id_formats: vec![NameIdFormat::Persistent, NameIdFormat::EmailAddress],
        want_authn_requests_signed: false,
        valid_until: None,
        cache_duration: None,
    };

    // Optional SP decryption key. Only meaningful with the xmlenc feature
    // on. The no-xmlenc branch still reads the field so the "unused field"
    // lint stays quiet without us reaching for #[allow(dead_code)].
    #[cfg(feature = "xmlenc")]
    let decryption_key = match fx.sp_decryption_key_pkcs1_pem_path {
        Some(rel) => {
            let pem =
                std::fs::read(corpus_path(rel)).map_err(|e| format!("read sp key {rel}: {e}"))?;
            Some(KeyPair::from_pkcs1_pem(&pem).map_err(|e| format!("sp key PKCS#1 {rel}: {e:?}"))?)
        }
        None => None,
    };
    #[cfg(not(feature = "xmlenc"))]
    let decryption_key: Option<saml::crypto::keypair::KeyPair> = {
        let _ = fx.sp_decryption_key_pkcs1_pem_path;
        None
    };

    let sp_cfg = ServiceProviderConfig {
        entity_id: audience,
        acs: vec![SsoResponseEndpoint::post(acs_url.as_str(), 0, true)],
        slo: vec![],
        name_id_formats: vec![NameIdFormat::Persistent, NameIdFormat::EmailAddress],
        signing_key: None,
        decryption_key,
        sign_authn_requests: false,
        want_signed: SpWantSigned {
            response: false,
            assertions: matches!(fx.assertion_signature, AssertionSignature::Required),
        },
        // Captured fixtures generally lack their original AuthnRequest state.
        allow_unsolicited: true,
        #[cfg(feature = "slo")]
        logout_signing: saml::SpLogoutSigning::default(),
        #[cfg(feature = "slo")]
        logout_want_signed: saml::SpLogoutWantSigned::default(),
        default_peer_crypto_policy: policy,
        outbound_signature_algorithm: SignatureAlgorithm::RsaSha256,
        outbound_digest_algorithm: DigestAlgorithm::Sha256,
    };
    let sp = ServiceProvider::new(sp_cfg).map_err(|e| format!("sp build: {e:?}"))?;

    // Pin `now` to the captured IssueInstant + 1 second so freshness checks
    // see a "just-issued" assertion regardless of when the test runs.
    let now = meta
        .issue_instant
        .checked_add(Duration::from_secs(fx.now_offset_secs))
        .ok_or_else(|| "issue_instant + fixture offset overflowed SystemTime".to_string())?;

    let tracker_owned = meta
        .in_response_to
        .as_deref()
        .map(|in_response_to| LoginTracker {
            request_id: in_response_to.to_owned(),
            issued_at: meta.issue_instant,
            idp_entity_id: meta.issuer.clone(),
            acs_endpoint: SsoResponseEndpoint::post(acs_url.as_str(), 0, true),
            requested_authn_context: None,
            requested_name_id_format: None,
        });

    sp.consume_response(ConsumeResponse {
        idp: &idp,
        peer_crypto_policy: None,
        saml_response: &xml,
        binding: SsoResponseBinding::HttpPost,
        relay_state: None,
        tracker: tracker_owned.as_ref(),
        expected_destination: acs_url.as_str(),
        now,
        clock_skew: Duration::from_mins(30),
        replay_cache: None,
        replay_mode: ReplayMode::All,
        holder_of_key_cert: None,
    })
    .map_err(|e| format!("consume_response: {e:?}"))
}

// =============================================================================
// One #[test] per fixture so individual failures show up clearly in output.
// =============================================================================

macro_rules! corpus_test {
    ($name:ident, $idx:expr) => {
        #[test]
        fn $name() {
            let fx = &FIXTURES[$idx];
            let result = run_fixture(fx);
            match (fx.expected, result) {
                (Expected::Ok, Ok(_)) => {}
                (Expected::Reject, Err(e)) => {
                    assert!(
                        e.starts_with("consume_response: "),
                        "[{}] rejection was only a runner/setup failure: {e}\n  fixture: {}",
                        fx.label,
                        fx.path,
                    );
                    assert!(
                        !e.contains("DisallowedAlgorithm"),
                        "[{}] rejection stopped at an algorithm-policy gate; \
                         this does not exercise the attack defense: {e}\n  fixture: {}",
                        fx.label,
                        fx.path,
                    );
                }
                (Expected::UnsupportedFixture(reason), Err(e)) if e.contains(reason) => {}
                (Expected::UnsupportedFixture(reason), Err(e)) => panic!(
                    "[{}] unsupported-fixture preflight changed; expected an error containing \
                     {reason:?}, got: {e}\n  fixture: {}",
                    fx.label, fx.path,
                ),
                (Expected::Ok, Err(e)) => panic!(
                    "[{}] expected Ok, got Err: {e}\n  fixture: {}",
                    fx.label, fx.path
                ),
                (Expected::Reject, Ok(_)) => panic!(
                    "[{}] expected Reject, got Ok — SECURITY ISSUE if the \
                     fixture is an XSW / XXE / expired / audience-mismatch \
                     case\n  fixture: {}",
                    fx.label, fx.path
                ),
                (Expected::UnsupportedFixture(reason), Ok(_)) => panic!(
                    "[{}] fixture previously marked unsupported ({reason}) is now runnable; \
                     promote it to a real positive/negative corpus case\n  fixture: {}",
                    fx.label, fx.path,
                ),
            }
        }
    };
}

corpus_test!(c01_adfs_sha256, 0);
corpus_test!(c02_adfs_sha384, 1);
corpus_test!(c03_adfs_sha512, 2);
#[cfg(feature = "weak-algos")]
corpus_test!(c04_adfs_sha1, 3);
#[cfg(feature = "weak-algos")]
corpus_test!(c05_xsw_wrapped, 4);
#[cfg(feature = "weak-algos")]
corpus_test!(c06_xsw_assertion_wrapped, 5);
#[cfg(feature = "weak-algos")]
corpus_test!(c07_node_text_attack_1, 6);
#[cfg(feature = "weak-algos")]
corpus_test!(c08_node_text_attack_2, 7);
#[cfg(feature = "weak-algos")]
corpus_test!(c09_node_text_attack_3, 8);
#[test]
fn c10_xxe() {
    // The XXE fixture is deliberately not a SAML Response, so metadata cannot
    // be extracted from it. Supply trusted peers out-of-band and send the raw
    // document through consume_response; a runner preflight error would not
    // demonstrate that the XML/SAML parser itself rejected the DOCTYPE.
    let xml = std::fs::read(corpus_path("ruby-saml/responses/attackxee.xml"))
        .expect("read ruby-saml XXE fixture");
    let base_sp = common::make_sp(
        "https://sp.example.com/xxe-corpus",
        "https://sp.example.com/xxe-corpus/acs",
        false,
    )
    .expect("build SP");
    let mut sp_config = base_sp.config().clone();
    sp_config.allow_unsolicited = true;
    let sp = ServiceProvider::new(sp_config).expect("rebuild unsolicited SP");
    let idp_role = common::make_idp(
        "https://idp.example.com/xxe-corpus",
        "https://idp.example.com/xxe-corpus/sso",
    )
    .expect("build IdP");
    let idp = common::idp_descriptor(&idp_role).expect("build IdP descriptor");
    let now = common::fixed_now().expect("fixed timestamp");

    let result = sp.consume_response(ConsumeResponse {
        idp: &idp,
        peer_crypto_policy: None,
        saml_response: &xml,
        binding: SsoResponseBinding::HttpPost,
        relay_state: None,
        tracker: None,
        expected_destination: "https://sp.example.com/xxe-corpus/acs",
        now,
        clock_skew: Duration::from_mins(2),
        replay_cache: None,
        replay_mode: ReplayMode::All,
        holder_of_key_cert: None,
    });

    match result {
        Err(Error::XmlParse(_) | Error::SchemaViolation { .. }) => {}
        other => panic!("expected XML/schema rejection for XXE fixture, got {other:?}"),
    }
}
#[cfg(feature = "weak-algos")]
corpus_test!(c11_no_signature_ns, 10);
#[cfg(feature = "weak-algos")]
corpus_test!(c12_unsigned, 11);
#[cfg(feature = "weak-algos")]
corpus_test!(c13_expired, 12);
#[cfg(feature = "weak-algos")]
corpus_test!(c14_no_audience, 13);
#[cfg(feature = "weak-algos")]
corpus_test!(c15_double_signed, 14);
#[cfg(feature = "weak-algos")]
corpus_test!(c16_signed_message_response, 15);
#[cfg(feature = "weak-algos")]
corpus_test!(c17_signed_assertion_response, 16);
// Two xmlenc-gated entries (py3 encrypted-assertion negatives — saml
// correctly rejects spec-violating Recipient/Issuer shapes).
#[cfg(all(feature = "weak-algos", feature = "xmlenc"))]
corpus_test!(c18_py3_encrypted_missing_recipient, 17);
#[cfg(all(feature = "weak-algos", feature = "xmlenc"))]
corpus_test!(c19_py3_encrypted_issuer_mismatch, 18);
// Index arithmetic shifts when xmlenc is off, so compute the base.
const POST_ENC: usize = if cfg!(feature = "xmlenc") { 19 } else { 17 };
#[cfg(feature = "weak-algos")]
corpus_test!(c21_ds_namespace_at_root, POST_ENC);
#[cfg(feature = "weak-algos")]
corpus_test!(c22_signed_assertion_2, POST_ENC + 1);
#[cfg(feature = "weak-algos")]
corpus_test!(c24_no_signature_explicit, POST_ENC + 2);
#[cfg(feature = "weak-algos")]
corpus_test!(c25_multiple_assertions, POST_ENC + 3);
#[cfg(feature = "weak-algos")]
corpus_test!(c26_empty_destination, POST_ENC + 4);
#[cfg(feature = "weak-algos")]
corpus_test!(c27_ruby_multiple_signed, POST_ENC + 5);
#[cfg(feature = "weak-algos")]
corpus_test!(c28_ruby_invalid_signed_element, POST_ENC + 6);
#[cfg(feature = "weak-algos")]
corpus_test!(c29_ruby_concealed_signed_assertion, POST_ENC + 7);
#[cfg(feature = "weak-algos")]
corpus_test!(c30_ruby_doubled_signed_assertion, POST_ENC + 8);
#[cfg(feature = "weak-algos")]
corpus_test!(c31_py3_sig_wrap_attack, POST_ENC + 9);
#[cfg(feature = "weak-algos")]
corpus_test!(c32_py3_sig_wrap_attack2, POST_ENC + 10);
#[cfg(feature = "weak-algos")]
corpus_test!(c33_py3_bad_reference, POST_ENC + 11);
#[cfg(feature = "weak-algos")]
corpus_test!(
    c34_xsw_pattern_5_assertion_in_signature_object,
    POST_ENC + 12
);
#[cfg(feature = "weak-algos")]
corpus_test!(c35_xsw_pattern_6_substituted_subject, POST_ENC + 13);
#[cfg(feature = "weak-algos")]
corpus_test!(c36_xsw_pattern_8_namespace_injection, POST_ENC + 14);
corpus_test!(c20_adfs_response_xmlns, POST_ENC + 15);

// Diagnostic helper: prints the actual rejection reason for each synthetic
// XSW pattern fixture. `#[ignore]`d so it doesn't run in the default test
// suite; invoke with
//     cargo test --test corpus_runner xsw_pattern_rejection_reasons --
//         --ignored --nocapture
// to see which validator path catches each attack.
#[test]
#[cfg(feature = "weak-algos")]
#[ignore = "diagnostic-only: prints rejection reasons for synthetic XSW patterns; invoke with --ignored --nocapture"]
fn xsw_pattern_rejection_reasons() {
    for fx in FIXTURES {
        if !fx.label.starts_with("xsw_pattern_") {
            continue;
        }
        let outcome = run_fixture(fx);
        println!("[{}] outcome: {:?}", fx.label, outcome);
    }
}

// =============================================================================
// KeyInfo trust negative test
// =============================================================================

/// Build the same SP/IdP setup as `run_fixture`, but explicitly REPLACE the
/// `signing_certs` on the IdP with a different (ruby-saml test) cert. The
/// attacker's response is the ADFS SHA-256 capture, signed by the ADFS
/// production cert embedded in its <ds:KeyInfo>. saml MUST reject — the
/// embedded cert is not trust-anchored, the only trust anchor is the
/// ruby-saml cert which obviously did not sign this response.
///
/// If this test PASSES, saml is correctly trust-anchoring on
/// `IdpDescriptor::signing_certs` and ignoring <ds:KeyInfo>. If it FAILS
/// (i.e. consume_response returns Ok or the wrong Err), that's CVE-class:
/// an attacker who can mint *any* SAML response and embed *their own* cert
/// in <ds:KeyInfo> can impersonate the IdP. The expected Err is
/// `SignatureVerification { .. }` (key mismatch / signature mismatch /
/// cert mismatch — anything in that family is acceptable). Anything else
/// — `Ok`, `XmlParse`, `IssuerMismatch`, etc. — fails the test loudly.
#[test]
fn attacker_keyinfo_cert_rejected_when_idp_trusts_different_cert() {
    // Reuse the c01_adfs_sha256 fixture's wire bytes — a real, verified
    // ADFS Response with its own cert embedded.
    let abs_path = corpus_path("ruby-saml/responses/adfs_response_sha256.xml");
    let xml = std::fs::read(&abs_path).unwrap_or_else(|e| panic!("read {abs_path}: {e}"));

    // Extract the wire metadata so we use the right Audience / Destination
    // / IssueInstant — the only thing we DO NOT take from the wire is the
    // signing cert.
    let meta = extract(&xml).unwrap_or_else(|e| panic!("extract: {e}"));

    // Trust anchor: ruby-saml's own self-signed cert, which obviously did
    // NOT sign the ADFS capture.
    let attacker_cert_pem = std::fs::read(corpus_path("ruby-saml/certificates/ruby-saml.crt"))
        .unwrap_or_else(|e| panic!("read ruby-saml.crt: {e}"));
    let trusted_cert = X509Certificate::from_pem(&attacker_cert_pem)
        .unwrap_or_else(|e| panic!("parse ruby-saml.crt: {e:?}"));

    // Sanity: the trusted cert must NOT equal the wire cert. If somehow
    // they did, the test would be a tautology.
    let wire_cert = meta
        .cert
        .as_ref()
        .unwrap_or_else(|| panic!("ADFS fixture is supposed to embed a cert"));
    assert!(
        wire_cert.to_der() != trusted_cert.to_der(),
        "test pre-condition broken: trusted cert equals wire cert"
    );

    let acs_url = meta
        .destination
        .clone()
        .unwrap_or_else(|| "https://sp.example.com/acs".to_string());
    let audience = meta
        .audience
        .clone()
        .unwrap_or_else(|| "https://sp.example.com/metadata".to_string());

    let idp = IdpDescriptor {
        entity_id: meta.issuer.clone(),
        sso_endpoints: vec![Endpoint::post("https://example.invalid/sso", 0, true)],
        slo_endpoints: vec![],
        artifact_resolution_endpoints: vec![],
        // The whole point of this test: trust ONLY the unrelated cert.
        signing_certs: vec![trusted_cert],
        encryption_certs: vec![],
        supported_name_id_formats: vec![NameIdFormat::Persistent, NameIdFormat::EmailAddress],
        want_authn_requests_signed: false,
        valid_until: None,
        cache_duration: None,
    };

    let sp_cfg = ServiceProviderConfig {
        entity_id: audience,
        acs: vec![SsoResponseEndpoint::post(acs_url.as_str(), 0, true)],
        slo: vec![],
        name_id_formats: vec![NameIdFormat::Persistent, NameIdFormat::EmailAddress],
        signing_key: None,
        decryption_key: None,
        sign_authn_requests: false,
        want_signed: SpWantSigned {
            response: false,
            assertions: false,
        },
        allow_unsolicited: true,
        #[cfg(feature = "slo")]
        logout_signing: saml::SpLogoutSigning::default(),
        #[cfg(feature = "slo")]
        logout_want_signed: saml::SpLogoutWantSigned::default(),
        default_peer_crypto_policy: PeerCryptoPolicy::strong_defaults(),
        outbound_signature_algorithm: SignatureAlgorithm::RsaSha256,
        outbound_digest_algorithm: DigestAlgorithm::Sha256,
    };
    let sp = ServiceProvider::new(sp_cfg).unwrap_or_else(|e| panic!("sp build: {e:?}"));

    let now = meta
        .issue_instant
        .checked_add(Duration::from_secs(1))
        .unwrap_or_else(|| panic!("issue_instant + 1s overflowed SystemTime"));

    // The ADFS fixture carries an InResponseTo; without a matching tracker
    // the response is rejected as `UnsolicitedNotAllowed` BEFORE the
    // signature check ever runs, which would let an attacker hide behind
    // the wrong error. Build a matching tracker so the signature check
    // *is* the gating condition.
    let tracker_owned = meta
        .in_response_to
        .as_deref()
        .map(|in_response_to| LoginTracker {
            request_id: in_response_to.to_owned(),
            issued_at: meta.issue_instant,
            idp_entity_id: meta.issuer.clone(),
            acs_endpoint: SsoResponseEndpoint::post(acs_url.as_str(), 0, true),
            requested_authn_context: None,
            requested_name_id_format: None,
        });

    let result = sp.consume_response(ConsumeResponse {
        idp: &idp,
        peer_crypto_policy: None,
        saml_response: &xml,
        binding: SsoResponseBinding::HttpPost,
        relay_state: None,
        tracker: tracker_owned.as_ref(),
        expected_destination: acs_url.as_str(),
        now,
        clock_skew: Duration::from_mins(30),
        replay_cache: None,
        replay_mode: ReplayMode::All,
        holder_of_key_cert: None,
    });

    match result {
        Ok(_) => panic!(
            "CVE: SP accepted a Response signed by a cert NOT in \
             IdpDescriptor.signing_certs. The KeyInfo cert was trusted \
             implicitly, defeating the trust anchor."
        ),
        Err(
            Error::SignatureVerification { .. }
            | Error::NoPeerSigningCert
            | Error::DisallowedAlgorithm { .. },
        ) => {
            // Expected: trust-anchor mismatch surfaced as a signature /
            // peer-cert error.
        }
        Err(other) => panic!(
            "expected SignatureVerification / NoPeerSigningCert / \
             DisallowedAlgorithm, got: {other:?}"
        ),
    }
}
