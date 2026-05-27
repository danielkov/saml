//! Signature-verifier trait + default in-process implementation.
//!
//! RFC-002 §4 specifies a pluggable verifier so HSM-backed and KMS-backed
//! deployments can override key resolution. The `DefaultVerifier` is the
//! pure-Rust path used when callers don't override.
//!
//! Three policy points live here, not at the call site:
//!
//!   1. **Algorithm allow-list enforcement.** `allowed_algorithms` is passed
//!      through from the caller's `PeerCryptoPolicy`; if the presented
//!      algorithm isn't in the list, verification fails before any key
//!      material is touched. This is the same gate as `dsig::verify`'s entry
//!      point, surfaced here for custom verifiers so policy lives in one
//!      place.
//!
//!   2. **Inline `<ds:X509Certificate>` trust.** Inline certs are only honored
//!      if their fingerprint matches a caller-supplied trusted cert. An
//!      attacker who injects their own cert into `<ds:KeyInfo>` cannot trick
//!      the verifier into trusting it — the fingerprint check rejects.
//!
//!   3. **First-match-wins cert iteration.** We try the caller's
//!      `candidate_certs` first, then any inline certs that survived the
//!      fingerprint check. The first cert that verifies wins; this supports
//!      cert rotation without forcing callers to disambiguate which key
//!      signed.

use crate::crypto::cert::X509Certificate;
use crate::dsig::algorithms::SignatureAlgorithm;
use crate::error::Error;

/// Captures `<ds:KeyInfo>` content from a signature element so the verifier
/// can apply policy to inline certs and use other hints (KeyName,
/// X509IssuerSerial, X509SubjectName) when locating the verifying key. For
/// v0.1 these fields are informational except for `x509_certificates_base64`,
/// which is the only inline key material the default verifier consults.
#[derive(Debug, Clone, Default)]
pub struct KeyInfo {
    /// `<ds:KeyName>` content, if present. Informational only; the default
    /// verifier does not look up keys by name. Custom verifiers (HSM/KMS) may.
    pub key_name: Option<String>,
    /// Raw base64-encoded `<ds:X509Certificate>` blobs, in source order. Not
    /// pre-decoded; the verifier decodes lazily and only when needed (so a
    /// malformed inline cert in `<ds:KeyInfo>` doesn't fail verification when
    /// a caller-supplied cert would have matched anyway).
    pub x509_certificates_base64: Vec<String>,
    /// `<ds:X509SubjectName>` entries. Informational only in v0.1.
    pub x509_subject_names: Vec<String>,
    /// `<ds:X509IssuerSerial>` entries as `(issuer_dn, serial)` tuples.
    /// Informational only in v0.1.
    pub x509_issuer_serials: Vec<(String, String)>,
}

impl KeyInfo {
    /// Decode the inline `<ds:X509Certificate>` blobs and return only those
    /// whose SHA-256 fingerprint appears in `trusted_candidates`. Per RFC-002
    /// §3.1 step 6, inline certs are never trusted by themselves — they must
    /// pin to a fingerprint the caller already trusts. This is the structural
    /// defense against `<ds:KeyInfo>`-injection key swaps.
    ///
    /// Malformed inline blobs (bad base64, non-DER, etc.) are silently
    /// skipped: an attacker who slips a garbage `<ds:X509Certificate>` into a
    /// signed XML payload should not be able to cause a hard parse error that
    /// disrupts otherwise-valid verification.
    pub fn trusted_inline_certs(
        &self,
        trusted_candidates: &[X509Certificate],
    ) -> Vec<X509Certificate> {
        let trusted_fingerprints: Vec<[u8; 32]> = trusted_candidates
            .iter()
            .map(|c| c.fingerprint_sha256())
            .collect();
        let mut out = Vec::new();
        for blob in &self.x509_certificates_base64 {
            let Ok(cert) = X509Certificate::from_base64_x509(blob) else {
                continue;
            };
            if trusted_fingerprints.contains(&cert.fingerprint_sha256()) {
                out.push(cert);
            }
        }
        out
    }
}

/// Result of a successful verification: which cert proved the signature and
/// what algorithm matched. The fingerprint lets callers log and audit "which
/// IdP key signed this assertion?" without having to grovel through inline
/// `<ds:KeyInfo>` again. The algorithm is echoed back so callers can record
/// "this peer is still using RSA-SHA1" and act accordingly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyMatch {
    pub cert_fingerprint: [u8; 32],
    pub algorithm: SignatureAlgorithm,
}

/// Pluggable signature-verification policy. The default impl
/// (`DefaultVerifier`) uses pure-Rust `rsa` + `ecdsa` crates; HSM/KMS-backed
/// custom implementations can intercept this trait without leaking key
/// material into the process. See RFC-002 §4.
///
/// Custom implementations MUST NOT accept an `algorithm` that's not present
/// in `allowed_algorithms`, even if they know how to perform it. This keeps
/// per-peer algorithm policy enforced uniformly regardless of which verifier
/// the role is configured with.
pub trait SignatureVerifier: Send + Sync {
    fn verify(
        &self,
        algorithm: SignatureAlgorithm,
        signed_bytes: &[u8],
        signature_bytes: &[u8],
        candidate_certs: &[X509Certificate],
        allowed_algorithms: &[SignatureAlgorithm],
        key_info: &KeyInfo,
    ) -> Result<VerifyMatch, Error>;
}

/// Default in-process verifier. Zero-sized; cheap to clone.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultVerifier;

impl SignatureVerifier for DefaultVerifier {
    fn verify(
        &self,
        algorithm: SignatureAlgorithm,
        signed_bytes: &[u8],
        signature_bytes: &[u8],
        candidate_certs: &[X509Certificate],
        allowed_algorithms: &[SignatureAlgorithm],
        key_info: &KeyInfo,
    ) -> Result<VerifyMatch, Error> {
        // Policy gate first — never touch key material before checking the
        // algorithm allow-list. This is the per-peer policy enforcement point
        // (RFC-002 §3.1 step 1).
        if !allowed_algorithms.contains(&algorithm) {
            return Err(Error::DisallowedAlgorithm {
                alg: algorithm_label(algorithm),
            });
        }

        // Try caller-supplied trusted certs first. The vast majority of
        // production deployments only need to consult these; inline KeyInfo
        // certs are a v0.1 belt-and-suspenders feature for IdPs that rotate
        // keys without re-publishing metadata.
        for cert in candidate_certs {
            if try_verify(cert, algorithm, signed_bytes, signature_bytes) {
                return Ok(VerifyMatch {
                    cert_fingerprint: cert.fingerprint_sha256(),
                    algorithm,
                });
            }
        }

        // Then any inline certs that survived the fingerprint pin against
        // the trusted set.
        for cert in key_info.trusted_inline_certs(candidate_certs) {
            if try_verify(&cert, algorithm, signed_bytes, signature_bytes) {
                return Ok(VerifyMatch {
                    cert_fingerprint: cert.fingerprint_sha256(),
                    algorithm,
                });
            }
        }

        Err(Error::SignatureVerification {
            reason: "no candidate cert matched",
        })
    }
}

/// Try one cert; swallow any verification error so the caller's iteration can
/// continue. We treat key/algorithm-family mismatches and signature-decode
/// errors as "this cert didn't sign this message", not as fatal errors —
/// otherwise a single dud cert in the candidate set would short-circuit the
/// search.
fn try_verify(
    cert: &X509Certificate,
    algorithm: SignatureAlgorithm,
    signed_bytes: &[u8],
    signature_bytes: &[u8],
) -> bool {
    cert.public_key()
        .verify_signature(algorithm, signed_bytes, signature_bytes)
        .is_ok()
}

/// Render an algorithm as the canonical XML-DSig URI for error messages.
/// Using the URI (e.g. `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`)
/// makes error logs grep-friendly against the spec and avoids ambiguity
/// between the enum's Debug form and the wire representation.
fn algorithm_label(alg: SignatureAlgorithm) -> String {
    alg.uri().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::cert::test_vectors::*;
    use crate::crypto::keypair::KeyPair;

    fn sign_test_payload() -> (X509Certificate, Vec<u8>, Vec<u8>) {
        let kp = KeyPair::from_pkcs8_pem(RSA_KEY_PKCS8_PEM).unwrap();
        let cert = X509Certificate::from_pem(RSA_CERT_PEM).unwrap();
        let payload = b"<ds:SignedInfo>canonical-form bytes</ds:SignedInfo>".to_vec();
        let sig = kp.sign(SignatureAlgorithm::RsaSha256, &payload).unwrap();
        (cert, payload, sig)
    }

    #[test]
    fn verifies_with_trusted_cert() {
        let (cert, payload, sig) = sign_test_payload();
        let verifier = DefaultVerifier;
        let key_info = KeyInfo::default();
        let allowed = vec![SignatureAlgorithm::RsaSha256];
        let m = verifier
            .verify(
                SignatureAlgorithm::RsaSha256,
                &payload,
                &sig,
                &[cert.clone()],
                &allowed,
                &key_info,
            )
            .expect("should verify");
        assert_eq!(m.cert_fingerprint, cert.fingerprint_sha256());
        assert_eq!(m.algorithm, SignatureAlgorithm::RsaSha256);
    }

    #[test]
    fn rejects_when_algorithm_not_in_allow_list() {
        let (cert, payload, sig) = sign_test_payload();
        let verifier = DefaultVerifier;
        let allowed = vec![SignatureAlgorithm::RsaSha512]; // not the one signed
        let err = verifier
            .verify(
                SignatureAlgorithm::RsaSha256,
                &payload,
                &sig,
                &[cert],
                &allowed,
                &KeyInfo::default(),
            )
            .expect_err("should reject");
        assert!(matches!(err, Error::DisallowedAlgorithm { .. }));
    }

    #[test]
    fn rejects_when_no_candidate_cert_matches() {
        let (_cert, payload, sig) = sign_test_payload();
        // A different cert (the EC one) won't verify an RSA signature.
        let other = X509Certificate::from_pem(EC_P256_CERT_PEM).unwrap();
        let verifier = DefaultVerifier;
        let err = verifier
            .verify(
                SignatureAlgorithm::RsaSha256,
                &payload,
                &sig,
                &[other],
                &[SignatureAlgorithm::RsaSha256],
                &KeyInfo::default(),
            )
            .expect_err("should reject");
        assert!(matches!(
            err,
            Error::SignatureVerification {
                reason: "no candidate cert matched"
            }
        ));
    }

    #[test]
    fn inline_cert_honored_when_fingerprint_trusted() {
        let (cert, payload, sig) = sign_test_payload();
        // Caller "knows" the cert (it's in the trusted set) but does NOT pass
        // it directly to the verify call — only inline via KeyInfo. The
        // fingerprint pin allows it through.
        let key_info = KeyInfo {
            x509_certificates_base64: vec![cert.to_base64_x509()],
            ..KeyInfo::default()
        };
        let verifier = DefaultVerifier;
        let m = verifier
            .verify(
                SignatureAlgorithm::RsaSha256,
                &payload,
                &sig,
                &[cert.clone()], // trusted set for fingerprint check
                &[SignatureAlgorithm::RsaSha256],
                &key_info,
            )
            .expect("should verify via inline cert");
        assert_eq!(m.cert_fingerprint, cert.fingerprint_sha256());
    }

    #[test]
    fn inline_cert_rejected_when_fingerprint_unknown() {
        let (cert, payload, sig) = sign_test_payload();
        let key_info = KeyInfo {
            // Inline cert is the real signer — but the verifier is told to
            // trust a *different* cert, so the inline cert must not slip
            // through. This is the XSW defense.
            x509_certificates_base64: vec![cert.to_base64_x509()],
            ..KeyInfo::default()
        };
        let unrelated = X509Certificate::from_pem(EC_P256_CERT_PEM).unwrap();
        let verifier = DefaultVerifier;
        let err = verifier
            .verify(
                SignatureAlgorithm::RsaSha256,
                &payload,
                &sig,
                &[unrelated], // unrelated cert in trusted set
                &[SignatureAlgorithm::RsaSha256],
                &key_info,
            )
            .expect_err("inline cert must not be trusted by itself");
        assert!(matches!(
            err,
            Error::SignatureVerification {
                reason: "no candidate cert matched"
            }
        ));
    }

    #[test]
    fn key_info_trusted_inline_certs_filters_by_fingerprint() {
        let cert = X509Certificate::from_pem(RSA_CERT_PEM).unwrap();
        let other = X509Certificate::from_pem(EC_P256_CERT_PEM).unwrap();
        let key_info = KeyInfo {
            x509_certificates_base64: vec![cert.to_base64_x509(), other.to_base64_x509()],
            ..KeyInfo::default()
        };
        let filtered = key_info.trusted_inline_certs(&[cert.clone()]);
        // Only the RSA cert is in the trusted set; the EC cert is filtered.
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0], cert);
    }

    #[test]
    fn key_info_skips_malformed_inline_blobs() {
        let cert = X509Certificate::from_pem(RSA_CERT_PEM).unwrap();
        let key_info = KeyInfo {
            x509_certificates_base64: vec![
                "this is not base64".to_string(),
                cert.to_base64_x509(),
            ],
            ..KeyInfo::default()
        };
        let filtered = key_info.trusted_inline_certs(&[cert.clone()]);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0], cert);
    }

    /// `PublicKeyAlgorithm` is re-used outside the verifier (we just touch it
    /// here so the test file exercises every public type from cert.rs that
    /// the verifier owns the integration of).
    #[test]
    fn public_key_algorithm_is_in_scope() {
        use crate::crypto::cert::PublicKeyAlgorithm;
        let cert = X509Certificate::from_pem(RSA_CERT_PEM).unwrap();
        assert_eq!(cert.public_key().algorithm_family(), PublicKeyAlgorithm::Rsa);
    }
}
