//! X.509 certificate wrapper and public key abstraction.
//!
//! `X509Certificate` wraps an `x509_cert::Certificate` along with the raw DER
//! bytes that produced it. The raw DER is retained so we can:
//!
//!   * Emit `<ds:X509Certificate>` payloads bit-for-bit (re-encoding through
//!     `x509-cert` would round-trip lossily for malformed-but-tolerable inputs
//!     the wider ecosystem ships).
//!   * Compute a stable SHA-256 fingerprint that matches what `openssl x509
//!     -fingerprint -sha256 -noout` would print.
//!   * Compare certificates for equality by their canonical DER form rather
//!     than by parsed-structure equality (which would diverge for any
//!     non-canonical-but-valid encoding).
//!
//! See `docs/rfcs/RFC-002-xml-crypto-core.md` §3 for how `PublicKey` is used by
//! the signature-verification path. The `verify_signature` helper here is the
//! single entry point that `crate::crypto::verifier::DefaultVerifier` uses; it
//! enforces algorithm/key-family matching and accepts both IEEE P1363 (raw
//! `r || s`) and ASN.1 DER ECDSA signatures, since SAML implementations in the
//! wild use both.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use sha2::{Digest as _, Sha256, Sha384, Sha512};
use std::fmt;
use std::time::SystemTime;

use const_oid::db::rfc5912::{ID_EC_PUBLIC_KEY, RSA_ENCRYPTION, SECP_256_R_1, SECP_384_R_1};
use rsa::RsaPublicKey;
use rsa::pkcs1v15::VerifyingKey as RsaPkcs1v15VerifyingKey;
use signature::Verifier as _;
use spki::SubjectPublicKeyInfoRef;
use x509_cert::Certificate;
use x509_cert::der::{Decode as _, DecodePem, Encode as _};

use crate::dsig::algorithms::SignatureAlgorithm;
use crate::error::Error;

/// A parsed X.509 v3 certificate.
///
/// Equality is defined on the canonical DER bytes — two `X509Certificate`s are
/// equal iff their `to_der()` output is byte-equal. This is what callers care
/// about for cert-pinning and for matching `<ds:X509Certificate>` payloads
/// against trusted metadata.
#[derive(Clone)]
pub struct X509Certificate {
    /// Parsed structure, used for accessor methods.
    inner: Certificate,
    /// Canonical DER bytes. Retained verbatim from the input so equality and
    /// fingerprinting are stable across parse-and-re-emit round trips.
    der: Vec<u8>,
    /// Lazily-computed cached public key (parsing the SPKI bit-string is
    /// non-trivial; the cache makes `public_key()` essentially free).
    public_key: PublicKey,
    /// Cached RFC 4514 subject DN string.
    subject_str: String,
    /// Cached RFC 4514 issuer DN string.
    issuer_str: String,
    /// SHA-256 fingerprint of the DER, cached so per-request signature
    /// verification doesn't re-hash the cert on every call.
    fingerprint: [u8; 32],
}

impl fmt::Debug for X509Certificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("X509Certificate")
            .field("subject", &self.subject_str)
            .field("issuer", &self.issuer_str)
            .field("der_len", &self.der.len())
            .finish()
    }
}

impl PartialEq for X509Certificate {
    fn eq(&self, other: &Self) -> bool {
        self.der == other.der
    }
}

impl Eq for X509Certificate {}

impl X509Certificate {
    /// Parse from a PEM-armored X.509 certificate (one `-----BEGIN
    /// CERTIFICATE-----` block).
    pub fn from_pem(pem: &[u8]) -> Result<Self, Error> {
        let cert = Certificate::from_pem(pem).map_err(|_| Error::X509Parse)?;
        let der = cert.to_der().map_err(|_| Error::X509Parse)?;
        Self::finalize(cert, der)
    }

    /// Parse from a DER-encoded X.509 certificate.
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let cert = Certificate::from_der(der).map_err(|_| Error::X509Parse)?;
        // Re-encode through x509-cert so the stored bytes are the canonical
        // form (this matters for equality and `<ds:X509Certificate>` emission).
        // For well-formed inputs this is a no-op; for inputs with non-canonical
        // encoding we normalize.
        let canonical = cert.to_der().map_err(|_| Error::X509Parse)?;
        Self::finalize(cert, canonical)
    }

    /// Parse from a base64-encoded DER blob — the form that appears inside
    /// `<ds:X509Certificate>` elements in `<ds:KeyInfo>`. Whitespace inside the
    /// blob (newlines, spaces) is tolerated, matching what XML serializers
    /// emit.
    pub fn from_base64_x509(b64: &str) -> Result<Self, Error> {
        let cleaned: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
        let der = BASE64_STANDARD
            .decode(cleaned.as_bytes())
            .map_err(|_| Error::Base64Decode)?;
        Self::from_der(&der)
    }

    fn finalize(cert: Certificate, der: Vec<u8>) -> Result<Self, Error> {
        let spki_der = cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|_| Error::X509Parse)?;
        let public_key = PublicKey::from_spki_der(&spki_der)?;
        let subject_str = cert.tbs_certificate.subject.to_string();
        let issuer_str = cert.tbs_certificate.issuer.to_string();
        let mut hasher = Sha256::new();
        hasher.update(&der);
        let fingerprint: [u8; 32] = hasher.finalize().into();
        Ok(Self {
            inner: cert,
            der,
            public_key,
            subject_str,
            issuer_str,
            fingerprint,
        })
    }

    /// Canonical DER encoding of the certificate.
    pub fn to_der(&self) -> &[u8] {
        &self.der
    }

    /// Base64-encoded DER, suitable for embedding directly inside
    /// `<ds:X509Certificate>`. No line breaks are inserted; the caller can wrap
    /// if desired.
    pub fn to_base64_x509(&self) -> String {
        BASE64_STANDARD.encode(&self.der)
    }

    /// SHA-256 fingerprint of the DER encoding. Matches `openssl x509
    /// -fingerprint -sha256 -noout`. Cached at parse time.
    pub fn fingerprint_sha256(&self) -> [u8; 32] {
        self.fingerprint
    }

    /// `notBefore` validity bound.
    pub fn not_before(&self) -> SystemTime {
        self.inner
            .tbs_certificate
            .validity
            .not_before
            .to_system_time()
    }

    /// `notAfter` validity bound.
    pub fn not_after(&self) -> SystemTime {
        self.inner
            .tbs_certificate
            .validity
            .not_after
            .to_system_time()
    }

    /// Subject distinguished name, RFC 4514 string form.
    pub fn subject(&self) -> &str {
        &self.subject_str
    }

    /// Issuer distinguished name, RFC 4514 string form.
    pub fn issuer(&self) -> &str {
        &self.issuer_str
    }

    /// Public key extracted from the certificate's `SubjectPublicKeyInfo`.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
}

/// Public-key algorithm family — used to police algorithm/key-family pairings
/// at sign-time and verify-time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicKeyAlgorithm {
    /// RSA (any key size).
    Rsa,
    /// ECDSA over NIST P-256 (secp256r1 / prime256v1).
    EcdsaP256,
    /// ECDSA over NIST P-384 (secp384r1).
    EcdsaP384,
}

/// Verification-side public key. Internally an enum over the supported
/// algorithm families. Construction goes through `from_spki_der` so the OIDs
/// in the SPKI header drive variant selection — there is no way to construct
/// a `PublicKey` whose algorithm tag disagrees with the underlying key
/// material.
#[derive(Clone, Debug)]
pub struct PublicKey {
    inner: PublicKeyInner,
}

#[derive(Clone, Debug)]
enum PublicKeyInner {
    Rsa(RsaPublicKey),
    EcdsaP256(p256::ecdsa::VerifyingKey),
    EcdsaP384(p384::ecdsa::VerifyingKey),
}

impl PublicKey {
    /// Decode a DER-encoded `SubjectPublicKeyInfo` and dispatch on the
    /// algorithm OID. Unrecognized OIDs map to `Error::X509Parse` so callers
    /// can treat the cert as untrusted rather than panic.
    pub fn from_spki_der(spki: &[u8]) -> Result<Self, Error> {
        let parsed = SubjectPublicKeyInfoRef::from_der(spki).map_err(|_| Error::X509Parse)?;
        let key_bytes = parsed
            .subject_public_key
            .as_bytes()
            .ok_or(Error::X509Parse)?;

        let oid = parsed.algorithm.oid;
        if oid == RSA_ENCRYPTION {
            // The subjectPublicKey BIT STRING for RSA contains a DER-encoded
            // RSAPublicKey (PKCS#1).
            let rsa = RsaPublicKey::from_pkcs1_der(key_bytes).map_err(|_| Error::X509Parse)?;
            Ok(Self {
                inner: PublicKeyInner::Rsa(rsa),
            })
        } else if oid == ID_EC_PUBLIC_KEY {
            // Algorithm parameters carry the curve OID for ECDSA keys; we use
            // it to pick between P-256 and P-384.
            let params = parsed.algorithm.parameters.ok_or(Error::X509Parse)?;
            let curve_oid = params
                .decode_as::<const_oid::ObjectIdentifier>()
                .map_err(|_| Error::X509Parse)?;
            if curve_oid == SECP_256_R_1 {
                let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(key_bytes)
                    .map_err(|_| Error::X509Parse)?;
                Ok(Self {
                    inner: PublicKeyInner::EcdsaP256(vk),
                })
            } else if curve_oid == SECP_384_R_1 {
                let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(key_bytes)
                    .map_err(|_| Error::X509Parse)?;
                Ok(Self {
                    inner: PublicKeyInner::EcdsaP384(vk),
                })
            } else {
                Err(Error::X509Parse)
            }
        } else {
            Err(Error::X509Parse)
        }
    }

    /// Algorithm family for this key, used by `KeyPair::sign` and the verifier
    /// to enforce algorithm/key-family pairings.
    pub fn algorithm_family(&self) -> PublicKeyAlgorithm {
        match &self.inner {
            PublicKeyInner::Rsa(_) => PublicKeyAlgorithm::Rsa,
            PublicKeyInner::EcdsaP256(_) => PublicKeyAlgorithm::EcdsaP256,
            PublicKeyInner::EcdsaP384(_) => PublicKeyAlgorithm::EcdsaP384,
        }
    }

    /// Verify a signature against `signed_bytes` using this public key under
    /// `algorithm`. Mismatched algorithm/key-family pairs return
    /// `Error::SignatureVerification { reason: "key/alg family mismatch" }`
    /// rather than attempting verification — this is the policy point for
    /// rejecting RSA signatures presented with an EC key, etc.
    ///
    /// For ECDSA, the signature is tried first as IEEE P1363 (raw `r || s`,
    /// the XML-DSig encoding) and then as ASN.1 DER (the format some legacy
    /// IdPs send). Most real-world SAML payloads use IEEE P1363.
    pub fn verify_signature(
        &self,
        algorithm: SignatureAlgorithm,
        signed_bytes: &[u8],
        signature_bytes: &[u8],
    ) -> Result<(), Error> {
        match (&self.inner, algorithm) {
            (PublicKeyInner::Rsa(rsa), SignatureAlgorithm::RsaSha256) => {
                let vk: RsaPkcs1v15VerifyingKey<Sha256> =
                    RsaPkcs1v15VerifyingKey::new(rsa.clone());
                let sig = rsa::pkcs1v15::Signature::try_from(signature_bytes)
                    .map_err(|_| Error::SignatureVerification {
                        reason: "signature parse failed",
                    })?;
                vk.verify(signed_bytes, &sig)
                    .map_err(|_| Error::SignatureVerification {
                        reason: "rsa-sha256 verify failed",
                    })
            }
            (PublicKeyInner::Rsa(rsa), SignatureAlgorithm::RsaSha384) => {
                let vk: RsaPkcs1v15VerifyingKey<Sha384> =
                    RsaPkcs1v15VerifyingKey::new(rsa.clone());
                let sig = rsa::pkcs1v15::Signature::try_from(signature_bytes)
                    .map_err(|_| Error::SignatureVerification {
                        reason: "signature parse failed",
                    })?;
                vk.verify(signed_bytes, &sig)
                    .map_err(|_| Error::SignatureVerification {
                        reason: "rsa-sha384 verify failed",
                    })
            }
            (PublicKeyInner::Rsa(rsa), SignatureAlgorithm::RsaSha512) => {
                let vk: RsaPkcs1v15VerifyingKey<Sha512> =
                    RsaPkcs1v15VerifyingKey::new(rsa.clone());
                let sig = rsa::pkcs1v15::Signature::try_from(signature_bytes)
                    .map_err(|_| Error::SignatureVerification {
                        reason: "signature parse failed",
                    })?;
                vk.verify(signed_bytes, &sig)
                    .map_err(|_| Error::SignatureVerification {
                        reason: "rsa-sha512 verify failed",
                    })
            }
            #[cfg(feature = "weak-algos")]
            (PublicKeyInner::Rsa(rsa), SignatureAlgorithm::RsaSha1) => {
                let vk: RsaPkcs1v15VerifyingKey<sha1::Sha1> =
                    RsaPkcs1v15VerifyingKey::new(rsa.clone());
                let sig = rsa::pkcs1v15::Signature::try_from(signature_bytes)
                    .map_err(|_| Error::SignatureVerification {
                        reason: "signature parse failed",
                    })?;
                vk.verify(signed_bytes, &sig)
                    .map_err(|_| Error::SignatureVerification {
                        reason: "rsa-sha1 verify failed",
                    })
            }
            (PublicKeyInner::EcdsaP256(vk), SignatureAlgorithm::EcdsaSha256) => {
                verify_ecdsa_p256(vk, signed_bytes, signature_bytes)
            }
            (PublicKeyInner::EcdsaP384(vk), SignatureAlgorithm::EcdsaSha384) => {
                verify_ecdsa_p384(vk, signed_bytes, signature_bytes)
            }
            // Off-curve / off-digest pairings — refuse rather than guess.
            // SAML's profile recommends matched curve/digest pairings (P-256
            // with SHA-256, P-384 with SHA-384); any other combination here
            // is a configuration error.
            _ => Err(Error::SignatureVerification {
                reason: "key/alg family mismatch",
            }),
        }
    }
}

/// Try IEEE P1363 first (the XML-DSig wire format), fall back to ASN.1 DER for
/// legacy IdPs that emit DER.
fn verify_ecdsa_p256(
    vk: &p256::ecdsa::VerifyingKey,
    signed_bytes: &[u8],
    signature_bytes: &[u8],
) -> Result<(), Error> {
    if let Ok(sig) = p256::ecdsa::Signature::from_slice(signature_bytes) {
        if vk.verify(signed_bytes, &sig).is_ok() {
            return Ok(());
        }
    }
    if let Ok(sig) = p256::ecdsa::DerSignature::try_from(signature_bytes) {
        if vk.verify(signed_bytes, &sig).is_ok() {
            return Ok(());
        }
    }
    Err(Error::SignatureVerification {
        reason: "ecdsa-p256 verify failed",
    })
}

fn verify_ecdsa_p384(
    vk: &p384::ecdsa::VerifyingKey,
    signed_bytes: &[u8],
    signature_bytes: &[u8],
) -> Result<(), Error> {
    if let Ok(sig) = p384::ecdsa::Signature::from_slice(signature_bytes) {
        if vk.verify(signed_bytes, &sig).is_ok() {
            return Ok(());
        }
    }
    if let Ok(sig) = p384::ecdsa::DerSignature::try_from(signature_bytes) {
        if vk.verify(signed_bytes, &sig).is_ok() {
            return Ok(());
        }
    }
    Err(Error::SignatureVerification {
        reason: "ecdsa-p384 verify failed",
    })
}

// `rsa::pkcs1::DecodeRsaPublicKey` provides `RsaPublicKey::from_pkcs1_der`
// via a blanket impl over `TryFrom<SubjectPublicKeyInfoRef>`; the trait must
// be in scope at the call site.
use rsa::pkcs1::DecodeRsaPublicKey as _;

#[cfg(test)]
pub(crate) mod test_vectors {
    //! Static keypair + cert vectors shared across crypto-module tests. These
    //! were generated once with OpenSSL and pinned here — using static
    //! vectors keeps unit-test runtime sub-millisecond and lets the verify-
    //! roundtrip tests pin against known-good byte-for-byte encodings.

    /// Self-signed RSA-2048 certificate, CN=saml-test, valid 100 years.
    pub const RSA_CERT_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----
MIIDCzCCAfOgAwIBAgIUMOn0qquTgAJJwHbKm2N1V464CDIwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJc2FtbC10ZXN0MCAXDTI2MDUyNjIxMzcwMVoYDzIxMjYw
NTAyMjEzNzAxWjAUMRIwEAYDVQQDDAlzYW1sLXRlc3QwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDaqL2wBXPWOtBqKErO58ddEa8L9r7OlI1Gh+SseXo1
ZYYH/cISplLMqch8SWk0rH4Aeg1/dcGYATVHYisToko785FphNiAVN3Mz4sL99lU
G7kogP88Beoe0N0s5o8Q53OXD2mHiLwkds0SoH5p8ghlM+Spw1gSq70+MJGKnaBS
O1XocupxARVb1MYhGnDDbJYAip2P2/eg0M7TPi4Kwe6yRndRbcTzKltTOECKaUBU
RbdE6fkwegMNOZ7vivQYsNUkrrgDYjEIKh8bmSsI61vNNhYJpdgja0UHnfguKinX
vF0GlFdtAWn9N8i+d7BfHyaj4TWjqRL8xM5ThM7Cts7BAgMBAAGjUzBRMB0GA1Ud
DgQWBBSyw8b031HFXwOSpE0SzavfT1RHxjAfBgNVHSMEGDAWgBSyw8b031HFXwOS
pE0SzavfT1RHxjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQDG
Tn/w5sMK7ceNJa1jAwJKdhumlwknBP3ifozKX3ikmdU+yAs4W1iiGXtaZaL9tv6/
Pg9YXJBJaEO5tyH/xwEjH7+QDqrCIZ77ljZk0Qf0Rl3jdUnnR6TGF4+ToKtN+uG0
gZwXRBtjo+B/hL5mxP72/AHqvowVGblTzuefruuEUs/2bOD11XjW7wKl7kzYLZ65
kj8IXjzTetBlAqqhmQrEmIwVAtcURS+lfLvl7QZVvRwuKadvIa63kJSybV51oahN
08amDJRd0NXHBYHpPlCCUwujcTw2aBGzRgR+Pkx/kJSTOcx4+QZiYBB3BCvYhzg5
UkTEs4+5J1kgDIklDumS
-----END CERTIFICATE-----
";

    /// PKCS#8 PEM of the RSA-2048 private key matching `RSA_CERT_PEM`.
    pub const RSA_KEY_PKCS8_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDaqL2wBXPWOtBq
KErO58ddEa8L9r7OlI1Gh+SseXo1ZYYH/cISplLMqch8SWk0rH4Aeg1/dcGYATVH
YisToko785FphNiAVN3Mz4sL99lUG7kogP88Beoe0N0s5o8Q53OXD2mHiLwkds0S
oH5p8ghlM+Spw1gSq70+MJGKnaBSO1XocupxARVb1MYhGnDDbJYAip2P2/eg0M7T
Pi4Kwe6yRndRbcTzKltTOECKaUBURbdE6fkwegMNOZ7vivQYsNUkrrgDYjEIKh8b
mSsI61vNNhYJpdgja0UHnfguKinXvF0GlFdtAWn9N8i+d7BfHyaj4TWjqRL8xM5T
hM7Cts7BAgMBAAECggEABncvn7czjwm/bKorFx3lqF/73PbTesyL9mJRjdOMPGy3
d0BGxzIll+Fr2Rf7HUh989HoGQUgf7gGbSlPFIYrm4T232fDFp1bzyDyb7zJD3p/
4b2Zvnq+yuE6bwfUwmdTpMt6/3vYs1vTccnu3v9eBe8QQ4BQGAI9xutc/Fwvl8rV
FZ+/Ze07Mbbxk9f+PROFI/xCopwup1/rMBuN5CEgaL1uZmZPl9snVADjMkn2TluV
XeS01xq7ahpJxjr/tIl5XgFC/214DpLLUxgxGPvKnvPOaUsSwnWZ0S2Se8VJsa7p
i/jM4R/VXa5j52kIDOf8gojg+7BxoRxCqxTzSJl9CQKBgQD/cO2rbHA/bj81xebh
Th5DzJHFdDQJEjPqg8E2jBKrUKli0LsH0WmtNozVjv2RrB4VU5dJmGINJu26i5p/
rbkhtoCfZqoCyWnz1pbHPHoe2OSQhIUv2Srd/VhbvqNTjAMdebnFH+s/ewrxlh9S
kpY8leANhIRJfYzkHylkHocNSQKBgQDbIzYMFd7oywEj3IE+LCLQXHEbwxrPfR23
rC0gfR0RseupxNosMTnHNRjF7bXg+qKO6AQ8MZaYgfyUjELDgpLrKhBOc84HgAvD
HuUz3xVlWIdOQS3LcReHjN7tyFjR+SUYywuRiPNskyZOfWlt8LnvjPy2Xx/bcHht
Vooqe2WNuQKBgBUmEmdo+PondJBNLEpnH1ZZr4/7iPtfSHEYK30Kp9kLOpr10SZa
jjdLFunvhsryxyLY4uOy/Bs+p9wUBtyfU36ZD5ki9Nx6NI19rMoeFbZMGtBkSGqn
vkbW3OPrqrYWF4PvOhQ6Ck4dL9DErx81B79IYV59JD65aFrSwaiKZoARAoGBANmE
DfXZD7ZLKwqJqdAoxzXDTJKeC1LBgmn6gaCqD9ysmpudRmJvSkauMbTly49RuWHY
c7u8DRu8ixZ4Uxz10xeSXTVCRdO0CfjYBfKDER3TzhqjH+28h/qIng+wullR0LzX
btg69EVlmrR2T9xNAoMBkycDLQAIl8EQEX0xlxAhAoGAWNKS/mkM7OTHp1sOzcZ+
3qNoH4s30zdYQAmSwdgZDe+LcCnvZn8IsxsR5aaJYbYFeziAeB+PVMfTdcW89/Qn
72b0KDgBZ9FpLMzYg86nuAZ0moDgg2hY49e+XD6VYVwiPWO5VL4CE+HGyfOsqgDx
K0dYsJzrrDnL23ajO1yzAak=
-----END PRIVATE KEY-----
";

    /// Self-signed ECDSA P-256 certificate, CN=saml-test-ec, valid 100 years.
    pub const EC_P256_CERT_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----
MIIBhjCCASugAwIBAgIUIDhNfIfD7gTLTdXhq71tw1iIC2wwCgYIKoZIzj0EAwIw
FzEVMBMGA1UEAwwMc2FtbC10ZXN0LWVjMCAXDTI2MDUyNjIxMzcxMVoYDzIxMjYw
NTAyMjEzNzExWjAXMRUwEwYDVQQDDAxzYW1sLXRlc3QtZWMwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAARl8G1SFcBNyne+bxbDAHOuyiRiYdmCoJBlImmQ+Vf3hGBk
BvyNQIF5OoHbcETByogPCvWTjBUQuHrS1g2EXM4Qo1MwUTAdBgNVHQ4EFgQUUh6K
seL1Zs34SE5SafvFvgKkXEMwHwYDVR0jBBgwFoAUUh6KseL1Zs34SE5SafvFvgKk
XEMwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEAqxK80oF18HlP
D0Ktg2leCWXxqyiFHYPgG70UdnEUIlECIQCd69CawEFkvs1qPiOiLzEylM2xxbI4
huUfJDvixBaz3Q==
-----END CERTIFICATE-----
";

    /// PKCS#8 PEM of the P-256 key matching `EC_P256_CERT_PEM`.
    pub const EC_P256_KEY_PKCS8_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgbBkjNsQ2GLWGz+fW
Dx7548VOkgOrFib1T44u/3qAoLShRANCAARl8G1SFcBNyne+bxbDAHOuyiRiYdmC
oJBlImmQ+Vf3hGBkBvyNQIF5OoHbcETByogPCvWTjBUQuHrS1g2EXM4Q
-----END PRIVATE KEY-----
";
}

#[cfg(test)]
mod tests {
    use super::test_vectors::*;
    use super::*;

    #[test]
    fn rsa_cert_pem_parses() {
        let cert = X509Certificate::from_pem(RSA_CERT_PEM).expect("parse PEM");
        assert_eq!(cert.public_key().algorithm_family(), PublicKeyAlgorithm::Rsa);
        assert!(cert.subject().contains("saml-test"));
        assert!(cert.issuer().contains("saml-test"));
    }

    #[test]
    fn rsa_cert_der_round_trip() {
        let cert = X509Certificate::from_pem(RSA_CERT_PEM).unwrap();
        let der = cert.to_der().to_vec();
        let cert2 = X509Certificate::from_der(&der).unwrap();
        // Equality is by canonical DER bytes — round-tripping must preserve.
        assert_eq!(cert, cert2);
        assert_eq!(cert.fingerprint_sha256(), cert2.fingerprint_sha256());
    }

    #[test]
    fn rsa_cert_base64_round_trip() {
        let cert = X509Certificate::from_pem(RSA_CERT_PEM).unwrap();
        let b64 = cert.to_base64_x509();
        let cert2 = X509Certificate::from_base64_x509(&b64).expect("base64 round trip");
        assert_eq!(cert, cert2);
    }

    #[test]
    fn rsa_cert_base64_tolerates_whitespace() {
        let cert = X509Certificate::from_pem(RSA_CERT_PEM).unwrap();
        let b64 = cert.to_base64_x509();
        // Insert newlines every 64 chars — many XML serializers do this.
        let wrapped: String = b64
            .as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        let cert2 = X509Certificate::from_base64_x509(&wrapped).expect("wrapped base64");
        assert_eq!(cert, cert2);
    }

    #[test]
    fn fingerprint_is_stable() {
        let cert1 = X509Certificate::from_pem(RSA_CERT_PEM).unwrap();
        let cert2 = X509Certificate::from_pem(RSA_CERT_PEM).unwrap();
        assert_eq!(cert1.fingerprint_sha256(), cert2.fingerprint_sha256());

        let mut hasher = Sha256::new();
        hasher.update(cert1.to_der());
        let direct: [u8; 32] = hasher.finalize().into();
        assert_eq!(cert1.fingerprint_sha256(), direct);
    }

    #[test]
    fn ec_p256_cert_pem_parses() {
        let cert = X509Certificate::from_pem(EC_P256_CERT_PEM).expect("parse EC PEM");
        assert_eq!(
            cert.public_key().algorithm_family(),
            PublicKeyAlgorithm::EcdsaP256
        );
    }

    #[test]
    fn validity_bounds_are_populated() {
        let cert = X509Certificate::from_pem(RSA_CERT_PEM).unwrap();
        // The test cert validity spans 100 years; not_before precedes not_after.
        assert!(cert.not_before() < cert.not_after());
    }

    #[test]
    fn malformed_input_is_rejected() {
        let r = X509Certificate::from_der(b"not actually a certificate");
        assert!(matches!(r, Err(Error::X509Parse)));
        let r = X509Certificate::from_base64_x509("not!base64!");
        assert!(matches!(r, Err(Error::Base64Decode)));
    }
}
