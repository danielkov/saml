//! Private-key material for signing AuthnRequests, Responses, Assertions, and
//! for decrypting `<xenc:EncryptedKey>` payloads.
//!
//! `KeyPair` is an enum over the algorithm families we support — RSA, ECDSA
//! P-256, ECDSA P-384. The private-key material is held in
//! `ZeroizeOnDrop`-derived inner types so dropping the `KeyPair` reliably
//! wipes secret bytes (within the limits Rust gives us — see the `zeroize`
//! crate's caveats about copies in moves).
//!
//! Constructors are intentionally narrow: PKCS#8 PEM (the canonical form for
//! v0.1, used by every RFC-003/004 example), PKCS#1 PEM (for legacy RSA
//! deployments), and PKCS#8 DER. There is no `from_components` API — callers
//! cannot construct a key from raw modulus/exponent integers, both because
//! the underlying crates' APIs gate that behind hazmat-style entry points and
//! because the surface should remain narrow.
//!
//! Algorithm/key-family matching (RFC-002 §5): RSA-SHA256/384/512 require an
//! RSA key; ECDSA-SHA256 requires a P-256 key; ECDSA-SHA384 requires a P-384
//! key; mismatches return `Error::DisallowedAlgorithm`. We deliberately do not
//! attempt to be clever about off-curve pairings (e.g. P-256 with SHA-512)
//! — SAML deployments in the wild stick to matched pairings, and accepting
//! mismatches would invite test-coverage gaps.

use pkcs8::DecodePrivateKey;
use rsa::RsaPrivateKey;
use sha2::{Sha256, Sha384, Sha512};
use std::str;
use zeroize::ZeroizeOnDrop;

use crate::crypto::cert::{PublicKey, PublicKeyAlgorithm, X509Certificate};
use crate::dsig::algorithms::SignatureAlgorithm;
use crate::error::Error;

/// OAEP digest options for `KeyPair::decrypt_rsa_oaep`. SHA-256 is the
/// modern default; SHA-1 is included for legacy `xmlenc11#rsa-oaep` with
/// MGF1-SHA1 (the digest itself is SHA-1 in the historical `xmlenc#rsa-1_5`
/// counterpart, which we don't support — but for OAEP, the digest and MGF
/// digests are conceptually separate; see RFC-002 §5).
#[cfg(feature = "xmlenc")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OaepDigest {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

/// A keypair bound to one of the supported asymmetric algorithm families.
///
/// The private-key material is wrapped so it is zeroized on drop. The optional
/// `cert` field holds the matching X.509 certificate; this is needed for
/// outbound signing flows that embed `<ds:X509Certificate>` in `<ds:KeyInfo>`
/// (RFC-002 §6).
#[derive(Clone)]
pub struct KeyPair {
    inner: KeyPairInner,
    cert: Option<X509Certificate>,
    // Cached public-key view so callers don't pay re-parsing cost.
    public_key: PublicKey,
}

#[derive(Clone)]
enum KeyPairInner {
    Rsa(RsaSecret),
    EcdsaP256(P256Secret),
    EcdsaP384(P384Secret),
}

/// RSA private key + a cached `RsaPublicKey` derived from it. Wrapped in a
/// `ZeroizeOnDrop`-derived struct so the secret state is wiped on drop. The
/// `rsa` crate's `RsaPrivateKey` itself zeroizes on drop, but holding it in
/// our own `ZeroizeOnDrop` wrapper documents the intent at the struct level
/// and gives us a single place to layer further zeroizing fields if we add
/// caches later.
#[derive(Clone, ZeroizeOnDrop)]
struct RsaSecret {
    key: RsaPrivateKey,
}

#[derive(Clone, ZeroizeOnDrop)]
struct P256Secret {
    key: p256::ecdsa::SigningKey,
}

#[derive(Clone, ZeroizeOnDrop)]
struct P384Secret {
    key: p384::ecdsa::SigningKey,
}

impl KeyPair {
    /// Parse a PKCS#8-PEM private key. The PEM label dispatches on the key
    /// material — RSA PRIVATE KEY headers route to `from_pkcs1_pem`; PRIVATE
    /// KEY (i.e. PKCS#8) is decoded here, with the inner algorithm OID picking
    /// the variant.
    pub fn from_pkcs8_pem(pem: &[u8]) -> Result<Self, Error> {
        let pem_str = str::from_utf8(pem).map_err(|_e| Error::InvalidConfiguration {
            reason: "private key PEM is not valid UTF-8",
        })?;
        // We try each algorithm in order. PKCS#8's PrivateKeyInfo encodes the
        // algorithm OID inside, but each crate's `from_pkcs8_pem` validates
        // that the OID matches before deserializing — so trying them in
        // sequence is correct and converges to one variant.
        if let Ok(key) = RsaPrivateKey::from_pkcs8_pem(pem_str) {
            return Self::from_rsa_private_key(key);
        }
        if let Ok(key) = p256::ecdsa::SigningKey::from_pkcs8_pem(pem_str) {
            return Self::from_p256_signing_key(key);
        }
        if let Ok(key) = p384::ecdsa::SigningKey::from_pkcs8_pem(pem_str) {
            return Self::from_p384_signing_key(key);
        }
        Err(Error::InvalidConfiguration {
            reason: "unrecognized PKCS#8 private key (not RSA / P-256 / P-384)",
        })
    }

    /// Parse a PKCS#1-PEM RSA private key (the legacy `RSA PRIVATE KEY`
    /// armor). PKCS#1 only encodes RSA — there is no EC equivalent — so this
    /// constructor is RSA-only by definition.
    pub fn from_pkcs1_pem(pem: &[u8]) -> Result<Self, Error> {
        use rsa::pkcs1::DecodeRsaPrivateKey as _;
        let pem_str = str::from_utf8(pem).map_err(|_e| Error::InvalidConfiguration {
            reason: "private key PEM is not valid UTF-8",
        })?;
        let key = RsaPrivateKey::from_pkcs1_pem(pem_str).map_err(|_e| {
            Error::InvalidConfiguration {
                reason: "PKCS#1 PEM parse failed",
            }
        })?;
        Self::from_rsa_private_key(key)
    }

    /// Parse a PKCS#8-DER private key (binary form of `from_pkcs8_pem`).
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, Error> {
        if let Ok(key) = RsaPrivateKey::from_pkcs8_der(der) {
            return Self::from_rsa_private_key(key);
        }
        if let Ok(key) = p256::ecdsa::SigningKey::from_pkcs8_der(der) {
            return Self::from_p256_signing_key(key);
        }
        if let Ok(key) = p384::ecdsa::SigningKey::from_pkcs8_der(der) {
            return Self::from_p384_signing_key(key);
        }
        Err(Error::InvalidConfiguration {
            reason: "unrecognized PKCS#8 DER private key",
        })
    }

    fn from_rsa_private_key(key: RsaPrivateKey) -> Result<Self, Error> {
        // Derive the public-key view via the canonical SPKI round-trip. This
        // keeps `PublicKey` construction in one place (cert.rs) and avoids
        // duplicating OID-handling logic here.
        use rsa::pkcs8::EncodePublicKey as _;
        let pub_der = key
            .to_public_key()
            .to_public_key_der()
            .map_err(|_e| Error::InvalidConfiguration {
                reason: "failed to derive public key from RSA private key",
            })?;
        let public_key = PublicKey::from_spki_der(pub_der.as_bytes())?;
        Ok(Self {
            inner: KeyPairInner::Rsa(RsaSecret { key }),
            cert: None,
            public_key,
        })
    }

    fn from_p256_signing_key(key: p256::ecdsa::SigningKey) -> Result<Self, Error> {
        use p256::pkcs8::EncodePublicKey as _;
        let vk = key.verifying_key();
        let pub_der =
            vk.to_public_key_der()
                .map_err(|_e| Error::InvalidConfiguration {
                    reason: "failed to derive P-256 public key",
                })?;
        let public_key = PublicKey::from_spki_der(pub_der.as_bytes())?;
        Ok(Self {
            inner: KeyPairInner::EcdsaP256(P256Secret { key }),
            cert: None,
            public_key,
        })
    }

    fn from_p384_signing_key(key: p384::ecdsa::SigningKey) -> Result<Self, Error> {
        use p384::pkcs8::EncodePublicKey as _;
        let vk = key.verifying_key();
        let pub_der =
            vk.to_public_key_der()
                .map_err(|_e| Error::InvalidConfiguration {
                    reason: "failed to derive P-384 public key",
                })?;
        let public_key = PublicKey::from_spki_der(pub_der.as_bytes())?;
        Ok(Self {
            inner: KeyPairInner::EcdsaP384(P384Secret { key }),
            cert: None,
            public_key,
        })
    }

    /// Attach a certificate to this keypair (consuming builder form). The cert
    /// is what `<ds:KeyInfo>/<ds:X509Data>` emits when outbound signing is
    /// configured to publish the signer's certificate. The library does NOT
    /// verify that the certificate's public key matches the private key —
    /// callers who care can compare `cert.public_key()` against
    /// `keypair.public_key()` themselves; v0.1's posture is that configuration
    /// is the caller's responsibility.
    pub fn with_certificate(mut self, cert: X509Certificate) -> Self {
        self.cert = Some(cert);
        self
    }

    /// Borrow the attached certificate, if any.
    pub fn certificate(&self) -> Option<&X509Certificate> {
        self.cert.as_ref()
    }

    /// Public-key view of this keypair. Useful for callers who want to embed
    /// only the public key (not the cert) somewhere, or to compare against
    /// metadata-derived keys.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Algorithm family of the underlying key material.
    pub fn algorithm_family(&self) -> PublicKeyAlgorithm {
        self.public_key.algorithm_family()
    }

    /// Sign `signed_bytes` (typically the canonical-form `<ds:SignedInfo>`)
    /// under `algorithm`. The XML-DSig spec mandates RSASSA-PKCS#1 v1.5 for
    /// RSA signing — RSA-PSS is not part of v0.1. For ECDSA, the output is the
    /// IEEE P1363 fixed-length `r || s` encoding (which XML-DSig consumes
    /// directly; the wire format is base64 of these raw bytes).
    pub fn sign(
        &self,
        algorithm: SignatureAlgorithm,
        signed_bytes: &[u8],
    ) -> Result<Vec<u8>, Error> {
        match (&self.inner, algorithm) {
            (KeyPairInner::Rsa(secret), SignatureAlgorithm::RsaSha256) => {
                sign_rsa::<Sha256>(&secret.key, signed_bytes)
            }
            (KeyPairInner::Rsa(secret), SignatureAlgorithm::RsaSha384) => {
                sign_rsa::<Sha384>(&secret.key, signed_bytes)
            }
            (KeyPairInner::Rsa(secret), SignatureAlgorithm::RsaSha512) => {
                sign_rsa::<Sha512>(&secret.key, signed_bytes)
            }
            #[cfg(feature = "weak-algos")]
            (KeyPairInner::Rsa(secret), SignatureAlgorithm::RsaSha1) => {
                sign_rsa::<sha1::Sha1>(&secret.key, signed_bytes)
            }
            (KeyPairInner::EcdsaP256(secret), SignatureAlgorithm::EcdsaSha256) => {
                use signature::Signer as _;
                let sig: p256::ecdsa::Signature =
                    secret.key.try_sign(signed_bytes).map_err(|_e| {
                        Error::SignatureVerification {
                            reason: "ecdsa-p256 sign failed",
                        }
                    })?;
                Ok(sig.to_bytes().to_vec())
            }
            (KeyPairInner::EcdsaP384(secret), SignatureAlgorithm::EcdsaSha384) => {
                use signature::Signer as _;
                let sig: p384::ecdsa::Signature =
                    secret.key.try_sign(signed_bytes).map_err(|_e| {
                        Error::SignatureVerification {
                            reason: "ecdsa-p384 sign failed",
                        }
                    })?;
                Ok(sig.to_bytes().to_vec())
            }
            _ => Err(Error::DisallowedAlgorithm {
                alg: format!(
                    "{:?} does not match key family {:?}",
                    algorithm,
                    self.algorithm_family()
                ),
            }),
        }
    }

    /// RSA-OAEP key transport unwrap, used by `<xenc:EncryptedKey>` with
    /// `KeyTransportAlgorithm::RsaOaep` or `RsaOaepMgf1Sha1`. The
    /// `oaep_digest` selects the OAEP hash function and the MGF1 hash; for
    /// `RsaOaepMgf1Sha1` callers should pass `OaepDigest::Sha1` even though
    /// the OAEP digest itself is SHA-256 in the spec's modern profile —
    /// see the XML-Enc 1.1 documentation. For v0.1 we pin the OAEP and MGF1
    /// digests to the same function (which matches the common-case profile
    /// every interop fixture we have uses); callers needing the MGF1-SHA1
    /// asymmetric profile use a future API.
    #[cfg(feature = "xmlenc")]
    pub fn decrypt_rsa_oaep(
        &self,
        ciphertext: &[u8],
        oaep_digest: OaepDigest,
    ) -> Result<Vec<u8>, Error> {
        let KeyPairInner::Rsa(secret) = &self.inner else {
            return Err(Error::DecryptFailed {
                reason: "key transport",
            });
        };
        let padding = match oaep_digest {
            OaepDigest::Sha1 => {
                #[cfg(feature = "weak-algos")]
                {
                    rsa::Oaep::new::<sha1::Sha1>()
                }
                #[cfg(not(feature = "weak-algos"))]
                {
                    return Err(Error::DisallowedAlgorithm {
                        alg: "RSA-OAEP-SHA1 requires the weak-algos feature".into(),
                    });
                }
            }
            OaepDigest::Sha256 => rsa::Oaep::new::<Sha256>(),
            OaepDigest::Sha384 => rsa::Oaep::new::<Sha384>(),
            OaepDigest::Sha512 => rsa::Oaep::new::<Sha512>(),
        };
        secret
            .key
            .decrypt(padding, ciphertext)
            .map_err(|_e| Error::DecryptFailed {
                reason: "key transport",
            })
    }

    /// RSA-PKCS1-v1.5 key transport unwrap. Used only for legacy interop with
    /// IdPs that still send `<xenc:EncryptionMethod
    /// Algorithm=".../rsa-1_5">` payloads. Every internal failure mode
    /// (padding error, length error, downstream RSA error) is folded into a
    /// single `Error::DecryptFailed { reason: "key transport" }` so the
    /// returned error does not leak chosen-ciphertext-distinguishable
    /// information to the attacker. See RFC-002 §7.3.
    ///
    /// Bleichenbacher hardening at the boundary relies on the `rsa` crate's
    /// `Pkcs1v15Encrypt` decrypter, which is documented to perform constant-
    /// time padding validation. The shape of this method (no separate
    /// "padding error" return, no early returns based on internal state) keeps
    /// callers from accidentally surfacing a side-channel.
    #[cfg(all(feature = "xmlenc", feature = "weak-algos"))]
    pub fn decrypt_rsa_pkcs1v15(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let KeyPairInner::Rsa(secret) = &self.inner else {
            return Err(Error::DecryptFailed {
                reason: "key transport",
            });
        };
        secret
            .key
            .decrypt(rsa::Pkcs1v15Encrypt, ciphertext)
            .map_err(|_e| Error::DecryptFailed {
                reason: "key transport",
            })
    }
}

fn sign_rsa<D>(key: &RsaPrivateKey, signed_bytes: &[u8]) -> Result<Vec<u8>, Error>
where
    D: digest::Digest + const_oid::AssociatedOid,
{
    use signature::SignatureEncoding as _;
    use signature::Signer as _;
    let signer = rsa::pkcs1v15::SigningKey::<D>::new(key.clone());
    let sig: rsa::pkcs1v15::Signature =
        signer
            .try_sign(signed_bytes)
            .map_err(|_e| Error::SignatureVerification {
                reason: "rsa sign failed",
            })?;
    Ok(sig.to_bytes().into_vec())
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material — even in Debug output. RFC-001 §2 calls
        // out that the library should not silently weaken security defaults;
        // accidental Debug-logging of a `KeyPair` should not leak modulus
        // bytes or curve points.
        f.debug_struct("KeyPair")
            .field("algorithm_family", &self.algorithm_family())
            .field("has_certificate", &self.cert.is_some())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::cert::test_vectors::*;

    #[test]
    fn rsa_pkcs8_pem_parses() {
        let kp = KeyPair::from_pkcs8_pem(RSA_KEY_PKCS8_PEM).expect("parse RSA PKCS#8");
        assert_eq!(kp.algorithm_family(), PublicKeyAlgorithm::Rsa);
    }

    #[test]
    fn ec_p256_pkcs8_pem_parses() {
        let kp = KeyPair::from_pkcs8_pem(EC_P256_KEY_PKCS8_PEM).expect("parse P-256 PKCS#8");
        assert_eq!(kp.algorithm_family(), PublicKeyAlgorithm::EcdsaP256);
    }

    #[test]
    fn with_certificate_attaches_cert() {
        let kp = KeyPair::from_pkcs8_pem(RSA_KEY_PKCS8_PEM).unwrap();
        let cert = X509Certificate::from_pem(RSA_CERT_PEM).unwrap();
        let kp_with_cert = kp.with_certificate(cert.clone());
        assert_eq!(kp_with_cert.certificate(), Some(&cert));
    }

    #[test]
    fn rsa_sign_verify_round_trip_sha256() {
        let kp = KeyPair::from_pkcs8_pem(RSA_KEY_PKCS8_PEM).unwrap();
        let cert = X509Certificate::from_pem(RSA_CERT_PEM).unwrap();
        let payload = b"<ds:SignedInfo>placeholder canonical bytes</ds:SignedInfo>";
        let sig = kp
            .sign(SignatureAlgorithm::RsaSha256, payload)
            .expect("sign");
        cert.public_key()
            .verify_signature(SignatureAlgorithm::RsaSha256, payload, &sig)
            .expect("verify");
    }

    #[test]
    fn rsa_sign_verify_round_trip_sha512() {
        let kp = KeyPair::from_pkcs8_pem(RSA_KEY_PKCS8_PEM).unwrap();
        let cert = X509Certificate::from_pem(RSA_CERT_PEM).unwrap();
        let payload = b"some other payload";
        let sig = kp
            .sign(SignatureAlgorithm::RsaSha512, payload)
            .expect("sign");
        cert.public_key()
            .verify_signature(SignatureAlgorithm::RsaSha512, payload, &sig)
            .expect("verify");
    }

    #[test]
    fn ecdsa_p256_sign_verify_round_trip() {
        let kp = KeyPair::from_pkcs8_pem(EC_P256_KEY_PKCS8_PEM).unwrap();
        let cert = X509Certificate::from_pem(EC_P256_CERT_PEM).unwrap();
        let payload = b"ecdsa payload";
        let sig = kp
            .sign(SignatureAlgorithm::EcdsaSha256, payload)
            .expect("sign");
        // Output should be the IEEE P1363 form: 64 bytes for P-256.
        assert_eq!(sig.len(), 64);
        cert.public_key()
            .verify_signature(SignatureAlgorithm::EcdsaSha256, payload, &sig)
            .expect("verify");
    }

    #[test]
    fn sign_rejects_algorithm_mismatched_with_key_family() {
        let kp = KeyPair::from_pkcs8_pem(EC_P256_KEY_PKCS8_PEM).unwrap();
        let err = kp
            .sign(SignatureAlgorithm::RsaSha256, b"x")
            .expect_err("should reject RSA algorithm with EC key");
        assert!(matches!(err, Error::DisallowedAlgorithm { .. }));
    }

    #[test]
    fn sign_rejects_p256_with_ecdsa_sha384() {
        let kp = KeyPair::from_pkcs8_pem(EC_P256_KEY_PKCS8_PEM).unwrap();
        let err = kp
            .sign(SignatureAlgorithm::EcdsaSha384, b"x")
            .expect_err("P-256 with SHA-384 is not a supported pairing");
        assert!(matches!(err, Error::DisallowedAlgorithm { .. }));
    }

    #[test]
    fn bad_pem_returns_invalid_config_error() {
        let err =
            KeyPair::from_pkcs8_pem(b"not a pem at all").expect_err("should reject garbage");
        assert!(matches!(err, Error::InvalidConfiguration { .. }));
    }
}
