//! XML-Encryption decryption per W3C XML-Encryption (TR/2002/REC-xmlenc-core-).
//! See `docs/rfcs/RFC-002-xml-crypto-core.md` §7.
//!
//! The entry point [`decrypt_encrypted_assertion`] unwraps a
//! `<saml:EncryptedAssertion>` element into the cleartext `<saml:Assertion>`,
//! returning the freshly-parsed element root. Algorithm acceptance is gated
//! by caller-supplied allow-lists (sourced from the peer's
//! `PeerCryptoPolicy`); compile-time `weak-algos` only controls which
//! variants exist — never which are accepted at runtime.

use aes::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;

use crate::crypto::keypair::{KeyPair, OaepDigest};
use crate::error::Error;
use crate::xml::parse::{Document, Element};
use crate::xmlenc::algorithms::{DataEncryptionAlgorithm, KeyTransportAlgorithm};

// =============================================================================
// XML namespace URIs we look up by.
// =============================================================================

const XENC_NS: &str = "http://www.w3.org/2001/04/xmlenc#";
const DS_NS: &str = "http://www.w3.org/2000/09/xmldsig#";

// XML-Enc digest method URIs we recognize when reading the OAEP digest.
const SHA1_DIGEST_URI: &str = "http://www.w3.org/2000/09/xmldsig#sha1";
const SHA256_DIGEST_URI: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const SHA384_DIGEST_URI: &str = "http://www.w3.org/2001/04/xmldsig-more#sha384";
const SHA512_DIGEST_URI: &str = "http://www.w3.org/2001/04/xmlenc#sha512";

// =============================================================================
// Public entry point
// =============================================================================

/// Decrypt a `<saml:EncryptedAssertion>` (or any element that contains an
/// `<xenc:EncryptedData>` payload) and return the cleartext element. The
/// returned element is freshly parsed from the decrypted XML bytes.
///
/// The algorithm allow-lists are sourced from the peer's effective
/// `PeerCryptoPolicy`; calling this function with a permissive list defeats
/// the policy. Roles MUST thread their per-peer allow-lists through unchanged.
///
/// Decryption-key rotation: `decryption_keys` is tried in order; the first
/// key whose `RSA` key-transport unwrap succeeds wins. Failures from earlier
/// keys are discarded (Bleichenbacher-safe per `KeyPair::decrypt_rsa_pkcs1v15`).
pub(crate) fn decrypt_encrypted_assertion(
    encrypted_assertion: &Element,
    decryption_keys: &[&KeyPair],
    allowed_data_algorithms: &[DataEncryptionAlgorithm],
    allowed_key_transport_algorithms: &[KeyTransportAlgorithm],
) -> Result<Element, Error> {
    // -- 1. Locate <xenc:EncryptedData>. --
    let encrypted_data = encrypted_assertion
        .child_element(Some(XENC_NS), "EncryptedData")
        .ok_or(Error::DecryptFailed {
            reason: "missing EncryptedData",
        })?;

    // -- 2. Read the data-encryption algorithm and policy-check it. --
    let data_em = encrypted_data
        .child_element(Some(XENC_NS), "EncryptionMethod")
        .ok_or(Error::DecryptFailed {
            reason: "missing EncryptedData/EncryptionMethod",
        })?;
    let data_alg_uri =
        data_em
            .attribute(None, "Algorithm")
            .ok_or(Error::DecryptFailed {
                reason: "missing EncryptionMethod/@Algorithm",
            })?;
    let data_algorithm = DataEncryptionAlgorithm::from_uri(data_alg_uri)?;
    if !allowed_data_algorithms.contains(&data_algorithm) {
        return Err(Error::DisallowedAlgorithm {
            alg: data_alg_uri.to_owned(),
        });
    }

    // -- 3. Locate <ds:KeyInfo>/<xenc:EncryptedKey>. --
    let key_info = encrypted_data
        .child_element(Some(DS_NS), "KeyInfo")
        .ok_or(Error::DecryptFailed {
            reason: "missing KeyInfo",
        })?;
    let encrypted_key = key_info
        .child_element(Some(XENC_NS), "EncryptedKey")
        .ok_or(Error::DecryptFailed {
            reason: "missing EncryptedKey",
        })?;
    let key_em = encrypted_key
        .child_element(Some(XENC_NS), "EncryptionMethod")
        .ok_or(Error::DecryptFailed {
            reason: "missing EncryptedKey/EncryptionMethod",
        })?;
    let key_alg_uri = key_em.attribute(None, "Algorithm").ok_or(Error::DecryptFailed {
        reason: "missing EncryptedKey/EncryptionMethod/@Algorithm",
    })?;
    let key_transport_algorithm = KeyTransportAlgorithm::from_uri(key_alg_uri)?;
    if !allowed_key_transport_algorithms.contains(&key_transport_algorithm) {
        return Err(Error::DisallowedAlgorithm {
            alg: key_alg_uri.to_owned(),
        });
    }

    // -- 4. Choose the OAEP digest from <ds:DigestMethod> when applicable. --
    let oaep_digest = match key_transport_algorithm {
        KeyTransportAlgorithm::RsaOaep => oaep_digest_from_method(key_em)?,
        KeyTransportAlgorithm::RsaOaepMgf1Sha1 => OaepDigest::Sha1,
        #[cfg(feature = "weak-algos")]
        KeyTransportAlgorithm::RsaPkcs1V15 => OaepDigest::Sha1, // unused
    };

    // -- 5. Base64-decode the wrapped session key. --
    let wrapped_key_bytes = extract_cipher_value(encrypted_key)?;

    // -- 6. Try each decryption key; first success wins. --
    let session_key = unwrap_session_key(
        &wrapped_key_bytes,
        decryption_keys,
        key_transport_algorithm,
        oaep_digest,
    )?;

    // -- 7. Verify key length matches the data algorithm. --
    if session_key.len() != data_algorithm.key_size() {
        return Err(Error::DecryptFailed {
            reason: "key size mismatch",
        });
    }

    // -- 8. Base64-decode the payload ciphertext (iv/nonce || ct [|| tag]). --
    let ciphertext = extract_cipher_value(encrypted_data)?;

    // -- 9. Decrypt the payload. --
    let plaintext = decrypt_data(data_algorithm, &session_key, &ciphertext)?;

    // -- 10. Re-parse the decrypted XML and return the root element. --
    let doc = Document::parse(&plaintext)?;
    Ok(doc.root().clone())
}

// =============================================================================
// Internal helpers
// =============================================================================

/// Read the OAEP digest from `<EncryptionMethod>/<ds:DigestMethod>`. Per the
/// project hint, when the algorithm URI is the modern `xmlenc11#rsa-oaep`
/// and no `<ds:DigestMethod>` is present we default to SHA-256 (the modern
/// profile default). Legacy `rsa-oaep-mgf1p` would default to SHA-1 — but
/// that path doesn't call this function (it pins SHA-1 directly).
fn oaep_digest_from_method(encryption_method: &Element) -> Result<OaepDigest, Error> {
    let Some(digest_method) = encryption_method.child_element(Some(DS_NS), "DigestMethod") else {
        return Ok(OaepDigest::Sha256);
    };
    let uri = digest_method
        .attribute(None, "Algorithm")
        .ok_or(Error::DecryptFailed {
            reason: "missing DigestMethod/@Algorithm",
        })?;
    match uri {
        SHA1_DIGEST_URI => Ok(OaepDigest::Sha1),
        SHA256_DIGEST_URI => Ok(OaepDigest::Sha256),
        SHA384_DIGEST_URI => Ok(OaepDigest::Sha384),
        SHA512_DIGEST_URI => Ok(OaepDigest::Sha512),
        other => Err(Error::DisallowedAlgorithm {
            alg: other.to_owned(),
        }),
    }
}

/// Extract and base64-decode the text content of
/// `<.../xenc:CipherData/xenc:CipherValue>`.
fn extract_cipher_value(parent: &Element) -> Result<Vec<u8>, Error> {
    let cipher_data = parent
        .child_element(Some(XENC_NS), "CipherData")
        .ok_or(Error::DecryptFailed {
            reason: "missing CipherData",
        })?;
    let cipher_value =
        cipher_data
            .child_element(Some(XENC_NS), "CipherValue")
            .ok_or(Error::DecryptFailed {
                reason: "missing CipherValue",
            })?;
    decode_base64_ws_tolerant(&cipher_value.text_content())
}

/// Base64-decode, tolerating any internal whitespace. `<xenc:CipherValue>`
/// payloads are commonly line-wrapped by XML serializers.
fn decode_base64_ws_tolerant(text: &str) -> Result<Vec<u8>, Error> {
    let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    BASE64_STANDARD
        .decode(cleaned.as_bytes())
        // Discarded intentionally: the underlying base64 decode error message
        // would echo per-byte details. Surface the generic variant.
        .map_err(|_err| Error::Base64Decode)
}

/// Try each candidate `KeyPair` against the wrapped session key until one
/// succeeds. Per RFC-002 §7.3, all per-key failure modes collapse into a
/// single generic `Error::DecryptFailed { reason: "key transport" }` so that
/// the failure does not leak chosen-ciphertext-distinguishable information.
fn unwrap_session_key(
    wrapped: &[u8],
    keys: &[&KeyPair],
    algorithm: KeyTransportAlgorithm,
    oaep_digest: OaepDigest,
) -> Result<Vec<u8>, Error> {
    for key in keys {
        let attempt = match algorithm {
            KeyTransportAlgorithm::RsaOaep | KeyTransportAlgorithm::RsaOaepMgf1Sha1 => {
                key.decrypt_rsa_oaep(wrapped, oaep_digest)
            }
            #[cfg(feature = "weak-algos")]
            KeyTransportAlgorithm::RsaPkcs1V15 => key.decrypt_rsa_pkcs1v15(wrapped),
        };
        if let Ok(session_key) = attempt {
            return Ok(session_key);
        }
        // Discard the error; try the next key. Bleichenbacher safety: do not
        // surface the per-key failure reason — `decrypt_rsa_pkcs1v15` already
        // folds its internal padding/length errors into a single
        // `DecryptFailed { reason: "key transport" }`, and we do the same here
        // for OAEP. Surfacing per-key reasons would let an attacker tell
        // "this key didn't match" apart from "padding parse failed", which is
        // the exact side-channel we are eliminating.
    }
    Err(Error::DecryptFailed {
        reason: "key transport",
    })
}

/// Decrypt `ciphertext` (formatted as `iv/nonce || ct [|| tag]`) under
/// `session_key`. Failure surfaces as `Error::DecryptFailed { reason: "data" }`
/// regardless of where in the AEAD/CBC pipeline it occurred.
fn decrypt_data(
    algorithm: DataEncryptionAlgorithm,
    session_key: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    match algorithm {
        DataEncryptionAlgorithm::Aes128Cbc => decrypt_cbc::<aes::Aes128>(session_key, ciphertext),
        DataEncryptionAlgorithm::Aes256Cbc => decrypt_cbc::<aes::Aes256>(session_key, ciphertext),
        DataEncryptionAlgorithm::Aes128Gcm => decrypt_gcm::<Aes128Gcm>(session_key, ciphertext),
        DataEncryptionAlgorithm::Aes256Gcm => decrypt_gcm::<Aes256Gcm>(session_key, ciphertext),
    }
}

fn decrypt_cbc<C>(session_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error>
where
    C: aes::cipher::BlockCipher + aes::cipher::BlockDecrypt + aes::cipher::KeyInit,
{
    if ciphertext.len() < 16 {
        return Err(Error::DecryptFailed { reason: "data" });
    }
    let (iv, ct) = ciphertext.split_at(16);
    // Discarded intentionally: surfacing the cipher-init reason would leak
    // session-key shape; collapse into a generic mismatch error.
    let decryptor = cbc::Decryptor::<C>::new_from_slices(session_key, iv).map_err(|_err| {
        Error::DecryptFailed {
            reason: "key size mismatch",
        }
    })?;
    // Use the buffer-to-buffer form so we don't require `cipher/alloc` —
    // the destination buffer is sized to the ciphertext length (PKCS#7
    // padding can only shrink, never grow, the unpadded output).
    let mut out = vec![0u8; ct.len()];
    // Discarded intentionally: padding-failure detail is a known side-channel
    // (cf. Vaudenay padding-oracle attacks); collapse to a generic reason.
    let written = decryptor
        .decrypt_padded_b2b_mut::<Pkcs7>(ct, &mut out)
        .map_err(|_err| Error::DecryptFailed { reason: "data" })?
        .len();
    out.truncate(written);
    Ok(out)
}

fn decrypt_gcm<C>(session_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error>
where
    C: KeyInit + Aead,
{
    if ciphertext.len() < 12 + 16 {
        return Err(Error::DecryptFailed { reason: "data" });
    }
    let (nonce_bytes, ct_with_tag) = ciphertext.split_at(12);
    // Discarded intentionally: see the CBC path; key-init detail is omitted.
    let cipher = C::new_from_slice(session_key).map_err(|_err| Error::DecryptFailed {
        reason: "key size mismatch",
    })?;
    cipher
        .decrypt(
            aes_gcm::Nonce::from_slice(nonce_bytes),
            Payload {
                msg: ct_with_tag,
                aad: &[],
            },
        )
        // Discarded intentionally: AEAD tag-failure detail must not be
        // surfaced; collapse to a single generic reason.
        .map_err(|_err| Error::DecryptFailed { reason: "data" })
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::cert::X509Certificate;
    use crate::crypto::cert::test_vectors::{RSA_CERT_PEM, RSA_KEY_PKCS8_PEM};
    use crate::xml::emit::emit_element;
    use crate::xml::parse::{Document, Node, QName};
    use crate::xmlenc::encrypt::encrypt_assertion;

    const SAML_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";

    /// Build a small `<saml:Assertion>` carrying its own xmlns declaration so
    /// `emit_element` can serialize it standalone.
    fn sample_assertion() -> Element {
        let subject = Element::build(QName::new(Some(SAML_NS.to_owned()), "Subject"))
            .with_text("alice@example.org")
            .finish();
        Element::build(QName::new(Some(SAML_NS.to_owned()), "Assertion"))
            .with_namespace(Some("saml".to_owned()), SAML_NS)
            .with_attribute(QName::new(None, "ID"), "_a1")
            .with_child(Node::Element(subject))
            .finish()
    }

    fn rsa_keypair() -> KeyPair {
        KeyPair::from_pkcs8_pem(RSA_KEY_PKCS8_PEM).unwrap()
    }

    fn rsa_cert() -> X509Certificate {
        X509Certificate::from_pem(RSA_CERT_PEM).unwrap()
    }

    /// Helper: encrypt with `data`/`kt`, then decrypt with default allow-lists
    /// covering those two algorithms.
    fn roundtrip(
        data: DataEncryptionAlgorithm,
        kt: KeyTransportAlgorithm,
    ) -> Result<Element, Error> {
        let assertion = sample_assertion();
        let encrypted = encrypt_assertion(&assertion, &rsa_cert(), data, kt)?;
        let kp = rsa_keypair();
        decrypt_encrypted_assertion(&encrypted, &[&kp], &[data], &[kt])
    }

    #[test]
    fn round_trip_aes256_gcm_rsa_oaep_sha256() {
        let assertion = sample_assertion();
        let encrypted = encrypt_assertion(
            &assertion,
            &rsa_cert(),
            DataEncryptionAlgorithm::Aes256Gcm,
            KeyTransportAlgorithm::RsaOaep,
        )
        .expect("encrypt");
        let kp = rsa_keypair();
        let decrypted = decrypt_encrypted_assertion(
            &encrypted,
            &[&kp],
            &[DataEncryptionAlgorithm::Aes256Gcm],
            &[KeyTransportAlgorithm::RsaOaep],
        )
        .expect("decrypt");

        assert_eq!(decrypted.qname().local(), "Assertion");
        assert_eq!(decrypted.qname().namespace(), Some(SAML_NS));
        let subject = decrypted
            .child_element(Some(SAML_NS), "Subject")
            .expect("Subject");
        assert_eq!(subject.text_content(), "alice@example.org");
    }

    #[test]
    fn round_trip_aes128_gcm_rsa_oaep() {
        let decrypted = roundtrip(
            DataEncryptionAlgorithm::Aes128Gcm,
            KeyTransportAlgorithm::RsaOaep,
        )
        .expect("round-trip");
        assert_eq!(decrypted.qname().local(), "Assertion");
    }

    #[test]
    fn round_trip_aes256_cbc_rsa_oaep() {
        let decrypted = roundtrip(
            DataEncryptionAlgorithm::Aes256Cbc,
            KeyTransportAlgorithm::RsaOaep,
        )
        .expect("CBC round-trip");
        let subject = decrypted
            .child_element(Some(SAML_NS), "Subject")
            .expect("Subject");
        assert_eq!(subject.text_content(), "alice@example.org");
    }

    /// AES-128-CBC + RSA-OAEP-MGF1-SHA1 is the legacy combination. SHA-1 OAEP
    /// requires `weak-algos`; we only assert the round-trip when that's on.
    #[cfg(feature = "weak-algos")]
    #[test]
    fn round_trip_aes128_cbc_rsa_oaep_mgf1_sha1() {
        let decrypted = roundtrip(
            DataEncryptionAlgorithm::Aes128Cbc,
            KeyTransportAlgorithm::RsaOaepMgf1Sha1,
        )
        .expect("legacy round-trip");
        assert_eq!(decrypted.qname().local(), "Assertion");
    }

    #[test]
    fn disallowed_data_algorithm_rejected() {
        let assertion = sample_assertion();
        let encrypted = encrypt_assertion(
            &assertion,
            &rsa_cert(),
            DataEncryptionAlgorithm::Aes128Cbc,
            KeyTransportAlgorithm::RsaOaep,
        )
        .expect("encrypt");
        let kp = rsa_keypair();
        let err = decrypt_encrypted_assertion(
            &encrypted,
            &[&kp],
            // Only GCM is allowed.
            &[DataEncryptionAlgorithm::Aes256Gcm],
            &[KeyTransportAlgorithm::RsaOaep],
        )
        .expect_err("CBC not in allow-list");
        match err {
            Error::DisallowedAlgorithm { alg } => {
                assert_eq!(alg, DataEncryptionAlgorithm::Aes128Cbc.uri());
            }
            other => panic!("expected DisallowedAlgorithm, got {other:?}"),
        }
    }

    #[test]
    fn disallowed_key_transport_algorithm_rejected() {
        let assertion = sample_assertion();
        let encrypted = encrypt_assertion(
            &assertion,
            &rsa_cert(),
            DataEncryptionAlgorithm::Aes256Gcm,
            KeyTransportAlgorithm::RsaOaep,
        )
        .expect("encrypt");
        let kp = rsa_keypair();
        // Force an allow-list that *doesn't* include RsaOaep.
        let err = decrypt_encrypted_assertion(
            &encrypted,
            &[&kp],
            &[DataEncryptionAlgorithm::Aes256Gcm],
            &[KeyTransportAlgorithm::RsaOaepMgf1Sha1],
        )
        .expect_err("RsaOaep not in allow-list");
        match err {
            Error::DisallowedAlgorithm { alg } => {
                assert_eq!(alg, KeyTransportAlgorithm::RsaOaep.uri());
            }
            other => panic!("expected DisallowedAlgorithm, got {other:?}"),
        }
    }

    /// Forge an EncryptedAssertion whose data algorithm is GCM but whose
    /// wrapped session key is the wrong size for GCM. The decrypter must
    /// reject this *after* successfully unwrapping, with
    /// `DecryptFailed { reason: "key size mismatch" }`.
    #[test]
    fn key_size_mismatch_rejected() {
        // Build a GCM-128 ciphertext but advertise it as GCM-256.
        let assertion = sample_assertion();
        let mut encrypted = encrypt_assertion(
            &assertion,
            &rsa_cert(),
            DataEncryptionAlgorithm::Aes128Gcm,
            KeyTransportAlgorithm::RsaOaep,
        )
        .expect("encrypt 128");
        // Walk into the tree and change the data EncryptionMethod's Algorithm
        // attribute to advertise AES-256-GCM.
        let new_uri = DataEncryptionAlgorithm::Aes256Gcm.uri().to_owned();
        mutate_data_em_algorithm(&mut encrypted, new_uri);

        let kp = rsa_keypair();
        let err = decrypt_encrypted_assertion(
            &encrypted,
            &[&kp],
            &[
                DataEncryptionAlgorithm::Aes128Gcm,
                DataEncryptionAlgorithm::Aes256Gcm,
            ],
            &[KeyTransportAlgorithm::RsaOaep],
        )
        .expect_err("key size mismatch should be caught");
        match err {
            Error::DecryptFailed { reason } => assert_eq!(reason, "key size mismatch"),
            other => panic!("expected DecryptFailed, got {other:?}"),
        }
    }

    /// Tamper with the GCM auth tag (last 16 bytes of CipherValue) — decrypt
    /// must fail.
    #[test]
    fn gcm_tag_tamper_rejected() {
        let assertion = sample_assertion();
        let mut encrypted = encrypt_assertion(
            &assertion,
            &rsa_cert(),
            DataEncryptionAlgorithm::Aes256Gcm,
            KeyTransportAlgorithm::RsaOaep,
        )
        .expect("encrypt");
        // Flip a bit in the last byte of the payload CipherValue.
        flip_last_byte_in_data_cipher_value(&mut encrypted);

        let kp = rsa_keypair();
        let err = decrypt_encrypted_assertion(
            &encrypted,
            &[&kp],
            &[DataEncryptionAlgorithm::Aes256Gcm],
            &[KeyTransportAlgorithm::RsaOaep],
        )
        .expect_err("tag tamper");
        match err {
            Error::DecryptFailed { reason } => assert_eq!(reason, "data"),
            other => panic!("expected DecryptFailed, got {other:?}"),
        }
    }

    /// Tamper with a CBC payload byte — PKCS#7 unpad should fail (or decrypt
    /// to non-XML, which would also be rejected at re-parse). Either way the
    /// decrypter must not silently accept.
    #[test]
    fn cbc_payload_tamper_rejected() {
        let assertion = sample_assertion();
        let mut encrypted = encrypt_assertion(
            &assertion,
            &rsa_cert(),
            DataEncryptionAlgorithm::Aes256Cbc,
            KeyTransportAlgorithm::RsaOaep,
        )
        .expect("encrypt CBC");
        flip_last_byte_in_data_cipher_value(&mut encrypted);

        let kp = rsa_keypair();
        let err = decrypt_encrypted_assertion(
            &encrypted,
            &[&kp],
            &[DataEncryptionAlgorithm::Aes256Cbc],
            &[KeyTransportAlgorithm::RsaOaep],
        )
        .expect_err("CBC tamper");
        // Tampering with the *last* CBC block invalidates PKCS#7 padding,
        // which our decoder surfaces as DecryptFailed { reason: "data" }. If
        // the byte happens to fall on a non-padding region, the unpadded
        // plaintext may still be non-XML and surface as Error::XmlParse.
        match err {
            Error::DecryptFailed { reason } => assert_eq!(reason, "data"),
            Error::XmlParse(_) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    /// Key rotation: the first key in the slice doesn't match, the second
    /// does. Decrypt must succeed by trying both in order.
    #[test]
    fn rotation_first_key_fails_second_succeeds() {
        let assertion = sample_assertion();
        let encrypted = encrypt_assertion(
            &assertion,
            &rsa_cert(),
            DataEncryptionAlgorithm::Aes256Gcm,
            KeyTransportAlgorithm::RsaOaep,
        )
        .expect("encrypt");

        // First key: P-256 (will fail at the RSA-OAEP unwrap because it's not
        // an RSA key — KeyPair::decrypt_rsa_oaep returns DecryptFailed). The
        // second is the real RSA decryption key. Both must be tried.
        use crate::crypto::cert::test_vectors::EC_P256_KEY_PKCS8_PEM;
        let wrong = KeyPair::from_pkcs8_pem(EC_P256_KEY_PKCS8_PEM).unwrap();
        let right = rsa_keypair();
        let decrypted = decrypt_encrypted_assertion(
            &encrypted,
            &[&wrong, &right],
            &[DataEncryptionAlgorithm::Aes256Gcm],
            &[KeyTransportAlgorithm::RsaOaep],
        )
        .expect("rotation must find the matching key");
        assert_eq!(decrypted.qname().local(), "Assertion");
    }

    #[test]
    fn missing_encrypted_data_rejected() {
        // Build a wrapper that has *no* EncryptedData child.
        let wrapper = Element::build(QName::new(Some(SAML_NS.to_owned()), "EncryptedAssertion"))
            .with_namespace(Some("saml".to_owned()), SAML_NS)
            .finish();
        let kp = rsa_keypair();
        let err = decrypt_encrypted_assertion(
            &wrapper,
            &[&kp],
            &[DataEncryptionAlgorithm::Aes256Gcm],
            &[KeyTransportAlgorithm::RsaOaep],
        )
        .expect_err("no EncryptedData");
        match err {
            Error::DecryptFailed { reason } => assert_eq!(reason, "missing EncryptedData"),
            other => panic!("expected DecryptFailed, got {other:?}"),
        }
    }

    /// Confirm we don't accidentally surface per-key reasons during rotation:
    /// when *every* key in the slice fails, the error must be the generic
    /// `key transport` variant.
    #[test]
    fn all_keys_fail_collapses_to_generic_error() {
        let assertion = sample_assertion();
        let encrypted = encrypt_assertion(
            &assertion,
            &rsa_cert(),
            DataEncryptionAlgorithm::Aes256Gcm,
            KeyTransportAlgorithm::RsaOaep,
        )
        .expect("encrypt");

        // Both candidates are wrong (EC key + a freshly-generated *different*
        // RSA key). The first fails fast at the key-family check; the second
        // fails at OAEP unwrap.
        use crate::crypto::cert::test_vectors::EC_P256_KEY_PKCS8_PEM;
        let wrong_ec = KeyPair::from_pkcs8_pem(EC_P256_KEY_PKCS8_PEM).unwrap();
        // Use the same EC key twice — both attempts must collapse into the
        // single generic "key transport" error.
        let wrong_again = KeyPair::from_pkcs8_pem(EC_P256_KEY_PKCS8_PEM).unwrap();
        let err = decrypt_encrypted_assertion(
            &encrypted,
            &[&wrong_ec, &wrong_again],
            &[DataEncryptionAlgorithm::Aes256Gcm],
            &[KeyTransportAlgorithm::RsaOaep],
        )
        .expect_err("no key works");
        match err {
            Error::DecryptFailed { reason } => assert_eq!(reason, "key transport"),
            other => panic!("expected DecryptFailed, got {other:?}"),
        }
    }

    /// Re-emit + re-parse round-trips the encrypted assertion shape — proves
    /// the `Element` returned by `encrypt_assertion` is serializable XML.
    #[test]
    fn emit_then_parse_then_decrypt_round_trip() {
        let assertion = sample_assertion();
        let encrypted = encrypt_assertion(
            &assertion,
            &rsa_cert(),
            DataEncryptionAlgorithm::Aes256Gcm,
            KeyTransportAlgorithm::RsaOaep,
        )
        .expect("encrypt");
        // Serialize and re-parse via Document::parse to get an Element with
        // its namespace context as a top-level document.
        let xml = emit_element(&encrypted).expect("emit");
        let doc = Document::parse(xml.as_bytes()).expect("re-parse");
        let kp = rsa_keypair();
        let decrypted = decrypt_encrypted_assertion(
            doc.root(),
            &[&kp],
            &[DataEncryptionAlgorithm::Aes256Gcm],
            &[KeyTransportAlgorithm::RsaOaep],
        )
        .expect("decrypt");
        assert_eq!(decrypted.qname().local(), "Assertion");
    }

    // ---------------------------------------------------------------------
    // Tree-mutation helpers used by the tamper tests. Tests for
    // tree-internal mutation aren't part of the production API; they live
    // here because `Element` fields are crate-private.
    // ---------------------------------------------------------------------

    /// Set the `Algorithm` attribute of the inner `<EncryptedData>`'s
    /// `<EncryptionMethod>` to a new value.
    fn mutate_data_em_algorithm(encrypted_assertion: &mut Element, new_uri: String) {
        for child in &mut encrypted_assertion.children {
            if let Node::Element(enc_data) = child
                && enc_data.qname.local == "EncryptedData"
            {
                for grandchild in &mut enc_data.children {
                    if let Node::Element(em) = grandchild
                        && em.qname.local == "EncryptionMethod"
                    {
                        for attr in &mut em.attributes {
                            if attr.qname.local == "Algorithm" {
                                attr.value = new_uri.clone();
                                return;
                            }
                        }
                    }
                }
            }
        }
        panic!("EncryptedData/EncryptionMethod/@Algorithm not found");
    }

    /// Flip the last byte of the *payload* `<xenc:CipherValue>` (i.e. the
    /// data ciphertext, not the wrapped key). Used to simulate auth-tag /
    /// CBC-block tampering.
    fn flip_last_byte_in_data_cipher_value(encrypted_assertion: &mut Element) {
        for child in &mut encrypted_assertion.children {
            if let Node::Element(enc_data) = child
                && enc_data.qname.local == "EncryptedData"
            {
                // Find <CipherData> at the EncryptedData level (skipping
                // EncryptionMethod and KeyInfo).
                for grandchild in &mut enc_data.children {
                    if let Node::Element(cipher_data) = grandchild
                        && cipher_data.qname.local == "CipherData"
                    {
                        for ggc in &mut cipher_data.children {
                            if let Node::Element(cipher_value) = ggc
                                && cipher_value.qname.local == "CipherValue"
                            {
                                // Decode, flip, re-encode in-place.
                                let mut bytes =
                                    decode_base64_ws_tolerant(&cipher_value.text_content())
                                        .expect("base64");
                                let last = bytes
                                    .len()
                                    .checked_sub(1)
                                    .expect("CipherValue must be non-empty");
                                bytes[last] ^= 0x01;
                                let re_encoded = BASE64_STANDARD.encode(&bytes);
                                cipher_value.children.clear();
                                cipher_value.children.push(Node::Text(re_encoded));
                                return;
                            }
                        }
                    }
                }
            }
        }
        panic!("EncryptedData/CipherData/CipherValue not found");
    }
}
