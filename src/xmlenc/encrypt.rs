//! XML-Encryption encryption per W3C XML-Encryption.
//! See `docs/rfcs/RFC-002-xml-crypto-core.md` §7.
//!
//! The entry point is `encrypt_assertion`: it serializes the input
//! `<saml:Assertion>`, encrypts it under a freshly-minted symmetric session
//! key (`data_algorithm`), wraps the session key under the recipient's RSA
//! public key (`key_transport_algorithm`), and emits the resulting
//! `<saml:EncryptedAssertion>` subtree.
//!
//! Algorithm defaults (RFC-002 §7.2): `Aes256Gcm` + `RsaOaep` with SHA-256.
//! CBC and MGF1-SHA1 are kept for compatibility but not promoted.

use aes::cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use rsa::RsaPublicKey;
use rsa::pkcs1::DecodeRsaPublicKey as _;
use rsa::rand_core::{OsRng, RngCore as _};
#[cfg(feature = "weak-algos")]
use sha1::Sha1;
use sha2::Sha256;
use x509_cert::Certificate;
use x509_cert::der::Decode as _;

use crate::crypto::cert::{PublicKeyAlgorithm, X509Certificate};
use crate::error::Error;
use crate::xml::emit::emit_element;
use crate::xml::parse::{Element, Node, QName};
use crate::xmlenc::algorithms::{DataEncryptionAlgorithm, KeyTransportAlgorithm};

// =============================================================================
// Namespace URIs and element local-names used by the emitted subtree.
// =============================================================================

const SAML_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const XENC_NS: &str = "http://www.w3.org/2001/04/xmlenc#";
const XENC11_NS: &str = "http://www.w3.org/2009/xmlenc11#";
const DS_NS: &str = "http://www.w3.org/2000/09/xmldsig#";

const SHA1_DIGEST_URI: &str = "http://www.w3.org/2000/09/xmldsig#sha1";
const SHA256_DIGEST_URI: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const MGF1_SHA256_URI: &str = "http://www.w3.org/2009/xmlenc11#mgf1sha256";

const ENCRYPTED_DATA_TYPE_ELEMENT: &str = "http://www.w3.org/2001/04/xmlenc#Element";

// =============================================================================
// Public entry point
// =============================================================================

/// Encrypt an `<saml:Assertion>` element into an `<saml:EncryptedAssertion>`.
///
/// The recipient's `<md:KeyDescriptor use="encryption">` certificate is used
/// to wrap a fresh symmetric session key via the chosen key-transport
/// algorithm. The session key encrypts the serialized assertion via the
/// chosen data-encryption algorithm.
///
/// Defaults documented in RFC-002 §7.2: `Aes256Gcm` + `RsaOaep` with SHA-256.
/// CBC and MGF1-SHA1 are compatibility opt-ins, not promoted.
pub(crate) fn encrypt_assertion(
    assertion: &Element,
    recipient_encryption_cert: &X509Certificate,
    data_algorithm: DataEncryptionAlgorithm,
    key_transport_algorithm: KeyTransportAlgorithm,
) -> Result<Element, Error> {
    // -- 1. Recipient must have an RSA public key. --
    if recipient_encryption_cert.public_key().algorithm_family() != PublicKeyAlgorithm::Rsa {
        return Err(Error::DisallowedAlgorithm {
            alg: "key transport requires RSA cert".into(),
        });
    }
    let rsa_public = rsa_public_key_from_cert(recipient_encryption_cert)?;

    // -- 2. Serialize the assertion to bytes. --
    let plaintext = emit_element(assertion)?.into_bytes();

    // -- 3. Generate session key + IV/nonce. --
    let mut session_key = vec![0u8; data_algorithm.key_size()];
    fill_random(&mut session_key)?;

    // -- 4. Encrypt plaintext under session key. --
    let (mut cipher_value, ciphertext_bytes) =
        encrypt_data(data_algorithm, &session_key, &plaintext)?;
    cipher_value.reserve_exact(ciphertext_bytes.len());
    cipher_value.extend_from_slice(&ciphertext_bytes);
    let data_cipher_b64 = BASE64_STANDARD.encode(&cipher_value);

    // -- 5. Wrap session key under recipient's RSA public key. --
    let wrapped_key_bytes = wrap_session_key(&rsa_public, key_transport_algorithm, &session_key)?;
    let wrapped_key_b64 = BASE64_STANDARD.encode(&wrapped_key_bytes);

    // -- 6. Build the <saml:EncryptedAssertion> tree. --
    Ok(build_encrypted_assertion_element(
        data_algorithm,
        key_transport_algorithm,
        &wrapped_key_b64,
        &data_cipher_b64,
    ))
}

// =============================================================================
// Internal helpers
// =============================================================================

/// Extract an `RsaPublicKey` from an X.509 certificate.
///
/// Goes via the cert's canonical DER so we don't need access to the cert's
/// inner `x509_cert::Certificate` (which is private). The cert was already
/// validated to be RSA in [`encrypt_assertion`].
fn rsa_public_key_from_cert(cert: &X509Certificate) -> Result<RsaPublicKey, Error> {
    // Discarded intentionally: the cert was already validated to be RSA by
    // the caller; surfacing the DER-level reason here adds no useful detail.
    let parsed = Certificate::from_der(cert.to_der()).map_err(|_err| Error::X509Parse)?;
    let key_bytes = parsed
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or(Error::X509Parse)?;
    // The SPKI BIT STRING for RSA wraps a DER-encoded PKCS#1 RSAPublicKey.
    // Discarded intentionally: collapse all DER-level reasons into X509Parse.
    RsaPublicKey::from_pkcs1_der(key_bytes).map_err(|_err| Error::X509Parse)
}

/// Fill a buffer with cryptographically random bytes. We use the OS RNG
/// provided by the `rsa` crate's re-export of `rand_core` (the same RNG type
/// the RSA encrypt path expects), so the entire encryption pipeline runs
/// against a single entropy source.
fn fill_random(buf: &mut [u8]) -> Result<(), Error> {
    let mut rng = OsRng;
    // Discarded intentionally: RNG failure detail is platform-specific and
    // not useful to callers; collapse to a generic reason.
    rng.try_fill_bytes(buf)
        .map_err(|_err| Error::DecryptFailed { reason: "rng" })
}

/// Encrypt `plaintext` under `session_key`, returning `(iv_or_nonce, ct)`.
/// For GCM, `ct` carries the auth tag appended at the end (per `aead::Aead`).
fn encrypt_data(
    algorithm: DataEncryptionAlgorithm,
    session_key: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    match algorithm {
        DataEncryptionAlgorithm::Aes128Cbc => {
            encrypt_cbc_with_random_iv::<aes::Aes128>(session_key, plaintext)
        }
        DataEncryptionAlgorithm::Aes256Cbc => {
            encrypt_cbc_with_random_iv::<aes::Aes256>(session_key, plaintext)
        }
        DataEncryptionAlgorithm::Aes128Gcm => encrypt_gcm::<Aes128Gcm>(session_key, plaintext),
        DataEncryptionAlgorithm::Aes256Gcm => encrypt_gcm::<Aes256Gcm>(session_key, plaintext),
    }
}

fn encrypt_cbc_with_random_iv<C>(
    session_key: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Error>
where
    C: aes::cipher::BlockCipher + aes::cipher::BlockEncrypt + aes::cipher::KeyInit,
{
    let mut iv = vec![0u8; 16];
    fill_random(&mut iv)?;
    let ct = encrypt_cbc::<C>(session_key, &iv, plaintext)?;
    Ok((iv, ct))
}

fn encrypt_gcm<C>(session_key: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error>
where
    C: KeyInit + Aead,
{
    let mut nonce = vec![0u8; 12];
    fill_random(&mut nonce)?;
    // Discarded intentionally: cipher-init detail would leak key shape.
    let cipher = C::new_from_slice(session_key).map_err(|_err| Error::DecryptFailed {
        reason: "key size mismatch",
    })?;
    let ct = cipher
        .encrypt(
            aes_gcm::Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &[],
            },
        )
        // Discarded intentionally: AEAD encrypt should not fail for valid
        // inputs; surface the generic reason.
        .map_err(|_err| Error::DecryptFailed { reason: "data" })?;
    Ok((nonce, ct))
}

fn encrypt_cbc<C>(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error>
where
    C: aes::cipher::BlockCipher + aes::cipher::BlockEncrypt + aes::cipher::KeyInit,
{
    // Discarded intentionally: cipher-init detail would leak key shape.
    let encryptor =
        cbc::Encryptor::<C>::new_from_slices(key, iv).map_err(|_err| Error::DecryptFailed {
            reason: "key size mismatch",
        })?;
    // Allocate enough room for the plaintext + one full padding block (PKCS#7
    // always appends 1..=block_size padding bytes). Block size is 16 for AES.
    let mut out = vec![
        0u8;
        plaintext
            .len()
            .checked_add(16)
            .ok_or(Error::DecryptFailed { reason: "data" })?
    ];
    let written = encryptor
        .encrypt_padded_b2b_mut::<Pkcs7>(plaintext, &mut out)
        // Discarded intentionally: padding-error detail is not actionable.
        .map_err(|_err| Error::DecryptFailed { reason: "data" })?
        .len();
    out.truncate(written);
    Ok(out)
}

/// Wrap the session key under the recipient's RSA public key.
///
/// `RsaOaep` is the modern XML-Enc 1.1 variant: `rsa::Oaep::new::<Sha256>()`
/// sets *both* the OAEP label hash and the MGF1 hash to SHA-256. The
/// `<xenc:EncryptionMethod>` emitted by
/// `build_key_transport_encryption_method` therefore declares SHA-256 as the
/// `<ds:DigestMethod>` and `mgf1sha256` as the `<xenc11:MGF>`, so a recipient
/// reading those parameters literally reconstructs the same padding.
///
/// `RsaOaepMgf1Sha1`: SHA-1 for the OAEP digest *and* MGF1, which is what the
/// `#rsa-oaep-mgf1p` URI pins by definition.
fn wrap_session_key(
    public: &RsaPublicKey,
    algorithm: KeyTransportAlgorithm,
    session_key: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut rng = OsRng;
    match algorithm {
        KeyTransportAlgorithm::RsaOaep => {
            let padding = rsa::Oaep::new::<Sha256>();
            public
                .encrypt(&mut rng, padding, session_key)
                // Discarded intentionally: RSA encrypt failure detail must not
                // be surfaced for Bleichenbacher safety; collapse to generic.
                .map_err(|_err| Error::DecryptFailed {
                    reason: "key transport",
                })
        }
        KeyTransportAlgorithm::RsaOaepMgf1Sha1 => {
            // OAEP with SHA-1 hash + MGF1-SHA-1. Encrypt requires the `sha1`
            // crate, which is only compiled when `weak-algos` is enabled. The
            // symmetric `KeyPair::decrypt_rsa_oaep(OaepDigest::Sha1)` path
            // makes the same gating decision.
            #[cfg(feature = "weak-algos")]
            {
                let padding = rsa::Oaep::new::<Sha1>();
                public
                    .encrypt(&mut rng, padding, session_key)
                    // Discarded intentionally: see RsaOaep arm above.
                    .map_err(|_err| Error::DecryptFailed {
                        reason: "key transport",
                    })
            }
            #[cfg(not(feature = "weak-algos"))]
            {
                Err(Error::DisallowedAlgorithm {
                    alg: "RSA-OAEP-SHA1 outbound requires the weak-algos feature".into(),
                })
            }
        }
        #[cfg(feature = "weak-algos")]
        KeyTransportAlgorithm::RsaPkcs1V15 => {
            // Outbound RSA-PKCS1-v1.5 is *not* a v0.1 supported emit path
            // (RFC-002 §9), so we refuse here even when the algorithm is
            // compiled in. Decrypt remains available for legacy interop.
            Err(Error::DisallowedAlgorithm {
                alg: "RSA-PKCS1-v1.5 outbound key transport is not supported".into(),
            })
        }
    }
}

/// Build the `<saml:EncryptedAssertion>` element tree with all xmlns
/// declarations on the outer wrapper.
fn build_encrypted_assertion_element(
    data_algorithm: DataEncryptionAlgorithm,
    key_transport_algorithm: KeyTransportAlgorithm,
    wrapped_key_b64: &str,
    data_cipher_b64: &str,
) -> Element {
    build_encrypted_assertion_with_key_encryption_method(
        data_algorithm,
        build_key_transport_encryption_method(key_transport_algorithm),
        wrapped_key_b64,
        data_cipher_b64,
    )
}

/// As [`build_encrypted_assertion_element`], but with the
/// `<xenc:EncryptedKey>/<xenc:EncryptionMethod>` supplied by the caller.
///
/// Split out so test fixtures can declare OAEP parameter combinations the
/// two production profiles do not emit, while sharing the rest of the tree.
fn build_encrypted_assertion_with_key_encryption_method(
    data_algorithm: DataEncryptionAlgorithm,
    key_em: Element,
    wrapped_key_b64: &str,
    data_cipher_b64: &str,
) -> Element {
    // ----- innermost: <xenc:CipherValue> for the wrapped session key -----
    let key_cipher_value = Element::build(QName::new(Some(XENC_NS.to_owned()), "CipherValue"))
        .with_text(wrapped_key_b64.to_owned())
        .finish();
    let key_cipher_data = Element::build(QName::new(Some(XENC_NS.to_owned()), "CipherData"))
        .with_child(Node::Element(key_cipher_value))
        .finish();

    let declares_mgf = key_em.child_element(Some(XENC11_NS), "MGF").is_some();

    // ----- <xenc:EncryptedKey> -----
    let encrypted_key = Element::build(QName::new(Some(XENC_NS.to_owned()), "EncryptedKey"))
        .with_child(Node::Element(key_em))
        .with_child(Node::Element(key_cipher_data))
        .finish();

    // ----- <ds:KeyInfo> wrapping the <xenc:EncryptedKey> -----
    let key_info = Element::build(QName::new(Some(DS_NS.to_owned()), "KeyInfo"))
        .with_child(Node::Element(encrypted_key))
        .finish();

    // ----- <xenc:EncryptionMethod> for the data-encryption algorithm -----
    let data_em = Element::build(QName::new(Some(XENC_NS.to_owned()), "EncryptionMethod"))
        .with_attribute(
            QName::new(None, "Algorithm"),
            data_algorithm.uri().to_owned(),
        )
        .finish();

    // ----- <xenc:CipherValue> for the encrypted payload -----
    let data_cipher_value = Element::build(QName::new(Some(XENC_NS.to_owned()), "CipherValue"))
        .with_text(data_cipher_b64.to_owned())
        .finish();
    let data_cipher_data = Element::build(QName::new(Some(XENC_NS.to_owned()), "CipherData"))
        .with_child(Node::Element(data_cipher_value))
        .finish();

    // ----- <xenc:EncryptedData> -----
    let encrypted_data = Element::build(QName::new(Some(XENC_NS.to_owned()), "EncryptedData"))
        .with_attribute(
            QName::new(None, "Type"),
            ENCRYPTED_DATA_TYPE_ELEMENT.to_owned(),
        )
        .with_child(Node::Element(data_em))
        .with_child(Node::Element(key_info))
        .with_child(Node::Element(data_cipher_data))
        .finish();

    // ----- outer <saml:EncryptedAssertion>; carry all xmlns decls here -----
    let mut wrapper = Element::build(QName::new(Some(SAML_NS.to_owned()), "EncryptedAssertion"))
        .with_namespace(Some("saml".to_owned()), SAML_NS)
        .with_namespace(Some("xenc".to_owned()), XENC_NS)
        .with_namespace(Some("ds".to_owned()), DS_NS);
    if declares_mgf {
        // Declare the xenc11 prefix once on the outer wrapper, and only when
        // an `<xenc11:MGF>` is actually present, so the element resolves to a
        // prefix without leaving an unused declaration on other profiles.
        wrapper = wrapper.with_namespace(Some("xenc11".to_owned()), XENC11_NS);
    }
    wrapper.with_child(Node::Element(encrypted_data)).finish()
}

/// Build the `<xenc:EncryptionMethod>` subtree inside `<xenc:EncryptedKey>`,
/// including the embedded `<ds:DigestMethod>` and (for the modern `#rsa-oaep`)
/// the `<xenc11:MGF>` declaration.
fn build_key_transport_encryption_method(algorithm: KeyTransportAlgorithm) -> Element {
    match algorithm {
        KeyTransportAlgorithm::RsaOaep => {
            // Modern RSA-OAEP: SHA-256 OAEP digest with MGF1-SHA256.
            // `wrap_session_key` below builds the padding with
            // `rsa::Oaep::new::<Sha256>()`, which sets *both* the OAEP label
            // hash and the MGF1 hash to SHA-256, so the declaration must say
            // `mgf1sha256`. Declaring `mgf1sha1` (as this did previously)
            // misdescribes the ciphertext: a recipient that reads
            // `<xenc11:MGF>` literally — which XML Encryption 1.1 §5.5.2
            // requires — derives the wrong mask and fails to unwrap the
            // session key.
            let digest = Element::build(QName::new(Some(DS_NS.to_owned()), "DigestMethod"))
                .with_attribute(QName::new(None, "Algorithm"), SHA256_DIGEST_URI.to_owned())
                .finish();
            let mgf = Element::build(QName::new(Some(XENC11_NS.to_owned()), "MGF"))
                .with_attribute(QName::new(None, "Algorithm"), MGF1_SHA256_URI.to_owned())
                .finish();
            Element::build(QName::new(Some(XENC_NS.to_owned()), "EncryptionMethod"))
                .with_attribute(QName::new(None, "Algorithm"), algorithm.uri().to_owned())
                .with_child(Node::Element(digest))
                .with_child(Node::Element(mgf))
                .finish()
        }
        KeyTransportAlgorithm::RsaOaepMgf1Sha1 => {
            // Legacy `#rsa-oaep-mgf1p`: SHA-1 OAEP + MGF1-SHA-1. No `<MGF>`
            // child — the `mgf1p` URI implies MGF1-SHA1 by spec.
            let digest = Element::build(QName::new(Some(DS_NS.to_owned()), "DigestMethod"))
                .with_attribute(QName::new(None, "Algorithm"), SHA1_DIGEST_URI.to_owned())
                .finish();
            Element::build(QName::new(Some(XENC_NS.to_owned()), "EncryptionMethod"))
                .with_attribute(QName::new(None, "Algorithm"), algorithm.uri().to_owned())
                .with_child(Node::Element(digest))
                .finish()
        }
        #[cfg(feature = "weak-algos")]
        KeyTransportAlgorithm::RsaPkcs1V15 => {
            // PKCS#1 v1.5 has no associated digest in the XML-Enc syntax.
            Element::build(QName::new(Some(XENC_NS.to_owned()), "EncryptionMethod"))
                .with_attribute(QName::new(None, "Algorithm"), algorithm.uri().to_owned())
                .finish()
        }
    }
}

// =============================================================================
// Test-only: encrypt with explicitly declared OAEP parameters
// =============================================================================

/// The RSA-OAEP parameters a test fixture should *declare* in the emitted
/// `<xenc:EncryptionMethod>`.
///
/// `None` means "omit the element", which is what exercises the XML
/// Encryption 1.1 §5.5.2 defaults. The ciphertext is always produced with the
/// effective parameters those declarations resolve to, so a fixture cannot
/// claim a combination it did not actually encrypt with — the failure mode
/// that XML string-rewriting fixtures hide.
#[cfg(test)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct DeclaredOaepParams {
    /// Emitted as `<ds:DigestMethod>`; `None` omits it (spec default SHA-1).
    pub digest: Option<crate::crypto::keypair::OaepDigest>,
    /// Emitted as `<xenc11:MGF>`; `None` omits it (spec default MGF1-SHA1).
    pub mgf1: Option<crate::crypto::keypair::OaepDigest>,
}

#[cfg(test)]
impl DeclaredOaepParams {
    /// The message digest actually used, after applying the §5.5.2 default.
    pub(crate) fn effective_digest(self) -> crate::crypto::keypair::OaepDigest {
        self.digest
            .unwrap_or(crate::crypto::keypair::OaepDigest::Sha1)
    }

    /// The MGF1 hash actually used, after applying the §5.5.2 default.
    pub(crate) fn effective_mgf1(self) -> crate::crypto::keypair::OaepDigest {
        self.mgf1
            .unwrap_or(crate::crypto::keypair::OaepDigest::Sha1)
    }
}

/// Encrypt an assertion under `key_transport_algorithm`, wrapping the session
/// key with exactly the OAEP parameters `params` declares (after standard
/// defaults) and emitting an `<xenc:EncryptionMethod>` that declares them.
///
/// This exists so interoperability fixtures can cover the independent
/// `hashAlgorithm` / `maskGenAlgorithm` combinations of RFC 8017 A.2.1
/// against real ciphertext.
#[cfg(test)]
pub(crate) fn encrypt_assertion_with_declared_oaep_params(
    assertion: &Element,
    recipient_encryption_cert: &X509Certificate,
    data_algorithm: DataEncryptionAlgorithm,
    key_transport_algorithm: KeyTransportAlgorithm,
    params: DeclaredOaepParams,
) -> Result<Element, Error> {
    use rsa::traits::PaddingScheme as _;

    let rsa_public = rsa_public_key_from_cert(recipient_encryption_cert)?;
    let plaintext = emit_element(assertion)?.into_bytes();

    let mut session_key = vec![0u8; data_algorithm.key_size()];
    fill_random(&mut session_key)?;

    let (mut cipher_value, ciphertext_bytes) =
        encrypt_data(data_algorithm, &session_key, &plaintext)?;
    cipher_value.reserve_exact(ciphertext_bytes.len());
    cipher_value.extend_from_slice(&ciphertext_bytes);
    let data_cipher_b64 = BASE64_STANDARD.encode(&cipher_value);

    // Wrap with the effective parameters — the same `oaep_padding` mapping the
    // decrypt side uses, so a round-trip proves both directions agree.
    let padding =
        crate::crypto::keypair::oaep_padding(params.effective_digest(), params.effective_mgf1())?;
    let mut rng = OsRng;
    let wrapped_key_bytes = padding
        .encrypt(&mut rng, &rsa_public, &session_key)
        .map_err(|_err| Error::DecryptFailed {
            reason: "key transport",
        })?;
    let wrapped_key_b64 = BASE64_STANDARD.encode(&wrapped_key_bytes);

    let mut em = Element::build(QName::new(Some(XENC_NS.to_owned()), "EncryptionMethod"))
        .with_attribute(
            QName::new(None, "Algorithm"),
            key_transport_algorithm.uri().to_owned(),
        );
    if let Some(digest) = params.digest {
        em = em.with_child(Node::Element(
            Element::build(QName::new(Some(DS_NS.to_owned()), "DigestMethod"))
                .with_attribute(QName::new(None, "Algorithm"), digest.uri().to_owned())
                .finish(),
        ));
    }
    if let Some(mgf1) = params.mgf1 {
        em = em.with_child(Node::Element(
            Element::build(QName::new(Some(XENC11_NS.to_owned()), "MGF"))
                .with_attribute(QName::new(None, "Algorithm"), mgf1.mgf1_uri().to_owned())
                .finish(),
        ));
    }

    Ok(build_encrypted_assertion_with_key_encryption_method(
        data_algorithm,
        em.finish(),
        &wrapped_key_b64,
        &data_cipher_b64,
    ))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::cert::X509Certificate;
    use crate::crypto::cert::test_vectors::RSA_CERT_PEM;
    use crate::xml::parse::Document;

    fn sample_assertion() -> Element {
        // Build an <saml:Assertion> with one nested element so we exercise
        // child encoding too. The outer element must carry the `saml` xmlns
        // declaration so `emit_element` can resolve prefixes.
        let subject = Element::build(QName::new(Some(SAML_NS.to_owned()), "Subject"))
            .with_text("alice@example.org")
            .finish();
        Element::build(QName::new(Some(SAML_NS.to_owned()), "Assertion"))
            .with_namespace(Some("saml".to_owned()), SAML_NS)
            .with_attribute(QName::new(None, "ID"), "_a1")
            .with_child(Node::Element(subject))
            .finish()
    }

    #[test]
    fn emits_well_formed_encrypted_assertion_aes256_gcm_rsa_oaep() {
        let assertion = sample_assertion();
        let cert = X509Certificate::from_pem(RSA_CERT_PEM).unwrap();
        let encrypted = encrypt_assertion(
            &assertion,
            &cert,
            DataEncryptionAlgorithm::Aes256Gcm,
            KeyTransportAlgorithm::RsaOaep,
        )
        .expect("encrypt");

        // Outer element shape.
        assert_eq!(encrypted.qname().namespace(), Some(SAML_NS));
        assert_eq!(encrypted.qname().local(), "EncryptedAssertion");

        // Re-emit + re-parse to verify well-formedness.
        let xml = emit_element(&encrypted).expect("emit");
        let doc = Document::parse(xml.as_bytes()).expect("re-parse");
        let enc_data = doc
            .root()
            .child_element(Some(XENC_NS), "EncryptedData")
            .expect("EncryptedData");
        assert_eq!(
            enc_data.attribute(None, "Type"),
            Some(ENCRYPTED_DATA_TYPE_ELEMENT)
        );
        let em = enc_data
            .child_element(Some(XENC_NS), "EncryptionMethod")
            .expect("EncryptionMethod");
        assert_eq!(
            em.attribute(None, "Algorithm"),
            Some(DataEncryptionAlgorithm::Aes256Gcm.uri())
        );
        let key_info = enc_data
            .child_element(Some(DS_NS), "KeyInfo")
            .expect("KeyInfo");
        let enc_key = key_info
            .child_element(Some(XENC_NS), "EncryptedKey")
            .expect("EncryptedKey");
        let _ = enc_key
            .child_element(Some(XENC_NS), "EncryptionMethod")
            .expect("EncryptedKey/EncryptionMethod");
    }

    /// `RsaOaepMgf1Sha1` outbound encryption requires the `weak-algos` feature
    /// for the SHA-1 OAEP digest. This test is gated to match.
    #[cfg(feature = "weak-algos")]
    #[test]
    fn emits_well_formed_encrypted_assertion_aes128_cbc_rsa_oaep_mgf1sha1() {
        let assertion = sample_assertion();
        let cert = X509Certificate::from_pem(RSA_CERT_PEM).unwrap();
        let encrypted = encrypt_assertion(
            &assertion,
            &cert,
            DataEncryptionAlgorithm::Aes128Cbc,
            KeyTransportAlgorithm::RsaOaepMgf1Sha1,
        )
        .expect("encrypt CBC + OAEP-MGF1-SHA1");
        let xml = emit_element(&encrypted).expect("emit");
        // We don't decrypt here (decrypt.rs owns the round-trip tests); just
        // confirm re-parsing succeeds and the algorithms match.
        let doc = Document::parse(xml.as_bytes()).expect("re-parse");
        let em = doc
            .root()
            .child_element(Some(XENC_NS), "EncryptedData")
            .and_then(|e| e.child_element(Some(XENC_NS), "EncryptionMethod"))
            .unwrap();
        assert_eq!(
            em.attribute(None, "Algorithm"),
            Some(DataEncryptionAlgorithm::Aes128Cbc.uri())
        );
    }
}
