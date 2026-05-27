//! XML-Signature, digest, and canonicalization algorithm enums, plus the
//! per-peer crypto policy that governs inbound acceptance.
//!
//! See `docs/rfcs/RFC-002-xml-crypto-core.md` §2 and §5.

use crate::error::Error;

/// XML-DSig signature algorithm.
///
/// Compilation of weak variants (`RsaSha1`, `DsaSha1`) is gated by the
/// `weak-algos` feature. Compilation alone does not imply acceptance —
/// inbound acceptance is filtered by the effective [`PeerCryptoPolicy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SignatureAlgorithm {
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    RsaSha256,
    /// RSASSA-PKCS1-v1_5 with SHA-384.
    RsaSha384,
    /// RSASSA-PKCS1-v1_5 with SHA-512.
    RsaSha512,
    /// ECDSA with SHA-256.
    EcdsaSha256,
    /// ECDSA with SHA-384.
    EcdsaSha384,
    /// ECDSA with SHA-512.
    EcdsaSha512,
    /// RSA with SHA-1. Weak; gated by `weak-algos`.
    #[cfg(feature = "weak-algos")]
    RsaSha1,
    /// DSA with SHA-1. Weak; gated by `weak-algos`.
    #[cfg(feature = "weak-algos")]
    DsaSha1,
}

impl SignatureAlgorithm {
    /// The default set accepted on inbound signatures (strong algorithms only).
    ///
    /// Used by [`PeerCryptoPolicy::strong_defaults`].
    pub const DEFAULTS: &'static [Self] = &[
        Self::RsaSha256,
        Self::RsaSha384,
        Self::RsaSha512,
        Self::EcdsaSha256,
        Self::EcdsaSha384,
        Self::EcdsaSha512,
    ];

    /// XML Signature algorithm URI.
    pub const fn uri(self) -> &'static str {
        match self {
            Self::RsaSha256 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            Self::RsaSha384 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
            Self::RsaSha512 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
            Self::EcdsaSha256 => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
            Self::EcdsaSha384 => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
            Self::EcdsaSha512 => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
            #[cfg(feature = "weak-algos")]
            Self::RsaSha1 => "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
            #[cfg(feature = "weak-algos")]
            Self::DsaSha1 => "http://www.w3.org/2000/09/xmldsig#dsa-sha1",
        }
    }

    /// Parse from XML-DSig URI. Returns `Error::DisallowedAlgorithm` for
    /// unknown URIs (including weak ones that weren't compiled in).
    pub fn from_uri(uri: &str) -> Result<Self, Error> {
        match uri {
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => Ok(Self::RsaSha256),
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" => Ok(Self::RsaSha384),
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" => Ok(Self::RsaSha512),
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256" => Ok(Self::EcdsaSha256),
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384" => Ok(Self::EcdsaSha384),
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512" => Ok(Self::EcdsaSha512),
            #[cfg(feature = "weak-algos")]
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1" => Ok(Self::RsaSha1),
            #[cfg(feature = "weak-algos")]
            "http://www.w3.org/2000/09/xmldsig#dsa-sha1" => Ok(Self::DsaSha1),
            _ => Err(Error::DisallowedAlgorithm {
                alg: uri.to_owned(),
            }),
        }
    }
}

/// XML-DSig digest algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DigestAlgorithm {
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
    /// SHA-1. Weak; gated by `weak-algos`.
    #[cfg(feature = "weak-algos")]
    Sha1,
}

impl DigestAlgorithm {
    /// XML Signature digest algorithm URI.
    pub const fn uri(self) -> &'static str {
        match self {
            Self::Sha256 => "http://www.w3.org/2001/04/xmlenc#sha256",
            Self::Sha384 => "http://www.w3.org/2001/04/xmldsig-more#sha384",
            Self::Sha512 => "http://www.w3.org/2001/04/xmlenc#sha512",
            #[cfg(feature = "weak-algos")]
            Self::Sha1 => "http://www.w3.org/2000/09/xmldsig#sha1",
        }
    }

    /// Parse from XML-DSig URI. Returns `Error::DisallowedAlgorithm` for
    /// unknown URIs (including weak ones that weren't compiled in).
    pub fn from_uri(uri: &str) -> Result<Self, Error> {
        match uri {
            "http://www.w3.org/2001/04/xmlenc#sha256" => Ok(Self::Sha256),
            "http://www.w3.org/2001/04/xmldsig-more#sha384" => Ok(Self::Sha384),
            "http://www.w3.org/2001/04/xmlenc#sha512" => Ok(Self::Sha512),
            #[cfg(feature = "weak-algos")]
            "http://www.w3.org/2000/09/xmldsig#sha1" => Ok(Self::Sha1),
            _ => Err(Error::DisallowedAlgorithm {
                alg: uri.to_owned(),
            }),
        }
    }

    /// Compute the digest of `bytes`.
    pub fn digest(self, bytes: &[u8]) -> Vec<u8> {
        use sha2::Digest as _;
        match self {
            Self::Sha256 => sha2::Sha256::digest(bytes).to_vec(),
            Self::Sha384 => sha2::Sha384::digest(bytes).to_vec(),
            Self::Sha512 => sha2::Sha512::digest(bytes).to_vec(),
            #[cfg(feature = "weak-algos")]
            Self::Sha1 => {
                use sha1::Digest as _;
                sha1::Sha1::digest(bytes).to_vec()
            }
        }
    }
}

/// XML canonicalization algorithm. See RFC-002 §2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum C14nAlgorithm {
    /// Exclusive XML Canonicalization 1.0 (no comments).
    /// URI: `http://www.w3.org/2001/10/xml-exc-c14n#`.
    ExclusiveCanonical,
    /// Exclusive XML Canonicalization 1.0 with comments.
    /// URI: `http://www.w3.org/2001/10/xml-exc-c14n#WithComments`.
    ExclusiveCanonicalWithComments,
    /// Inclusive Canonical XML 1.0 (no comments).
    /// URI: `http://www.w3.org/TR/2001/REC-xml-c14n-20010315`.
    InclusiveCanonical,
    /// Inclusive Canonical XML 1.0 with comments.
    /// URI: `http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments`.
    InclusiveCanonicalWithComments,
}

impl C14nAlgorithm {
    /// Canonicalization algorithm URI.
    pub const fn uri(self) -> &'static str {
        match self {
            Self::ExclusiveCanonical => "http://www.w3.org/2001/10/xml-exc-c14n#",
            Self::ExclusiveCanonicalWithComments => {
                "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"
            }
            Self::InclusiveCanonical => "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
            Self::InclusiveCanonicalWithComments => {
                "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
            }
        }
    }

    /// Parse from URI. Returns `Error::DisallowedAlgorithm` for unknown URIs.
    pub fn from_uri(uri: &str) -> Result<Self, Error> {
        match uri {
            "http://www.w3.org/2001/10/xml-exc-c14n#" => Ok(Self::ExclusiveCanonical),
            "http://www.w3.org/2001/10/xml-exc-c14n#WithComments" => {
                Ok(Self::ExclusiveCanonicalWithComments)
            }
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315" => Ok(Self::InclusiveCanonical),
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments" => {
                Ok(Self::InclusiveCanonicalWithComments)
            }
            _ => Err(Error::DisallowedAlgorithm {
                alg: uri.to_owned(),
            }),
        }
    }

    /// Whether this algorithm preserves XML comments.
    pub fn includes_comments(self) -> bool {
        matches!(
            self,
            Self::ExclusiveCanonicalWithComments | Self::InclusiveCanonicalWithComments
        )
    }

    /// Whether this is an Exclusive (vs Inclusive) canonicalization.
    pub fn is_exclusive(self) -> bool {
        matches!(
            self,
            Self::ExclusiveCanonical | Self::ExclusiveCanonicalWithComments
        )
    }
}

/// Inbound-acceptance crypto policy scoped to a single peer.
///
/// See RFC-002 §5 (last paragraph) and the role-layer default policy
/// described in RFC-003 / RFC-004. Compilation of an algorithm via
/// `weak-algos` does not imply acceptance — acceptance is determined by
/// whether the algorithm appears in the effective `PeerCryptoPolicy` selected
/// for the message being consumed.
#[derive(Debug, Clone)]
pub struct PeerCryptoPolicy {
    /// Inbound XML-DSig and HTTP-Redirect detached signature algorithms.
    pub allowed_signature_algorithms: Vec<SignatureAlgorithm>,
    /// Inbound XML-Enc data-encryption algorithms.
    #[cfg(feature = "xmlenc")]
    pub allowed_data_encryption_algorithms:
        Vec<crate::xmlenc::algorithms::DataEncryptionAlgorithm>,
    /// Inbound XML-Enc key-transport algorithms.
    #[cfg(feature = "xmlenc")]
    pub allowed_key_transport_algorithms: Vec<crate::xmlenc::algorithms::KeyTransportAlgorithm>,
}

impl PeerCryptoPolicy {
    /// Strong defaults per RFC-002 §5:
    ///
    /// - Signature algorithms: [`SignatureAlgorithm::DEFAULTS`]
    ///   (RSA-SHA{256,384,512} + ECDSA-SHA{256,384,512}; no SHA-1, no DSA).
    /// - Data encryption: AES-128-GCM and AES-256-GCM (CBC is compatibility opt-in).
    /// - Key transport: RSA-OAEP only (MGF1-SHA1 and RSA-PKCS1-v1.5 are
    ///   compatibility / `weak-algos` opt-ins respectively).
    pub fn strong_defaults() -> Self {
        Self {
            allowed_signature_algorithms: SignatureAlgorithm::DEFAULTS.to_vec(),
            #[cfg(feature = "xmlenc")]
            allowed_data_encryption_algorithms: vec![
                crate::xmlenc::algorithms::DataEncryptionAlgorithm::Aes128Gcm,
                crate::xmlenc::algorithms::DataEncryptionAlgorithm::Aes256Gcm,
            ],
            #[cfg(feature = "xmlenc")]
            allowed_key_transport_algorithms: vec![
                crate::xmlenc::algorithms::KeyTransportAlgorithm::RsaOaep,
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_uri_roundtrip() {
        for alg in [
            SignatureAlgorithm::RsaSha256,
            SignatureAlgorithm::RsaSha384,
            SignatureAlgorithm::RsaSha512,
            SignatureAlgorithm::EcdsaSha256,
            SignatureAlgorithm::EcdsaSha384,
            SignatureAlgorithm::EcdsaSha512,
        ] {
            assert_eq!(SignatureAlgorithm::from_uri(alg.uri()).unwrap(), alg);
        }

        #[cfg(feature = "weak-algos")]
        for alg in [SignatureAlgorithm::RsaSha1, SignatureAlgorithm::DsaSha1] {
            assert_eq!(SignatureAlgorithm::from_uri(alg.uri()).unwrap(), alg);
        }
    }

    #[test]
    fn signature_from_unknown_uri_is_disallowed() {
        let err = SignatureAlgorithm::from_uri("http://example.com/unknown").unwrap_err();
        match err {
            Error::DisallowedAlgorithm { alg } => assert_eq!(alg, "http://example.com/unknown"),
            other => panic!("expected DisallowedAlgorithm, got {other:?}"),
        }
    }

    #[cfg(not(feature = "weak-algos"))]
    #[test]
    fn signature_rsa_sha1_uri_rejected_without_weak_algos() {
        let err =
            SignatureAlgorithm::from_uri("http://www.w3.org/2000/09/xmldsig#rsa-sha1").unwrap_err();
        match err {
            Error::DisallowedAlgorithm { alg } => {
                assert_eq!(alg, "http://www.w3.org/2000/09/xmldsig#rsa-sha1");
            }
            other => panic!("expected DisallowedAlgorithm, got {other:?}"),
        }
    }

    #[test]
    fn digest_uri_roundtrip() {
        for alg in [
            DigestAlgorithm::Sha256,
            DigestAlgorithm::Sha384,
            DigestAlgorithm::Sha512,
        ] {
            assert_eq!(DigestAlgorithm::from_uri(alg.uri()).unwrap(), alg);
        }

        #[cfg(feature = "weak-algos")]
        {
            let alg = DigestAlgorithm::Sha1;
            assert_eq!(DigestAlgorithm::from_uri(alg.uri()).unwrap(), alg);
        }
    }

    #[test]
    fn digest_from_unknown_uri_is_disallowed() {
        let err = DigestAlgorithm::from_uri("http://example.com/unknown").unwrap_err();
        match err {
            Error::DisallowedAlgorithm { alg } => assert_eq!(alg, "http://example.com/unknown"),
            other => panic!("expected DisallowedAlgorithm, got {other:?}"),
        }
    }

    #[test]
    fn digest_known_answer_vectors_empty_input() {
        // RFC 6234 / FIPS 180-4 known answers for the empty string.
        let sha256_empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let sha384_empty = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b";
        let sha512_empty = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";

        assert_eq!(hex::encode(DigestAlgorithm::Sha256.digest(b"")), sha256_empty);
        assert_eq!(hex::encode(DigestAlgorithm::Sha384.digest(b"")), sha384_empty);
        assert_eq!(hex::encode(DigestAlgorithm::Sha512.digest(b"")), sha512_empty);

        #[cfg(feature = "weak-algos")]
        {
            let sha1_empty = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
            assert_eq!(hex::encode(DigestAlgorithm::Sha1.digest(b"")), sha1_empty);
        }
    }

    #[test]
    fn digest_known_answer_vector_abc() {
        // FIPS 180-4 KAT for "abc".
        assert_eq!(
            hex::encode(DigestAlgorithm::Sha256.digest(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        );
    }

    #[test]
    fn c14n_uri_roundtrip() {
        for alg in [
            C14nAlgorithm::ExclusiveCanonical,
            C14nAlgorithm::ExclusiveCanonicalWithComments,
            C14nAlgorithm::InclusiveCanonical,
            C14nAlgorithm::InclusiveCanonicalWithComments,
        ] {
            assert_eq!(C14nAlgorithm::from_uri(alg.uri()).unwrap(), alg);
        }
    }

    #[test]
    fn c14n_from_unknown_uri_is_disallowed() {
        let err = C14nAlgorithm::from_uri("http://example.com/unknown").unwrap_err();
        match err {
            Error::DisallowedAlgorithm { alg } => assert_eq!(alg, "http://example.com/unknown"),
            other => panic!("expected DisallowedAlgorithm, got {other:?}"),
        }
    }

    #[test]
    fn c14n_includes_comments_and_is_exclusive() {
        assert!(!C14nAlgorithm::ExclusiveCanonical.includes_comments());
        assert!(C14nAlgorithm::ExclusiveCanonicalWithComments.includes_comments());
        assert!(!C14nAlgorithm::InclusiveCanonical.includes_comments());
        assert!(C14nAlgorithm::InclusiveCanonicalWithComments.includes_comments());

        assert!(C14nAlgorithm::ExclusiveCanonical.is_exclusive());
        assert!(C14nAlgorithm::ExclusiveCanonicalWithComments.is_exclusive());
        assert!(!C14nAlgorithm::InclusiveCanonical.is_exclusive());
        assert!(!C14nAlgorithm::InclusiveCanonicalWithComments.is_exclusive());
    }

    #[test]
    fn strong_defaults_excludes_weak_signature_algorithms() {
        let policy = PeerCryptoPolicy::strong_defaults();
        let sigs = &policy.allowed_signature_algorithms;

        // Strong DEFAULTS are exactly the set we expect.
        assert_eq!(sigs.as_slice(), SignatureAlgorithm::DEFAULTS);

        // No SHA-1 / DSA flavours, even with weak-algos compiled.
        #[cfg(feature = "weak-algos")]
        {
            assert!(!sigs.contains(&SignatureAlgorithm::RsaSha1));
            assert!(!sigs.contains(&SignatureAlgorithm::DsaSha1));
        }
    }

    #[cfg(feature = "xmlenc")]
    #[test]
    fn strong_defaults_xmlenc_choices() {
        use crate::xmlenc::algorithms::{DataEncryptionAlgorithm, KeyTransportAlgorithm};

        let policy = PeerCryptoPolicy::strong_defaults();

        // GCM only — CBC is a compatibility opt-in.
        assert_eq!(
            policy.allowed_data_encryption_algorithms,
            vec![
                DataEncryptionAlgorithm::Aes128Gcm,
                DataEncryptionAlgorithm::Aes256Gcm,
            ]
        );
        assert!(
            !policy
                .allowed_data_encryption_algorithms
                .contains(&DataEncryptionAlgorithm::Aes128Cbc)
        );
        assert!(
            !policy
                .allowed_data_encryption_algorithms
                .contains(&DataEncryptionAlgorithm::Aes256Cbc)
        );

        // RSA-OAEP only — MGF1-SHA1 is a compatibility opt-in.
        assert_eq!(
            policy.allowed_key_transport_algorithms,
            vec![KeyTransportAlgorithm::RsaOaep]
        );
        assert!(
            !policy
                .allowed_key_transport_algorithms
                .contains(&KeyTransportAlgorithm::RsaOaepMgf1Sha1)
        );

        #[cfg(feature = "weak-algos")]
        assert!(
            !policy
                .allowed_key_transport_algorithms
                .contains(&KeyTransportAlgorithm::RsaPkcs1V15)
        );
    }
}
