//! XML-Encryption algorithm enums.
//!
//! See `docs/rfcs/RFC-002-xml-crypto-core.md` §5.

use crate::error::Error;

/// Block-cipher algorithms used to encrypt the payload (`<xenc:EncryptedData>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DataEncryptionAlgorithm {
    /// AES-128 in CBC mode. URI: `http://www.w3.org/2001/04/xmlenc#aes128-cbc`.
    Aes128Cbc,
    /// AES-256 in CBC mode. URI: `http://www.w3.org/2001/04/xmlenc#aes256-cbc`.
    Aes256Cbc,
    /// AES-128 in GCM mode. URI: `http://www.w3.org/2009/xmlenc11#aes128-gcm`.
    Aes128Gcm,
    /// AES-256 in GCM mode. URI: `http://www.w3.org/2009/xmlenc11#aes256-gcm`.
    Aes256Gcm,
}

impl DataEncryptionAlgorithm {
    /// XML-Enc algorithm URI.
    pub const fn uri(self) -> &'static str {
        match self {
            Self::Aes128Cbc => "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
            Self::Aes256Cbc => "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
            Self::Aes128Gcm => "http://www.w3.org/2009/xmlenc11#aes128-gcm",
            Self::Aes256Gcm => "http://www.w3.org/2009/xmlenc11#aes256-gcm",
        }
    }

    /// Parse from XML-Enc URI. Returns `Error::DisallowedAlgorithm` for unknown URIs.
    pub fn from_uri(uri: &str) -> Result<Self, Error> {
        match uri {
            "http://www.w3.org/2001/04/xmlenc#aes128-cbc" => Ok(Self::Aes128Cbc),
            "http://www.w3.org/2001/04/xmlenc#aes256-cbc" => Ok(Self::Aes256Cbc),
            "http://www.w3.org/2009/xmlenc11#aes128-gcm" => Ok(Self::Aes128Gcm),
            "http://www.w3.org/2009/xmlenc11#aes256-gcm" => Ok(Self::Aes256Gcm),
            _ => Err(Error::DisallowedAlgorithm {
                alg: uri.to_owned(),
            }),
        }
    }

    /// Symmetric key size in bytes.
    pub const fn key_size(self) -> usize {
        match self {
            Self::Aes128Cbc | Self::Aes128Gcm => 16,
            Self::Aes256Cbc | Self::Aes256Gcm => 32,
        }
    }

    /// Whether the mode is GCM (AEAD) as opposed to CBC.
    pub const fn is_gcm(self) -> bool {
        matches!(self, Self::Aes128Gcm | Self::Aes256Gcm)
    }
}

/// Asymmetric key-transport algorithms used to wrap the session key
/// (`<xenc:EncryptedKey>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeyTransportAlgorithm {
    /// RSA-OAEP with SHA-256 + MGF1-SHA1 by default. URI:
    /// `http://www.w3.org/2009/xmlenc11#rsa-oaep`.
    RsaOaep,
    /// Legacy RSA-OAEP with MGF1-SHA1. URI:
    /// `http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p`.
    RsaOaepMgf1Sha1,
    /// RSA PKCS#1 v1.5. Disabled unless the `weak-algos` feature is enabled.
    /// URI: `http://www.w3.org/2001/04/xmlenc#rsa-1_5`.
    #[cfg(feature = "weak-algos")]
    RsaPkcs1V15,
}

impl KeyTransportAlgorithm {
    /// XML-Enc algorithm URI.
    pub const fn uri(self) -> &'static str {
        match self {
            Self::RsaOaep => "http://www.w3.org/2009/xmlenc11#rsa-oaep",
            Self::RsaOaepMgf1Sha1 => "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
            #[cfg(feature = "weak-algos")]
            Self::RsaPkcs1V15 => "http://www.w3.org/2001/04/xmlenc#rsa-1_5",
        }
    }

    /// Parse from XML-Enc URI. Returns `Error::DisallowedAlgorithm` for unknown
    /// URIs (including weak ones that weren't compiled in).
    pub fn from_uri(uri: &str) -> Result<Self, Error> {
        match uri {
            "http://www.w3.org/2009/xmlenc11#rsa-oaep" => Ok(Self::RsaOaep),
            "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p" => Ok(Self::RsaOaepMgf1Sha1),
            #[cfg(feature = "weak-algos")]
            "http://www.w3.org/2001/04/xmlenc#rsa-1_5" => Ok(Self::RsaPkcs1V15),
            _ => Err(Error::DisallowedAlgorithm {
                alg: uri.to_owned(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_enc_uri_roundtrip() {
        for alg in [
            DataEncryptionAlgorithm::Aes128Cbc,
            DataEncryptionAlgorithm::Aes256Cbc,
            DataEncryptionAlgorithm::Aes128Gcm,
            DataEncryptionAlgorithm::Aes256Gcm,
        ] {
            assert_eq!(DataEncryptionAlgorithm::from_uri(alg.uri()).unwrap(), alg);
        }
    }

    #[test]
    fn data_enc_from_unknown_uri_is_disallowed() {
        let err = DataEncryptionAlgorithm::from_uri("http://example.com/unknown").unwrap_err();
        match err {
            Error::DisallowedAlgorithm { alg } => assert_eq!(alg, "http://example.com/unknown"),
            other => panic!("expected DisallowedAlgorithm, got {other:?}"),
        }
    }

    #[test]
    fn data_enc_key_size_and_is_gcm() {
        assert_eq!(DataEncryptionAlgorithm::Aes128Cbc.key_size(), 16);
        assert_eq!(DataEncryptionAlgorithm::Aes256Cbc.key_size(), 32);
        assert_eq!(DataEncryptionAlgorithm::Aes128Gcm.key_size(), 16);
        assert_eq!(DataEncryptionAlgorithm::Aes256Gcm.key_size(), 32);

        assert!(!DataEncryptionAlgorithm::Aes128Cbc.is_gcm());
        assert!(!DataEncryptionAlgorithm::Aes256Cbc.is_gcm());
        assert!(DataEncryptionAlgorithm::Aes128Gcm.is_gcm());
        assert!(DataEncryptionAlgorithm::Aes256Gcm.is_gcm());
    }

    #[test]
    fn key_transport_uri_roundtrip() {
        for alg in [
            KeyTransportAlgorithm::RsaOaep,
            KeyTransportAlgorithm::RsaOaepMgf1Sha1,
        ] {
            assert_eq!(KeyTransportAlgorithm::from_uri(alg.uri()).unwrap(), alg);
        }

        #[cfg(feature = "weak-algos")]
        {
            let alg = KeyTransportAlgorithm::RsaPkcs1V15;
            assert_eq!(KeyTransportAlgorithm::from_uri(alg.uri()).unwrap(), alg);
        }
    }

    #[test]
    fn key_transport_from_unknown_uri_is_disallowed() {
        let err = KeyTransportAlgorithm::from_uri("http://example.com/unknown").unwrap_err();
        match err {
            Error::DisallowedAlgorithm { alg } => assert_eq!(alg, "http://example.com/unknown"),
            other => panic!("expected DisallowedAlgorithm, got {other:?}"),
        }
    }

    #[cfg(not(feature = "weak-algos"))]
    #[test]
    fn key_transport_rsa_pkcs1_v15_uri_rejected_without_weak_algos() {
        let err = KeyTransportAlgorithm::from_uri("http://www.w3.org/2001/04/xmlenc#rsa-1_5")
            .unwrap_err();
        match err {
            Error::DisallowedAlgorithm { alg } => {
                assert_eq!(alg, "http://www.w3.org/2001/04/xmlenc#rsa-1_5");
            }
            other => panic!("expected DisallowedAlgorithm, got {other:?}"),
        }
    }
}
