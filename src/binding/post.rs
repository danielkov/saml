//! HTTP-POST binding per SAML 2.0 Bindings §3.5.
//!
//! Encoding: base64-encode the XML bytes into a `SAMLRequest` / `SAMLResponse`
//! form field, plus an optional `RelayState` form field. The caller renders
//! an auto-submitting HTML form (or uses any other transport that delivers
//! a `POST application/x-www-form-urlencoded` body). The signature, if any,
//! is enveloped inside the XML (XML-DSig); no detached signature.
//!
//! See `docs/rfcs/RFC-002-xml-crypto-core.md` §3 (XML-DSig path).

use crate::binding::{Dispatch, PostForm, SsoResponseDispatch, SsoResponsePostForm};
use crate::error::Error;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use url::Url;

/// Default upper bound on POST-binding base64-decoded payload size. Same
/// 10 MiB cap as the Redirect binding's inflation guard.
pub const DEFAULT_MAX_DECODED_BYTES: usize = 10 * 1024 * 1024;

/// Encode an outbound XML payload for the HTTP-POST binding (request side).
/// `xml` must already contain any enveloped XML-DSig signature.
pub(crate) fn encode_request(destination: &Url, xml: &[u8], relay_state: Option<&str>) -> Dispatch {
    Dispatch::Post(PostForm {
        action: destination.clone(),
        saml_request: Some(BASE64.encode(xml)),
        saml_response: None,
        relay_state: relay_state.map(str::to_owned),
    })
}

/// Encode an outbound XML payload for the HTTP-POST binding (response side).
/// `xml` must already contain any enveloped XML-DSig signature.
#[cfg(any(test, feature = "slo"))]
pub(crate) fn encode_response(
    destination: &Url,
    xml: &[u8],
    relay_state: Option<&str>,
) -> Dispatch {
    Dispatch::Post(PostForm {
        action: destination.clone(),
        saml_request: None,
        saml_response: Some(BASE64.encode(xml)),
        relay_state: relay_state.map(str::to_owned),
    })
}

/// Encode an outbound `<samlp:Response>` for the HTTP-POST binding into an
/// `SsoResponseDispatch::Post` (type-narrowed: only POST or Artifact for SSO
/// Responses per SAML 2.0 Profiles §4.1.4).
pub(crate) fn encode_sso_response(
    destination: &Url,
    xml: &[u8],
    relay_state: Option<&str>,
) -> SsoResponseDispatch {
    SsoResponseDispatch::Post(SsoResponsePostForm {
        action: destination.clone(),
        saml_response: BASE64.encode(xml),
        relay_state: relay_state.map(str::to_owned),
    })
}

#[derive(Debug, Clone)]
pub struct DecodedPost {
    /// Base64-decoded XML bytes (the SAML message itself).
    pub xml: Vec<u8>,
    pub relay_state: Option<String>,
}

/// Decode an inbound POST-bound payload. The caller provides the
/// base64-encoded `SAMLRequest` or `SAMLResponse` form value (after form-URL
/// decoding) and optional `RelayState`.
pub fn decode(
    saml_request_or_response_b64: &str,
    relay_state: Option<&str>,
) -> Result<DecodedPost, Error> {
    decode_with_limit(
        saml_request_or_response_b64,
        relay_state,
        DEFAULT_MAX_DECODED_BYTES,
    )
}

/// Decode an inbound POST-bound payload with a caller-selected decoded-size
/// limit. ASCII whitespace in Base64 is accepted for interoperability with
/// line-wrapping IdPs, but bounded before allocating the cleaned input.
pub fn decode_with_limit(
    saml_request_or_response_b64: &str,
    relay_state: Option<&str>,
    max_decoded_bytes: usize,
) -> Result<DecodedPost, Error> {
    let max_base64_input_len = max_decoded_bytes
        .checked_add(2)
        .and_then(|value| value.checked_div(3))
        .and_then(|value| value.checked_mul(4))
        .and_then(|value| value.checked_add(4))
        .ok_or(Error::MessageTooLarge {
            limit: max_decoded_bytes,
        })?;

    // Reject oversized payloads before decoding to avoid allocating a large
    // buffer. A second bound permits ordinary line wrapping without allowing
    // unbounded whitespace amplification.
    let max_raw_input_len = max_base64_input_len.saturating_mul(2);
    if saml_request_or_response_b64.len() > max_raw_input_len {
        return Err(Error::MessageTooLarge {
            limit: max_decoded_bytes,
        });
    }
    let meaningful_len = saml_request_or_response_b64
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .count();
    if meaningful_len > max_base64_input_len {
        return Err(Error::MessageTooLarge {
            limit: max_decoded_bytes,
        });
    }

    let cleaned = saml_request_or_response_b64
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    let xml = BASE64.decode(cleaned).map_err(|_err| Error::Base64Decode)?;

    if xml.len() > max_decoded_bytes {
        return Err(Error::MessageTooLarge {
            limit: max_decoded_bytes,
        });
    }

    Ok(DecodedPost {
        xml,
        relay_state: relay_state.map(str::to_owned),
    })
}

// ── tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn dest() -> Url {
        Url::parse("https://sp.example.com/acs").unwrap()
    }

    #[test]
    fn encode_decode_roundtrip_request() {
        let xml = b"<samlp:AuthnRequest ID=\"_a\"/>";
        let dispatch = encode_request(&dest(), xml, None);
        let Dispatch::Post(form) = dispatch else {
            panic!("expected Post");
        };
        assert_eq!(form.action, dest());
        let b64 = form.saml_request.unwrap();
        assert!(form.saml_response.is_none());
        assert!(form.relay_state.is_none());

        let decoded = decode(&b64, None).unwrap();
        assert_eq!(decoded.xml, xml);
        assert!(decoded.relay_state.is_none());
    }

    #[test]
    fn encode_decode_roundtrip_response_with_relay_state() {
        let xml = b"<samlp:LogoutResponse/>";
        let relay = "opaque-state-blob";
        let dispatch = encode_response(&dest(), xml, Some(relay));
        let Dispatch::Post(form) = dispatch else {
            panic!("expected Post");
        };
        let b64 = form.saml_response.unwrap();
        assert!(form.saml_request.is_none());
        assert_eq!(form.relay_state.as_deref(), Some(relay));

        let decoded = decode(&b64, Some(relay)).unwrap();
        assert_eq!(decoded.xml, xml);
        assert_eq!(decoded.relay_state.as_deref(), Some(relay));
    }

    #[test]
    fn encode_sso_response_produces_post_variant() {
        let xml = b"<samlp:Response ID=\"_x\"/>";
        let dispatch = encode_sso_response(&dest(), xml, Some("rs"));
        let SsoResponseDispatch::Post(form) = dispatch else {
            panic!("expected Post");
        };
        assert_eq!(form.action, dest());
        assert_eq!(form.relay_state.as_deref(), Some("rs"));
        let decoded = decode(&form.saml_response, form.relay_state.as_deref()).unwrap();
        assert_eq!(decoded.xml, xml);
        assert_eq!(decoded.relay_state.as_deref(), Some("rs"));
    }

    #[test]
    fn encode_sso_response_without_relay_state() {
        let xml = b"<samlp:Response/>";
        let dispatch = encode_sso_response(&dest(), xml, None);
        let SsoResponseDispatch::Post(form) = dispatch else {
            panic!("expected Post");
        };
        assert!(form.relay_state.is_none());
        let decoded = decode(&form.saml_response, None).unwrap();
        assert_eq!(decoded.xml, xml);
    }

    #[test]
    fn decode_malformed_base64_errors() {
        // `!!!!` is not valid standard-alphabet base64.
        let err = decode("!!!!", None).unwrap_err();
        match err {
            Error::Base64Decode => {}
            other => panic!("expected Base64Decode, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_oversized_input_before_decoding() {
        let oversized = BASE64.encode([b'X'; 17]);
        let err = decode_with_limit(&oversized, None, 16).unwrap_err();
        match err {
            Error::MessageTooLarge { limit: 16 } => {}
            other => panic!("expected MessageTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_whitespace_amplification() {
        // The meaningful Base64 content is empty, but the raw form value is
        // still bounded so line-wrapping tolerance cannot become a cheap CPU
        // or allocation amplification primitive.
        let oversized_whitespace = " ".repeat(57);
        let err = decode_with_limit(&oversized_whitespace, None, 16).unwrap_err();
        assert!(matches!(err, Error::MessageTooLarge { limit: 16 }));
    }

    #[test]
    fn decode_accepts_line_wrapped_base64() {
        let payload = b"<samlp:Response ID=\"_wrapped\"/>";
        let encoded = BASE64.encode(payload);
        let wrapped = encoded
            .as_bytes()
            .chunks(8)
            .map(|chunk| std::str::from_utf8(chunk).expect("Base64 is ASCII"))
            .collect::<Vec<_>>()
            .join("\r\n");

        let decoded = decode_with_limit(&wrapped, Some("relay"), 1024).unwrap();
        assert_eq!(decoded.xml, payload);
        assert_eq!(decoded.relay_state.as_deref(), Some("relay"));
    }

    #[test]
    fn decode_below_size_limit_succeeds() {
        // Verify a non-trivial (but small) payload round-trips. The full
        // MAX_DECODED_BYTES path is exercised conceptually by the length
        // gate above; this keeps the test suite fast.
        let payload = vec![b'X'; 1024];
        let b64 = BASE64.encode(&payload);
        let decoded = decode(&b64, None).unwrap();
        assert_eq!(decoded.xml.len(), 1024);
    }

    #[test]
    fn encode_request_uses_standard_base64_with_padding() {
        // 1 byte input → 4 base64 chars with two `=` padding chars.
        let dispatch = encode_request(&dest(), b"A", None);
        let Dispatch::Post(form) = dispatch else {
            panic!("expected Post");
        };
        let b64 = form.saml_request.unwrap();
        assert_eq!(b64, "QQ==");
    }
}
