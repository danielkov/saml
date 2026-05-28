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
#[cfg(any(test, feature = "slo"))]
use crate::error::Error;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use url::Url;

/// Hard upper bound on POST-binding base64-decoded payload size. Same 10 MiB
/// cap as the Redirect binding's inflation guard.
#[cfg(any(test, feature = "slo"))]
const MAX_DECODED_BYTES: usize = 10 * 1024 * 1024;

/// Precomputed upper bound on the base64-encoded input length such that the
/// decoded output cannot exceed `MAX_DECODED_BYTES`. Each base64 char encodes
/// 6 bits → 3 output bytes per 4 input chars, plus a small slack for padding.
#[cfg(any(test, feature = "slo"))]
const MAX_BASE64_INPUT_LEN: usize = MAX_DECODED_BYTES
    .saturating_mul(4)
    .saturating_div(3)
    .saturating_add(4);

/// Encode an outbound XML payload for the HTTP-POST binding (request side).
/// `xml` must already contain any enveloped XML-DSig signature.
pub(crate) fn encode_request(
    destination: &Url,
    xml: &[u8],
    relay_state: Option<&str>,
) -> Dispatch {
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

#[cfg(any(test, feature = "slo"))]
#[derive(Debug, Clone)]
pub struct DecodedPost {
    /// Base64-decoded XML bytes (the SAML message itself).
    pub xml: Vec<u8>,
    pub relay_state: Option<String>,
}

/// Decode an inbound POST-bound payload. The caller provides the
/// base64-encoded `SAMLRequest` or `SAMLResponse` form value (after form-URL
/// decoding) and optional `RelayState`.
#[cfg(any(test, feature = "slo"))]
pub(crate) fn decode(
    saml_request_or_response_b64: &str,
    relay_state: Option<&str>,
) -> Result<DecodedPost, Error> {
    // Reject oversized payloads before decoding to avoid allocating a large
    // buffer. Any input longer than `MAX_BASE64_INPUT_LEN` cannot possibly
    // decode to ≤ MAX_DECODED_BYTES; fail fast.
    if saml_request_or_response_b64.len() > MAX_BASE64_INPUT_LEN {
        return Err(Error::Base64Decode);
    }

    let xml = BASE64
        .decode(saml_request_or_response_b64.as_bytes())
        .map_err(|_err| Error::Base64Decode)?;

    if xml.len() > MAX_DECODED_BYTES {
        return Err(Error::Base64Decode);
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
        // Any input longer than the precomputed max base64 length must be
        // rejected without allocating a >10MiB output buffer.
        // We don't need to actually fill ~14MiB — the length check is the
        // gate; build a string just past the threshold.
        let oversized = "A".repeat(MAX_BASE64_INPUT_LEN + 1);
        let err = decode(&oversized, None).unwrap_err();
        match err {
            Error::Base64Decode => {}
            other => panic!("expected Base64Decode, got {other:?}"),
        }
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
