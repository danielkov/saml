//! HTTP-Redirect binding per SAML 2.0 Bindings §3.4.
//!
//! Encoding: DEFLATE-compress raw XML bytes → base64-encode → URL-encode →
//! place in `SAMLRequest` / `SAMLResponse` query parameter. The signature, if
//! any, is detached: a base64-encoded raw signature in the `Signature`
//! parameter, with the algorithm URI in `SigAlg`. The signed bytes are the
//! URL-encoded query parameters in a spec-mandated order — `SAMLRequest=...
//! &RelayState=...&SigAlg=...` for requests, or `SAMLResponse=...&RelayState=...
//! &SigAlg=...` for responses. The decoded XML is NEVER the signed input.
//!
//! See `docs/rfcs/RFC-002-xml-crypto-core.md` §3.3.

use crate::binding::Dispatch;
use crate::error::Error;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use flate2::Compression;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use percent_encoding::{AsciiSet, CONTROLS, percent_decode_str, utf8_percent_encode};
use std::fmt::Write as _;
use std::io::{Read, Write};
use url::Url;

/// Percent-encode set covering everything except unreserved chars
/// (ALPHA / DIGIT / `-` / `_` / `.` / `~`). This matches the SAML 2.0
/// requirement that `+`, `/`, `=` (base64 characters) and all reserved
/// URI characters are percent-encoded.
const ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'!')
    .add(b'"')
    .add(b'#')
    .add(b'$')
    .add(b'%')
    .add(b'&')
    .add(b'\'')
    .add(b'(')
    .add(b')')
    .add(b'*')
    .add(b'+')
    .add(b',')
    .add(b'/')
    .add(b':')
    .add(b';')
    .add(b'<')
    .add(b'=')
    .add(b'>')
    .add(b'?')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

/// Hard upper bound on DEFLATE inflation output. Prevents zip-bomb-style
/// resource exhaustion where a tiny ciphertext expands to many gigabytes.
const MAX_INFLATED_BYTES: usize = 10 * 1024 * 1024;

/// One side of a redirect-bound SAML message direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectDirection {
    /// Outbound *request*: `SAMLRequest=...` parameter.
    Request,
    /// Outbound *response*: `SAMLResponse=...` parameter.
    Response,
}

impl RedirectDirection {
    /// The query parameter name used for the SAML payload in this direction.
    const fn param_name(self) -> &'static str {
        match self {
            RedirectDirection::Request => "SAMLRequest",
            RedirectDirection::Response => "SAMLResponse",
        }
    }
}

/// Encode an outbound XML payload for the HTTP-Redirect binding.
///
/// `destination` is the endpoint URL the SP/IdP advertises; the encoded
/// SAML payload is appended as a query parameter. `xml` is the raw SAML XML
/// (already serialized). `relay_state` is propagated round-trip if present.
///
/// The returned `Dispatch::Redirect(Url)` carries everything the caller
/// needs to issue an HTTP 302.
pub(crate) fn encode_unsigned(
    destination: &Url,
    direction: RedirectDirection,
    xml: &[u8],
    relay_state: Option<&str>,
) -> Result<Dispatch, Error> {
    let encoded_payload = deflate_and_base64(xml)?;

    let mut query = String::new();
    write_pct_pair(&mut query, direction.param_name(), &encoded_payload);
    if let Some(rs) = relay_state {
        query.push('&');
        write_pct_pair(&mut query, "RelayState", rs);
    }

    let url = append_query(destination, &query)?;
    Ok(Dispatch::Redirect(url))
}

/// Encode an outbound XML payload for the HTTP-Redirect binding, with a
/// detached signature appended.
///
/// `sig_alg_uri` is the algorithm URI to set in the `SigAlg` parameter.
/// `sign` is called with the canonical signed query string (the spec-mandated
/// concatenation, after URL-encoding, of `SAMLRequest=...&RelayState=...
/// &SigAlg=...` or `SAMLResponse=...&RelayState=...&SigAlg=...`); it returns
/// the raw signature bytes. The library does not own a `KeyPair` here — the
/// caller threads its own signer through (sp.rs / idp.rs will pass a closure
/// over the role's signing key).
pub(crate) fn encode_signed(
    destination: &Url,
    direction: RedirectDirection,
    xml: &[u8],
    relay_state: Option<&str>,
    sig_alg_uri: &str,
    sign: impl FnOnce(&[u8]) -> Result<Vec<u8>, Error>,
) -> Result<Dispatch, Error> {
    let encoded_payload = deflate_and_base64(xml)?;

    // Canonical signed query string per SAML 2.0 §3.4.4.1: spec-mandated order,
    // `RelayState=` segment omitted entirely when absent.
    let mut signed_qs = String::new();
    write_pct_pair(&mut signed_qs, direction.param_name(), &encoded_payload);
    if let Some(rs) = relay_state {
        signed_qs.push('&');
        write_pct_pair(&mut signed_qs, "RelayState", rs);
    }
    signed_qs.push('&');
    write_pct_pair(&mut signed_qs, "SigAlg", sig_alg_uri);

    let signature_bytes = sign(signed_qs.as_bytes())?;
    let signature_b64 = BASE64.encode(&signature_bytes);

    let mut full_query = signed_qs;
    full_query.push('&');
    write_pct_pair(&mut full_query, "Signature", &signature_b64);

    let url = append_query(destination, &full_query)?;
    Ok(Dispatch::Redirect(url))
}

/// Append `name=value` to `out`, percent-encoding `value` against
/// `ENCODE_SET`. `name` is assumed to already be a safe ASCII token.
fn write_pct_pair(out: &mut String, name: &str, value: &str) {
    out.push_str(name);
    out.push('=');
    // `utf8_percent_encode` is a Display-impl iterator; write directly to
    // avoid the intermediate `.to_string()` allocation.
    let _ = write!(out, "{}", utf8_percent_encode(value, ENCODE_SET));
}

/// Decoded fields extracted from an inbound Redirect-bound request.
#[derive(Debug, Clone)]
pub struct DecodedRedirect {
    /// DEFLATE-decompressed XML bytes.
    pub xml: Vec<u8>,
    pub relay_state: Option<String>,
    /// Detached signature bytes (base64-decoded), if `Signature` was present.
    pub signature: Option<Vec<u8>>,
    /// `SigAlg` URI, if `SigAlg` was present.
    pub sig_alg: Option<String>,
    /// Canonical query string that was signed, IFF `Signature` was present.
    /// This is what the verifier hashes — NOT the decoded XML. See SAML 2.0
    /// §3.4.4.1.
    pub signed_query_string: Option<String>,
}

/// Decode an inbound Redirect-bound payload.
///
/// `raw_query_string` is the exact, percent-encoded query string the SP/IdP
/// received in the request URL (everything after `?`, before `#`). The
/// function picks out `SAMLRequest` / `SAMLResponse` / `RelayState` /
/// `Signature` / `SigAlg` and reconstructs the canonical signed-input bytes
/// per spec.
pub(crate) fn decode(
    raw_query_string: &str,
    direction: RedirectDirection,
) -> Result<DecodedRedirect, Error> {
    let param_name = direction.param_name();

    let mut saml_raw: Option<&str> = None;
    let mut relay_state_raw: Option<&str> = None;
    let mut sig_alg_raw: Option<&str> = None;
    let mut signature_raw: Option<&str> = None;
    let mut has_signature_pair = false;

    // Iterate raw pairs preserving the sender's percent-encoding.
    for pair in raw_query_string.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some(kv) => kv,
            None => (pair, ""),
        };
        match k {
            n if n == param_name => saml_raw = Some(v),
            "RelayState" => relay_state_raw = Some(v),
            "SigAlg" => sig_alg_raw = Some(v),
            "Signature" => {
                signature_raw = Some(v);
                has_signature_pair = true;
            }
            _ => {}
        }
    }

    let saml_pct = saml_raw.ok_or(Error::InvalidConfiguration {
        reason: "missing SAMLRequest/SAMLResponse parameter",
    })?;

    let saml_b64 = pct_decode(saml_pct)?;
    let deflated = BASE64
        .decode(saml_b64.as_bytes())
        .map_err(|_| Error::Base64Decode)?;
    let xml = inflate_capped(&deflated)?;

    let relay_state = relay_state_raw.map(pct_decode).transpose()?;
    let sig_alg = sig_alg_raw.map(pct_decode).transpose()?;

    let signature = match signature_raw {
        Some(sig_pct) => {
            let sig_b64 = pct_decode(sig_pct)?;
            let bytes = BASE64
                .decode(sig_b64.as_bytes())
                .map_err(|_| Error::Base64Decode)?;
            Some(bytes)
        }
        None => None,
    };

    // Reconstruct the canonical signed query string. Per SAML 2.0 §3.4.4.1:
    // preserve the exact bytes sent for SAMLRequest/SAMLResponse, RelayState,
    // and SigAlg in the spec-mandated order, omitting the Signature pair.
    let signed_query_string = if has_signature_pair {
        let mut qs = format!("{}={}", param_name, saml_pct);
        if let Some(rs) = relay_state_raw {
            qs.push_str("&RelayState=");
            qs.push_str(rs);
        }
        if let Some(sa) = sig_alg_raw {
            qs.push_str("&SigAlg=");
            qs.push_str(sa);
        }
        Some(qs)
    } else {
        None
    };

    Ok(DecodedRedirect {
        xml,
        relay_state,
        signature,
        sig_alg,
        signed_query_string,
    })
}

// ── helpers ───────────────────────────────────────────────────────────

/// Percent-decode a single query-string value into an owned UTF-8 string.
/// UTF-8 decode failures surface as `Error::Base64Decode` (we don't have a
/// distinct percent-decode error variant, and the caller's next step on these
/// values is always a base64 decode anyway).
fn pct_decode(value: &str) -> Result<String, Error> {
    percent_decode_str(value)
        .decode_utf8()
        .map(|cow| cow.into_owned())
        .map_err(|_| Error::Base64Decode)
}

/// DEFLATE-compress `xml` (raw deflate, no zlib header) and base64-encode.
fn deflate_and_base64(xml: &[u8]) -> Result<String, Error> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(xml)
        .map_err(|e| Error::XmlEmit(format!("DEFLATE write failed: {e}")))?;
    let deflated = encoder
        .finish()
        .map_err(|e| Error::XmlEmit(format!("DEFLATE finish failed: {e}")))?;
    Ok(BASE64.encode(&deflated))
}

/// DEFLATE-decompress, capping the output at `MAX_INFLATED_BYTES`.
fn inflate_capped(deflated: &[u8]) -> Result<Vec<u8>, Error> {
    let mut decoder = DeflateDecoder::new(deflated);
    // Cap at MAX_INFLATED_BYTES + 1 so we can detect over-limit reads.
    let mut buf = Vec::new();
    let limit = MAX_INFLATED_BYTES as u64 + 1;
    let mut limited = (&mut decoder).take(limit);
    limited
        .read_to_end(&mut buf)
        .map_err(|_| Error::Inflate)?;
    if buf.len() > MAX_INFLATED_BYTES {
        return Err(Error::Inflate);
    }
    Ok(buf)
}

/// Append a `query` string to `base`. If `base` already has a query, the
/// new pairs are joined with `&`; otherwise a `?` is prepended.
fn append_query(base: &Url, query: &str) -> Result<Url, Error> {
    let mut s = base.as_str().to_string();
    // Strip fragment if any (URLs in SAML endpoints shouldn't have one, but
    // be defensive).
    if let Some(fragment_start) = s.find('#') {
        s.truncate(fragment_start);
    }
    if s.contains('?') {
        if !s.ends_with('?') && !s.ends_with('&') {
            s.push('&');
        }
    } else {
        s.push('?');
    }
    s.push_str(query);
    Url::parse(&s).map_err(|_| Error::InvalidConfiguration {
        reason: "destination URL is not a valid base URL",
    })
}

// ── tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::Dispatch;

    fn dest() -> Url {
        Url::parse("https://idp.example.com/sso").unwrap()
    }

    fn extract_query(d: &Dispatch) -> String {
        match d {
            Dispatch::Redirect(url) => url.query().expect("redirect has query").to_string(),
            _ => panic!("expected Redirect"),
        }
    }

    #[test]
    fn unsigned_roundtrip_request() {
        let xml = b"<samlp:AuthnRequest/>";
        let dispatch = encode_unsigned(&dest(), RedirectDirection::Request, xml, None).unwrap();
        let query = extract_query(&dispatch);
        let decoded = decode(&query, RedirectDirection::Request).unwrap();
        assert_eq!(decoded.xml, xml);
        assert!(decoded.relay_state.is_none());
        assert!(decoded.signature.is_none());
        assert!(decoded.sig_alg.is_none());
        assert!(decoded.signed_query_string.is_none());
    }

    #[test]
    fn unsigned_roundtrip_response() {
        let xml = b"<samlp:Response/>";
        let dispatch = encode_unsigned(&dest(), RedirectDirection::Response, xml, None).unwrap();
        let query = extract_query(&dispatch);
        let decoded = decode(&query, RedirectDirection::Response).unwrap();
        assert_eq!(decoded.xml, xml);
    }

    #[test]
    fn unsigned_roundtrip_with_relay_state() {
        let xml = b"<samlp:AuthnRequest ID=\"_abc\"/>";
        let relay = "https://sp.example.com/resource?id=42&foo=bar";
        let dispatch =
            encode_unsigned(&dest(), RedirectDirection::Request, xml, Some(relay)).unwrap();
        let query = extract_query(&dispatch);
        let decoded = decode(&query, RedirectDirection::Request).unwrap();
        assert_eq!(decoded.xml, xml);
        assert_eq!(decoded.relay_state.as_deref(), Some(relay));
    }

    #[test]
    fn encoded_payload_has_no_raw_base64_special_chars_in_query() {
        // The percent-encoded query string MUST NOT contain raw `+`, `/`, or
        // `=` from base64 — they must be percent-encoded.
        let xml = vec![0u8; 256]; // forces base64 with `=` padding and likely `+/`
        let dispatch =
            encode_unsigned(&dest(), RedirectDirection::Request, &xml, None).unwrap();
        let query = extract_query(&dispatch);
        // After the `SAMLRequest=` literal, no raw `+`, `/`, or `=` should
        // appear (the literal `=` after `SAMLRequest` is the only one).
        let value = query.strip_prefix("SAMLRequest=").unwrap();
        assert!(!value.contains('+'), "raw `+` leaked into query: {value}");
        assert!(!value.contains('/'), "raw `/` leaked into query: {value}");
        assert!(!value.contains('='), "raw `=` leaked into query: {value}");
    }

    #[test]
    fn decode_precomputed_payload() {
        // Precomputed: DEFLATE + base64 of the literal bytes `<r/>`.
        // We build the payload deterministically and assert decode returns
        // the same bytes.
        let xml = b"<r/>";
        let encoded = deflate_and_base64(xml).unwrap();
        let payload_pct = utf8_percent_encode(&encoded, ENCODE_SET).to_string();
        let query = format!("SAMLRequest={payload_pct}");
        let decoded = decode(&query, RedirectDirection::Request).unwrap();
        assert_eq!(decoded.xml, xml);
    }

    #[test]
    fn decode_ignores_unknown_params() {
        let xml = b"<r/>";
        let encoded = deflate_and_base64(xml).unwrap();
        let payload_pct = utf8_percent_encode(&encoded, ENCODE_SET).to_string();
        let query = format!("foo=bar&SAMLRequest={payload_pct}&baz=qux");
        let decoded = decode(&query, RedirectDirection::Request).unwrap();
        assert_eq!(decoded.xml, xml);
    }

    #[test]
    fn decode_missing_saml_param() {
        let err = decode("RelayState=foo", RedirectDirection::Request).unwrap_err();
        match err {
            Error::InvalidConfiguration { reason } => {
                assert!(reason.contains("SAMLRequest"));
            }
            other => panic!("expected InvalidConfiguration, got {other:?}"),
        }
    }

    #[test]
    fn signed_encode_decode_roundtrip() {
        let xml = b"<samlp:AuthnRequest ID=\"_x\"/>";
        let sig_alg = "test-alg";
        let dispatch = encode_signed(
            &dest(),
            RedirectDirection::Request,
            xml,
            None,
            sig_alg,
            |signed_bytes| {
                // Stash for verification that signer received the canonical bytes.
                assert!(signed_bytes.starts_with(b"SAMLRequest="));
                assert!(signed_bytes.ends_with(b"&SigAlg=test-alg"));
                Ok(vec![0u8; 64])
            },
        )
        .unwrap();

        let query = extract_query(&dispatch);
        let decoded = decode(&query, RedirectDirection::Request).unwrap();
        assert_eq!(decoded.xml, xml);
        assert_eq!(decoded.signature, Some(vec![0u8; 64]));
        assert_eq!(decoded.sig_alg.as_deref(), Some("test-alg"));
        assert!(decoded.signed_query_string.is_some());
    }

    #[test]
    fn signed_canonical_query_string_round_trip_identity() {
        // Property: the bytes passed to `sign` during encode_signed MUST
        // equal the `signed_query_string` returned by decode.
        let xml = b"<samlp:AuthnRequest ID=\"_y\"/>";
        let relay = "state-token-123";
        let sig_alg = "urn:test:alg";

        let captured_signed_bytes: std::cell::RefCell<Option<Vec<u8>>> =
            std::cell::RefCell::new(None);

        let dispatch = encode_signed(
            &dest(),
            RedirectDirection::Request,
            xml,
            Some(relay),
            sig_alg,
            |signed_bytes| {
                *captured_signed_bytes.borrow_mut() = Some(signed_bytes.to_vec());
                Ok(vec![1u8; 32])
            },
        )
        .unwrap();

        let query = extract_query(&dispatch);
        let decoded = decode(&query, RedirectDirection::Request).unwrap();

        let encoded_signed = captured_signed_bytes.into_inner().unwrap();
        let decoded_signed = decoded.signed_query_string.unwrap();
        assert_eq!(
            decoded_signed.as_bytes(),
            encoded_signed.as_slice(),
            "canonical signed query string must round-trip byte-for-byte"
        );
    }

    #[test]
    fn signed_response_canonical_order_uses_samlresponse() {
        let xml = b"<samlp:Response ID=\"_r\"/>";
        let dispatch = encode_signed(
            &dest(),
            RedirectDirection::Response,
            xml,
            Some("rs"),
            "alg-x",
            |signed_bytes| {
                let s = std::str::from_utf8(signed_bytes).unwrap();
                assert!(s.starts_with("SAMLResponse="));
                assert!(s.contains("&RelayState=rs"));
                assert!(s.ends_with("&SigAlg=alg-x"));
                Ok(vec![7u8; 16])
            },
        )
        .unwrap();
        let query = extract_query(&dispatch);
        let decoded = decode(&query, RedirectDirection::Response).unwrap();
        assert_eq!(decoded.xml, xml);
        assert_eq!(decoded.relay_state.as_deref(), Some("rs"));
        assert_eq!(decoded.sig_alg.as_deref(), Some("alg-x"));
        assert_eq!(decoded.signature, Some(vec![7u8; 16]));
    }

    #[test]
    fn signed_without_relay_state_omits_segment_entirely() {
        let xml = b"<samlp:AuthnRequest/>";
        let dispatch = encode_signed(
            &dest(),
            RedirectDirection::Request,
            xml,
            None,
            "alg-y",
            |signed_bytes| {
                let s = std::str::from_utf8(signed_bytes).unwrap();
                assert!(!s.contains("RelayState"), "RelayState must be omitted: {s}");
                assert!(s.contains("&SigAlg=alg-y"));
                Ok(vec![2u8; 8])
            },
        )
        .unwrap();
        let _ = dispatch;
    }

    #[test]
    fn decode_unsigned_when_no_signature_param() {
        let xml = b"<r/>";
        let encoded = deflate_and_base64(xml).unwrap();
        let payload_pct = utf8_percent_encode(&encoded, ENCODE_SET).to_string();
        // Has SigAlg but no Signature → signed_query_string must still be None.
        let query = format!("SAMLRequest={payload_pct}&SigAlg=anything");
        let decoded = decode(&query, RedirectDirection::Request).unwrap();
        assert!(decoded.signature.is_none());
        assert!(decoded.signed_query_string.is_none());
        assert_eq!(decoded.sig_alg.as_deref(), Some("anything"));
    }

    #[test]
    fn malformed_base64_yields_base64_decode_error() {
        // `!!!!` percent-encoded is not valid base64 (wrong alphabet).
        let query = "SAMLRequest=%21%21%21%21";
        let err = decode(query, RedirectDirection::Request).unwrap_err();
        match err {
            Error::Base64Decode => {}
            other => panic!("expected Base64Decode, got {other:?}"),
        }
    }

    #[test]
    fn zip_bomb_defense_oversize_inflation_rejected() {
        // Build a DEFLATE payload that decompresses to MAX + 1 bytes.
        let huge = vec![b'A'; MAX_INFLATED_BYTES + 1];
        let mut enc = DeflateEncoder::new(Vec::new(), Compression::best());
        enc.write_all(&huge).unwrap();
        let deflated = enc.finish().unwrap();
        let b64 = BASE64.encode(&deflated);
        let pct = utf8_percent_encode(&b64, ENCODE_SET).to_string();
        let query = format!("SAMLRequest={pct}");

        let err = decode(&query, RedirectDirection::Request).unwrap_err();
        match err {
            Error::Inflate => {}
            other => panic!("expected Inflate, got {other:?}"),
        }
    }

    #[test]
    fn append_query_preserves_existing_query() {
        let base = Url::parse("https://idp.example.com/sso?tenant=foo").unwrap();
        let xml = b"<x/>";
        let dispatch = encode_unsigned(&base, RedirectDirection::Request, xml, None).unwrap();
        let url = match dispatch {
            Dispatch::Redirect(u) => u,
            _ => panic!("expected Redirect"),
        };
        let q = url.query().unwrap();
        assert!(q.starts_with("tenant=foo&SAMLRequest="), "got {q}");
    }
}
