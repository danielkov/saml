//! HMAC-signed session cookie.
//!
//! Layout: `<base64url(json_payload)>.<base64url(hmac_sha256)>`. Verification
//! is constant-time so a forged signature can't be guessed by timing the
//! response. This is NOT an encrypted cookie - the payload (NameID, email,
//! attributes) is readable by anyone who has the cookie. That's the same
//! property as a typical signed-session-cookie setup (Rails, Express,
//! `tower-sessions` default backend); the cookie integrity check is what
//! keeps the SP from trusting a tampered payload.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Maximum age of a session cookie before we treat it as expired, even if the
/// HMAC still verifies. Mirrors the IdP's SessionNotOnOrAfter when available.
pub const SESSION_TTL_SECS: u64 = 8 * 60 * 60;

pub const COOKIE_NAME: &str = "saml_demo_session";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionAttribute {
    pub name: String,
    pub friendly_name: Option<String>,
    pub values: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub name_id_value: String,
    pub name_id_format: String,
    pub session_index: Option<String>,
    pub authn_instant_unix: u64,
    pub issued_at_unix: u64,
    pub idp_entity_id: String,
    /// Provider slug we matched the inbound Response to. Mirrors the
    /// `[[provider]].id` from `providers.toml` and is what the dashboard
    /// uses to look up the per-vendor attribute mappings.
    pub provider_id: String,
    pub attributes: Vec<SessionAttribute>,
}

impl Session {
    /// Best-effort lookup of an attribute by either the full `Name` URI or
    /// its FriendlyName.
    pub fn attribute(&self, key: &str) -> Option<&SessionAttribute> {
        self.attributes
            .iter()
            .find(|a| a.name == key || a.friendly_name.as_deref() == Some(key))
    }

    /// First value of the named attribute, if any.
    pub fn attribute_first(&self, key: &str) -> Option<&str> {
        self.attribute(key)
            .and_then(|a| a.values.first().map(String::as_str))
    }

    /// Walk an ordered list of attribute names and return the first hit's
    /// first value. Used by the dashboard's per-provider lookup tables.
    pub fn attribute_first_of(&self, keys: &[String]) -> Option<&str> {
        for k in keys {
            if let Some(v) = self.attribute_first(k) {
                return Some(v);
            }
        }
        None
    }
}

/// Session cookie decode/verify error. We hand-roll `Display` + `Error`
/// rather than pull in `thiserror` for a four-variant enum.
#[derive(Debug)]
pub enum SessionError {
    Malformed,
    BadSignature,
    BadPayload,
    Expired,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed => f.write_str("session cookie is malformed"),
            Self::BadSignature => f.write_str("session cookie signature does not verify"),
            Self::BadPayload => f.write_str("session cookie payload is not valid JSON"),
            Self::Expired => f.write_str("session cookie is past its TTL"),
        }
    }
}
impl std::error::Error for SessionError {}

pub fn encode(session: &Session, key: &[u8]) -> Result<String, SessionError> {
    let json = serde_json::to_vec(session).map_err(|_| SessionError::BadPayload)?;
    let payload_b64 = B64.encode(&json);

    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| SessionError::BadSignature)?;
    mac.update(payload_b64.as_bytes());
    let tag = mac.finalize().into_bytes();
    let tag_b64 = B64.encode(tag);

    Ok(format!("{payload_b64}.{tag_b64}"))
}

pub fn decode(cookie_value: &str, key: &[u8], now_unix: u64) -> Result<Session, SessionError> {
    let (payload_b64, tag_b64) = cookie_value.split_once('.').ok_or(SessionError::Malformed)?;

    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| SessionError::BadSignature)?;
    mac.update(payload_b64.as_bytes());
    let expected = mac.finalize().into_bytes();

    let provided = B64.decode(tag_b64).map_err(|_| SessionError::Malformed)?;
    if expected.ct_eq(provided.as_slice()).unwrap_u8() != 1 {
        return Err(SessionError::BadSignature);
    }

    let payload = B64.decode(payload_b64).map_err(|_| SessionError::Malformed)?;
    let session: Session = serde_json::from_slice(&payload).map_err(|_| SessionError::BadPayload)?;

    let age = now_unix.saturating_sub(session.issued_at_unix);
    if age > SESSION_TTL_SECS {
        return Err(SessionError::Expired);
    }

    Ok(session)
}

/// Build the `Set-Cookie` header value for the session. Uses `HttpOnly`,
/// `SameSite=Lax` (so the IdP can POST back to us cross-site), `Path=/`, and
/// `Max-Age=<TTL>`. `Secure` is intentionally omitted because the demo runs
/// over plain HTTP on localhost; in production this should be unconditionally
/// set.
pub fn set_cookie_header(value: &str) -> String {
    format!("{COOKIE_NAME}={value}; HttpOnly; SameSite=Lax; Path=/; Max-Age={SESSION_TTL_SECS}")
}

pub fn clear_cookie_header() -> String {
    format!("{COOKIE_NAME}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0")
}

pub fn extract_cookie_value(header: &str) -> Option<&str> {
    for piece in header.split(';') {
        let piece = piece.trim();
        if let Some(rest) = piece.strip_prefix(&format!("{COOKIE_NAME}=")) {
            return Some(rest);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        [0x42u8; 32]
    }

    fn sample() -> Session {
        Session {
            name_id_value: "alice@saml-demo.test".into(),
            name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".into(),
            session_index: Some("idx-1".into()),
            authn_instant_unix: 1_700_000_000,
            issued_at_unix: 1_700_000_000,
            idp_entity_id: "https://example.com/idp".into(),
            provider_id: "zitadel".into(),
            attributes: vec![SessionAttribute {
                name: "Email".into(),
                friendly_name: Some("Email".into()),
                values: vec!["alice@saml-demo.test".into()],
            }],
        }
    }

    #[test]
    fn roundtrip_encode_decode() {
        let s = sample();
        let cookie = encode(&s, &key()).unwrap();
        let back = decode(&cookie, &key(), 1_700_000_001).unwrap();
        assert_eq!(back.name_id_value, s.name_id_value);
        assert_eq!(back.provider_id, "zitadel");
    }

    #[test]
    fn tampered_payload_fails_verification() {
        let s = sample();
        let cookie = encode(&s, &key()).unwrap();
        let (head, tail) = cookie.split_once('.').unwrap();
        let mut bytes = head.as_bytes().to_vec();
        if let Some(b) = bytes.first_mut() {
            *b ^= 0x01;
        }
        let tampered = format!("{}.{}", String::from_utf8(bytes).unwrap(), tail);
        match decode(&tampered, &key(), 1_700_000_001) {
            Err(SessionError::BadSignature | SessionError::Malformed) => {}
            other => panic!("expected BadSignature/Malformed, got {other:?}"),
        }
    }

    #[test]
    fn expired_cookie_rejected() {
        let s = sample();
        let cookie = encode(&s, &key()).unwrap();
        let way_later = 1_700_000_000_u64 + SESSION_TTL_SECS + 60;
        assert!(matches!(
            decode(&cookie, &key(), way_later),
            Err(SessionError::Expired)
        ));
    }

    #[test]
    fn extract_cookie_value_picks_named_cookie() {
        let h = format!("foo=bar; {COOKIE_NAME}=abc.def; baz=qux");
        assert_eq!(extract_cookie_value(&h), Some("abc.def"));
    }

    #[test]
    fn extract_cookie_value_returns_none_when_absent() {
        let h = "foo=bar; baz=qux";
        assert_eq!(extract_cookie_value(h), None);
    }

    #[test]
    fn attribute_first_of_walks_ordered_keys() {
        let s = sample();
        assert_eq!(
            s.attribute_first_of(&["nope".into(), "Email".into()]),
            Some("alice@saml-demo.test")
        );
        assert_eq!(
            s.attribute_first_of(&["nope".into(), "alsonope".into()]),
            None
        );
    }
}
