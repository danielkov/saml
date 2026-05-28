//! HMAC-signed session cookie. Mirrors the demo SP's cookie shape: the
//! payload is a JSON-serialized [`Session`], base64-URL encoded, with an
//! HMAC-SHA256 tag appended after a `.` separator. Verification is
//! constant-time so a forged signature can't be guessed by timing.
//!
//! This is NOT an encrypted cookie. Anyone with the cookie can read the
//! payload; the HMAC is what stops them from forging a different one. The
//! demo runs over plain HTTP on localhost; in production this cookie
//! would carry `Secure` unconditionally.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Maximum age of a session cookie before it's treated as expired, even
/// if the HMAC still verifies. The IdP also issues SAML SessionIndex
/// values; this TTL is the SP-side analogue for its own UI session.
pub const SESSION_TTL_SECS: u64 = 8 * 60 * 60;

pub const COOKIE_NAME: &str = "saml_idp_session";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Local user id from `users.toml` (`alice`, `bob`, …).
    pub user_id: String,
    /// Email address asserted to SPs as the NameID value when the SP
    /// requests EmailAddress format.
    pub email: String,
    /// `<first_name> <last_name>` join, surfaced as the `displayName`
    /// attribute and used to render the consent / landing screens.
    pub display_name: String,
    /// SessionIndex value attached to every Assertion issued during this
    /// session. The SP can use it to target SLO at this specific session.
    pub session_index: String,
    /// `authn_instant` of the user's actual password validation. SAML
    /// requires this on every Assertion the IdP issues during the
    /// session, so we capture it once at login time.
    pub authn_instant_unix: u64,
    /// Unix timestamp of cookie issuance. Used together with
    /// [`SESSION_TTL_SECS`] to expire stale sessions before the SP-side
    /// `Max-Age` would.
    pub issued_at_unix: u64,
}

/// Session cookie decode/verify error.
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
    let session: Session =
        serde_json::from_slice(&payload).map_err(|_| SessionError::BadPayload)?;

    let age = now_unix.saturating_sub(session.issued_at_unix);
    if age > SESSION_TTL_SECS {
        return Err(SessionError::Expired);
    }

    Ok(session)
}

/// Build the `Set-Cookie` header value for a freshly-issued session. Uses
/// `HttpOnly`, `SameSite=Lax`, `Path=/`, and a TTL matching
/// [`SESSION_TTL_SECS`]. `Secure` is intentionally omitted because the
/// demo runs over plain HTTP on localhost.
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
        [0x77u8; 32]
    }

    fn sample() -> Session {
        Session {
            user_id: "alice".into(),
            email: "alice@saml-demo.local".into(),
            display_name: "Alice Anderson".into(),
            session_index: "idx-1".into(),
            authn_instant_unix: 1_700_000_000,
            issued_at_unix: 1_700_000_000,
        }
    }

    #[test]
    fn roundtrip_encode_decode() {
        let s = sample();
        let cookie = encode(&s, &key()).unwrap();
        let back = decode(&cookie, &key(), 1_700_000_001).unwrap();
        assert_eq!(back.email, s.email);
        assert_eq!(back.user_id, "alice");
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
}
