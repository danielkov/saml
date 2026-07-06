//! Common Domain Cookie profile (SAML 2.0 Profiles §4.3).
//!
//! Federation members share a *common domain* (e.g. `cd.example-fed.org`).
//! After each successful authentication an IdP appends its entityID to the
//! `_saml_idp` cookie scoped to that domain; an SP wanting to discover the
//! user's IdP reads the cookie back from its own presence in the common
//! domain. The cookie value is a space-separated list of base64-encoded
//! entityIDs, most recently used **last** (Profiles §4.3.1).
//!
//! [`CommonDomainCookie`] is a pure value codec — reading the `Cookie`
//! header and writing `Set-Cookie` (domain, `Secure`, expiry) stay with the
//! caller. On the wire the space separator is percent-encoded (`%20`) since
//! a raw space is not a valid cookie octet (RFC 6265 §4.1.1); base64's
//! alphabet needs no escaping. [`parse`](CommonDomainCookie::parse) accepts
//! both the raw and the percent-encoded form.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use percent_encoding::percent_decode_str;

use crate::error::Error;

/// Cookie name fixed by SAML 2.0 Profiles §4.3.1.
pub const COMMON_DOMAIN_COOKIE_NAME: &str = "_saml_idp";

/// Decoded view of the `_saml_idp` common-domain cookie value.
///
/// `entity_ids` is ordered oldest-first; the last entry is the most recently
/// used IdP (the one an SP should try first).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommonDomainCookie {
    pub entity_ids: Vec<String>,
}

impl CommonDomainCookie {
    /// Decode a cookie value. `cookie_value` may be raw or percent-encoded
    /// (browsers echo back whatever the IdP set; implementations in the wild
    /// percent-encode the space separator, some encode the whole value).
    ///
    /// A value that is not percent-decodable UTF-8, carries a non-base64
    /// token, or decodes to an empty entityID is rejected — a malformed
    /// cookie means some peer in the common domain is broken, and silently
    /// dropping entries would mask that.
    pub fn parse(cookie_value: &str) -> Result<Self, Error> {
        let decoded = percent_decode_str(cookie_value)
            .decode_utf8()
            .map_err(|_utf8_err| Error::CommonDomainCookieMalformed {
                reason: "cookie value is not valid UTF-8 after percent-decoding",
            })?;

        let mut entity_ids = Vec::new();
        for token in decoded.split(' ') {
            if token.is_empty() {
                continue;
            }
            let bytes = BASE64_STANDARD.decode(token).map_err(|_b64_err| {
                Error::CommonDomainCookieMalformed {
                    reason: "cookie entry is not valid base64",
                }
            })?;
            let entity_id = String::from_utf8(bytes).map_err(|_utf8_err| {
                Error::CommonDomainCookieMalformed {
                    reason: "cookie entry does not decode to UTF-8",
                }
            })?;
            if entity_id.is_empty() {
                return Err(Error::CommonDomainCookieMalformed {
                    reason: "cookie entry decodes to an empty entityID",
                });
            }
            entity_ids.push(entity_id);
        }
        Ok(Self { entity_ids })
    }

    /// The most recently used IdP — the last list entry (Profiles §4.3.1).
    pub fn most_recent(&self) -> Option<&str> {
        self.entity_ids.last().map(String::as_str)
    }

    /// Record a successful authentication at `entity_id`: any existing
    /// occurrence is removed, then the entityID is appended as the new
    /// most-recent entry. This is the IdP-side write described in Profiles
    /// §4.3.2 (and what a discovery service does after an interactive pick).
    pub fn record(&mut self, entity_id: &str) {
        self.entity_ids.retain(|existing| existing != entity_id);
        self.entity_ids.push(entity_id.to_owned());
    }

    /// Encode back to a cookie value: each entityID base64-encoded, joined by
    /// a percent-encoded space (`%20`). The result is ready to place in a
    /// `Set-Cookie` header value.
    pub fn to_cookie_value(&self) -> String {
        let encoded: Vec<String> = self
            .entity_ids
            .iter()
            .map(|id| BASE64_STANDARD.encode(id.as_bytes()))
            .collect();
        encoded.join("%20")
    }

    /// Drop oldest entries until the encoded value fits `max_value_len`
    /// bytes. Browsers cap a cookie around 4 KiB; long federation histories
    /// hit that, and the spec's most-recent-last ordering makes the front of
    /// the list the right thing to sacrifice.
    pub fn truncate_to_fit(&mut self, max_value_len: usize) {
        while !self.entity_ids.is_empty() && self.to_cookie_value().len() > max_value_len {
            self.entity_ids.remove(0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_value_parses_to_empty_cookie() {
        let cookie = CommonDomainCookie::parse("").unwrap();
        assert!(cookie.entity_ids.is_empty());
        assert_eq!(cookie.most_recent(), None);
        assert_eq!(cookie.to_cookie_value(), "");
    }

    #[test]
    fn roundtrip_preserves_order_and_most_recent() {
        let mut cookie = CommonDomainCookie::default();
        cookie.record("https://idp-a.example.com");
        cookie.record("https://idp-b.example.com");

        let value = cookie.to_cookie_value();
        assert!(value.contains("%20"), "separator must be encoded: {value}");

        let reparsed = CommonDomainCookie::parse(&value).unwrap();
        assert_eq!(
            reparsed.entity_ids,
            vec!["https://idp-a.example.com", "https://idp-b.example.com"]
        );
        assert_eq!(reparsed.most_recent(), Some("https://idp-b.example.com"));
    }

    #[test]
    fn parse_accepts_raw_space_separator() {
        let raw = format!(
            "{} {}",
            BASE64_STANDARD.encode("https://idp-a.example.com"),
            BASE64_STANDARD.encode("https://idp-b.example.com"),
        );
        let cookie = CommonDomainCookie::parse(&raw).unwrap();
        assert_eq!(cookie.entity_ids.len(), 2);
    }

    #[test]
    fn parse_accepts_fully_percent_encoded_value() {
        // Some stacks percent-encode the entire cookie value, base64 padding
        // included ('=' → %3D).
        let b64 = BASE64_STANDARD.encode("https://idp.example.com/saml");
        let fully_encoded: String = b64
            .chars()
            .flat_map(|c| {
                if c == '=' {
                    "%3D".chars().collect::<Vec<_>>()
                } else {
                    vec![c]
                }
            })
            .collect();
        let cookie = CommonDomainCookie::parse(&fully_encoded).unwrap();
        assert_eq!(cookie.entity_ids, vec!["https://idp.example.com/saml"]);
    }

    #[test]
    fn record_moves_existing_entry_to_most_recent() {
        let mut cookie = CommonDomainCookie::default();
        cookie.record("https://idp-a.example.com");
        cookie.record("https://idp-b.example.com");
        cookie.record("https://idp-a.example.com");

        assert_eq!(
            cookie.entity_ids,
            vec!["https://idp-b.example.com", "https://idp-a.example.com"]
        );
        assert_eq!(cookie.most_recent(), Some("https://idp-a.example.com"));
    }

    #[test]
    fn base64_plus_character_survives_roundtrip() {
        // '+' is in the base64 alphabet. It must NOT be treated as an
        // encoded space anywhere in the codec, or entityIDs whose base64
        // form contains '+' would corrupt on reparse.
        let entity_id = "https://idp.example.com/tenant?~~"; // b64 contains '+'
        let b64 = BASE64_STANDARD.encode(entity_id);
        assert!(b64.contains('+'), "fixture must exercise '+': {b64}");

        let mut cookie = CommonDomainCookie::default();
        cookie.record(entity_id);
        let reparsed = CommonDomainCookie::parse(&cookie.to_cookie_value()).unwrap();
        assert_eq!(reparsed.entity_ids, vec![entity_id]);
    }

    #[test]
    fn rejects_non_base64_entry() {
        let err = CommonDomainCookie::parse("not-base64!!!").unwrap_err();
        assert!(matches!(err, Error::CommonDomainCookieMalformed { .. }));
    }

    #[test]
    fn rejects_entry_decoding_to_invalid_utf8() {
        let bad = BASE64_STANDARD.encode([0xFF, 0xFE, 0x00]);
        let err = CommonDomainCookie::parse(&bad).unwrap_err();
        assert!(matches!(
            err,
            Error::CommonDomainCookieMalformed {
                reason: "cookie entry does not decode to UTF-8"
            }
        ));
    }

    #[test]
    fn truncate_to_fit_drops_oldest_first() {
        let mut cookie = CommonDomainCookie::default();
        for i in 0..50 {
            cookie.record(&format!("https://idp-{i}.example-federation.org/saml"));
        }
        let full_len = cookie.to_cookie_value().len();
        assert!(full_len > 1024);

        cookie.truncate_to_fit(1024);
        assert!(cookie.to_cookie_value().len() <= 1024);
        // Most recent entry survives; oldest are gone.
        assert_eq!(
            cookie.most_recent(),
            Some("https://idp-49.example-federation.org/saml")
        );
        assert_ne!(
            cookie.entity_ids.first().map(String::as_str),
            Some("https://idp-0.example-federation.org/saml")
        );
    }

    #[test]
    fn truncate_to_zero_empties_the_cookie() {
        let mut cookie = CommonDomainCookie::default();
        cookie.record("https://idp.example.com");
        cookie.truncate_to_fit(0);
        assert!(cookie.entity_ids.is_empty());
    }
}
