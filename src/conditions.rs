//! `<saml:Conditions>` parsed fields.
//!
//! `Conditions` is intentionally a flat parsed view. The semantic checks
//! (`NotBefore`, `NotOnOrAfter`, audience, `OneTimeUse`) are applied inside
//! the response-validation pipeline (RFC-003 §4.1 steps 12–14), not on this
//! struct.

use std::time::SystemTime;

/// Parsed `<saml:Conditions>` element.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Conditions {
    /// `Conditions/@NotBefore` — assertion is not yet valid before this
    /// instant. Compared against `now + clock_skew`.
    pub not_before: Option<SystemTime>,
    /// `Conditions/@NotOnOrAfter` — assertion is expired at this instant.
    /// Compared against `now - clock_skew`.
    pub not_on_or_after: Option<SystemTime>,
    /// All `<saml:AudienceRestriction>/<saml:Audience>` values, flattened.
    /// Multiple `AudienceRestriction` blocks each carrying their own
    /// `Audience` are conjunctive per spec; the conjunction is enforced at
    /// validation time, not here.
    pub audiences: Vec<String>,
    /// `<saml:OneTimeUse>` was present. The caller is expected to enforce
    /// single-use semantics by deduping on `assertion_id`.
    pub one_time_use: bool,
    /// `<saml:ProxyRestriction Count="…">` value.
    pub proxy_restriction_count: Option<u32>,
    /// `<saml:ProxyRestriction>/<saml:Audience>` values.
    pub proxy_restriction_audiences: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    fn sample() -> Conditions {
        Conditions {
            not_before: UNIX_EPOCH.checked_add(Duration::from_secs(1)),
            not_on_or_after: UNIX_EPOCH.checked_add(Duration::from_hours(1)),
            audiences: vec!["https://sp.example.com".into()],
            one_time_use: false,
            proxy_restriction_count: None,
            proxy_restriction_audiences: vec![],
        }
    }

    #[test]
    fn fields_settable_and_readable() {
        let c = sample();
        assert!(c.not_before.is_some());
        assert!(c.not_on_or_after.is_some());
        assert_eq!(c.audiences, vec!["https://sp.example.com".to_string()]);
        assert!(!c.one_time_use);
        assert!(c.proxy_restriction_count.is_none());
        assert!(c.proxy_restriction_audiences.is_empty());
    }

    #[test]
    fn proxy_restriction_count_and_audiences_independent() {
        // ProxyRestriction may carry Count, Audiences, or both.
        let c = Conditions {
            not_before: None,
            not_on_or_after: None,
            audiences: vec![],
            one_time_use: false,
            proxy_restriction_count: Some(3),
            proxy_restriction_audiences: vec!["https://downstream.example.com".into()],
        };
        assert_eq!(c.proxy_restriction_count, Some(3));
        assert_eq!(c.proxy_restriction_audiences.len(), 1);
    }

    #[test]
    fn one_time_use_flag_independent_of_other_fields() {
        let mut c = sample();
        c.one_time_use = true;
        c.audiences.clear();
        assert!(c.one_time_use);
        assert!(c.audiences.is_empty());
    }

    #[test]
    fn clone_preserves_fields() {
        let c = sample();
        let d = c.clone();
        assert_eq!(d.audiences, c.audiences);
        assert_eq!(d.not_before, c.not_before);
        assert_eq!(d.not_on_or_after, c.not_on_or_after);
    }
}
