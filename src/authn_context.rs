//! `<saml:AuthnContext>` / `<samlp:RequestedAuthnContext>` types.
//!
//! Used both inbound (the AuthnStatement's actual class ref) and outbound
//! (a request-side hint that the SP requires a particular authentication
//! strength, e.g. MFA). Non-downgrade is enforced in response validation
//! (RFC-003 §4.1 step 17, RFC-005 §7); this module is just the type surface.

/// `<samlp:RequestedAuthnContext Comparison>` — how the IdP's actual
/// `AuthnContextClassRef` is compared against the requested set.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AuthnContextComparison {
    /// Default. Returned context must match one of the requested class refs
    /// exactly.
    Exact,
    /// Returned context must be at least as strong as the weakest requested.
    Minimum,
    /// Returned context must be no stronger than the strongest requested.
    Maximum,
    /// Returned context must be strictly stronger than every requested.
    Better,
}

/// Standard `<saml:AuthnContextClassRef>` URIs from
/// [SAML 2.0 Authentication Context]. Unrecognized URIs become `Custom`.
///
/// Note on `MultiFactorAuth`: SAML 2.0 does not define a single canonical
/// "MFA" class ref — the spec ships a catalogue of specific contexts. The
/// URI used here, `urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactorAuthentication`,
/// is what real-world IdPs (Okta, Azure AD, Auth0) advertise when they want
/// to signal a generic multi-factor result. Vendors emitting the more
/// specific `MobileTwoFactorContract`, `SecondFactorIGTKey`, etc., land in
/// `Custom`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AuthnContextClassRef {
    Password,
    PasswordProtectedTransport,
    TlsClient,
    Smartcard,
    SmartcardPki,
    Kerberos,
    PreviousSession,
    Unspecified,
    /// Generic multi-factor authentication. See type-level note above.
    MultiFactorAuth,
    TimeSyncToken,
    Custom(String),
}

impl AuthnContextClassRef {
    /// URI for this class ref.
    pub fn as_uri(&self) -> &str {
        match self {
            AuthnContextClassRef::Password => "urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
            AuthnContextClassRef::PasswordProtectedTransport => {
                "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
            }
            AuthnContextClassRef::TlsClient => "urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient",
            AuthnContextClassRef::Smartcard => "urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard",
            AuthnContextClassRef::SmartcardPki => {
                "urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI"
            }
            AuthnContextClassRef::Kerberos => "urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos",
            AuthnContextClassRef::PreviousSession => {
                "urn:oasis:names:tc:SAML:2.0:ac:classes:PreviousSession"
            }
            AuthnContextClassRef::Unspecified => {
                "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified"
            }
            AuthnContextClassRef::MultiFactorAuth => {
                "urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactorAuthentication"
            }
            AuthnContextClassRef::TimeSyncToken => {
                "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken"
            }
            AuthnContextClassRef::Custom(s) => s.as_str(),
        }
    }

    /// Parse a URI into the corresponding variant. Unrecognized URIs become
    /// `Custom`.
    pub fn from_uri(uri: &str) -> Self {
        match uri {
            "urn:oasis:names:tc:SAML:2.0:ac:classes:Password" => AuthnContextClassRef::Password,
            "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport" => {
                AuthnContextClassRef::PasswordProtectedTransport
            }
            "urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient" => AuthnContextClassRef::TlsClient,
            "urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard" => AuthnContextClassRef::Smartcard,
            "urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI" => {
                AuthnContextClassRef::SmartcardPki
            }
            "urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos" => AuthnContextClassRef::Kerberos,
            "urn:oasis:names:tc:SAML:2.0:ac:classes:PreviousSession" => {
                AuthnContextClassRef::PreviousSession
            }
            "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified" => {
                AuthnContextClassRef::Unspecified
            }
            "urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactorAuthentication" => {
                AuthnContextClassRef::MultiFactorAuth
            }
            "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken" => {
                AuthnContextClassRef::TimeSyncToken
            }
            other => AuthnContextClassRef::Custom(other.to_string()),
        }
    }
}

/// `<samlp:RequestedAuthnContext>` request hint, attached to an AuthnRequest
/// and re-attached to a `LoginTracker` so the response-side validator can
/// enforce non-downgrade.
///
/// SAML 2.0 also allows `<AuthnContextDeclRef>` in addition to
/// `<AuthnContextClassRef>`; declaration refs are out of scope for v0.1 per
/// RFC-001 §12.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RequestedAuthnContext {
    pub class_refs: Vec<AuthnContextClassRef>,
    pub comparison: AuthnContextComparison,
}

/// Coarse strength ranking of the standard `AuthnContextClassRef` URIs.
///
/// SAML 2.0 §3.3.2.2.1 says that the relative ordering of authentication
/// classes is implementation-defined; the SAML 2.0 Authentication Context
/// document only enumerates the classes. The ordering below is the de-facto
/// convention used by interoperable products (Shibboleth, Okta, Azure AD,
/// Auth0): a small integer with `Unspecified < PreviousSession < Password <
/// PasswordProtectedTransport < TimeSyncToken < {Kerberos, TlsClient} <
/// Smartcard < SmartcardPKI < MultiFactorAuth`.
///
/// `Custom(_)` URIs are intentionally non-rankable — callers can't know where
/// a vendor-specific class lands on the ladder. Strength-ordered comparators
/// (`minimum`, `maximum`, `better`) therefore reject unknown URIs by failing
/// closed; `exact` still works for `Custom` by URI equality.
#[must_use]
pub fn class_ref_strength(cr: &AuthnContextClassRef) -> Option<u8> {
    match cr {
        AuthnContextClassRef::Unspecified => Some(0),
        AuthnContextClassRef::PreviousSession => Some(1),
        AuthnContextClassRef::Password => Some(2),
        AuthnContextClassRef::PasswordProtectedTransport => Some(3),
        AuthnContextClassRef::TimeSyncToken => Some(4),
        AuthnContextClassRef::Kerberos | AuthnContextClassRef::TlsClient => Some(5),
        AuthnContextClassRef::Smartcard => Some(6),
        AuthnContextClassRef::SmartcardPki => Some(7),
        AuthnContextClassRef::MultiFactorAuth => Some(8),
        AuthnContextClassRef::Custom(_) => None,
    }
}

/// Result of evaluating a [`RequestedAuthnContext`] against an actual
/// `AuthnContextClassRef` URI under a comparator. Returned by
/// [`StandardComparator::evaluate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComparatorOutcome {
    /// The actual class ref satisfies the requested set under the chosen
    /// comparison.
    Satisfied,
    /// The actual class ref does not satisfy the requested set: it is too
    /// weak (`minimum`/`better`), too strong (`maximum`), or simply not in
    /// the requested set (`exact`).
    NotSatisfied,
    /// One or both sides could not be ranked because the URI is not a
    /// recognized standard class ref. Strength-ordered comparators treat this
    /// as a fail-closed condition; `exact` never returns this variant.
    NotComparable,
}

/// SAML 2.0 §3.3.2.2.1 `<RequestedAuthnContext Comparison>` evaluator.
///
/// The comparator implements all four standard semantics with set-aggregating
/// behavior over the requested class refs:
///
/// * `Exact` — `actual` URI equals at least one requested URI. Works for
///   `Custom` refs (string equality).
/// * `Minimum` — `actual` is at least as strong as the *weakest* requested
///   ref. Equivalently, `strength(actual) ≥ min(strength(requested))`.
/// * `Maximum` — `actual` is no stronger than the *strongest* requested ref.
///   Equivalently, `strength(actual) ≤ max(strength(requested))`.
/// * `Better` — `actual` is strictly stronger than *every* requested ref, per
///   spec ("better than the specified authentication contexts"). Equivalently,
///   `strength(actual) > max(strength(requested))`.
///
/// The `Better` semantics are the load-bearing difference from a naive
/// per-element fold: spec mandates "better than each", not "better than some".
#[derive(Debug, Clone, Copy, Default)]
pub struct StandardComparator;

impl StandardComparator {
    /// Evaluate `actual_uri` against `requested` under
    /// `requested.comparison`.
    ///
    /// Returns [`ComparatorOutcome::Satisfied`] iff the actual class ref
    /// satisfies the requested set. An empty `requested.class_refs` yields
    /// [`ComparatorOutcome::NotComparable`] for ordered comparisons (nothing
    /// to compare against) and [`ComparatorOutcome::NotSatisfied`] for
    /// `Exact` (vacuously fails).
    #[must_use]
    pub fn evaluate(
        self,
        requested: &RequestedAuthnContext,
        actual_uri: &str,
    ) -> ComparatorOutcome {
        // Exact bypasses strength ranking — URI equality is authoritative and
        // works for Custom refs that aren't on the strength ladder.
        if matches!(requested.comparison, AuthnContextComparison::Exact) {
            if requested.class_refs.is_empty() {
                return ComparatorOutcome::NotSatisfied;
            }
            return if requested
                .class_refs
                .iter()
                .any(|c| c.as_uri() == actual_uri)
            {
                ComparatorOutcome::Satisfied
            } else {
                ComparatorOutcome::NotSatisfied
            };
        }

        // Strength-ordered branches: actual must be rankable.
        let actual = AuthnContextClassRef::from_uri(actual_uri);
        let Some(actual_strength) = class_ref_strength(&actual) else {
            return ComparatorOutcome::NotComparable;
        };
        // All requested refs that are rankable.
        let mut requested_strengths = requested.class_refs.iter().filter_map(class_ref_strength);
        // If every requested ref is Custom/non-rankable, we cannot order at all.
        let Some(first) = requested_strengths.next() else {
            return ComparatorOutcome::NotComparable;
        };
        let (mut min_req, mut max_req) = (first, first);
        for s in requested_strengths {
            if s < min_req {
                min_req = s;
            }
            if s > max_req {
                max_req = s;
            }
        }

        let satisfied = match requested.comparison {
            // Already handled by the early-return above. If we somehow reach
            // here with Exact, fail closed.
            AuthnContextComparison::Exact => false,
            AuthnContextComparison::Minimum => actual_strength >= min_req,
            AuthnContextComparison::Maximum => actual_strength <= max_req,
            AuthnContextComparison::Better => actual_strength > max_req,
        };
        if satisfied {
            ComparatorOutcome::Satisfied
        } else {
            ComparatorOutcome::NotSatisfied
        }
    }

    /// Convenience wrapper: returns `true` iff
    /// [`Self::evaluate`] returns [`ComparatorOutcome::Satisfied`].
    #[must_use]
    pub fn is_satisfied(self, requested: &RequestedAuthnContext, actual_uri: &str) -> bool {
        matches!(
            self.evaluate(requested, actual_uri),
            ComparatorOutcome::Satisfied
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_known_class_refs() {
        for cr in [
            AuthnContextClassRef::Password,
            AuthnContextClassRef::PasswordProtectedTransport,
            AuthnContextClassRef::TlsClient,
            AuthnContextClassRef::Smartcard,
            AuthnContextClassRef::SmartcardPki,
            AuthnContextClassRef::Kerberos,
            AuthnContextClassRef::PreviousSession,
            AuthnContextClassRef::Unspecified,
            AuthnContextClassRef::MultiFactorAuth,
            AuthnContextClassRef::TimeSyncToken,
        ] {
            let uri = cr.as_uri().to_string();
            assert_eq!(AuthnContextClassRef::from_uri(&uri), cr);
        }
    }

    #[test]
    fn mfa_uri_is_well_known() {
        assert_eq!(
            AuthnContextClassRef::MultiFactorAuth.as_uri(),
            "urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactorAuthentication"
        );
    }

    #[test]
    fn unrecognized_uri_becomes_custom() {
        let uri = "urn:example:com:custom:strong-auth";
        let v = AuthnContextClassRef::from_uri(uri);
        assert_eq!(v, AuthnContextClassRef::Custom(uri.to_string()));
        assert_eq!(v.as_uri(), uri);
    }

    #[test]
    fn requested_authn_context_holds_multiple_class_refs() {
        let r = RequestedAuthnContext {
            class_refs: vec![
                AuthnContextClassRef::PasswordProtectedTransport,
                AuthnContextClassRef::MultiFactorAuth,
            ],
            comparison: AuthnContextComparison::Minimum,
        };
        assert_eq!(r.class_refs.len(), 2);
        assert_eq!(r.comparison, AuthnContextComparison::Minimum);
    }

    #[test]
    fn comparison_variants_distinct() {
        assert_ne!(
            AuthnContextComparison::Exact,
            AuthnContextComparison::Minimum
        );
        assert_ne!(
            AuthnContextComparison::Maximum,
            AuthnContextComparison::Better
        );
    }

    #[test]
    fn serde_round_trip_compiles() {
        fn assert_serde<T: serde::Serialize + serde::de::DeserializeOwned>() {}
        assert_serde::<AuthnContextClassRef>();
        assert_serde::<AuthnContextComparison>();
        assert_serde::<RequestedAuthnContext>();
    }

    // -------------------------------------------------------------------------
    // StandardComparator
    // -------------------------------------------------------------------------
    //
    // The strength ladder is:
    //   0 Unspecified
    //   1 PreviousSession
    //   2 Password
    //   3 PasswordProtectedTransport
    //   4 TimeSyncToken
    //   5 Kerberos / TlsClient
    //   6 Smartcard
    //   7 SmartcardPKI
    //   8 MultiFactorAuth
    //
    // Custom URIs are non-rankable and trip the NotComparable arm for any
    // strength-ordered comparison.

    fn requested(
        comparison: AuthnContextComparison,
        refs: &[AuthnContextClassRef],
    ) -> RequestedAuthnContext {
        RequestedAuthnContext {
            class_refs: refs.to_vec(),
            comparison,
        }
    }

    // ---- Exact ----

    #[test]
    fn exact_matches_one_of_the_requested_uris() {
        let req = requested(
            AuthnContextComparison::Exact,
            &[
                AuthnContextClassRef::Password,
                AuthnContextClassRef::MultiFactorAuth,
            ],
        );
        let c = StandardComparator;
        assert_eq!(
            c.evaluate(&req, AuthnContextClassRef::MultiFactorAuth.as_uri()),
            ComparatorOutcome::Satisfied,
        );
        assert!(c.is_satisfied(&req, AuthnContextClassRef::Password.as_uri()));
    }

    #[test]
    fn exact_rejects_non_matching_uri() {
        let req = requested(
            AuthnContextComparison::Exact,
            &[AuthnContextClassRef::Password],
        );
        let c = StandardComparator;
        assert_eq!(
            c.evaluate(&req, AuthnContextClassRef::MultiFactorAuth.as_uri()),
            ComparatorOutcome::NotSatisfied,
        );
    }

    #[test]
    fn exact_works_for_custom_uris() {
        let custom = "urn:example:vendor:strong";
        let req = requested(
            AuthnContextComparison::Exact,
            &[AuthnContextClassRef::Custom(custom.into())],
        );
        let c = StandardComparator;
        assert_eq!(c.evaluate(&req, custom), ComparatorOutcome::Satisfied);
        assert_eq!(
            c.evaluate(&req, "urn:example:vendor:other"),
            ComparatorOutcome::NotSatisfied,
        );
    }

    #[test]
    fn exact_with_empty_requested_set_fails() {
        let req = requested(AuthnContextComparison::Exact, &[]);
        let c = StandardComparator;
        assert_eq!(
            c.evaluate(&req, AuthnContextClassRef::Password.as_uri()),
            ComparatorOutcome::NotSatisfied,
        );
    }

    // ---- Minimum ----

    #[test]
    fn minimum_satisfied_when_actual_is_equal() {
        // Requested PasswordProtectedTransport(3); actual PPT(3) → Satisfied
        let req = requested(
            AuthnContextComparison::Minimum,
            &[AuthnContextClassRef::PasswordProtectedTransport],
        );
        let c = StandardComparator;
        assert_eq!(
            c.evaluate(
                &req,
                AuthnContextClassRef::PasswordProtectedTransport.as_uri()
            ),
            ComparatorOutcome::Satisfied,
        );
    }

    #[test]
    fn minimum_satisfied_when_actual_is_stronger() {
        // Requested PPT(3); actual MultiFactorAuth(8) → Satisfied
        let req = requested(
            AuthnContextComparison::Minimum,
            &[AuthnContextClassRef::PasswordProtectedTransport],
        );
        let c = StandardComparator;
        assert_eq!(
            c.evaluate(&req, AuthnContextClassRef::MultiFactorAuth.as_uri()),
            ComparatorOutcome::Satisfied,
        );
    }

    #[test]
    fn minimum_rejects_weaker_actual() {
        // Requested PPT(3); actual Password(2) → NotSatisfied (downgrade)
        let req = requested(
            AuthnContextComparison::Minimum,
            &[AuthnContextClassRef::PasswordProtectedTransport],
        );
        let c = StandardComparator;
        assert_eq!(
            c.evaluate(&req, AuthnContextClassRef::Password.as_uri()),
            ComparatorOutcome::NotSatisfied,
        );
    }

    #[test]
    fn minimum_with_multiple_requested_uses_weakest_floor() {
        // Requested {Password(2), Smartcard(6)} → floor is Password(2).
        // Actual PPT(3) ≥ 2 → Satisfied even though it's below Smartcard(6).
        let req = requested(
            AuthnContextComparison::Minimum,
            &[
                AuthnContextClassRef::Password,
                AuthnContextClassRef::Smartcard,
            ],
        );
        let c = StandardComparator;
        assert_eq!(
            c.evaluate(
                &req,
                AuthnContextClassRef::PasswordProtectedTransport.as_uri()
            ),
            ComparatorOutcome::Satisfied,
        );
    }

    // ---- Maximum ----

    #[test]
    fn maximum_satisfied_when_actual_is_weaker_or_equal() {
        // Requested Smartcard(6); actual Password(2) → 2 ≤ 6 → Satisfied
        let req = requested(
            AuthnContextComparison::Maximum,
            &[AuthnContextClassRef::Smartcard],
        );
        let c = StandardComparator;
        assert_eq!(
            c.evaluate(&req, AuthnContextClassRef::Password.as_uri()),
            ComparatorOutcome::Satisfied,
        );
        assert_eq!(
            c.evaluate(&req, AuthnContextClassRef::Smartcard.as_uri()),
            ComparatorOutcome::Satisfied,
        );
    }

    #[test]
    fn maximum_rejects_stronger_actual() {
        // Requested Smartcard(6); actual MultiFactorAuth(8) → NotSatisfied
        let req = requested(
            AuthnContextComparison::Maximum,
            &[AuthnContextClassRef::Smartcard],
        );
        let c = StandardComparator;
        assert_eq!(
            c.evaluate(&req, AuthnContextClassRef::MultiFactorAuth.as_uri()),
            ComparatorOutcome::NotSatisfied,
        );
    }

    #[test]
    fn maximum_with_multiple_requested_uses_strongest_ceiling() {
        // Requested {Password(2), Smartcard(6)}; ceiling is Smartcard(6).
        // Actual Kerberos(5) ≤ 6 → Satisfied even though it exceeds Password(2).
        let req = requested(
            AuthnContextComparison::Maximum,
            &[
                AuthnContextClassRef::Password,
                AuthnContextClassRef::Smartcard,
            ],
        );
        let c = StandardComparator;
        assert_eq!(
            c.evaluate(&req, AuthnContextClassRef::Kerberos.as_uri()),
            ComparatorOutcome::Satisfied,
        );
    }

    // ---- Better ----

    #[test]
    fn better_rejects_equal_strength() {
        // Spec: strictly stronger. Equal must fail.
        let req = requested(
            AuthnContextComparison::Better,
            &[AuthnContextClassRef::PasswordProtectedTransport],
        );
        let c = StandardComparator;
        assert_eq!(
            c.evaluate(
                &req,
                AuthnContextClassRef::PasswordProtectedTransport.as_uri()
            ),
            ComparatorOutcome::NotSatisfied,
        );
    }

    #[test]
    fn better_accepts_strictly_stronger() {
        // Requested PPT(3); actual Smartcard(6) → Satisfied
        let req = requested(
            AuthnContextComparison::Better,
            &[AuthnContextClassRef::PasswordProtectedTransport],
        );
        let c = StandardComparator;
        assert_eq!(
            c.evaluate(&req, AuthnContextClassRef::Smartcard.as_uri()),
            ComparatorOutcome::Satisfied,
        );
    }

    #[test]
    fn better_must_exceed_every_requested_not_just_one() {
        // Spec §3.3.2.2.1: "better" means stronger than EACH requested. With
        // requested = {Password(2), Smartcard(6)}, a Kerberos(5) actual is
        // *only* stronger than Password — NOT stronger than Smartcard — so it
        // must fail. (A naive per-element `any` fold would incorrectly accept.)
        let req = requested(
            AuthnContextComparison::Better,
            &[
                AuthnContextClassRef::Password,
                AuthnContextClassRef::Smartcard,
            ],
        );
        let c = StandardComparator;
        assert_eq!(
            c.evaluate(&req, AuthnContextClassRef::Kerberos.as_uri()),
            ComparatorOutcome::NotSatisfied,
        );
        // MultiFactorAuth(8) > Smartcard(6) > Password(2) → Satisfied.
        assert_eq!(
            c.evaluate(&req, AuthnContextClassRef::MultiFactorAuth.as_uri()),
            ComparatorOutcome::Satisfied,
        );
    }

    // ---- Non-rankable URIs ----

    #[test]
    fn ordered_comparison_with_custom_actual_is_not_comparable() {
        let req = requested(
            AuthnContextComparison::Minimum,
            &[AuthnContextClassRef::PasswordProtectedTransport],
        );
        let c = StandardComparator;
        assert_eq!(
            c.evaluate(&req, "urn:example:vendor:strong"),
            ComparatorOutcome::NotComparable,
        );
        // is_satisfied() collapses NotComparable to false (fail closed).
        assert!(!c.is_satisfied(&req, "urn:example:vendor:strong"));
    }

    #[test]
    fn ordered_comparison_with_only_custom_requested_is_not_comparable() {
        let req = requested(
            AuthnContextComparison::Maximum,
            &[AuthnContextClassRef::Custom(
                "urn:example:vendor:weak".into(),
            )],
        );
        let c = StandardComparator;
        assert_eq!(
            c.evaluate(&req, AuthnContextClassRef::Password.as_uri()),
            ComparatorOutcome::NotComparable,
        );
    }

    #[test]
    fn ordered_comparison_skips_custom_among_known_requested() {
        // Mix of {Custom(unranked), Password(2)} under Minimum: the Custom is
        // skipped (filter_map drops it), the floor is Password(2). Actual
        // PPT(3) ≥ 2 → Satisfied.
        let req = requested(
            AuthnContextComparison::Minimum,
            &[
                AuthnContextClassRef::Custom("urn:example:vendor:weak".into()),
                AuthnContextClassRef::Password,
            ],
        );
        let c = StandardComparator;
        assert_eq!(
            c.evaluate(
                &req,
                AuthnContextClassRef::PasswordProtectedTransport.as_uri()
            ),
            ComparatorOutcome::Satisfied,
        );
    }

    // ---- Strength ladder sanity ----

    #[test]
    fn strength_ladder_monotonic_through_known_refs() {
        // Sanity: the standard ladder is strictly ascending through the
        // distinct rungs (Kerberos and TlsClient share rung 5; everything
        // else is unique).
        let ranks = [
            class_ref_strength(&AuthnContextClassRef::Unspecified).unwrap(),
            class_ref_strength(&AuthnContextClassRef::PreviousSession).unwrap(),
            class_ref_strength(&AuthnContextClassRef::Password).unwrap(),
            class_ref_strength(&AuthnContextClassRef::PasswordProtectedTransport).unwrap(),
            class_ref_strength(&AuthnContextClassRef::TimeSyncToken).unwrap(),
            class_ref_strength(&AuthnContextClassRef::Kerberos).unwrap(),
            class_ref_strength(&AuthnContextClassRef::Smartcard).unwrap(),
            class_ref_strength(&AuthnContextClassRef::SmartcardPki).unwrap(),
            class_ref_strength(&AuthnContextClassRef::MultiFactorAuth).unwrap(),
        ];
        for w in ranks.windows(2) {
            assert!(w[0] < w[1], "ranks not strictly ascending: {ranks:?}");
        }
        // TlsClient shares a rung with Kerberos by design (both are similar
        // strength PKI-light methods).
        assert_eq!(
            class_ref_strength(&AuthnContextClassRef::TlsClient),
            class_ref_strength(&AuthnContextClassRef::Kerberos),
        );
    }

    #[test]
    fn strength_ladder_custom_is_none() {
        assert_eq!(
            class_ref_strength(&AuthnContextClassRef::Custom("urn:x".into())),
            None,
        );
    }
}
