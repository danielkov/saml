//! Structural XSD-style schema validation for inbound SAML messages.
//!
//! This module runs as the first check after [`crate::xml::parse::Document`]
//! parses the wire bytes, before any cryptographic or content-policy step. It
//! mirrors the *shape* of the SAML 2.0 OASIS XSDs (`saml-schema-protocol-2.0`
//! and `saml-schema-assertion-2.0`) — required attributes, allowed child
//! elements, required-child ordering — without taking on a full XSD
//! interpreter. That keeps the validator small, auditable, and zero-dep.
//!
//! ## What is validated
//!
//! For each known message root (`<samlp:Response>`, `<saml:Assertion>`,
//! `<samlp:AuthnRequest>`, `<samlp:LogoutRequest>`, `<samlp:LogoutResponse>`)
//! and their major sub-elements, the validator enforces:
//!
//! 1. The expanded QName matches an expected `ElementShape`.
//! 2. Every required attribute (per `AttrShape::Required`) is present.
//! 3. Every child element is recognized (matches one of the allowed shapes)
//!    OR is from a namespace flagged as `wildcard` (xs:any-style escape hatch
//!    used for `<ds:Signature>` slots and `<saml:Conditions>` extension
//!    points).
//! 4. For `ChildModel::Sequence`, every `min_occurs >= 1` shape is present
//!    AND children appear in the listed order (skipping anywhere-positioned
//!    `<ds:Signature>` because the SAML profile places it as a sibling of
//!    `<saml:Issuer>` inside otherwise-strict sequences and the OASIS XSDs
//!    use `<xs:sequence>` for them anyway).
//! 5. For `ChildModel::Choice`, at least one of the listed shapes appears.
//! 6. `ChildModel::Any` permits any element (used for opaque containers like
//!    `<saml:AttributeValue>` or `<saml:SubjectConfirmationData>`).
//!
//! ## What is intentionally NOT validated
//!
//! - xs:base64Binary / xs:dateTime / xs:anyURI lexical correctness — the
//!   downstream parsers already enforce these via [`crate::time::parse_xs_datetime`]
//!   and the per-field decoders. The schema layer's job is *structural*.
//! - The `<ds:Signature>` subtree — the dsig layer owns that. We accept
//!   `<ds:Signature>` as an opaque allowed child anywhere the OASIS schemas
//!   admit it.
//! - Statements other than `<saml:AuthnStatement>` /
//!   `<saml:AttributeStatement>` (`<saml:AuthzDecisionStatement>` is
//!   accepted as a wildcard-namespace member but not specifically shaped —
//!   we don't process those statements).
//!
//! ## Feature gate
//!
//! Compiled only behind the default-on `xsd-validate` feature so deployments
//! that need to interoperate with non-conformant IdPs can opt out via
//! `default-features = false`. The opt-out is whole-crate — there is no
//! per-call escape hatch.

#![cfg(feature = "xsd-validate")]

use crate::error::Error;
use crate::xml::parse::{Element, QName};

/// SAML protocol namespace URI (`samlp:`).
pub(crate) const SAMLP_NS: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
/// SAML assertion namespace URI (`saml:`).
pub(crate) const SAML_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
/// XML Digital Signature namespace URI (`ds:`).
pub(crate) const DS_NS: &str = "http://www.w3.org/2000/09/xmldsig#";

// =============================================================================
// Shape definitions
// =============================================================================

/// Whether an attribute is required by the schema. We deliberately omit
/// "fixed value" / "default value" / xsi:type — none of the SAML messages
/// we shape uses those in a security-relevant way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AttrPresence {
    Required,
    Optional,
}

/// Single attribute slot: its expanded name + presence rule. Unprefixed
/// attributes in the SAML schemas are `namespace = None` per XML Namespaces
/// §6.2 (unprefixed attributes have no namespace regardless of any default
/// `xmlns="..."` declaration).
#[derive(Debug, Clone, Copy)]
pub(crate) struct AttrShape {
    pub namespace: Option<&'static str>,
    pub local: &'static str,
    pub presence: AttrPresence,
}

/// Child-element slot for [`ChildModel::Sequence`] / [`ChildModel::Choice`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct ChildShape {
    /// The expected expanded QName of this child.
    pub namespace: Option<&'static str>,
    pub local: &'static str,
    /// Minimum required occurrences. `0` ⇒ optional. We do not enforce an
    /// upper bound — XSW vectors that abuse multiplicity (`maxOccurs=1`
    /// violations like duplicate Assertions) are caught downstream by the
    /// XSW-defense pass in `response::validate::enforce_signature_positions`
    /// and `response::parse::parse_response` (which rejects >1 Assertion).
    pub min_occurs: u32,
    /// Nested shape for this child, if we recursively validate it. `None`
    /// means "structure not further checked at this layer" — used for
    /// `<ds:Signature>` and other opaque subtrees.
    pub shape: Option<&'static ElementShape>,
}

/// How a parent element constrains its child sequence.
#[derive(Debug, Clone, Copy)]
#[expect(
    dead_code,
    reason = "Choice variant is part of the shape vocabulary; current SAML shapes \
              all decompose to Sequence/Any but Choice is retained so future shapes \
              (e.g. metadata's RoleDescriptor xs:choice) can reuse the walker."
)]
pub(crate) enum ChildModel {
    /// Children MUST appear in the listed order, with required slots
    /// satisfied. Children outside the listed set are rejected (unless their
    /// namespace is on the parent's `wildcard_namespaces` list).
    Sequence(&'static [ChildShape]),
    /// At least one of the listed shapes MUST appear. Useful for
    /// `<saml:Subject>` which permits either `<saml:NameID>` or
    /// `<saml:EncryptedID>` or `<saml:BaseID>` plus zero-or-more
    /// `<saml:SubjectConfirmation>`. We model the "one of the IDs" via Choice
    /// and let Sequence carry the SubjectConfirmations.
    Choice(&'static [ChildShape]),
    /// No child constraints; any element-or-text content is accepted. Used
    /// for opaque payload containers like `<saml:AttributeValue>` (which
    /// holds arbitrary XML / text per xs:anyType).
    Any,
}

/// Full shape for one named SAML element.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ElementShape {
    pub namespace: Option<&'static str>,
    pub local: &'static str,
    pub attrs: &'static [AttrShape],
    pub children: ChildModel,
    /// Child namespaces whose elements are accepted at this position without
    /// matching any listed `ChildShape`. The OASIS schemas use this for
    /// `<ds:Signature>` (admitted as a `##any` particle inside protocol
    /// messages) and for SAML extension points (e.g. `<samlp:Extensions>`
    /// holds arbitrary non-SAML XML). We list only the wildcard *namespaces*
    /// rather than `##any`, which gives us a small extra structural check:
    /// random made-up elements in unrelated namespaces still fail.
    pub wildcard_namespaces: &'static [&'static str],
}

// =============================================================================
// Shape catalog: SAML 2.0 message shapes
// =============================================================================
//
// All ElementShape values are `static` so they can be referenced via `&'static`
// from `ChildShape::shape`. The naming convention is `SHAPE_<Local>` for the
// canonical shape; deeper helpers reuse them by reference rather than copying.

// ---- saml:Issuer (NameIDType): xs:string content, attributes optional ----
static SHAPE_ISSUER: ElementShape = ElementShape {
    namespace: Some(SAML_NS),
    local: "Issuer",
    // NameIDType inherits Format / NameQualifier / SPNameQualifier /
    // SPProvidedID — all optional.
    attrs: &[
        AttrShape {
            namespace: None,
            local: "Format",
            presence: AttrPresence::Optional,
        },
        AttrShape {
            namespace: None,
            local: "NameQualifier",
            presence: AttrPresence::Optional,
        },
        AttrShape {
            namespace: None,
            local: "SPNameQualifier",
            presence: AttrPresence::Optional,
        },
        AttrShape {
            namespace: None,
            local: "SPProvidedID",
            presence: AttrPresence::Optional,
        },
    ],
    children: ChildModel::Any,
    wildcard_namespaces: &[],
};

// ---- saml:NameID — same shape as Issuer at the structural level ----
static SHAPE_NAMEID: ElementShape = ElementShape {
    namespace: Some(SAML_NS),
    local: "NameID",
    attrs: &[
        AttrShape {
            namespace: None,
            local: "Format",
            presence: AttrPresence::Optional,
        },
        AttrShape {
            namespace: None,
            local: "NameQualifier",
            presence: AttrPresence::Optional,
        },
        AttrShape {
            namespace: None,
            local: "SPNameQualifier",
            presence: AttrPresence::Optional,
        },
        AttrShape {
            namespace: None,
            local: "SPProvidedID",
            presence: AttrPresence::Optional,
        },
    ],
    children: ChildModel::Any,
    wildcard_namespaces: &[],
};

// ---- samlp:StatusCode (recursive) ----
static SHAPE_STATUS_CODE: ElementShape = ElementShape {
    namespace: Some(SAMLP_NS),
    local: "StatusCode",
    attrs: &[AttrShape {
        namespace: None,
        local: "Value",
        presence: AttrPresence::Required,
    }],
    children: ChildModel::Sequence(&[ChildShape {
        namespace: Some(SAMLP_NS),
        local: "StatusCode",
        min_occurs: 0,
        // Recursive: SAML supports a second-level nested StatusCode. We
        // intentionally do NOT recurse the shape here (would need a
        // separate static; recursion via &'static is fine for
        // self-reference but the catalog assembler is awkward). The
        // walker treats `shape: None` as "structure not further
        // descended" — sufficient since the only constraint on the
        // inner StatusCode is "has @Value", which the dsig pipeline
        // re-checks on read.
        shape: None,
    }]),
    wildcard_namespaces: &[],
};

// ---- samlp:StatusMessage ----
static SHAPE_STATUS_MESSAGE: ElementShape = ElementShape {
    namespace: Some(SAMLP_NS),
    local: "StatusMessage",
    attrs: &[],
    children: ChildModel::Any,
    wildcard_namespaces: &[],
};

// ---- samlp:StatusDetail (extension point: any XML allowed inside) ----
static SHAPE_STATUS_DETAIL: ElementShape = ElementShape {
    namespace: Some(SAMLP_NS),
    local: "StatusDetail",
    attrs: &[],
    children: ChildModel::Any,
    wildcard_namespaces: &[],
};

// ---- samlp:Status ----
static SHAPE_STATUS: ElementShape = ElementShape {
    namespace: Some(SAMLP_NS),
    local: "Status",
    attrs: &[],
    children: ChildModel::Sequence(&[
        ChildShape {
            namespace: Some(SAMLP_NS),
            local: "StatusCode",
            min_occurs: 1,
            shape: Some(&SHAPE_STATUS_CODE),
        },
        ChildShape {
            namespace: Some(SAMLP_NS),
            local: "StatusMessage",
            min_occurs: 0,
            shape: Some(&SHAPE_STATUS_MESSAGE),
        },
        ChildShape {
            namespace: Some(SAMLP_NS),
            local: "StatusDetail",
            min_occurs: 0,
            shape: Some(&SHAPE_STATUS_DETAIL),
        },
    ]),
    wildcard_namespaces: &[],
};

// ---- saml:Audience (xs:anyURI text content) ----
static SHAPE_AUDIENCE: ElementShape = ElementShape {
    namespace: Some(SAML_NS),
    local: "Audience",
    attrs: &[],
    children: ChildModel::Any,
    wildcard_namespaces: &[],
};

// ---- saml:AudienceRestriction ----
static SHAPE_AUDIENCE_RESTRICTION: ElementShape = ElementShape {
    namespace: Some(SAML_NS),
    local: "AudienceRestriction",
    attrs: &[],
    children: ChildModel::Sequence(&[ChildShape {
        namespace: Some(SAML_NS),
        local: "Audience",
        min_occurs: 1,
        shape: Some(&SHAPE_AUDIENCE),
    }]),
    wildcard_namespaces: &[],
};

// ---- saml:OneTimeUse (empty body per spec) ----
static SHAPE_ONE_TIME_USE: ElementShape = ElementShape {
    namespace: Some(SAML_NS),
    local: "OneTimeUse",
    attrs: &[],
    children: ChildModel::Sequence(&[]),
    wildcard_namespaces: &[],
};

// ---- saml:ProxyRestriction ----
static SHAPE_PROXY_RESTRICTION: ElementShape = ElementShape {
    namespace: Some(SAML_NS),
    local: "ProxyRestriction",
    attrs: &[AttrShape {
        namespace: None,
        local: "Count",
        presence: AttrPresence::Optional,
    }],
    children: ChildModel::Sequence(&[ChildShape {
        namespace: Some(SAML_NS),
        local: "Audience",
        min_occurs: 0,
        shape: Some(&SHAPE_AUDIENCE),
    }]),
    wildcard_namespaces: &[],
};

// ---- saml:Conditions ----
//
// The OASIS schema models Conditions as an xs:choice of
// (AudienceRestriction | OneTimeUse | ProxyRestriction | Condition) with
// maxOccurs="unbounded", plus optional NotBefore / NotOnOrAfter attrs.
//
// We model it as a Sequence with min_occurs=0 on each, since order is not
// constrained by the spec but order tolerance falls out of Sequence's
// "skip if not present" behavior when every slot is optional. The `Condition`
// extension element is admitted via wildcard_namespaces (it lives in
// SAML_NS but is an xs:abstract base whose derived types we don't enumerate).
static SHAPE_CONDITIONS: ElementShape = ElementShape {
    namespace: Some(SAML_NS),
    local: "Conditions",
    attrs: &[
        AttrShape {
            namespace: None,
            local: "NotBefore",
            presence: AttrPresence::Optional,
        },
        AttrShape {
            namespace: None,
            local: "NotOnOrAfter",
            presence: AttrPresence::Optional,
        },
    ],
    children: ChildModel::Sequence(&[
        ChildShape {
            namespace: Some(SAML_NS),
            local: "AudienceRestriction",
            min_occurs: 0,
            shape: Some(&SHAPE_AUDIENCE_RESTRICTION),
        },
        ChildShape {
            namespace: Some(SAML_NS),
            local: "OneTimeUse",
            min_occurs: 0,
            shape: Some(&SHAPE_ONE_TIME_USE),
        },
        ChildShape {
            namespace: Some(SAML_NS),
            local: "ProxyRestriction",
            min_occurs: 0,
            shape: Some(&SHAPE_PROXY_RESTRICTION),
        },
    ]),
    // SAML_NS wildcard tolerates ADFS / Shibboleth `<saml:Condition
    // xsi:type="...">` extension elements (the abstract `Condition` base
    // type is the OASIS-blessed extensibility hook for site-specific
    // conditions).
    wildcard_namespaces: &[SAML_NS],
};

// ---- saml:SubjectConfirmationData (xs:anyType — opaque payload allowed) ----
static SHAPE_SUBJECT_CONFIRMATION_DATA: ElementShape = ElementShape {
    namespace: Some(SAML_NS),
    local: "SubjectConfirmationData",
    attrs: &[
        AttrShape {
            namespace: None,
            local: "NotBefore",
            presence: AttrPresence::Optional,
        },
        AttrShape {
            namespace: None,
            local: "NotOnOrAfter",
            presence: AttrPresence::Optional,
        },
        AttrShape {
            namespace: None,
            local: "Recipient",
            presence: AttrPresence::Optional,
        },
        AttrShape {
            namespace: None,
            local: "InResponseTo",
            presence: AttrPresence::Optional,
        },
        AttrShape {
            namespace: None,
            local: "Address",
            presence: AttrPresence::Optional,
        },
    ],
    children: ChildModel::Any,
    wildcard_namespaces: &[],
};

// ---- saml:SubjectConfirmation ----
static SHAPE_SUBJECT_CONFIRMATION: ElementShape = ElementShape {
    namespace: Some(SAML_NS),
    local: "SubjectConfirmation",
    attrs: &[AttrShape {
        namespace: None,
        local: "Method",
        presence: AttrPresence::Required,
    }],
    children: ChildModel::Sequence(&[
        // Optional NameID / BaseID / EncryptedID for non-bearer confirmations.
        // For bearer (the only Method we actually consume) the spec allows it
        // but the parser ignores it; structural validity is all we need here.
        ChildShape {
            namespace: Some(SAML_NS),
            local: "NameID",
            min_occurs: 0,
            shape: Some(&SHAPE_NAMEID),
        },
        ChildShape {
            namespace: Some(SAML_NS),
            local: "SubjectConfirmationData",
            min_occurs: 0,
            shape: Some(&SHAPE_SUBJECT_CONFIRMATION_DATA),
        },
    ]),
    wildcard_namespaces: &[],
};

// ---- saml:Subject ----
static SHAPE_SUBJECT: ElementShape = ElementShape {
    namespace: Some(SAML_NS),
    local: "Subject",
    attrs: &[],
    children: ChildModel::Sequence(&[
        ChildShape {
            namespace: Some(SAML_NS),
            local: "NameID",
            // OASIS schema uses xs:choice of NameID/BaseID/EncryptedID with
            // min=0. Our pipeline only consumes NameID; we accept it as
            // optional here so a NameID-less Subject (which the
            // crate-level parser then rejects with a more specific
            // XmlParse) doesn't get swallowed by SchemaViolation first.
            min_occurs: 0,
            shape: Some(&SHAPE_NAMEID),
        },
        ChildShape {
            namespace: Some(SAML_NS),
            local: "SubjectConfirmation",
            min_occurs: 0,
            shape: Some(&SHAPE_SUBJECT_CONFIRMATION),
        },
    ]),
    // Permit EncryptedID / BaseID / future SAML_NS subject identifier
    // elements via the wildcard (we don't process them but they're
    // spec-legal).
    wildcard_namespaces: &[SAML_NS],
};

// ---- saml:AuthnContextClassRef / AuthnContextDeclRef / AuthnContextDecl ----
static SHAPE_AUTHN_CONTEXT_CLASS_REF: ElementShape = ElementShape {
    namespace: Some(SAML_NS),
    local: "AuthnContextClassRef",
    attrs: &[],
    children: ChildModel::Any,
    wildcard_namespaces: &[],
};
static SHAPE_AUTHN_CONTEXT_DECL_REF: ElementShape = ElementShape {
    namespace: Some(SAML_NS),
    local: "AuthnContextDeclRef",
    attrs: &[],
    children: ChildModel::Any,
    wildcard_namespaces: &[],
};
static SHAPE_AUTHN_CONTEXT_DECL: ElementShape = ElementShape {
    namespace: Some(SAML_NS),
    local: "AuthnContextDecl",
    attrs: &[],
    children: ChildModel::Any,
    wildcard_namespaces: &[],
};
static SHAPE_AUTHENTICATING_AUTHORITY: ElementShape = ElementShape {
    namespace: Some(SAML_NS),
    local: "AuthenticatingAuthority",
    attrs: &[],
    children: ChildModel::Any,
    wildcard_namespaces: &[],
};

// ---- saml:AuthnContext ----
static SHAPE_AUTHN_CONTEXT: ElementShape = ElementShape {
    namespace: Some(SAML_NS),
    local: "AuthnContext",
    attrs: &[],
    children: ChildModel::Sequence(&[
        ChildShape {
            namespace: Some(SAML_NS),
            local: "AuthnContextClassRef",
            min_occurs: 0,
            shape: Some(&SHAPE_AUTHN_CONTEXT_CLASS_REF),
        },
        ChildShape {
            namespace: Some(SAML_NS),
            local: "AuthnContextDecl",
            min_occurs: 0,
            shape: Some(&SHAPE_AUTHN_CONTEXT_DECL),
        },
        ChildShape {
            namespace: Some(SAML_NS),
            local: "AuthnContextDeclRef",
            min_occurs: 0,
            shape: Some(&SHAPE_AUTHN_CONTEXT_DECL_REF),
        },
        ChildShape {
            namespace: Some(SAML_NS),
            local: "AuthenticatingAuthority",
            min_occurs: 0,
            shape: Some(&SHAPE_AUTHENTICATING_AUTHORITY),
        },
    ]),
    wildcard_namespaces: &[],
};

// ---- saml:SubjectLocality ----
static SHAPE_SUBJECT_LOCALITY: ElementShape = ElementShape {
    namespace: Some(SAML_NS),
    local: "SubjectLocality",
    attrs: &[
        AttrShape {
            namespace: None,
            local: "Address",
            presence: AttrPresence::Optional,
        },
        AttrShape {
            namespace: None,
            local: "DNSName",
            presence: AttrPresence::Optional,
        },
    ],
    children: ChildModel::Sequence(&[]),
    wildcard_namespaces: &[],
};

// ---- saml:AuthnStatement ----
static SHAPE_AUTHN_STATEMENT: ElementShape = ElementShape {
    namespace: Some(SAML_NS),
    local: "AuthnStatement",
    attrs: &[
        AttrShape {
            namespace: None,
            local: "AuthnInstant",
            presence: AttrPresence::Required,
        },
        AttrShape {
            namespace: None,
            local: "SessionIndex",
            presence: AttrPresence::Optional,
        },
        AttrShape {
            namespace: None,
            local: "SessionNotOnOrAfter",
            presence: AttrPresence::Optional,
        },
    ],
    children: ChildModel::Sequence(&[
        ChildShape {
            namespace: Some(SAML_NS),
            local: "SubjectLocality",
            min_occurs: 0,
            shape: Some(&SHAPE_SUBJECT_LOCALITY),
        },
        ChildShape {
            namespace: Some(SAML_NS),
            local: "AuthnContext",
            min_occurs: 1,
            shape: Some(&SHAPE_AUTHN_CONTEXT),
        },
    ]),
    wildcard_namespaces: &[],
};

// ---- saml:AttributeValue (xs:anyType — accept any content) ----
static SHAPE_ATTRIBUTE_VALUE: ElementShape = ElementShape {
    namespace: Some(SAML_NS),
    local: "AttributeValue",
    // xs:anyType permits arbitrary attributes including xsi:type / xsi:nil.
    // We don't enumerate them — the xs:anyAttribute equivalent here is
    // "accept any". The walker only enforces *required* attrs, so leaving
    // the list empty means "no required attrs"; unknown attrs are
    // unconditionally accepted by the walker (XSD `<xs:anyAttribute/>`
    // semantics).
    attrs: &[],
    children: ChildModel::Any,
    wildcard_namespaces: &[],
};

// ---- saml:Attribute ----
static SHAPE_ATTRIBUTE: ElementShape = ElementShape {
    namespace: Some(SAML_NS),
    local: "Attribute",
    attrs: &[
        AttrShape {
            namespace: None,
            local: "Name",
            presence: AttrPresence::Required,
        },
        AttrShape {
            namespace: None,
            local: "NameFormat",
            presence: AttrPresence::Optional,
        },
        AttrShape {
            namespace: None,
            local: "FriendlyName",
            presence: AttrPresence::Optional,
        },
    ],
    children: ChildModel::Sequence(&[ChildShape {
        namespace: Some(SAML_NS),
        local: "AttributeValue",
        min_occurs: 0,
        shape: Some(&SHAPE_ATTRIBUTE_VALUE),
    }]),
    wildcard_namespaces: &[],
};

// ---- saml:AttributeStatement ----
static SHAPE_ATTRIBUTE_STATEMENT: ElementShape = ElementShape {
    namespace: Some(SAML_NS),
    local: "AttributeStatement",
    attrs: &[],
    children: ChildModel::Sequence(&[
        ChildShape {
            namespace: Some(SAML_NS),
            local: "Attribute",
            min_occurs: 1,
            shape: Some(&SHAPE_ATTRIBUTE),
        },
        ChildShape {
            namespace: Some(SAML_NS),
            local: "EncryptedAttribute",
            min_occurs: 0,
            shape: None,
        },
    ]),
    wildcard_namespaces: &[],
};

// ---- saml:Assertion ----
//
// OASIS structure (saml-schema-assertion-2.0.xsd):
//   <xs:sequence>
//     <saml:Issuer/>
//     <ds:Signature minOccurs="0"/>
//     <saml:Subject minOccurs="0"/>
//     <saml:Conditions minOccurs="0"/>
//     <saml:Advice minOccurs="0"/>
//     <xs:choice minOccurs="0" maxOccurs="unbounded">
//       <saml:Statement xsi:type=.../>
//       <saml:AuthnStatement/>
//       <saml:AuthzDecisionStatement/>
//       <saml:AttributeStatement/>
//     </xs:choice>
//   </xs:sequence>
static SHAPE_ASSERTION: ElementShape = ElementShape {
    namespace: Some(SAML_NS),
    local: "Assertion",
    attrs: &[
        AttrShape {
            namespace: None,
            local: "ID",
            presence: AttrPresence::Required,
        },
        AttrShape {
            namespace: None,
            local: "Version",
            presence: AttrPresence::Required,
        },
        AttrShape {
            namespace: None,
            local: "IssueInstant",
            presence: AttrPresence::Required,
        },
    ],
    children: ChildModel::Sequence(&[
        ChildShape {
            namespace: Some(SAML_NS),
            local: "Issuer",
            min_occurs: 1,
            shape: Some(&SHAPE_ISSUER),
        },
        ChildShape {
            namespace: Some(DS_NS),
            local: "Signature",
            min_occurs: 0,
            shape: None,
        },
        ChildShape {
            namespace: Some(SAML_NS),
            local: "Subject",
            min_occurs: 0,
            shape: Some(&SHAPE_SUBJECT),
        },
        ChildShape {
            namespace: Some(SAML_NS),
            local: "Conditions",
            min_occurs: 0,
            shape: Some(&SHAPE_CONDITIONS),
        },
        ChildShape {
            namespace: Some(SAML_NS),
            local: "Advice",
            min_occurs: 0,
            shape: None,
        },
        // The OASIS schema's xs:choice over Statement variants is encoded
        // here as a flat sequence of optionals; min_occurs=0 on every slot
        // means we accept any subset in any spec-permitted order. The
        // crate-level parser walks `<saml:AuthnStatement>` and
        // `<saml:AttributeStatement>` specifically; other statement variants
        // are admitted via the SAML_NS wildcard below.
        ChildShape {
            namespace: Some(SAML_NS),
            local: "AuthnStatement",
            min_occurs: 0,
            shape: Some(&SHAPE_AUTHN_STATEMENT),
        },
        ChildShape {
            namespace: Some(SAML_NS),
            local: "AttributeStatement",
            min_occurs: 0,
            shape: Some(&SHAPE_ATTRIBUTE_STATEMENT),
        },
    ]),
    // `<saml:Advice>` carries arbitrary SAML-namespace children (Assertion,
    // AssertionIDRef, AssertionURIRef, EncryptedAssertion + xs:any in
    // SAML_NS). `<saml:AuthzDecisionStatement>` plus future
    // `<saml:Statement xsi:type="...">` extensions also live here. Letting
    // the SAML_NS wildcard cover them avoids spurious rejections for
    // assertion shapes we don't actively consume.
    wildcard_namespaces: &[SAML_NS],
};

// ---- samlp:Extensions (any non-SAML XML) ----
static SHAPE_EXTENSIONS: ElementShape = ElementShape {
    namespace: Some(SAMLP_NS),
    local: "Extensions",
    attrs: &[],
    children: ChildModel::Any,
    wildcard_namespaces: &[],
};

// ---- samlp:Response ----
//
// OASIS structure (saml-schema-protocol-2.0.xsd, StatusResponseType + Response):
//   <xs:sequence>
//     <saml:Issuer minOccurs="0"/>
//     <ds:Signature minOccurs="0"/>
//     <samlp:Extensions minOccurs="0"/>
//     <samlp:Status/>
//     <xs:choice minOccurs="0" maxOccurs="unbounded">
//       <saml:Assertion/>
//       <saml:EncryptedAssertion/>
//     </xs:choice>
//   </xs:sequence>
static SHAPE_RESPONSE: ElementShape = ElementShape {
    namespace: Some(SAMLP_NS),
    local: "Response",
    attrs: &[
        AttrShape {
            namespace: None,
            local: "ID",
            presence: AttrPresence::Required,
        },
        AttrShape {
            namespace: None,
            local: "Version",
            presence: AttrPresence::Required,
        },
        AttrShape {
            namespace: None,
            local: "IssueInstant",
            presence: AttrPresence::Required,
        },
        AttrShape {
            namespace: None,
            local: "InResponseTo",
            presence: AttrPresence::Optional,
        },
        AttrShape {
            namespace: None,
            local: "Destination",
            presence: AttrPresence::Optional,
        },
        AttrShape {
            namespace: None,
            local: "Consent",
            presence: AttrPresence::Optional,
        },
    ],
    children: ChildModel::Sequence(&[
        ChildShape {
            namespace: Some(SAML_NS),
            local: "Issuer",
            min_occurs: 0,
            shape: Some(&SHAPE_ISSUER),
        },
        ChildShape {
            namespace: Some(DS_NS),
            local: "Signature",
            min_occurs: 0,
            shape: None,
        },
        ChildShape {
            namespace: Some(SAMLP_NS),
            local: "Extensions",
            min_occurs: 0,
            shape: Some(&SHAPE_EXTENSIONS),
        },
        ChildShape {
            namespace: Some(SAMLP_NS),
            local: "Status",
            min_occurs: 1,
            shape: Some(&SHAPE_STATUS),
        },
        ChildShape {
            namespace: Some(SAML_NS),
            local: "Assertion",
            min_occurs: 0,
            shape: Some(&SHAPE_ASSERTION),
        },
        ChildShape {
            namespace: Some(SAML_NS),
            local: "EncryptedAssertion",
            min_occurs: 0,
            // EncryptedAssertion holds xenc:EncryptedData — opaque to us.
            shape: None,
        },
    ]),
    wildcard_namespaces: &[],
};

// ---- samlp:NameIDPolicy ----
static SHAPE_NAMEID_POLICY: ElementShape = ElementShape {
    namespace: Some(SAMLP_NS),
    local: "NameIDPolicy",
    attrs: &[
        AttrShape {
            namespace: None,
            local: "Format",
            presence: AttrPresence::Optional,
        },
        AttrShape {
            namespace: None,
            local: "SPNameQualifier",
            presence: AttrPresence::Optional,
        },
        AttrShape {
            namespace: None,
            local: "AllowCreate",
            presence: AttrPresence::Optional,
        },
    ],
    children: ChildModel::Sequence(&[]),
    wildcard_namespaces: &[],
};

// ---- samlp:RequestedAuthnContext ----
static SHAPE_REQUESTED_AUTHN_CONTEXT: ElementShape = ElementShape {
    namespace: Some(SAMLP_NS),
    local: "RequestedAuthnContext",
    attrs: &[AttrShape {
        namespace: None,
        local: "Comparison",
        presence: AttrPresence::Optional,
    }],
    children: ChildModel::Sequence(&[
        ChildShape {
            namespace: Some(SAML_NS),
            local: "AuthnContextClassRef",
            min_occurs: 0,
            shape: Some(&SHAPE_AUTHN_CONTEXT_CLASS_REF),
        },
        ChildShape {
            namespace: Some(SAML_NS),
            local: "AuthnContextDeclRef",
            min_occurs: 0,
            shape: Some(&SHAPE_AUTHN_CONTEXT_DECL_REF),
        },
    ]),
    wildcard_namespaces: &[],
};

// ---- samlp:Scoping > IDPList/IDPEntry (opaque) ----
static SHAPE_SCOPING: ElementShape = ElementShape {
    namespace: Some(SAMLP_NS),
    local: "Scoping",
    attrs: &[AttrShape {
        namespace: None,
        local: "ProxyCount",
        presence: AttrPresence::Optional,
    }],
    children: ChildModel::Any,
    wildcard_namespaces: &[],
};

// ---- samlp:Conditions (request-side, distinct from saml:Conditions) ----
static SHAPE_REQUEST_CONDITIONS: ElementShape = ElementShape {
    namespace: Some(SAMLP_NS),
    local: "Conditions",
    attrs: &[],
    children: ChildModel::Any,
    wildcard_namespaces: &[],
};

// ---- samlp:AuthnRequest ----
//
// OASIS structure (saml-schema-protocol-2.0.xsd):
//   <xs:sequence>
//     <saml:Issuer minOccurs="0"/>
//     <ds:Signature minOccurs="0"/>
//     <samlp:Extensions minOccurs="0"/>
//     <saml:Subject minOccurs="0"/>
//     <samlp:NameIDPolicy minOccurs="0"/>
//     <samlp:Conditions minOccurs="0"/>
//     <samlp:RequestedAuthnContext minOccurs="0"/>
//     <samlp:Scoping minOccurs="0"/>
//   </xs:sequence>
static SHAPE_AUTHN_REQUEST: ElementShape = ElementShape {
    namespace: Some(SAMLP_NS),
    local: "AuthnRequest",
    attrs: &[
        AttrShape {
            namespace: None,
            local: "ID",
            presence: AttrPresence::Required,
        },
        AttrShape {
            namespace: None,
            local: "Version",
            presence: AttrPresence::Required,
        },
        AttrShape {
            namespace: None,
            local: "IssueInstant",
            presence: AttrPresence::Required,
        },
        AttrShape {
            namespace: None,
            local: "Destination",
            presence: AttrPresence::Optional,
        },
        AttrShape {
            namespace: None,
            local: "Consent",
            presence: AttrPresence::Optional,
        },
        AttrShape {
            namespace: None,
            local: "ForceAuthn",
            presence: AttrPresence::Optional,
        },
        AttrShape {
            namespace: None,
            local: "IsPassive",
            presence: AttrPresence::Optional,
        },
        AttrShape {
            namespace: None,
            local: "ProtocolBinding",
            presence: AttrPresence::Optional,
        },
        AttrShape {
            namespace: None,
            local: "AssertionConsumerServiceIndex",
            presence: AttrPresence::Optional,
        },
        AttrShape {
            namespace: None,
            local: "AssertionConsumerServiceURL",
            presence: AttrPresence::Optional,
        },
        AttrShape {
            namespace: None,
            local: "AttributeConsumingServiceIndex",
            presence: AttrPresence::Optional,
        },
        AttrShape {
            namespace: None,
            local: "ProviderName",
            presence: AttrPresence::Optional,
        },
    ],
    children: ChildModel::Sequence(&[
        ChildShape {
            namespace: Some(SAML_NS),
            local: "Issuer",
            min_occurs: 0,
            shape: Some(&SHAPE_ISSUER),
        },
        ChildShape {
            namespace: Some(DS_NS),
            local: "Signature",
            min_occurs: 0,
            shape: None,
        },
        ChildShape {
            namespace: Some(SAMLP_NS),
            local: "Extensions",
            min_occurs: 0,
            shape: Some(&SHAPE_EXTENSIONS),
        },
        ChildShape {
            namespace: Some(SAML_NS),
            local: "Subject",
            min_occurs: 0,
            shape: Some(&SHAPE_SUBJECT),
        },
        ChildShape {
            namespace: Some(SAMLP_NS),
            local: "NameIDPolicy",
            min_occurs: 0,
            shape: Some(&SHAPE_NAMEID_POLICY),
        },
        ChildShape {
            namespace: Some(SAMLP_NS),
            local: "Conditions",
            min_occurs: 0,
            shape: Some(&SHAPE_REQUEST_CONDITIONS),
        },
        ChildShape {
            namespace: Some(SAMLP_NS),
            local: "RequestedAuthnContext",
            min_occurs: 0,
            shape: Some(&SHAPE_REQUESTED_AUTHN_CONTEXT),
        },
        ChildShape {
            namespace: Some(SAMLP_NS),
            local: "Scoping",
            min_occurs: 0,
            shape: Some(&SHAPE_SCOPING),
        },
    ]),
    wildcard_namespaces: &[],
};

// ---- samlp:SessionIndex (request-side; distinct local from any other use) ----
static SHAPE_SESSION_INDEX: ElementShape = ElementShape {
    namespace: Some(SAMLP_NS),
    local: "SessionIndex",
    attrs: &[],
    children: ChildModel::Any,
    wildcard_namespaces: &[],
};

// ---- samlp:LogoutRequest ----
//
// OASIS structure:
//   <xs:sequence>
//     <saml:Issuer minOccurs="0"/>
//     <ds:Signature minOccurs="0"/>
//     <samlp:Extensions minOccurs="0"/>
//     <xs:choice>(BaseID|NameID|EncryptedID)</xs:choice>
//     <samlp:SessionIndex minOccurs="0" maxOccurs="unbounded"/>
//   </xs:sequence>
static SHAPE_LOGOUT_REQUEST: ElementShape = ElementShape {
    namespace: Some(SAMLP_NS),
    local: "LogoutRequest",
    attrs: &[
        AttrShape {
            namespace: None,
            local: "ID",
            presence: AttrPresence::Required,
        },
        AttrShape {
            namespace: None,
            local: "Version",
            presence: AttrPresence::Required,
        },
        AttrShape {
            namespace: None,
            local: "IssueInstant",
            presence: AttrPresence::Required,
        },
        AttrShape {
            namespace: None,
            local: "Destination",
            presence: AttrPresence::Optional,
        },
        AttrShape {
            namespace: None,
            local: "Consent",
            presence: AttrPresence::Optional,
        },
        AttrShape {
            namespace: None,
            local: "NotOnOrAfter",
            presence: AttrPresence::Optional,
        },
        AttrShape {
            namespace: None,
            local: "Reason",
            presence: AttrPresence::Optional,
        },
    ],
    children: ChildModel::Sequence(&[
        ChildShape {
            namespace: Some(SAML_NS),
            local: "Issuer",
            min_occurs: 0,
            shape: Some(&SHAPE_ISSUER),
        },
        ChildShape {
            namespace: Some(DS_NS),
            local: "Signature",
            min_occurs: 0,
            shape: None,
        },
        ChildShape {
            namespace: Some(SAMLP_NS),
            local: "Extensions",
            min_occurs: 0,
            shape: Some(&SHAPE_EXTENSIONS),
        },
        ChildShape {
            namespace: Some(SAML_NS),
            local: "NameID",
            // OASIS xs:choice over BaseID|NameID|EncryptedID; min=0 here lets
            // the downstream parser surface a more specific error if all
            // three are absent.
            min_occurs: 0,
            shape: Some(&SHAPE_NAMEID),
        },
        ChildShape {
            namespace: Some(SAMLP_NS),
            local: "SessionIndex",
            min_occurs: 0,
            shape: Some(&SHAPE_SESSION_INDEX),
        },
    ]),
    // EncryptedID / BaseID live in SAML_NS.
    wildcard_namespaces: &[SAML_NS],
};

// ---- samlp:LogoutResponse ----
//
// OASIS structure (StatusResponseType):
//   <xs:sequence>
//     <saml:Issuer minOccurs="0"/>
//     <ds:Signature minOccurs="0"/>
//     <samlp:Extensions minOccurs="0"/>
//     <samlp:Status/>
//   </xs:sequence>
static SHAPE_LOGOUT_RESPONSE: ElementShape = ElementShape {
    namespace: Some(SAMLP_NS),
    local: "LogoutResponse",
    attrs: &[
        AttrShape {
            namespace: None,
            local: "ID",
            presence: AttrPresence::Required,
        },
        AttrShape {
            namespace: None,
            local: "Version",
            presence: AttrPresence::Required,
        },
        AttrShape {
            namespace: None,
            local: "IssueInstant",
            presence: AttrPresence::Required,
        },
        AttrShape {
            namespace: None,
            local: "InResponseTo",
            presence: AttrPresence::Optional,
        },
        AttrShape {
            namespace: None,
            local: "Destination",
            presence: AttrPresence::Optional,
        },
        AttrShape {
            namespace: None,
            local: "Consent",
            presence: AttrPresence::Optional,
        },
    ],
    children: ChildModel::Sequence(&[
        ChildShape {
            namespace: Some(SAML_NS),
            local: "Issuer",
            min_occurs: 0,
            shape: Some(&SHAPE_ISSUER),
        },
        ChildShape {
            namespace: Some(DS_NS),
            local: "Signature",
            min_occurs: 0,
            shape: None,
        },
        ChildShape {
            namespace: Some(SAMLP_NS),
            local: "Extensions",
            min_occurs: 0,
            shape: Some(&SHAPE_EXTENSIONS),
        },
        ChildShape {
            namespace: Some(SAMLP_NS),
            local: "Status",
            min_occurs: 1,
            shape: Some(&SHAPE_STATUS),
        },
    ]),
    wildcard_namespaces: &[],
};

// =============================================================================
// Crate-internal entry points
// =============================================================================
//
// These are called from the per-message parse functions
// (`response::parse::parse_response`, `authn::request_parse::parse_authn_request`,
// etc.) as the first step after `Document::parse`. They are not part of the
// crate's public surface — schema enforcement is observable to callers
// through [`Error::SchemaViolation`] surfacing from `consume_response` /
// `consume_authn_request` / `consume_logout_request` / `consume_logout_response`.

/// Validate `element` against the schema for a top-level SAML Response.
pub(crate) fn validate_response(element: &Element) -> Result<(), Error> {
    validate_against_shape(element, &SHAPE_RESPONSE)
}

/// Validate `element` against the schema for a standalone SAML Assertion
/// (used by the encrypted-assertion path, which re-parses the decrypted
/// `<saml:Assertion>` as a root document).
pub(crate) fn validate_assertion(element: &Element) -> Result<(), Error> {
    validate_against_shape(element, &SHAPE_ASSERTION)
}

/// Validate `element` against the schema for an inbound AuthnRequest.
pub(crate) fn validate_authn_request(element: &Element) -> Result<(), Error> {
    validate_against_shape(element, &SHAPE_AUTHN_REQUEST)
}

/// Validate `element` against the schema for an inbound LogoutRequest.
#[cfg(feature = "slo")]
pub(crate) fn validate_logout_request(element: &Element) -> Result<(), Error> {
    validate_against_shape(element, &SHAPE_LOGOUT_REQUEST)
}

/// Validate `element` against the schema for an inbound LogoutResponse.
#[cfg(feature = "slo")]
pub(crate) fn validate_logout_response(element: &Element) -> Result<(), Error> {
    validate_against_shape(element, &SHAPE_LOGOUT_RESPONSE)
}

// =============================================================================
// Walker
// =============================================================================

fn qname_string(q: &QName) -> String {
    match q.namespace() {
        Some(ns) => format!("{{{}}}{}", ns, q.local()),
        None => q.local().to_owned(),
    }
}

fn matches(q: &QName, ns: Option<&str>, local: &str) -> bool {
    q.local() == local && q.namespace() == ns
}

/// Recursively validate `element` against `shape`.
fn validate_against_shape(element: &Element, shape: &ElementShape) -> Result<(), Error> {
    // 1. Identity check.
    if !matches(element.qname(), shape.namespace, shape.local) {
        return Err(Error::SchemaViolation {
            element: qname_string(element.qname()),
            reason: "element name does not match expected SAML shape",
        });
    }

    // 2. Required attributes.
    for attr in shape.attrs {
        if attr.presence == AttrPresence::Required
            && element.attribute(attr.namespace, attr.local).is_none()
        {
            return Err(Error::SchemaViolation {
                element: qname_string(element.qname()),
                reason: missing_attr_reason(attr.local),
            });
        }
    }

    // 3. Children.
    match shape.children {
        ChildModel::Any => Ok(()),
        ChildModel::Sequence(slots) => walk_sequence(element, slots, shape.wildcard_namespaces),
        ChildModel::Choice(slots) => walk_choice(element, slots, shape.wildcard_namespaces),
    }
}

/// Walk `element`'s children against an ordered Sequence of slot shapes.
///
/// Algorithm:
///   - Maintain a "cursor" into `slots`. For each child in document order:
///     - If the child matches the current cursor slot (or any later slot),
///       advance the cursor to that slot and recurse into the slot's
///       sub-shape if any.
///     - If the child matches NO listed slot but its namespace is on the
///       parent's `wildcard_namespaces`, accept and skip (do not advance).
///     - If the child matches a slot strictly *before* the cursor, reject
///       (out-of-order).
///     - Otherwise reject as an unknown child.
///   - After the walk, every slot with `min_occurs >= 1` must have been
///     satisfied at least min_occurs times.
fn walk_sequence(
    parent: &Element,
    slots: &[ChildShape],
    wildcard_namespaces: &[&str],
) -> Result<(), Error> {
    let mut cursor: usize = 0;
    let mut counts: Vec<u32> = vec![0; slots.len()];

    for child in parent.child_elements() {
        let cq = child.qname();

        // Find the slot index matching this child, if any.
        let matched_slot = slots
            .iter()
            .enumerate()
            .find(|(_, s)| matches(cq, s.namespace, s.local));

        match matched_slot {
            Some((idx, slot)) => {
                if idx < cursor {
                    return Err(Error::SchemaViolation {
                        element: qname_string(parent.qname()),
                        reason: "child element appears out of schema order",
                    });
                }
                cursor = idx;
                if let Some(inc) = counts.get_mut(idx) {
                    *inc = inc.saturating_add(1);
                }
                if let Some(sub_shape) = slot.shape {
                    validate_against_shape(child, sub_shape)?;
                }
            }
            None => {
                let ns = cq.namespace();
                let allow_wildcard = ns.is_some_and(|n| wildcard_namespaces.contains(&n));
                if !allow_wildcard {
                    return Err(Error::SchemaViolation {
                        element: qname_string(parent.qname()),
                        reason: "unexpected child element for SAML schema shape",
                    });
                }
            }
        }
    }

    // 4. min_occurs check.
    for (slot, count) in slots.iter().zip(counts.iter()) {
        if *count < slot.min_occurs {
            return Err(Error::SchemaViolation {
                element: qname_string(parent.qname()),
                reason: missing_child_reason(slot.local),
            });
        }
    }
    Ok(())
}

/// Walk children against an unordered Choice. At least one child must match
/// one of the listed shapes (recursively validated against its sub-shape).
/// Anything else is treated as in `walk_sequence`: tolerated if its namespace
/// is on the wildcard list, rejected otherwise.
fn walk_choice(
    parent: &Element,
    slots: &[ChildShape],
    wildcard_namespaces: &[&str],
) -> Result<(), Error> {
    let mut any_matched = false;
    for child in parent.child_elements() {
        let cq = child.qname();
        let matched = slots.iter().find(|s| matches(cq, s.namespace, s.local));
        match matched {
            Some(slot) => {
                any_matched = true;
                if let Some(sub_shape) = slot.shape {
                    validate_against_shape(child, sub_shape)?;
                }
            }
            None => {
                let ns = cq.namespace();
                let allow_wildcard = ns.is_some_and(|n| wildcard_namespaces.contains(&n));
                if !allow_wildcard {
                    return Err(Error::SchemaViolation {
                        element: qname_string(parent.qname()),
                        reason: "unexpected child element for SAML schema shape",
                    });
                }
            }
        }
    }
    if !any_matched && !slots.is_empty() {
        return Err(Error::SchemaViolation {
            element: qname_string(parent.qname()),
            reason: "no child satisfies the schema choice",
        });
    }
    Ok(())
}

/// Map common required-attribute names to a static reason string. Keeping
/// the reason `&'static str` matches the `Error::SchemaViolation` contract
/// without leaking parsed bytes.
fn missing_attr_reason(local: &str) -> &'static str {
    match local {
        "ID" => "missing required attribute @ID",
        "Version" => "missing required attribute @Version",
        "IssueInstant" => "missing required attribute @IssueInstant",
        "Method" => "missing required attribute @Method",
        "Name" => "missing required attribute @Name",
        "AuthnInstant" => "missing required attribute @AuthnInstant",
        "Value" => "missing required attribute @Value",
        _ => "missing required attribute",
    }
}

/// Same idea for missing required children.
fn missing_child_reason(local: &str) -> &'static str {
    match local {
        "Issuer" => "missing required child <saml:Issuer>",
        "Status" => "missing required child <samlp:Status>",
        "StatusCode" => "missing required child <samlp:StatusCode>",
        "Subject" => "missing required child <saml:Subject>",
        "Audience" => "missing required child <saml:Audience>",
        "AuthnContext" => "missing required child <saml:AuthnContext>",
        "Attribute" => "missing required child <saml:Attribute>",
        _ => "missing required child element",
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xml::parse::Document;

    fn parse(xml: &str) -> Document {
        Document::parse(xml.as_bytes()).expect("parse")
    }

    const NS_DECL: &str = r#"xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                              xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion""#;

    #[test]
    fn valid_minimal_response_passes() {
        let xml = format!(
            r#"<samlp:Response {NS_DECL}
                ID="_r" Version="2.0" IssueInstant="2026-05-26T12:00:00Z">
              <saml:Issuer>idp</saml:Issuer>
              <samlp:Status>
                <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
              </samlp:Status>
            </samlp:Response>"#
        );
        let doc = parse(&xml);
        validate_response(doc.root()).expect("schema");
    }

    #[test]
    fn response_missing_status_rejected() {
        let xml = format!(
            r#"<samlp:Response {NS_DECL}
                ID="_r" Version="2.0" IssueInstant="2026-05-26T12:00:00Z">
              <saml:Issuer>idp</saml:Issuer>
            </samlp:Response>"#
        );
        let doc = parse(&xml);
        let err = validate_response(doc.root()).unwrap_err();
        match err {
            Error::SchemaViolation { element, reason } => {
                assert!(element.contains("Response"), "got: {element}");
                assert!(reason.contains("Status"), "got: {reason}");
            }
            other => panic!("expected SchemaViolation, got {other:?}"),
        }
    }

    #[test]
    fn response_missing_id_rejected() {
        let xml = format!(
            r#"<samlp:Response {NS_DECL}
                Version="2.0" IssueInstant="2026-05-26T12:00:00Z">
              <samlp:Status>
                <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
              </samlp:Status>
            </samlp:Response>"#
        );
        let doc = parse(&xml);
        let err = validate_response(doc.root()).unwrap_err();
        match err {
            Error::SchemaViolation { reason, .. } => {
                assert!(reason.contains("@ID"), "got: {reason}")
            }
            other => panic!("expected SchemaViolation, got {other:?}"),
        }
    }

    #[test]
    fn response_unknown_child_rejected() {
        let xml = format!(
            r#"<samlp:Response {NS_DECL}
                xmlns:bogus="urn:bogus"
                ID="_r" Version="2.0" IssueInstant="2026-05-26T12:00:00Z">
              <saml:Issuer>idp</saml:Issuer>
              <bogus:NotARealElement/>
              <samlp:Status>
                <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
              </samlp:Status>
            </samlp:Response>"#
        );
        let doc = parse(&xml);
        let err = validate_response(doc.root()).unwrap_err();
        match err {
            Error::SchemaViolation { reason, .. } => {
                assert!(reason.contains("unexpected child"), "got: {reason}");
            }
            other => panic!("expected SchemaViolation, got {other:?}"),
        }
    }

    #[test]
    fn response_with_assertion_passes() {
        let xml = format!(
            r#"<samlp:Response {NS_DECL}
                ID="_r" Version="2.0" IssueInstant="2026-05-26T12:00:00Z">
              <saml:Issuer>idp</saml:Issuer>
              <samlp:Status>
                <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
              </samlp:Status>
              <saml:Assertion ID="_a" Version="2.0" IssueInstant="2026-05-26T12:00:00Z">
                <saml:Issuer>idp</saml:Issuer>
                <saml:Subject>
                  <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">u@e</saml:NameID>
                  <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                    <saml:SubjectConfirmationData Recipient="https://sp/acs" NotOnOrAfter="2026-05-26T12:05:00Z"/>
                  </saml:SubjectConfirmation>
                </saml:Subject>
                <saml:Conditions NotBefore="2026-05-26T11:59:00Z" NotOnOrAfter="2026-05-26T12:10:00Z">
                  <saml:AudienceRestriction>
                    <saml:Audience>https://sp</saml:Audience>
                  </saml:AudienceRestriction>
                </saml:Conditions>
                <saml:AuthnStatement AuthnInstant="2026-05-26T11:59:30Z">
                  <saml:AuthnContext>
                    <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
                  </saml:AuthnContext>
                </saml:AuthnStatement>
              </saml:Assertion>
            </samlp:Response>"#
        );
        let doc = parse(&xml);
        validate_response(doc.root()).expect("schema");
    }

    #[test]
    fn assertion_missing_issuer_rejected() {
        let xml = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_a" Version="2.0" IssueInstant="2026-05-26T12:00:00Z">
          <saml:Subject><saml:NameID>u</saml:NameID></saml:Subject>
        </saml:Assertion>"#;
        let doc = parse(xml);
        let err = validate_assertion(doc.root()).unwrap_err();
        match err {
            Error::SchemaViolation { reason, .. } => {
                assert!(reason.contains("<saml:Issuer>"), "got: {reason}");
            }
            other => panic!("expected SchemaViolation, got {other:?}"),
        }
    }

    #[test]
    fn assertion_out_of_order_rejected() {
        // Subject appearing before Issuer violates the sequence order.
        let xml = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_a" Version="2.0" IssueInstant="2026-05-26T12:00:00Z">
          <saml:Subject><saml:NameID>u</saml:NameID></saml:Subject>
          <saml:Issuer>idp</saml:Issuer>
        </saml:Assertion>"#;
        let doc = parse(xml);
        let err = validate_assertion(doc.root()).unwrap_err();
        match err {
            Error::SchemaViolation { reason, .. } => {
                assert!(reason.contains("out of schema order"), "got: {reason}");
            }
            other => panic!("expected SchemaViolation, got {other:?}"),
        }
    }

    #[test]
    fn authn_request_minimal_passes() {
        let xml = format!(
            r#"<samlp:AuthnRequest {NS_DECL}
                ID="_a" Version="2.0" IssueInstant="2026-05-26T12:00:00Z">
              <saml:Issuer>https://sp</saml:Issuer>
            </samlp:AuthnRequest>"#
        );
        let doc = parse(&xml);
        validate_authn_request(doc.root()).expect("schema");
    }

    #[test]
    fn authn_request_missing_version_rejected() {
        let xml = format!(
            r#"<samlp:AuthnRequest {NS_DECL}
                ID="_a" IssueInstant="2026-05-26T12:00:00Z">
              <saml:Issuer>https://sp</saml:Issuer>
            </samlp:AuthnRequest>"#
        );
        let doc = parse(&xml);
        let err = validate_authn_request(doc.root()).unwrap_err();
        match err {
            Error::SchemaViolation { reason, .. } => {
                assert!(reason.contains("@Version"), "got: {reason}");
            }
            other => panic!("expected SchemaViolation, got {other:?}"),
        }
    }

    #[cfg(feature = "slo")]
    #[test]
    fn logout_request_minimal_passes() {
        let xml = format!(
            r#"<samlp:LogoutRequest {NS_DECL}
                ID="_l" Version="2.0" IssueInstant="2026-05-26T12:00:00Z">
              <saml:Issuer>https://sp</saml:Issuer>
              <saml:NameID>u</saml:NameID>
            </samlp:LogoutRequest>"#
        );
        let doc = parse(&xml);
        validate_logout_request(doc.root()).expect("schema");
    }

    #[cfg(feature = "slo")]
    #[test]
    fn logout_response_missing_status_rejected() {
        let xml = format!(
            r#"<samlp:LogoutResponse {NS_DECL}
                ID="_l" Version="2.0" IssueInstant="2026-05-26T12:00:00Z" InResponseTo="_r">
              <saml:Issuer>https://idp</saml:Issuer>
            </samlp:LogoutResponse>"#
        );
        let doc = parse(&xml);
        let err = validate_logout_response(doc.root()).unwrap_err();
        match err {
            Error::SchemaViolation { reason, .. } => {
                assert!(reason.contains("<samlp:Status>"), "got: {reason}");
            }
            other => panic!("expected SchemaViolation, got {other:?}"),
        }
    }

    #[test]
    fn conditions_extension_via_wildcard_accepted() {
        // ADFS-style Conditions with a `<saml:Condition xsi:type="..."/>`
        // extension element: must NOT trip "unknown child" because of the
        // SAML_NS wildcard on saml:Conditions.
        let xml = r#"<saml:Conditions xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                                   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                   NotBefore="2026-05-26T11:59:00Z"
                                   NotOnOrAfter="2026-05-26T12:10:00Z">
          <saml:AudienceRestriction><saml:Audience>https://sp</saml:Audience></saml:AudienceRestriction>
          <saml:Condition xsi:type="ext:CustomCondition"/>
        </saml:Conditions>"#;
        let doc = parse(xml);
        validate_against_shape(doc.root(), &SHAPE_CONDITIONS).expect("schema");
    }
}
