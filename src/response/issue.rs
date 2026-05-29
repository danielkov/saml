//! Issue outbound `<samlp:Response>` from the IdP role.
//!
//! See `docs/rfcs/RFC-004-identity-provider.md` §3 (success Response) and §4
//! (error Response).

use std::time::{Duration, SystemTime};

use rsa::rand_core::{OsRng, RngCore as _};

use crate::attribute::Attribute;
use crate::authn_context::AuthnContextClassRef;
use crate::binding::{SsoResponseBinding, SsoResponseDispatch, SsoResponseEndpoint};
use crate::crypto::keypair::KeyPair;
use crate::descriptor::SpDescriptor;
use crate::dsig::algorithms::{C14nAlgorithm, DigestAlgorithm, SignatureAlgorithm};
use crate::dsig::sign::{SignOptions, sign_element};
use crate::error::Error;
use crate::nameid::{NameId, NameIdFormat};
use crate::response::{SAML_NS, SAMLP_NS, saml_qname, samlp_qname};
use crate::time::format_xs_datetime;
use crate::xml::emit::emit_document;
use crate::xml::parse::{Document, Element, Node, QName};
#[cfg(feature = "xmlenc")]
use crate::xmlenc::algorithms::{DataEncryptionAlgorithm, KeyTransportAlgorithm};

/// SAML 2.0 status URI for Success.
const STATUS_SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
/// SAML 2.0 SubjectConfirmation Method URI for bearer.
const SUBJECT_CONFIRMATION_BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

/// Inputs for [`issue_response`]. See RFC-004 §3.
pub(crate) struct IssueResponseInputs<'a> {
    pub sp: &'a SpDescriptor,
    pub idp_entity_id: &'a str,
    /// Request ID to echo via InResponseTo. None for IdP-initiated SSO
    /// (allowed when SP advertises allow_unsolicited).
    pub in_response_to: Option<&'a str>,
    pub name_id: NameId,
    pub attributes: Vec<Attribute>,
    pub authn_instant: SystemTime,
    pub session_index: String,
    pub session_not_on_or_after: Option<SystemTime>,
    pub authn_context_class_ref: AuthnContextClassRef,
    /// `Some(true)` forces, `Some(false)` forbids, `None` defaults per
    /// (encrypt_when_possible && sp.encryption_cert().is_some()).
    pub force_encrypt_assertion: Option<bool>,
    pub encrypt_assertions_when_possible: bool,
    pub now: SystemTime,
    pub assertion_lifetime: Duration,
    pub subject_confirmation_lifetime: Duration,
    /// IdP signing key.
    pub signing_key: &'a KeyPair,
    pub sign_responses: bool,
    pub sign_assertions: bool,
    pub outbound_signature_algorithm: SignatureAlgorithm,
    pub outbound_digest_algorithm: DigestAlgorithm,
    pub outbound_c14n: C14nAlgorithm,
    #[cfg(feature = "xmlenc")]
    pub outbound_data_encryption_algorithm: DataEncryptionAlgorithm,
    #[cfg(feature = "xmlenc")]
    pub outbound_key_transport_algorithm: KeyTransportAlgorithm,
    /// Resolved ACS endpoint (from the SP descriptor); determines POST vs Artifact.
    pub acs_endpoint: &'a SsoResponseEndpoint,
    pub relay_state: Option<&'a str>,
}

/// Build the SSO Response and return a binding-encoded dispatch.
pub(crate) fn issue_response(input: IssueResponseInputs<'_>) -> Result<SsoResponseDispatch, Error> {
    let response_id = generate_xml_id();
    let assertion_id = generate_xml_id();

    let assertion_elem = build_assertion(&BuildAssertionParams {
        assertion_id: &assertion_id,
        idp_entity_id: input.idp_entity_id,
        name_id: &input.name_id,
        sp_entity_id: input.sp.entity_id.as_str(),
        acs_url: input.acs_endpoint.url.as_str(),
        in_response_to: input.in_response_to,
        now: input.now,
        assertion_lifetime: input.assertion_lifetime,
        subject_confirmation_lifetime: input.subject_confirmation_lifetime,
        session_index: input.session_index.as_str(),
        session_not_on_or_after: input.session_not_on_or_after,
        authn_context_class_ref: &input.authn_context_class_ref,
        authn_instant: input.authn_instant,
        attributes: &input.attributes,
    })?;

    // ---- Optionally sign the assertion in-place. ---------------------------
    let assertion_elem = maybe_sign(
        assertion_elem,
        input.sign_assertions,
        input.signing_key,
        input.outbound_signature_algorithm,
        input.outbound_digest_algorithm,
        input.outbound_c14n,
    )?;

    // ---- Decide whether to encrypt the assertion. --------------------------
    let should_encrypt = input.force_encrypt_assertion.unwrap_or_else(|| {
        input.encrypt_assertions_when_possible && input.sp.encryption_cert().is_some()
    });

    let assertion_or_encrypted = if should_encrypt {
        #[cfg(feature = "xmlenc")]
        {
            let cert = input
                .sp
                .encryption_cert()
                .ok_or(Error::InvalidConfiguration {
                    reason: "encryption requested but SP has no encryption_cert in metadata",
                })?;
            crate::xmlenc::encrypt::encrypt_assertion(
                &assertion_elem,
                cert,
                input.outbound_data_encryption_algorithm,
                input.outbound_key_transport_algorithm,
            )?
        }
        #[cfg(not(feature = "xmlenc"))]
        {
            let _ = &assertion_elem;
            return Err(Error::InvalidConfiguration {
                reason: "EncryptedAssertion requires the `xmlenc` feature",
            });
        }
    } else {
        assertion_elem
    };

    let response_elem = build_response(
        &response_id,
        input.idp_entity_id,
        input.acs_endpoint.url.as_str(),
        input.in_response_to,
        input.now,
        Status::success(),
        Some(assertion_or_encrypted),
    )?;

    let response_elem = maybe_sign(
        response_elem,
        input.sign_responses,
        input.signing_key,
        input.outbound_signature_algorithm,
        input.outbound_digest_algorithm,
        input.outbound_c14n,
    )?;

    // Serialize + dispatch via the configured ACS binding.
    let doc = Document::new(response_elem)?;
    let xml = emit_document(&doc)?.into_bytes();

    dispatch_binding(
        input.acs_endpoint,
        &xml,
        input.relay_state,
        input.idp_entity_id,
    )
}

// =============================================================================
// Error Response (RFC-004 §4)
// =============================================================================

/// Standard `Status/StatusCode/@Value` URIs per SAML 2.0 Core §3.2.2.2.
///
/// This is the public surface for IdP-side error responses (RFC-004 §4).
/// `Custom(String)` carries any URI not modeled as a variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SamlStatusCode {
    Requester,
    Responder,
    VersionMismatch,
    AuthnFailed,
    InvalidAttrNameOrValue,
    InvalidNameIdPolicy,
    NoAuthnContext,
    NoAvailableIdp,
    NoPassive,
    NoSupportedIdp,
    PartialLogout,
    ProxyCountExceeded,
    RequestDenied,
    RequestUnsupported,
    RequestVersionDeprecated,
    RequestVersionTooHigh,
    RequestVersionTooLow,
    ResourceNotRecognized,
    TooManyResponses,
    UnknownAttrProfile,
    UnknownPrincipal,
    UnsupportedBinding,
    Custom(String),
}

impl SamlStatusCode {
    /// Status code URI for this variant.
    pub fn uri(&self) -> &str {
        match self {
            Self::Requester => "urn:oasis:names:tc:SAML:2.0:status:Requester",
            Self::Responder => "urn:oasis:names:tc:SAML:2.0:status:Responder",
            Self::VersionMismatch => "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch",
            Self::AuthnFailed => "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
            Self::InvalidAttrNameOrValue => {
                "urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue"
            }
            Self::InvalidNameIdPolicy => "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy",
            Self::NoAuthnContext => "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext",
            Self::NoAvailableIdp => "urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP",
            Self::NoPassive => "urn:oasis:names:tc:SAML:2.0:status:NoPassive",
            Self::NoSupportedIdp => "urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP",
            Self::PartialLogout => "urn:oasis:names:tc:SAML:2.0:status:PartialLogout",
            Self::ProxyCountExceeded => "urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded",
            Self::RequestDenied => "urn:oasis:names:tc:SAML:2.0:status:RequestDenied",
            Self::RequestUnsupported => "urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported",
            Self::RequestVersionDeprecated => {
                "urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated"
            }
            Self::RequestVersionTooHigh => {
                "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh"
            }
            Self::RequestVersionTooLow => "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow",
            Self::ResourceNotRecognized => {
                "urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized"
            }
            Self::TooManyResponses => "urn:oasis:names:tc:SAML:2.0:status:TooManyResponses",
            Self::UnknownAttrProfile => "urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile",
            Self::UnknownPrincipal => "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal",
            Self::UnsupportedBinding => "urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding",
            Self::Custom(s) => s.as_str(),
        }
    }
}

/// Inputs for [`issue_error_response`]. Symmetric with `IssueResponseInputs`
/// but trimmed: no assertion, no encryption.
pub(crate) struct IssueErrorResponseInputs<'a> {
    pub idp_entity_id: &'a str,
    pub in_response_to: Option<&'a str>,
    pub now: SystemTime,
    pub status_code: SamlStatusCode,
    pub second_level_status_code: Option<SamlStatusCode>,
    pub message: Option<String>,
    pub signing_key: &'a KeyPair,
    pub sign_responses: bool,
    pub outbound_signature_algorithm: SignatureAlgorithm,
    pub outbound_digest_algorithm: DigestAlgorithm,
    pub outbound_c14n: C14nAlgorithm,
    pub acs_endpoint: &'a SsoResponseEndpoint,
    pub relay_state: Option<&'a str>,
}

/// Issue an error Response — Status != Success, no Assertion.
pub(crate) fn issue_error_response(
    input: IssueErrorResponseInputs<'_>,
) -> Result<SsoResponseDispatch, Error> {
    let response_id = generate_xml_id();

    let status = Status {
        code_uri: input.status_code.uri().to_owned(),
        second_level: input.second_level_status_code.map(|c| c.uri().to_owned()),
        message: input.message,
    };

    let response_elem = build_response(
        &response_id,
        input.idp_entity_id,
        input.acs_endpoint.url.as_str(),
        input.in_response_to,
        input.now,
        status,
        None,
    )?;

    let response_elem = maybe_sign(
        response_elem,
        input.sign_responses,
        input.signing_key,
        input.outbound_signature_algorithm,
        input.outbound_digest_algorithm,
        input.outbound_c14n,
    )?;

    let doc = Document::new(response_elem)?;
    let xml = emit_document(&doc)?.into_bytes();

    dispatch_binding(
        input.acs_endpoint,
        &xml,
        input.relay_state,
        input.idp_entity_id,
    )
}

/// Wrap `element` in a stash [`Document`] and sign it (returning the signed
/// element) when `should_sign`; otherwise return `element` untouched. The
/// stash document only exists to give `sign_element` the document context it
/// needs for canonicalization — the caller re-wraps the returned element in a
/// fresh document before emit.
fn maybe_sign(
    element: Element,
    should_sign: bool,
    signing_key: &KeyPair,
    sig_alg: SignatureAlgorithm,
    digest_alg: DigestAlgorithm,
    c14n: C14nAlgorithm,
) -> Result<Element, Error> {
    if !should_sign {
        return Ok(element);
    }
    let stash = Document::new(element)?;
    sign_element(
        stash.root().clone(),
        &stash,
        SignOptions {
            signing_key,
            sig_alg,
            digest_alg,
            c14n_alg: c14n,
            inclusive_namespaces: &[],
            include_x509_cert: true,
        },
    )
}

// =============================================================================
// Internal element builders
// =============================================================================

struct Status {
    code_uri: String,
    second_level: Option<String>,
    message: Option<String>,
}

impl Status {
    fn success() -> Self {
        Self {
            code_uri: STATUS_SUCCESS.to_owned(),
            second_level: None,
            message: None,
        }
    }
}

/// Inputs for [`build_assertion`].
struct BuildAssertionParams<'a> {
    assertion_id: &'a str,
    idp_entity_id: &'a str,
    name_id: &'a NameId,
    sp_entity_id: &'a str,
    acs_url: &'a str,
    in_response_to: Option<&'a str>,
    now: SystemTime,
    assertion_lifetime: Duration,
    subject_confirmation_lifetime: Duration,
    session_index: &'a str,
    session_not_on_or_after: Option<SystemTime>,
    authn_context_class_ref: &'a AuthnContextClassRef,
    authn_instant: SystemTime,
    attributes: &'a [Attribute],
}

fn build_assertion(params: &BuildAssertionParams<'_>) -> Result<Element, Error> {
    let &BuildAssertionParams {
        assertion_id,
        idp_entity_id,
        name_id,
        sp_entity_id,
        acs_url,
        in_response_to,
        now,
        assertion_lifetime,
        subject_confirmation_lifetime,
        session_index,
        session_not_on_or_after,
        authn_context_class_ref,
        authn_instant,
        attributes,
    } = params;

    let issuer = Element::build(saml_qname("Issuer"))
        .with_text(idp_entity_id.to_owned())
        .finish();

    // ---- Subject ----
    let mut name_id_builder = Element::build(saml_qname("NameID"))
        .with_attribute(
            QName::new(None, "Format"),
            name_id.format.as_uri().to_owned(),
        )
        .with_text(name_id.value.clone());
    if let Some(nq) = &name_id.name_qualifier {
        name_id_builder =
            name_id_builder.with_attribute(QName::new(None, "NameQualifier"), nq.clone());
    }
    // For Persistent format: always populate SPNameQualifier with the SP entity
    // ID for privacy (RFC-004 §3.1). If the caller already set it, prefer that.
    let sp_name_qualifier = name_id.sp_name_qualifier.clone().or_else(|| {
        matches!(name_id.format, NameIdFormat::Persistent).then(|| sp_entity_id.to_owned())
    });
    if let Some(spq) = sp_name_qualifier {
        name_id_builder = name_id_builder.with_attribute(QName::new(None, "SPNameQualifier"), spq);
    }
    if let Some(provided) = &name_id.sp_provided_id {
        name_id_builder =
            name_id_builder.with_attribute(QName::new(None, "SPProvidedID"), provided.clone());
    }
    let name_id_elem = name_id_builder.finish();

    let subject_confirmation_not_on_or_after = now
        .checked_add(subject_confirmation_lifetime)
        .ok_or(Error::InvalidConfiguration {
            reason: "now + subject_confirmation_lifetime overflows SystemTime",
        })?;
    let mut scd_builder = Element::build(saml_qname("SubjectConfirmationData"))
        .with_attribute(QName::new(None, "Recipient"), acs_url.to_owned())
        .with_attribute(
            QName::new(None, "NotOnOrAfter"),
            format_xs_datetime(subject_confirmation_not_on_or_after)?,
        );
    if let Some(irt) = in_response_to {
        scd_builder = scd_builder.with_attribute(QName::new(None, "InResponseTo"), irt.to_owned());
    }
    let scd = scd_builder.finish();
    let subject_confirmation = Element::build(saml_qname("SubjectConfirmation"))
        .with_attribute(
            QName::new(None, "Method"),
            SUBJECT_CONFIRMATION_BEARER.to_owned(),
        )
        .with_child(Node::Element(scd))
        .finish();

    let subject = Element::build(saml_qname("Subject"))
        .with_child(Node::Element(name_id_elem))
        .with_child(Node::Element(subject_confirmation))
        .finish();

    // ---- Conditions ----
    let audience = Element::build(saml_qname("Audience"))
        .with_text(sp_entity_id.to_owned())
        .finish();
    let audience_restriction = Element::build(saml_qname("AudienceRestriction"))
        .with_child(Node::Element(audience))
        .finish();
    let conditions_not_before =
        now.checked_sub(Duration::from_mins(1))
            .ok_or(Error::InvalidConfiguration {
                reason: "now - 1min underflows SystemTime",
            })?;
    let conditions_not_on_or_after =
        now.checked_add(assertion_lifetime)
            .ok_or(Error::InvalidConfiguration {
                reason: "now + assertion_lifetime overflows SystemTime",
            })?;
    let conditions = Element::build(saml_qname("Conditions"))
        .with_attribute(
            QName::new(None, "NotBefore"),
            format_xs_datetime(conditions_not_before)?,
        )
        .with_attribute(
            QName::new(None, "NotOnOrAfter"),
            format_xs_datetime(conditions_not_on_or_after)?,
        )
        .with_child(Node::Element(audience_restriction))
        .finish();

    // ---- AuthnStatement ----
    let class_ref = Element::build(saml_qname("AuthnContextClassRef"))
        .with_text(authn_context_class_ref.as_uri().to_owned())
        .finish();
    let authn_context = Element::build(saml_qname("AuthnContext"))
        .with_child(Node::Element(class_ref))
        .finish();
    let mut authn_stmt_builder = Element::build(saml_qname("AuthnStatement"))
        .with_attribute(
            QName::new(None, "AuthnInstant"),
            format_xs_datetime(authn_instant)?,
        )
        .with_attribute(QName::new(None, "SessionIndex"), session_index.to_owned());
    if let Some(snoa) = session_not_on_or_after {
        authn_stmt_builder = authn_stmt_builder.with_attribute(
            QName::new(None, "SessionNotOnOrAfter"),
            format_xs_datetime(snoa)?,
        );
    }
    let authn_stmt = authn_stmt_builder
        .with_child(Node::Element(authn_context))
        .finish();

    // ---- Assertion ----
    let mut assertion_builder = Element::build(saml_qname("Assertion"))
        .with_namespace(Some("saml".to_owned()), SAML_NS)
        .with_attribute(QName::new(None, "ID"), assertion_id.to_owned())
        .with_attribute(QName::new(None, "Version"), "2.0")
        .with_attribute(QName::new(None, "IssueInstant"), format_xs_datetime(now)?)
        .with_child(Node::Element(issuer))
        .with_child(Node::Element(subject))
        .with_child(Node::Element(conditions))
        .with_child(Node::Element(authn_stmt));

    if !attributes.is_empty() {
        let mut attr_stmt = Element::build(saml_qname("AttributeStatement"));
        for attr in attributes {
            attr_stmt = attr_stmt.with_child(Node::Element(build_attribute(attr)));
        }
        assertion_builder = assertion_builder.with_child(Node::Element(attr_stmt.finish()));
    }

    Ok(assertion_builder.finish())
}

fn build_attribute(attr: &Attribute) -> Element {
    let mut b = Element::build(saml_qname("Attribute"))
        .with_attribute(QName::new(None, "Name"), attr.name.clone());
    if let Some(fmt) = &attr.name_format {
        b = b.with_attribute(QName::new(None, "NameFormat"), fmt.clone());
    }
    if let Some(friendly) = &attr.friendly_name {
        b = b.with_attribute(QName::new(None, "FriendlyName"), friendly.clone());
    }
    for value in &attr.values {
        let v = Element::build(saml_qname("AttributeValue"))
            .with_text(value.clone())
            .finish();
        b = b.with_child(Node::Element(v));
    }
    b.finish()
}

fn build_response(
    response_id: &str,
    idp_entity_id: &str,
    destination: &str,
    in_response_to: Option<&str>,
    now: SystemTime,
    status: Status,
    assertion_or_encrypted: Option<Element>,
) -> Result<Element, Error> {
    let issuer = Element::build(saml_qname("Issuer"))
        .with_text(idp_entity_id.to_owned())
        .finish();

    let mut status_code_builder = Element::build(samlp_qname("StatusCode"))
        .with_attribute(QName::new(None, "Value"), status.code_uri.clone());
    if let Some(sl) = &status.second_level {
        let nested = Element::build(samlp_qname("StatusCode"))
            .with_attribute(QName::new(None, "Value"), sl.clone())
            .finish();
        status_code_builder = status_code_builder.with_child(Node::Element(nested));
    }
    let status_code = status_code_builder.finish();
    let mut status_builder =
        Element::build(samlp_qname("Status")).with_child(Node::Element(status_code));
    if let Some(msg) = &status.message {
        let m = Element::build(samlp_qname("StatusMessage"))
            .with_text(msg.clone())
            .finish();
        status_builder = status_builder.with_child(Node::Element(m));
    }
    let status_elem = status_builder.finish();

    let mut response_builder = Element::build(samlp_qname("Response"))
        .with_namespace(Some("samlp".to_owned()), SAMLP_NS)
        .with_namespace(Some("saml".to_owned()), SAML_NS)
        .with_attribute(QName::new(None, "ID"), response_id.to_owned())
        .with_attribute(QName::new(None, "Version"), "2.0")
        .with_attribute(QName::new(None, "IssueInstant"), format_xs_datetime(now)?)
        .with_attribute(QName::new(None, "Destination"), destination.to_owned());
    if let Some(irt) = in_response_to {
        response_builder =
            response_builder.with_attribute(QName::new(None, "InResponseTo"), irt.to_owned());
    }
    response_builder = response_builder
        .with_child(Node::Element(issuer))
        .with_child(Node::Element(status_elem));
    if let Some(a) = assertion_or_encrypted {
        response_builder = response_builder.with_child(Node::Element(a));
    }
    Ok(response_builder.finish())
}

// =============================================================================
// Binding dispatch
// =============================================================================

fn dispatch_binding(
    acs_endpoint: &SsoResponseEndpoint,
    xml: &[u8],
    relay_state: Option<&str>,
    idp_entity_id: &str,
) -> Result<SsoResponseDispatch, Error> {
    match acs_endpoint.binding {
        SsoResponseBinding::HttpPost => {
            let url = url::Url::parse(&acs_endpoint.url).map_err(|_url_parse_err| {
                Error::InvalidConfiguration {
                    reason: "ACS endpoint URL is not a valid URL",
                }
            })?;
            Ok(crate::binding::post::encode_sso_response(
                &url,
                xml,
                relay_state,
            ))
        }
        SsoResponseBinding::HttpArtifact => {
            issue_artifact(acs_endpoint, xml, relay_state, idp_entity_id)
        }
    }
}

#[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
fn issue_artifact(
    acs_endpoint: &SsoResponseEndpoint,
    xml: &[u8],
    relay_state: Option<&str>,
    idp_entity_id: &str,
) -> Result<SsoResponseDispatch, Error> {
    let url = url::Url::parse(&acs_endpoint.url).map_err(|_url_parse_err| {
        Error::InvalidConfiguration {
            reason: "ACS endpoint URL is not a valid URL",
        }
    })?;
    let xml_str = std::str::from_utf8(xml).map_err(|_utf8_err| {
        Error::XmlEmit("non-UTF-8 XML bytes for artifact response".to_string())
    })?;
    let redirect = crate::binding::artifact::build_artifact_redirect(
        &url,
        idp_entity_id,
        acs_endpoint.index.unwrap_or(0),
        xml_str.to_owned(),
        relay_state,
    )?;
    Ok(SsoResponseDispatch::Artifact(redirect))
}

#[cfg(not(all(feature = "artifact-binding", feature = "weak-algos")))]
fn issue_artifact(
    _acs_endpoint: &SsoResponseEndpoint,
    _xml: &[u8],
    _relay_state: Option<&str>,
    _idp_entity_id: &str,
) -> Result<SsoResponseDispatch, Error> {
    Err(Error::UnsupportedByPeer {
        binding: crate::binding::Binding::HttpArtifact,
    })
}

// =============================================================================
// Helpers
// =============================================================================

/// Generate an XML `ID` of the shape `_<32 hex chars>` (16 random bytes,
/// hex-encoded with a leading underscore for XML `xs:ID` legality).
fn generate_xml_id() -> String {
    let mut bytes = [0u8; 16];
    // OsRng essentially never fails on production OSes; on the rare failure
    // path we still emit a well-formed (if low-entropy) ID rather than panic.
    let _fill_result = OsRng.try_fill_bytes(&mut bytes);
    let mut out = String::with_capacity(33);
    out.push('_');
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for b in bytes {
        let hi = usize::from(b >> 4);
        let lo = usize::from(b & 0x0f);
        // SAFETY-via-construction: `hi` and `lo` are in 0..16 by definition of
        // the right-shift and mask, and `HEX` is a 16-byte table.
        if let (Some(&h), Some(&l)) = (HEX.get(hi), HEX.get(lo)) {
            out.push(h as char);
            out.push(l as char);
        }
    }
    out
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::cert::X509Certificate;
    use crate::crypto::cert::test_vectors::{RSA_CERT_PEM, RSA_KEY_PKCS8_PEM};
    use crate::nameid::NameIdFormat;
    use crate::response::parse::parse_response;
    use crate::response::validate::{ValidateResponse, validate_response};
    use crate::xml::parse::Document;
    use std::time::{Duration, UNIX_EPOCH};

    fn rsa_signing_key() -> KeyPair {
        let kp = KeyPair::from_pkcs8_pem(RSA_KEY_PKCS8_PEM).unwrap();
        let cert = X509Certificate::from_pem(RSA_CERT_PEM).unwrap();
        kp.with_certificate(cert)
    }

    fn sp_descriptor(with_encryption_cert: bool) -> SpDescriptor {
        let signing_certs = vec![X509Certificate::from_pem(RSA_CERT_PEM).unwrap()];
        let encryption_certs = if with_encryption_cert {
            vec![X509Certificate::from_pem(RSA_CERT_PEM).unwrap()]
        } else {
            vec![]
        };
        SpDescriptor {
            entity_id: "https://sp.example.com".to_owned(),
            assertion_consumer_services: vec![SsoResponseEndpoint::post(
                "https://sp.example.com/acs",
                0,
                true,
            )],
            single_logout_services: vec![],
            signing_certs,
            encryption_certs,
            supported_name_id_formats: vec![],
            want_assertions_signed: true,
            authn_requests_signed: false,
            valid_until: None,
            cache_duration: None,
        }
    }

    fn idp_descriptor() -> crate::descriptor::IdpDescriptor {
        crate::descriptor::IdpDescriptor {
            entity_id: "https://idp.example.com".to_owned(),
            sso_endpoints: vec![],
            slo_endpoints: vec![],
            artifact_resolution_endpoints: vec![],
            signing_certs: vec![X509Certificate::from_pem(RSA_CERT_PEM).unwrap()],
            encryption_certs: vec![],
            supported_name_id_formats: vec![],
            want_authn_requests_signed: false,
            valid_until: None,
            cache_duration: None,
        }
    }

    fn fixed_now() -> SystemTime {
        // 2026-05-26T12:00:00Z == 494388 hours past UNIX_EPOCH.
        UNIX_EPOCH
            .checked_add(Duration::from_hours(494_388))
            .expect("UNIX_EPOCH + small duration fits in SystemTime")
    }

    fn make_inputs<'a>(
        sp: &'a SpDescriptor,
        signing_key: &'a KeyPair,
        attributes: Vec<Attribute>,
        name_id: NameId,
    ) -> IssueResponseInputs<'a> {
        IssueResponseInputs {
            sp,
            idp_entity_id: "https://idp.example.com",
            in_response_to: Some("_req1"),
            name_id,
            attributes,
            authn_instant: fixed_now(),
            session_index: "sess-7".to_owned(),
            session_not_on_or_after: fixed_now().checked_add(Duration::from_hours(1)),
            authn_context_class_ref: AuthnContextClassRef::Password,
            force_encrypt_assertion: None,
            encrypt_assertions_when_possible: false,
            now: fixed_now(),
            assertion_lifetime: Duration::from_mins(10),
            subject_confirmation_lifetime: Duration::from_mins(5),
            signing_key,
            sign_responses: false,
            sign_assertions: true,
            outbound_signature_algorithm: SignatureAlgorithm::RsaSha256,
            outbound_digest_algorithm: DigestAlgorithm::Sha256,
            outbound_c14n: C14nAlgorithm::ExclusiveCanonical,
            #[cfg(feature = "xmlenc")]
            outbound_data_encryption_algorithm: DataEncryptionAlgorithm::Aes256Gcm,
            #[cfg(feature = "xmlenc")]
            outbound_key_transport_algorithm: KeyTransportAlgorithm::RsaOaep,
            acs_endpoint: &sp.assertion_consumer_services[0],
            relay_state: Some("opaque-state"),
        }
    }

    #[test]
    fn round_trip_issue_then_validate() {
        let sp = sp_descriptor(false);
        let kp = rsa_signing_key();
        let inputs = make_inputs(
            &sp,
            &kp,
            vec![Attribute::email("alice@example.com")],
            NameId::email("alice@example.com"),
        );
        let dispatch = issue_response(inputs).expect("issue");

        // Extract the POST form.
        let form = match dispatch {
            SsoResponseDispatch::Post(f) => f,
            other @ SsoResponseDispatch::Artifact(_) => {
                panic!("expected Post, got {other:?}")
            }
        };
        assert_eq!(form.action.as_str(), "https://sp.example.com/acs");
        assert_eq!(form.relay_state.as_deref(), Some("opaque-state"));

        // Round-trip the SAMLResponse base64.
        let decoded =
            crate::binding::post::decode(&form.saml_response, form.relay_state.as_deref())
                .expect("decode");
        let doc = Document::parse(&decoded.xml).expect("reparse");
        let (parsed, _) = parse_response(&doc).expect("parse");

        let idp = idp_descriptor();
        let policy = crate::dsig::algorithms::PeerCryptoPolicy::strong_defaults();
        let validate_input = ValidateResponse {
            document: &doc,
            parsed,
            idp: &idp,
            peer_crypto_policy: &policy,
            #[cfg(feature = "xmlenc")]
            decryption_keys: &[],
            sp_entity_id: "https://sp.example.com",
            expected_destination: "https://sp.example.com/acs",
            tracker_request_id: Some("_req1"),
            allow_unsolicited: false,
            want_response_signed: false,
            want_assertions_signed: true,
            now: fixed_now() + Duration::from_secs(30),
            clock_skew: Duration::from_mins(1),
            requested_authn_context: None,
        };
        let identity = validate_response(validate_input).expect("validate");
        assert_eq!(identity.name_id.value, "alice@example.com");
        assert_eq!(identity.session_index.as_deref(), Some("sess-7"));
        assert_eq!(identity.attributes.len(), 1);
    }

    #[test]
    fn persistent_name_id_sets_sp_name_qualifier() {
        let sp = sp_descriptor(false);
        let kp = rsa_signing_key();
        let inputs = make_inputs(
            &sp,
            &kp,
            vec![],
            NameId::new("opaque-pairwise-id", NameIdFormat::Persistent),
        );
        let dispatch = issue_response(inputs).expect("issue");

        let form = match dispatch {
            SsoResponseDispatch::Post(f) => f,
            other @ SsoResponseDispatch::Artifact(_) => {
                panic!("expected Post, got {other:?}")
            }
        };
        let decoded = crate::binding::post::decode(&form.saml_response, None).expect("decode");
        let doc = Document::parse(&decoded.xml).expect("reparse");

        // Walk the tree to find the NameID and confirm SPNameQualifier is set
        // to the SP entity ID.
        let response = doc.root();
        let assertion = response
            .child_element(Some(SAML_NS), "Assertion")
            .expect("assertion");
        let subject = assertion
            .child_element(Some(SAML_NS), "Subject")
            .expect("subject");
        let name_id = subject
            .child_element(Some(SAML_NS), "NameID")
            .expect("name_id");
        assert_eq!(
            name_id.attribute(None, "SPNameQualifier"),
            Some(sp.entity_id.as_str())
        );
        assert_eq!(name_id.text_content(), "opaque-pairwise-id");
        assert_eq!(
            name_id.attribute(None, "Format"),
            Some(NameIdFormat::Persistent.as_uri())
        );
    }

    #[cfg(feature = "xmlenc")]
    #[test]
    fn encryption_is_invoked_when_sp_has_encryption_cert() {
        let sp = sp_descriptor(true);
        let kp = rsa_signing_key();
        let mut inputs = make_inputs(&sp, &kp, vec![], NameId::email("alice@example.com"));
        inputs.encrypt_assertions_when_possible = true;
        // Disable assertion-signing because signing inside an EncryptedAssertion
        // wrapper isn't meaningful — the signature lives inside the ciphertext.
        // The Response root would normally be signed in production; in this
        // test we just confirm the encryption was applied.
        inputs.sign_assertions = false;
        let dispatch = issue_response(inputs).expect("issue");
        let form = match dispatch {
            SsoResponseDispatch::Post(f) => f,
            other @ SsoResponseDispatch::Artifact(_) => {
                panic!("expected Post, got {other:?}")
            }
        };
        let decoded = crate::binding::post::decode(&form.saml_response, None).expect("decode");
        let doc = Document::parse(&decoded.xml).expect("reparse");
        let response = doc.root();
        // The outbound Response carries <saml:EncryptedAssertion> instead of
        // <saml:Assertion>.
        assert!(
            response
                .child_element(Some(SAML_NS), "EncryptedAssertion")
                .is_some(),
            "expected EncryptedAssertion child"
        );
        assert!(
            response.child_element(Some(SAML_NS), "Assertion").is_none(),
            "should not also emit a cleartext Assertion"
        );
    }

    #[test]
    fn force_encrypt_off_overrides_when_possible_flag() {
        let sp = sp_descriptor(true);
        let kp = rsa_signing_key();
        let mut inputs = make_inputs(&sp, &kp, vec![], NameId::email("alice@example.com"));
        inputs.encrypt_assertions_when_possible = true;
        inputs.force_encrypt_assertion = Some(false);
        let dispatch = issue_response(inputs).expect("issue");
        let form = match dispatch {
            SsoResponseDispatch::Post(f) => f,
            other @ SsoResponseDispatch::Artifact(_) => {
                panic!("expected Post, got {other:?}")
            }
        };
        let decoded = crate::binding::post::decode(&form.saml_response, None).expect("decode");
        let doc = Document::parse(&decoded.xml).expect("reparse");
        // Even though encryption-when-possible is true, force_encrypt=Some(false)
        // wins.
        assert!(
            doc.root()
                .child_element(Some(SAML_NS), "EncryptedAssertion")
                .is_none()
        );
        assert!(
            doc.root()
                .child_element(Some(SAML_NS), "Assertion")
                .is_some()
        );
    }

    #[test]
    fn samlp_status_code_uris_match_spec() {
        assert_eq!(
            SamlStatusCode::Requester.uri(),
            "urn:oasis:names:tc:SAML:2.0:status:Requester"
        );
        assert_eq!(
            SamlStatusCode::AuthnFailed.uri(),
            "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"
        );
        assert_eq!(
            SamlStatusCode::InvalidNameIdPolicy.uri(),
            "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy"
        );
        assert_eq!(
            SamlStatusCode::Custom("urn:x:foo".to_owned()).uri(),
            "urn:x:foo"
        );
    }

    #[test]
    fn issue_error_response_emits_status_not_success() {
        let sp = sp_descriptor(false);
        let kp = rsa_signing_key();
        let inputs = IssueErrorResponseInputs {
            idp_entity_id: "https://idp.example.com",
            in_response_to: Some("_req1"),
            now: fixed_now(),
            status_code: SamlStatusCode::AuthnFailed,
            second_level_status_code: Some(SamlStatusCode::NoAuthnContext),
            message: Some("MFA not satisfied".to_owned()),
            signing_key: &kp,
            sign_responses: false,
            outbound_signature_algorithm: SignatureAlgorithm::RsaSha256,
            outbound_digest_algorithm: DigestAlgorithm::Sha256,
            outbound_c14n: C14nAlgorithm::ExclusiveCanonical,
            acs_endpoint: &sp.assertion_consumer_services[0],
            relay_state: None,
        };
        let dispatch = issue_error_response(inputs).expect("issue error");
        let form = match dispatch {
            SsoResponseDispatch::Post(f) => f,
            other @ SsoResponseDispatch::Artifact(_) => {
                panic!("expected Post, got {other:?}")
            }
        };
        let decoded = crate::binding::post::decode(&form.saml_response, None).expect("decode");
        let doc = Document::parse(&decoded.xml).expect("reparse");

        // parse_response is strict — it requires an assertion, which we
        // intentionally omit on the error path. Walk the tree directly to
        // confirm the wire shape.
        let response = doc.root();
        assert_eq!(response.qname().local(), "Response");
        let status = response
            .child_element(Some(SAMLP_NS), "Status")
            .expect("status");
        let code = status
            .child_element(Some(SAMLP_NS), "StatusCode")
            .expect("status code");
        assert_eq!(
            code.attribute(None, "Value"),
            Some(SamlStatusCode::AuthnFailed.uri())
        );
        let nested = code
            .child_element(Some(SAMLP_NS), "StatusCode")
            .expect("nested status code");
        assert_eq!(
            nested.attribute(None, "Value"),
            Some(SamlStatusCode::NoAuthnContext.uri())
        );
        let msg = status
            .child_element(Some(SAMLP_NS), "StatusMessage")
            .expect("status message");
        assert_eq!(msg.text_content(), "MFA not satisfied");
        // No assertion present.
        assert!(response.child_element(Some(SAML_NS), "Assertion").is_none());
        // parse_response surfaces the status-code-only shape — validate_response
        // is where StatusNotSuccess short-circuits before the missing-assertion
        // check.
        let (parsed, _) = parse_response(&doc).expect("parse error response");
        assert!(parsed.assertion.is_none());
        assert_eq!(parsed.status_code, SamlStatusCode::AuthnFailed.uri());
    }

    #[cfg(all(feature = "artifact-binding", feature = "weak-algos"))]
    #[test]
    fn artifact_binding_dispatch_returns_artifact_redirect() {
        let mut sp = sp_descriptor(false);
        sp.assertion_consumer_services = vec![SsoResponseEndpoint::artifact(
            "https://sp.example.com/acs/art",
            2,
            true,
        )];
        let kp = rsa_signing_key();
        let inputs = make_inputs(
            &sp,
            &kp,
            vec![Attribute::email("alice@example.com")],
            NameId::email("alice@example.com"),
        );
        let dispatch = issue_response(inputs).expect("issue");
        match dispatch {
            SsoResponseDispatch::Artifact(redirect) => {
                assert!(
                    redirect
                        .redirect_to
                        .as_str()
                        .starts_with("https://sp.example.com/acs/art")
                );
                assert!(!redirect.artifact.is_empty());
                assert!(
                    redirect.response_xml.contains("<samlp:Response")
                        || redirect.response_xml.contains("Response")
                );
            }
            other @ SsoResponseDispatch::Post(_) => {
                panic!("expected Artifact, got {other:?}")
            }
        }
    }

    #[cfg(not(all(feature = "artifact-binding", feature = "weak-algos")))]
    #[test]
    fn artifact_binding_returns_unsupported_when_feature_off() {
        let mut sp = sp_descriptor(false);
        sp.assertion_consumer_services = vec![SsoResponseEndpoint::artifact(
            "https://sp.example.com/acs/art",
            2,
            true,
        )];
        let kp = rsa_signing_key();
        let inputs = make_inputs(&sp, &kp, vec![], NameId::email("alice@example.com"));
        let err = issue_response(inputs).unwrap_err();
        match err {
            Error::UnsupportedByPeer { binding } => {
                assert_eq!(binding, crate::binding::Binding::HttpArtifact);
            }
            other => panic!("expected UnsupportedByPeer, got {other:?}"),
        }
    }
}
