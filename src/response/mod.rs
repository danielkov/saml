//! `<samlp:Response>` + `<saml:Assertion>` parse, validate, issue, identity extraction.

use crate::xml::parse::QName;

pub mod identity;
pub mod issue;
pub mod parse;
pub mod validate;

pub use identity::Identity;

pub(crate) const SAMLP_NS: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
pub(crate) const SAML_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";

pub(crate) fn samlp_qname(local: &str) -> QName {
    QName::new(Some(SAMLP_NS.to_owned()), local)
}

pub(crate) fn saml_qname(local: &str) -> QName {
    QName::new(Some(SAML_NS.to_owned()), local)
}
