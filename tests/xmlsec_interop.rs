//! Cross-check our emitted XML-DSig signatures against `xmlsec1`, the reference
//! XML Security Library verifier that Shibboleth, SimpleSAMLphp and
//! mod_auth_mellon build on. Our own round-trip tests are self-consistent; this
//! proves a *foreign* verifier accepts our output, which is the stronger interop
//! claim (ROADMAP "Live `xmlsec1` cross-check on metadata signing").
//!
//! The test self-skips when `xmlsec1` is not on `PATH`, so it is a no-op on
//! machines without the tool. CI installs the `xmlsec1` package before running.
//!
//! macOS install: `brew install libxmlsec1`. Debian/Ubuntu: `apt-get install
//! xmlsec1`.

mod common;

use std::io;
use std::process::{Command, Output};

/// True when a working `xmlsec1` binary is on `PATH`.
fn xmlsec1_available() -> bool {
    Command::new("xmlsec1")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Write `xml` + the signing cert to temp files and run `xmlsec1 --verify`.
///
/// The signing cert is carried inside the signature's
/// `<ds:KeyInfo>/<ds:X509Data>`, but it is self-signed, so we pass it via
/// `--trusted-pem` to anchor trust. `--id-attr:ID <node>` registers SAML's `ID`
/// attribute as the xml:id target so the `Reference URI="#..."` resolves.
fn verify_with_xmlsec1(xml: &str, id_node: &str, tag: &str) -> io::Result<Output> {
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let doc_path = dir.join(format!("saml-xmlsec-{pid}-{tag}.xml"));
    let cert_path = dir.join(format!("saml-xmlsec-{pid}-{tag}-cert.pem"));
    std::fs::write(&doc_path, xml)?;
    std::fs::write(&cert_path, common::RSA_CERT_PEM)?;

    let output = Command::new("xmlsec1")
        .arg("--verify")
        .arg("--enabled-key-data")
        .arg("x509")
        .arg("--trusted-pem")
        .arg(&cert_path)
        .arg("--id-attr:ID")
        .arg(id_node)
        .arg(&doc_path)
        .output();

    // Best-effort cleanup; cleanup failures are irrelevant to the test outcome.
    for path in [&doc_path, &cert_path] {
        if std::fs::remove_file(path).is_err() {
            // Temp files land in std::env::temp_dir(); leaving one behind on a
            // cleanup error is harmless.
        }
    }
    output
}

#[test]
fn xmlsec1_accepts_signed_idp_metadata() {
    if !xmlsec1_available() {
        eprintln!("skipping: xmlsec1 not on PATH");
        return;
    }
    let idp = common::make_idp(
        "https://idp.example.com/saml",
        "https://idp.example.com/sso",
    )
    .expect("idp builds");
    let xml = idp.metadata_xml(true).expect("signed idp metadata");
    let out = verify_with_xmlsec1(&xml, "EntityDescriptor", "idp").expect("run xmlsec1");
    assert!(
        out.status.success(),
        "xmlsec1 rejected our IdP metadata signature.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

#[test]
fn xmlsec1_accepts_signed_sp_metadata() {
    if !xmlsec1_available() {
        eprintln!("skipping: xmlsec1 not on PATH");
        return;
    }
    let sp = common::make_sp(
        "https://sp.example.com/saml",
        "https://sp.example.com/acs",
        true,
    )
    .expect("sp builds");
    let xml = sp.metadata_xml(true).expect("signed sp metadata");
    let out = verify_with_xmlsec1(&xml, "EntityDescriptor", "sp").expect("run xmlsec1");
    assert!(
        out.status.success(),
        "xmlsec1 rejected our SP metadata signature.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

/// Negative control: tampering with the signed content must make `xmlsec1`
/// *reject* the signature. Without this, a vacuous `--verify` that silently
/// passed would give false confidence in the positive tests above.
#[test]
fn xmlsec1_rejects_tampered_idp_metadata() {
    if !xmlsec1_available() {
        eprintln!("skipping: xmlsec1 not on PATH");
        return;
    }
    let idp = common::make_idp(
        "https://idp.example.com/saml",
        "https://idp.example.com/sso",
    )
    .expect("idp builds");
    let xml = idp.metadata_xml(true).expect("signed idp metadata");
    // Flip a signed attribute value: the entityID is covered by the enveloped
    // signature's digest, so any change invalidates it.
    let tampered = xml.replace(
        "https://idp.example.com/saml",
        "https://evil.example.com/saml",
    );
    assert_ne!(tampered, xml, "tamper precondition: entityID present");
    let out =
        verify_with_xmlsec1(&tampered, "EntityDescriptor", "idp-tampered").expect("run xmlsec1");
    assert!(
        !out.status.success(),
        "xmlsec1 accepted a tampered signature — the cross-check is vacuous.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}
