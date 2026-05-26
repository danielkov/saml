# RFC-006: Metadata

**Status**: Draft
**Date**: 2026-05-26

## Summary

SAML metadata is the XML mechanism by which SPs and IdPs publish their configuration: endpoints, certificates, supported NameID formats, signing requirements. Every SP must consume IdP metadata to know which IdP to trust; every IdP must consume SP metadata to know which SPs may send AuthnRequests. This RFC specifies metadata parsing and emission.

---

## 1. Wire format

Two top-level elements per OASIS *Metadata for the OASIS Security Assertion Markup Language (SAML) V2.0*:

- `<md:EntityDescriptor>` — describes a single entity by EntityID. Contains one or more role descriptors (`<md:IDPSSODescriptor>`, `<md:SPSSODescriptor>`, optionally `<md:AuthnAuthorityDescriptor>` and others).
- `<md:EntitiesDescriptor>` — a federation aggregate, containing multiple `<md:EntityDescriptor>` children. Used by federations like InCommon and eduGAIN.

---

## 2. Parsed descriptors

```rust
pub struct IdpDescriptor {
    pub entity_id: String,
    pub sso_endpoints: Vec<Endpoint>,
    pub slo_endpoints: Vec<Endpoint>,
    pub artifact_resolution_endpoints: Vec<Endpoint>,
    pub signing_certs: Vec<X509Certificate>,
    pub encryption_certs: Vec<X509Certificate>,
    pub supported_name_id_formats: Vec<NameIdFormat>,
    pub want_authn_requests_signed: bool,
    pub valid_until: Option<SystemTime>,
    pub cache_duration: Option<Duration>,
}

pub struct SpDescriptor {
    pub entity_id: String,
    /// Type-narrowed per SAML 2.0 Profiles §4.1.4: ACS endpoints can only
    /// carry POST or Artifact bindings. `SpDescriptor::from_metadata_xml`
    /// rejects metadata that advertises an `<md:AssertionConsumerService>`
    /// with Redirect or SOAP — that's a non-conformant SP and accepting it
    /// would let the IdP later mint a Response over Redirect.
    pub assertion_consumer_services: Vec<SsoResponseEndpoint>,
    pub single_logout_services: Vec<Endpoint>,
    pub signing_certs: Vec<X509Certificate>,
    pub encryption_certs: Vec<X509Certificate>,
    pub supported_name_id_formats: Vec<NameIdFormat>,
    pub want_assertions_signed: bool,
    pub authn_requests_signed: bool,
    pub valid_until: Option<SystemTime>,
    pub cache_duration: Option<Duration>,
}

impl IdpDescriptor {
    pub fn from_metadata_xml(xml: &[u8]) -> Result<Self, Error>;
    pub fn from_entity_descriptor_element(element: &Element) -> Result<Self, Error>;

    pub fn sso_endpoint(&self, binding: Binding) -> Option<&Endpoint>;
    pub fn slo_endpoint(&self, binding: Binding) -> Option<&Endpoint>;
    pub fn artifact_resolution_endpoint(&self) -> Option<&Endpoint>;
}

impl SpDescriptor {
    pub fn from_metadata_xml(xml: &[u8]) -> Result<Self, Error>;
    pub fn from_entity_descriptor_element(element: &Element) -> Result<Self, Error>;

    pub fn acs_endpoint_by_index(&self, index: u16) -> Option<&SsoResponseEndpoint>;
    pub fn acs_endpoint_by_url(&self, url: &str) -> Option<&SsoResponseEndpoint>;
    pub fn default_acs(&self) -> Option<&SsoResponseEndpoint>;
    pub fn slo_endpoint(&self, binding: Binding) -> Option<&Endpoint>;
    pub fn encryption_cert(&self) -> Option<&X509Certificate>;
}
```

### 2.1 SP metadata conformance check

When `SpDescriptor::from_metadata_xml` encounters `<md:AssertionConsumerService>` entries, it narrows each to `SsoResponseEndpoint` via `SsoResponseEndpoint::try_from_endpoint`. Entries advertising `Binding=urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect` or `…:SOAP` fail this narrowing and cause the entire descriptor parse to fail with `Error::InvalidConfiguration { reason: "SP metadata advertises ACS with non-POST/Artifact binding" }`.

This is intentional: SAML 2.0 Profiles §4.1.4 disallows those bindings for Web Browser SSO Responses, and silently accepting them would re-open the IdP-emits-Response-over-Redirect hole at AuthnRequest time. Federations that publish non-conformant SP entries (rare but documented for some legacy government SPs) must either be filtered before parse or — better — fixed upstream.

---

## 3. Federation aggregates

```rust
pub struct EntitiesDescriptor {
    pub name: Option<String>,
    pub valid_until: Option<SystemTime>,
    pub entities: Vec<MetadataEntry>,
}

pub enum MetadataEntry {
    Idp(IdpDescriptor),
    Sp(SpDescriptor),
    /// Some entities advertise both roles (Shibboleth proxies, for example).
    Dual(IdpDescriptor, SpDescriptor),
    /// AuthnAuthority, AttributeAuthority, PDP, etc. — out of scope for v0.1.
    Other,
}

impl EntitiesDescriptor {
    pub fn from_metadata_xml(xml: &[u8]) -> Result<Self, Error>;
    pub fn find_idp(&self, entity_id: &str) -> Option<&IdpDescriptor>;
    pub fn find_sp(&self, entity_id: &str) -> Option<&SpDescriptor>;
    pub fn iter_idps(&self) -> impl Iterator<Item = &IdpDescriptor>;
    pub fn iter_sps(&self) -> impl Iterator<Item = &SpDescriptor>;
}
```

Nested `EntitiesDescriptor` elements (federations of federations) are flattened at parse time.

---

## 4. Cert-use discrimination

Per spec, `<md:KeyDescriptor>` carries `use="signing"`, `use="encryption"`, or no `use` attribute (means both). The library partitions certs accordingly:

- `signing_certs` = certs with `use="signing"` OR no `use` attribute.
- `encryption_certs` = certs with `use="encryption"` OR no `use` attribute.

When both lists need to be checked (for example, a Response signature), all signing certs are tried in order; the first to verify wins, and its fingerprint is reported back in `Identity.verifying_cert_fingerprint` so the caller can log key-rotation events.

```rust
impl X509Certificate {
    pub fn fingerprint_sha256(&self) -> [u8; 32];
    pub fn not_before(&self) -> SystemTime;
    pub fn not_after(&self) -> SystemTime;
    pub fn subject(&self) -> &str;
    pub fn issuer(&self) -> &str;
    pub fn public_key(&self) -> &PublicKey;
}
```

---

## 5. Metadata signature verification

```rust
pub struct VerifyMetadata<'a> {
    pub metadata_xml: &'a [u8],
    pub trusted_signing_cert: &'a X509Certificate,
}

pub fn verify_metadata_signature(input: VerifyMetadata<'_>) -> Result<(), Error>;

/// Verify-then-parse helper. Verifies the metadata XML's XML-DSig against
/// `trusted_signing_cert` and only then parses the descriptors. Use this
/// instead of calling `verify_metadata_signature` + `*::from_metadata_xml`
/// separately — sequencing those two manually is the documented footgun.
pub fn parse_signed_entities_descriptor(
    metadata_xml: &[u8],
    trusted_signing_cert: &X509Certificate,
) -> Result<EntitiesDescriptor, Error>;

pub fn parse_signed_idp_descriptor(
    metadata_xml: &[u8],
    trusted_signing_cert: &X509Certificate,
) -> Result<IdpDescriptor, Error>;

pub fn parse_signed_sp_descriptor(
    metadata_xml: &[u8],
    trusted_signing_cert: &X509Certificate,
) -> Result<SpDescriptor, Error>;
```

Used when a federation publishes signed aggregate metadata (for example, InCommon). The caller pins the federation's signing cert (out-of-band trust establishment) and the library verifies the metadata file's XML-DSig before parsing it.

This is optional — many enterprise deployments fetch metadata over HTTPS from a trusted source and skip the XML-DSig step.

**When verification is required, use the `parse_signed_*` helpers.** They verify the XML-DSig first and parse only on success, atomically. The two-step alternative (`verify_metadata_signature` + `*::from_metadata_xml`) exists for advanced callers who need the parsed `EntityDescriptor` element to inspect signature metadata themselves, but it puts the ordering burden on the caller — and getting it wrong means descriptors are constructed from attacker-supplied XML before any signature check has run.

---

## 6. Metadata emission

```rust
impl ServiceProvider {
    /// Emit SP-side <md:EntityDescriptor> XML, suitable for IdPs to consume.
    /// Optionally signed with `signing_key`.
    pub fn metadata_xml(&self, sign: bool) -> Result<String, Error>;

    /// Same as `metadata_xml` but adds <md:Organization> + <md:ContactPerson>.
    pub fn metadata_xml_with_extras(
        &self,
        sign: bool,
        extras: &MetadataExtras,
    ) -> Result<String, Error>;
}

impl IdentityProvider {
    /// Emit IdP-side <md:EntityDescriptor> XML, suitable for SPs to consume.
    pub fn metadata_xml(&self, sign: bool) -> Result<String, Error>;

    /// Same as `metadata_xml` but adds <md:Organization> + <md:ContactPerson>.
    pub fn metadata_xml_with_extras(
        &self,
        sign: bool,
        extras: &MetadataExtras,
    ) -> Result<String, Error>;
}
```

### 6.1 SP emission

Produces `<md:EntityDescriptor>` containing `<md:SPSSODescriptor>` with:

- `protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"`.
- `AuthnRequestsSigned` if `config.sign_authn_requests`.
- `WantAssertionsSigned` if `config.want_assertions_signed`.
- `<md:KeyDescriptor use="signing">` with the SP signing cert (derived from `config.signing_key`).
- `<md:KeyDescriptor use="encryption">` with the SP encryption cert (derived from `config.decryption_key`), including `<xenc:EncryptionMethod>` declarations for the supported data-encryption algorithms.
- `<md:NameIDFormat>` entries from `config.name_id_formats`.
- `<md:AssertionConsumerService>` entries from `config.acs`, with `index`, `Binding` (always POST or Artifact — `SsoResponseEndpoint` makes this structural), `Location`, and `isDefault`.
- `<md:SingleLogoutService>` entries from `config.slo`.

### 6.2 IdP emission

Produces `<md:EntityDescriptor>` containing `<md:IDPSSODescriptor>` with:

- `protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"`.
- `WantAuthnRequestsSigned` if `config.want_authn_requests_signed`.
- `<md:KeyDescriptor use="signing">` with the IdP signing cert.
- `<md:KeyDescriptor use="encryption">` with the IdP encryption cert (if `decryption_key` is set).
- `<md:NameIDFormat>` entries from `config.supported_name_id_formats`.
- `<md:SingleSignOnService>` entries from `config.sso`.
- `<md:SingleLogoutService>` entries from `config.slo`.
- `<md:ArtifactResolutionService>` entries from `config.artifact_resolution`.

### 6.3 Extended metadata fields

Both emit paths accept an optional extension struct for `<md:Organization>` and `<md:ContactPerson>`:

```rust
pub struct MetadataExtras {
    pub organization: Option<MetadataOrganization>,
    pub contacts: Vec<MetadataContact>,
}

pub struct MetadataOrganization {
    pub name: String,
    pub display_name: String,
    pub url: String,
    pub language: String,  // RFC 5646
}

pub struct MetadataContact {
    pub contact_type: MetadataContactType,  // technical / support / administrative / billing / other
    pub given_name: Option<String>,
    pub surname: Option<String>,
    pub email_addresses: Vec<String>,
    pub telephone_numbers: Vec<String>,
    pub company: Option<String>,
}

impl ServiceProvider {
    // (declared in §6, repeated here for the extras struct definition's locality)
}
impl IdentityProvider {
    // (also declared in §6)
}
```

### 6.4 Signing

When `sign = true`, the emitted XML is signed at the `<md:EntityDescriptor>` level with the role's signing key (`config.signing_key` for SP, `config.signing_key` for IdP). The signature covers the EntityDescriptor element via `Reference URI="#<entity-descriptor-id>"` and uses Exclusive C14N by default.

---

## 7. Caching policy

Out of scope for this library. The library exposes `valid_until` and `cache_duration` from parsed descriptors; the caller decides whether to refresh metadata on a timer, on cache miss, on parse failure, or in response to webhook notifications.

The motivation for the punt is operational pluralism: some deployments fetch metadata once at boot, some on a 24h cron, some on every request via a local cache, some in response to push notifications from the federation. There is no single right answer the library should encode.

A future `saml-metadata-cache` sibling crate may provide opinionated helpers for the common case. Until then, applications wire `reqwest` (or any HTTP client) to fetch metadata XML and feed it into the parsers.

---

## 8. Example

```rust
// Consuming signed federation metadata. Verification is performed BEFORE
// descriptors are constructed — `parse_signed_*` enforces ordering atomically
// so an attacker-supplied XML blob is never parsed into a usable type.
let federation = parse_signed_entities_descriptor(
    &inc_common_metadata_xml,
    &inc_common_signing_cert, // pinned out-of-band
)?;
let idp = federation
    .find_idp("https://idp.university.edu/saml")
    .ok_or(Error::UnknownEntity { entity_id: "https://idp.university.edu/saml".into() })?;

// Consuming a single-entity IdP metadata file from Okta (fetched over HTTPS
// from a trusted source; no XML-DSig in the file itself, so plain parse).
let okta_idp = IdpDescriptor::from_metadata_xml(&okta_metadata_xml)?;

// Serving SP metadata.
let xml = sp.metadata_xml(/* sign = */ false)?;
// HTTP handler returns it at /saml/metadata with
// Content-Type: application/samlmetadata+xml.

// Serving IdP metadata with organization + contact extras.
let xml = idp.metadata_xml_with_extras(
    /* sign = */ true,
    &MetadataExtras {
        organization: Some(MetadataOrganization {
            name: "Example Corp".into(),
            display_name: "Example Corporation".into(),
            url: "https://example.com".into(),
            language: "en".into(),
        }),
        contacts: vec![MetadataContact {
            contact_type: MetadataContactType::Technical,
            given_name: Some("Alex".into()),
            surname: Some("Operator".into()),
            email_addresses: vec!["sso-admin@example.com".into()],
            telephone_numbers: vec![],
            company: Some("Example Corp".into()),
        }],
    },
)?;
```
