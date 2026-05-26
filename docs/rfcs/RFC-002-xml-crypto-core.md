# RFC-002: XML and cryptographic core

**Status**: Draft
**Date**: 2026-05-26

## Summary

This RFC specifies the XML-Signature (XML-DSig), XML-Canonicalization (C14N), and XML-Encryption (XML-Enc) layer that every other SAML feature depends on. Correct behavior here is the difference between a usable library and a CVE producer. The design constraints are: pure-Rust, XSW-resistant by structure, transform whitelist by default, weak algorithms feature-gated.

---

## 1. XML parsing model

The wire format is XML, but we do not need full DOM tree semantics — only:

- Hierarchical access to elements by namespaced name.
- Attribute lookup, including the `ID` attribute used by signature `Reference URI` resolution.
- Faithful preservation of the parsed XML node set: namespace context, attribute values (after XML 1.0 normalization), character data, and document order. This is what C14N (§2) operates on — canonicalization is a deterministic function from the parsed node set to bytes, not a recovery of the original source bytes. Two conformant parsers given the same input must produce the same canonical output even when their source bytes (whitespace inside tags, attribute order, character vs entity references) differ.
- Namespace context tracking. Required for Exclusive C14N.

We build a thin `Element` tree directly on top of `quick-xml`'s event stream:

```rust
pub(crate) struct Document {
    root: Element,
    /// Map from `ID` attribute value to element handle. Populated during
    /// parse, used for signature `Reference URI` resolution. Duplicate IDs
    /// cause the parse itself to fail (§1.1), so this index is unique by
    /// construction.
    id_index: std::collections::HashMap<String, ElementId>,
}

pub(crate) struct Element {
    qname: QName,
    namespaces_declared_here: Vec<(Option<String>, String)>, // (prefix, URI)
    attributes: Vec<(QName, String)>,
    children: Vec<Node>,
}

pub(crate) enum Node {
    Element(Element),
    Text(String),
    /// Comments are tracked because Inclusive C14N preserves them; Exclusive
    /// C14N (without comments) drops them. The decision is made at canonicalize
    /// time, not at parse time.
    Comment(String),
}
```

### 1.1 Hardening at parse time

- **DTDs are rejected.** `quick-xml` is configured with no DTD support; encountering `<!DOCTYPE` returns `Error::XmlParse`. This eliminates the entire XXE / billion-laughs attack class.
- **Internal entity expansion is rejected** by the same path.
- **Processing instructions are rejected.**
- **Duplicate `ID` attribute values are rejected at parse time.** If two elements declare the same `ID` (in any namespace — SAML uses `ID`, but the rule covers `xml:id` and any `xsi:type`-declared `xs:ID` attribute), `Document` construction fails with `Error::XmlParse` carrying reason `"duplicate ID"`. This is a structural XSW defense: subsequent `Reference URI="#x"` resolution cannot be ambiguous because the parser would not have accepted the document. Without this check, a HashMap with last-write-wins semantics would let attackers shadow the signed element after the fact; with this check, signature `Reference` resolution and post-verification payload extraction necessarily reach the same `ElementId`.
- **Element / attribute depth and count limits** (default: depth 100, total nodes 100k) bound parse-time resource usage. Configurable via `XmlLimits`.

```rust
pub struct XmlLimits {
    pub max_depth: usize,            // default 100
    pub max_total_nodes: usize,      // default 100_000
    pub max_attribute_count: usize,  // default 100 per element
    pub max_text_length: usize,      // default 1_048_576 (1 MiB)
}
```

---

## 2. Canonicalization

SAML signatures use one of:

| Algorithm URI | Mnemonic |
| --- | --- |
| `http://www.w3.org/2001/10/xml-exc-c14n#` | Exclusive XML Canonicalization 1.0 (no comments) |
| `http://www.w3.org/2001/10/xml-exc-c14n#WithComments` | Exclusive, with comments |
| `http://www.w3.org/TR/2001/REC-xml-c14n-20010315` | Inclusive Canonical XML 1.0 (no comments) |
| `http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments` | Inclusive, with comments |

Of these, **Exclusive C14N (without comments) is overwhelmingly the SAML default.** The other three are implemented for spec completeness and odd-IdP interop; Exclusive C14N (no comments) is the canonical path.

```rust
pub enum C14nAlgorithm {
    ExclusiveCanonical,
    ExclusiveCanonicalWithComments,
    InclusiveCanonical,
    InclusiveCanonicalWithComments,
}

pub(crate) fn canonicalize(
    element: &Element,
    algorithm: C14nAlgorithm,
    inclusive_namespace_prefixes: &[&str],
) -> Vec<u8>;
```

### 2.1 Exclusive C14N rules (RFC 3741, summarized)

- Output element start tag, attributes, namespace declarations, children, end tag, in canonical form.
- Attribute order: namespace declarations first (sorted by local name), then attributes (sorted by namespace URI then local name).
- Only emit a namespace declaration on an element if (a) the element or one of its attributes uses that namespace, AND (b) the declaration is not already in scope from an ancestor in the canonical output, OR (c) the prefix is in the `InclusiveNamespaces/PrefixList` extension.
- Character data is normalized: `&` → `&amp;`, `<` → `&lt;`, `>` → `&gt;`, `"` → `&quot;` in attribute values; whitespace normalized in attributes per XML 1.0 §3.3.3.
- Tab, newline, carriage return in text content emitted as `&#9;`, `&#10;`, `&#13;` where required.

### 2.2 Hardening

- Canonicalization is a deterministic function from the parsed XML node set to a byte sequence, applied to the same `Element` tree used everywhere else in validation. The parser preserves enough fidelity (namespace context, attribute values after XML 1.0 normalization, character data, document order) for the canonicalized output to match what a conformant signer produced. There is no second parse, no byte-range slicing of the source, and no string re-emit pass — the same parsed tree feeds digest comparison and payload extraction.
- The `<ec:InclusiveNamespaces PrefixList="...">` extension is parsed and honored. Failing to honor it is a known XSW vector.

### 2.3 Test vectors

Known-answer test vectors from the W3C XML-C14N test suite are bundled in `tests/common/c14n_vectors/`. Each test case is a `(input.xml, expected_output.bytes, algorithm, inclusive_prefixes)` tuple.

---

## 3. XML-Signature: verification

The verification entry point:

```rust
pub(crate) fn verify_signature(
    document: &Document,
    signature_element: &Element,
    candidate_certs: &[X509Certificate],
    /// Per-call allow-list of acceptable signature algorithms. Sourced from
    /// the peer's `PeerCryptoPolicy`. Algorithms that are compiled in
    /// (under `weak-algos`) but not in this list MUST be rejected.
    /// This is the policy enforcement point: feature gating controls whether
    /// an algorithm is compiled at all; this allow-list controls whether it
    /// is acceptable for THIS verification call.
    allowed_algorithms: &[SignatureAlgorithm],
) -> Result<VerifiedSignature, Error>;

pub(crate) struct VerifiedSignature {
    /// The element whose canonical form was signed. The caller MUST use THIS
    /// element when extracting the validated payload — not get-by-id, not
    /// "the first Assertion", not any other lookup. Byte-pointer identity.
    pub signed_element: ElementId,
    /// Which cert from the candidate set matched. For logging and cert rotation.
    pub verifying_cert_fingerprint: [u8; 32],
    pub signature_algorithm: SignatureAlgorithm,
}
```

### 3.1 Steps (RFC 3275, refined by SAML profile constraints)

1. Locate the `<ds:SignedInfo>` child of `<ds:Signature>`. Parse:
   - `CanonicalizationMethod/@Algorithm` — must be in the `C14nAlgorithm` enum, else `Error::DisallowedAlgorithm`.
   - `SignatureMethod/@Algorithm` — must parse to a `SignatureAlgorithm` variant **AND** appear in the caller-supplied `allowed_algorithms` slice. Both checks must pass; the enum check alone is insufficient because `weak-algos` may have compiled additional variants that are not policy-acceptable for this peer. Otherwise `Error::DisallowedAlgorithm`.
   - `Reference` — must be exactly one. Multiple `Reference`s are a known XSW vector; rejected by default.
   - `Reference/@URI` — must be either empty (the document root) or `#xyz` where `xyz` resolves to an element via `Document::id_index`.
   - `Reference/Transforms` — every transform's `@Algorithm` must be in `{enveloped-signature, exc-c14n, exc-c14n#WithComments, c14n, c14n#WithComments}`. Any other transform — XSLT, XPath, base64 — is rejected with `Error::DisallowedTransform`.
   - `Reference/DigestMethod/@Algorithm` — must be in `DigestAlgorithm` enum.
   - `Reference/DigestValue` — base64-decoded digest bytes.

2. **Resolve the reference.** If `URI` is empty → root element. If `URI` is `#xyz` → look up in `id_index`. The index is unique by construction (duplicate IDs are rejected at parse time, §1.1), so there is no ambiguity. If lookup fails → `Error::ReferenceResolution`. Record the resolved `ElementId`.

3. **Apply transforms** to the resolved element in order:
   - `enveloped-signature`: remove the `<ds:Signature>` element from the subtree (it cannot include itself in its own digest).
   - `exc-c14n` / `c14n` etc.: canonicalize per §2 above. The output is bytes.

4. **Compute digest** of the canonical bytes using `DigestMethod`. Compare to `DigestValue`. Mismatch → `Error::SignatureVerification { reason: "digest mismatch" }`.

5. **Canonicalize `<ds:SignedInfo>` itself** (using its declared `CanonicalizationMethod`). The result is the signed bytes.

6. **Locate the verifying public key.** Try, in order:
   - Each cert in `candidate_certs` (provided by caller — e.g., signing certs from peer metadata).
   - Certs embedded in `<ds:KeyInfo>/<ds:X509Data>/<ds:X509Certificate>` IF they appear in `candidate_certs` by fingerprint. Embedded certs that don't match a known-trusted fingerprint are ignored — never trust an inline cert by itself.
   - `<ds:KeyInfo>/<ds:KeyName>` is informational only; lookup is up to the caller via `SignatureVerifier` trait (see §6).

7. **Verify** the signature bytes against the SignedInfo bytes using the resolved key + algorithm.

8. **Return** `VerifiedSignature { signed_element: <the ElementId resolved in step 2>, ... }`.

### 3.2 XSW resistance — structural property

The critical property: the caller can only extract the validated payload via `Document::element(verified.signed_element)`. There is no `validated_assertion()` accessor that doesn't accept a verified signature handle. This prevents the canonical XSW pattern (sign element A, present element B with the same ID — the attacker's wrapper element rebinds the ID lookup).

Concretely, the response-parsing path looks like:

```rust
let document = parse_xml(&body)?;
let signature_elem = document.find("ds:Signature")?;
let peer_policy = input.peer_crypto_policy.unwrap_or(&config.default_peer_crypto_policy);
let verified = verify_signature(
    &document,
    signature_elem,
    &idp.signing_certs,
    &peer_policy.allowed_signature_algorithms,
)?;
// The Assertion the caller gets is fetched by ElementId — not by name lookup.
let assertion_elem = document.element(verified.signed_element);
let identity = parse_assertion(assertion_elem)?;
```

Multiple-Reference signatures: rejected by default. A `permissive_multi_reference` feature flag can re-enable them, but the API contract becomes "the caller must verify every Reference points to a payload they will use" — and the default API doesn't expose that.

### 3.3 HTTP-Redirect detached signatures

The HTTP-Redirect binding (SAML 2.0 §3.4.4.1) does NOT use XML-DSig. Instead, the signature is a detached query-string signature over the canonical query string: a base64-encoded raw signature in the `Signature` parameter, with the algorithm URI in `SigAlg`. The signed bytes are the URL-encoded query parameters in a spec-mandated order (`SAMLRequest=...&RelayState=...&SigAlg=...` for requests, or `SAMLResponse=...&RelayState=...&SigAlg=...` for responses), **not** the decoded XML.

Detached signature verification is a separate entry point — the XML-DSig path (`verify_signature`) does not apply. The same allow-list discipline applies:

```rust
pub(crate) fn verify_detached_signature(
    /// The canonical query string per spec §3.4.4.1: the URL-encoded parameter
    /// list (excluding `Signature`) in the spec-mandated order.
    signed_query_string: &[u8],
    /// Raw signature bytes (caller has already base64-decoded the `Signature`
    /// query parameter).
    signature_bytes: &[u8],
    /// Algorithm URI from the `SigAlg` query parameter, parsed to enum.
    sig_alg: SignatureAlgorithm,
    candidate_certs: &[X509Certificate],
    /// Same allow-list contract as `verify_signature`. Role layer MUST thread
    /// `peer_policy.allowed_signature_algorithms` through. Without this,
    /// weak-algos would leak through the Redirect path even when the peer's
    /// policy excludes them.
    allowed_algorithms: &[SignatureAlgorithm],
) -> Result<VerifyMatch, Error>;
```

Rule (parallels §3.1 step 1): `sig_alg` MUST parse to a `SignatureAlgorithm` variant **AND** appear in `allowed_algorithms`; otherwise `Error::DisallowedAlgorithm`.

Role layers calling Redirect-side validation (`consume_authn_request` for AuthnRequest, both consume methods for SLO when binding is HTTP-Redirect) MUST pass `peer_policy.allowed_signature_algorithms` into this function, exactly as they do for XML-DSig verification.

---

## 4. SignatureVerifier trait

Some users will want to override key resolution (HSM-backed verifying keys, KMS lookups, custom KeyInfo resolution). For those, the verifier is pluggable:

```rust
pub trait SignatureVerifier: Send + Sync {
    /// Verify a precomputed signed-bytes / signature-bytes pair against a key.
    /// The implementation MUST NOT accept an `algorithm` that is not present in
    /// `allowed_algorithms`, even if the implementation knows how to perform
    /// that algorithm. This is the same policy gate as `verify_signature`'s
    /// allow-list, surfaced for custom verifiers (HSM, KMS) so policy lives in
    /// one place.
    fn verify(
        &self,
        algorithm: SignatureAlgorithm,
        signed_bytes: &[u8],
        signature_bytes: &[u8],
        candidate_certs: &[X509Certificate],
        allowed_algorithms: &[SignatureAlgorithm],
        key_info: &KeyInfo,
    ) -> Result<VerifyMatch, Error>;
}

pub struct DefaultVerifier; // pure-Rust rsa + ecdsa, enabled by default features
```

The default impl is selected when `ServiceProviderConfig` / `IdentityProviderConfig` don't override the verifier. Role layers MUST pass the effective peer policy's `allowed_signature_algorithms` through unchanged on every `verify_signature` / `SignatureVerifier::verify` call. The effective policy is selected per consumed message: caller-supplied peer override when present, otherwise the role's default policy. This keeps a legacy peer that needs RSA-SHA1 from widening acceptance for every other peer handled by the same role instance.

---

## 5. Algorithms

```rust
#[non_exhaustive]
pub enum SignatureAlgorithm {
    RsaSha256,        // http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
    RsaSha384,        // http://www.w3.org/2001/04/xmldsig-more#rsa-sha384
    RsaSha512,        // http://www.w3.org/2001/04/xmldsig-more#rsa-sha512
    EcdsaSha256,      // http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256
    EcdsaSha384,
    EcdsaSha512,
    #[cfg(feature = "weak-algos")] RsaSha1,
    #[cfg(feature = "weak-algos")] DsaSha1,
}

impl SignatureAlgorithm {
    /// The default set accepted on inbound signatures.
    pub const DEFAULTS: &'static [Self] = &[
        Self::RsaSha256, Self::RsaSha384, Self::RsaSha512,
        Self::EcdsaSha256, Self::EcdsaSha384, Self::EcdsaSha512,
    ];
}

#[non_exhaustive]
pub enum DigestAlgorithm {
    Sha256, // http://www.w3.org/2001/04/xmlenc#sha256
    Sha384,
    Sha512,
    #[cfg(feature = "weak-algos")] Sha1,
}

#[non_exhaustive]
pub enum DataEncryptionAlgorithm {
    Aes128Cbc, // http://www.w3.org/2001/04/xmlenc#aes128-cbc
    Aes256Cbc,
    Aes128Gcm, // http://www.w3.org/2009/xmlenc11#aes128-gcm
    Aes256Gcm,
}

#[non_exhaustive]
pub enum KeyTransportAlgorithm {
    RsaOaep,           // http://www.w3.org/2009/xmlenc11#rsa-oaep with SHA-256 + MGF1-SHA1 by default
    RsaOaepMgf1Sha1,   // legacy IdPs
    #[cfg(feature = "weak-algos")] RsaPkcs1V15,
}
```

Outbound signing defaults: `RsaSha256` + `ExclusiveCanonical` + `Sha256` digest.
Outbound encryption defaults: `Aes256Gcm` + `RsaOaep` with SHA-256.

Inbound algorithm acceptance is represented by an explicit peer-scoped policy:

```rust
pub struct PeerCryptoPolicy {
    /// Inbound XML-DSig and HTTP-Redirect detached signatures.
    pub allowed_signature_algorithms: Vec<SignatureAlgorithm>,
    /// Inbound XML-Enc data-encryption algorithms.
    pub allowed_data_encryption_algorithms: Vec<DataEncryptionAlgorithm>,
    /// Inbound XML-Enc key-transport algorithms.
    pub allowed_key_transport_algorithms: Vec<KeyTransportAlgorithm>,
}

impl PeerCryptoPolicy {
    /// Strong defaults: signature algorithms from `SignatureAlgorithm::DEFAULTS`,
    /// AES-GCM data encryption, and RSA-OAEP key transport. CBC and
    /// RSA-OAEP-MGF1-SHA1 are compatibility opt-ins; RSA-PKCS1-v1.5 requires
    /// `weak-algos` and an explicit peer policy.
    pub fn strong_defaults() -> Self;
}
```

The `weak-algos` feature flag controls **compilation** of `RsaSha1` / `DsaSha1` / `Sha1` / `RsaPkcs1V15` variants. It does **not** control whether they will be accepted at verification/decryption time. Acceptance is gated by the effective `PeerCryptoPolicy` selected for that specific peer. A process that has `weak-algos` compiled but excludes `RsaSha1` from every effective peer policy will reject RSA-SHA1 signatures everywhere. A process that includes `RsaSha1` in one legacy peer's policy will accept RSA-SHA1 only for messages consumed with that policy.

---

## 6. XML-Signature: signing (outbound)

Mirror image of verification:

```rust
pub(crate) fn sign_element(
    element: &mut Element,
    signing_key: &KeyPair,
    algorithm: SignatureAlgorithm,
    digest: DigestAlgorithm,
    c14n: C14nAlgorithm,
    inclusive_namespace_prefixes: &[&str],
    include_x509_cert: bool,
) -> Result<(), Error>;
```

Produces an enveloped signature inside the target element (typically `<samlp:Response>`, `<saml:Assertion>`, `<samlp:AuthnRequest>`, or `<samlp:LogoutRequest>`), positioned after the `<saml:Issuer>` element per SAML 2.0 schema requirements.

The `Reference URI` is always the target element's `ID` attribute (SAML 2.0 mandates `ID` on every signable protocol element). If `include_x509_cert` is true, the signing certificate is embedded in `<ds:KeyInfo>/<ds:X509Data>/<ds:X509Certificate>`.

---

## 7. XML-Encryption

Two layers per spec:

- **Key transport**: `<xenc:EncryptedKey>` — an asymmetric algorithm encrypts a fresh symmetric session key against the recipient's public encryption key.
- **Data encryption**: `<xenc:EncryptedData>` — the symmetric session key (block cipher) encrypts the actual `<Assertion>` payload.

### 7.1 Decrypt entry point

```rust
pub(crate) fn decrypt_encrypted_assertion(
    encrypted_assertion: &Element,
    decryption_keys: &[&KeyPair],
    allowed_data_algorithms: &[DataEncryptionAlgorithm],
    allowed_key_transport_algorithms: &[KeyTransportAlgorithm],
) -> Result<Element, Error>;  // returns the cleartext <saml:Assertion> element
```

Before attempting decryption, the `<xenc:EncryptedData>` and `<xenc:EncryptedKey>` algorithm URIs MUST parse to known enum variants and appear in the supplied allow-lists. Each key in `decryption_keys` is tried in order — the first that successfully decrypts `<xenc:EncryptedKey>` wins. This supports decryption-key rotation without allowing weak XML-Enc algorithms merely because they were compiled.

### 7.2 Encrypt entry point

```rust
pub(crate) fn encrypt_assertion(
    assertion: &Element,
    recipient_encryption_cert: &X509Certificate,
    data_algorithm: DataEncryptionAlgorithm,
    key_transport_algorithm: KeyTransportAlgorithm,
) -> Result<Element, Error>;
```

Defaults: `Aes256Gcm` + `RsaOaep` with SHA-256 MGF1. The defaults reflect modern recommendations; `Aes128Cbc` and `RsaOaepMgf1Sha1` are kept for compatibility, not promoted.

### 7.3 Bleichenbacher hardening

When `weak-algos` is enabled and `RsaPkcs1V15` is in use, decryption errors are folded into a generic `Error::DecryptFailed { reason: "key transport" }` with no distinguishing information about whether padding parsing or key-transport itself failed. This is the standard mitigation for chosen-ciphertext oracles against PKCS#1 v1.5 unwrapping.

---

## 8. Hardening summary

| Attack class | Mitigation |
| --- | --- |
| XML Signature Wrapping (XSW) | Reference URI must resolve to a single element; validated payload accessed via that element's `ElementId`, not by re-lookup. Multiple References rejected by default. |
| Transform-based escalation (XSLT/XPath) | Transforms whitelisted; XSLT/XPath rejected at verification time. |
| External entity injection (XXE) | DTDs rejected at parse layer. |
| Billion-laughs / quadratic blowup | DTDs rejected; node-count and depth limits. |
| Comment-position confusion | Inclusive C14N with comments is implemented per spec; SAML default Exclusive C14N (no comments) drops comments deterministically. Test vectors include adversarial comment positioning. |
| Namespace declaration smuggling | `InclusiveNamespaces/PrefixList` honored. |
| Bleichenbacher (RSA-PKCS1-v1.5) | Generic decrypt error; algorithm itself gated behind `weak-algos` and explicit peer key-transport policy. |
| Algorithm confusion / downgrade | Each consume call uses an effective `PeerCryptoPolicy`; defaults reject RSA-SHA1, RSA-1.5, DSA, and non-default XML-Enc algorithms. |
| Cert chain confusion | Inline `<ds:X509Certificate>` in KeyInfo only honored if fingerprint matches a caller-supplied trusted cert. |
| Replay | Assertion ID + `NotOnOrAfter` exposed to caller for dedupe. |
| Forged metadata | Optional metadata signature verification against pinned cert (RFC-006 §6). |

---

## 9. Out-of-scope for v0.1.0

- XPath, XSLT, base64 transforms in `<ds:Reference/Transforms>`.
- SHA-1 outbound signing.
- RSA-PKCS1-v1.5 outbound key transport. Decrypt-only under `weak-algos` for legacy interop.
- DSA outbound signing.
- `<ds:Manifest>` references.
- `<ds:KeyInfo>/<ds:RetrievalMethod>` (out-of-band key fetch).
- `<ds:KeyInfo>/<ds:AgreementMethod>` (DH/ECDH key agreement).
- Per-element streaming (entire signed element loaded into memory; bounded by `XmlLimits`).
