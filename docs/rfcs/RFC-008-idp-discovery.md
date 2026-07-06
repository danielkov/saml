# RFC-008: Identity Provider Discovery

**Status**: Draft
**Date**: 2026-07-06

## Summary

Before an SP can start Web-Browser SSO it has to answer "which IdP does this user belong to?". SAML 2.0 standardizes two cooperating mechanisms: the **Common Domain Cookie profile** (SAML 2.0 Profiles §4.3), where IdPs record their entityID in a cookie scoped to a federation-shared domain, and the **Identity Provider Discovery Service Protocol and Profile** (OASIS `sstc-saml-idp-discovery-cs-01`), a redirect-based protocol between an SP and a central discovery service. The `idp-disco` feature (off by default) implements both as pure codecs plus the `<idpdisc:DiscoveryResponse>` metadata parse/emit they depend on. Nothing here touches HTTP or cookies directly — consistent with RFC-001 §2, the caller owns headers, redirects, and UI; the library owns encoding, decoding, and the one trust decision in the protocol (return-URL validation).

---

## 1. Scope

In scope:

- Common Domain Cookie value codec (`_saml_idp`): parse, most-recent lookup, record-authentication write, re-encode, size-bounded truncation.
- Discovery service protocol, SP side: build the request redirect URL, parse the return redirect's query string.
- Discovery service protocol, service side: parse the request query string, validate the `return` URL against SP metadata, build the return redirect URL.
- Metadata: `<idpdisc:DiscoveryResponse>` (an `md:IndexedEndpointType` inside `<md:Extensions>` of `<md:SPSSODescriptor>`) — parsed into `SpDescriptor::discovery_response_endpoints`, emitted via `MetadataExtras::discovery_response_endpoints`.

Out of scope:

- HTTP: reading `Cookie` / writing `Set-Cookie` headers, issuing redirects, discovery UI. All caller-owned.
- The common domain itself (DNS, cookie `Domain`/`Secure` attributes, hosting a shared image/iframe endpoint). Deployment concerns per Profiles §4.3.2–4.3.4.
- Any persistence. Both mechanisms are stateless by construction.

## 2. Common Domain Cookie (`disco::cdc`)

Wire format per Profiles §4.3.1: cookie named `_saml_idp`, value is a space-separated list of base64-encoded IdP entityIDs, **most recently used last**.

`CommonDomainCookie` is a `Vec<String>` of decoded entityIDs with:

- `parse(value)` — percent-decodes first (a raw space is not a valid cookie octet per RFC 6265 §4.1.1, so real deployments percent-encode the separator or the whole value), then splits on spaces and base64-decodes each token. Malformed tokens are a hard `Error::CommonDomainCookieMalformed`, not silently dropped — a bad entry means a broken federation peer, and the caller should know.
- `most_recent()` — the last entry; what an SP tries first.
- `record(entity_id)` — dedupe + append-as-newest; the IdP-side write after successful authentication (§4.3.2), also what a discovery service does after an interactive pick.
- `to_cookie_value()` — base64 entries joined by `%20`, ready for a `Set-Cookie` value.
- `truncate_to_fit(max_len)` — drops oldest entries to respect browser cookie-size caps.

`'+'` is in the base64 alphabet and never treated as an encoded space anywhere in the codec; the separator is strictly `' '`/`%20`. (Treating `'+'` as space — form-urlencoded semantics — would corrupt any entityID whose base64 form contains it.)

## 3. Discovery service protocol (`disco::service`)

Request parameters (§2.4.1): `entityID` (SP's own, mandatory), `return` (optional), `returnIDParam` (optional, default `entityID`), `policy` (optional, single defined value), `isPassive` (optional xs:boolean). Response: redirect to the return URL with the chosen IdP entityID in the `returnIDParam` parameter — or without it when a passive request found no IdP.

Design decisions:

- **`policy` is parse-side only.** `…:idp-discovery-protocol:single` is the only value the spec defines and the implied default. The request builder never emits it; the service-side parser rejects anything else.
- **Duplicate parameters are rejected**, not first-match-wins, on both the request and response parse paths. Parameter pollution must not depend on parser iteration order.
- **`returnIDParam` is constrained to `[A-Za-z0-9_.-]+`.** The value is echoed into the response URL as a parameter *name*; anything wilder is an injection attempt, not a legitimate name.
- **Return-URL validation is the trust boundary.** `validate_discovery_return_url` accepts a `return` URL only when scheme, host, port (default-normalized), and path each equal those of a registered `<idpdisc:DiscoveryResponse>` endpoint; only the query string may differ, which is how SPs thread state through the round-trip. Fragments and userinfo are rejected outright. Comparison happens on *parsed* URLs, never string prefixes, so `https://sp.example.com.evil.test/…` and `https://sp.example.com@evil.test/…` don't match. With no `return` parameter, the `isDefault` (else first) registered endpoint is used. Failure is `Error::DiscoveryReturnUrlNotRegistered` — redirecting anyway would be an open redirect.

## 4. Metadata

`<idpdisc:DiscoveryResponse>` (namespace `urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol`, which is also the fixed `Binding` attribute value) lives inside `<md:Extensions>`, the schema-mandated first child of `<md:SPSSODescriptor>`.

- Parse: `SpDescriptor::discovery_response_endpoints` (feature-gated field) + `default_discovery_response()` mirroring `default_acs()`. A present entry with the wrong `Binding` or a missing `Location`/`index` is a hard parse error — the discovery service bases its redirect trust decision on these fields and must not guess. Absent `Extensions` parses to an empty list.
- Emit: `MetadataExtras::discovery_response_endpoints` (feature-gated field), consumed by the SP emit path only; the IdP role has no discovery-response concept. `DiscoveryResponseEndpoint` models only the variable fields (`url`, `index`, `is_default`) since the binding is fixed by the profile.

## 5. Error surface

| Variant | Meaning |
| --- | --- |
| `DiscoveryRequestMalformed { reason }` | Inbound request query violated the protocol (missing `entityID`, duplicate parameter, unsupported `policy`, non-boolean `isPassive`, unsafe `returnIDParam`, unparseable `return`). |
| `DiscoveryResponseMalformed { reason }` | Return redirect carried a duplicated chosen-IdP parameter. |
| `DiscoveryReturnUrlNotRegistered { return_url }` | The open-redirect gate fired. |
| `CommonDomainCookieMalformed { reason }` | `_saml_idp` value failed the percent / base64 / UTF-8 decode stack. |

## 6. Testing

- Unit tests per module: CDC round-trips (raw, separator-encoded, fully-encoded), `'+'`-in-base64 integrity, ordering, truncation; request/response build↔parse round-trips, defaults, duplicate-parameter and policy rejection, `returnIDParam` injection rejection; return-URL lookalike battery (host-suffix, userinfo, scheme, port, path-traversal, fragment, relative, `javascript:`).
- `tests/disco_flow_test.rs`: the full journey over the public API — SP metadata emit → registrar parse → request → validation → CDC-driven choice → response → SP consumption — plus the passive-no-choice and unregistered-return negative paths.
