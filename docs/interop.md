# Interop: Known IdP Quirks

Field notes from building the multi-IdP demo. These are quirks observed
against real IdP deployments, the workarounds used in the demo, and the
crate-side limitations that callers should be aware of.

The intent is operational, not aspirational. Each entry describes a
specific behavior, where to verify it, and what to do about it.

---

## Zitadel — SP-init SLO returns `Success` but doesn't terminate the session

Zitadel's hosted SAML 2.0 endpoint accepts SP-initiated Single Logout
(SLO) requests and responds with `Status=Success`. It does **not**
actually invalidate the user's Zitadel session. The user appears logged
out from the SP but remains authenticated at Zitadel, so a subsequent
AuthnRequest skips the login prompt.

Verified against Zitadel's open-source SAML handler at
`zitadel/saml/pkg/provider/logout.go` — the handler returns `Success`
without invalidating sessions on its side.

This is out of our control: the SAML response is well-formed and signed,
and the protocol-level outcome is `Success`. There is nothing for the SP
to do differently on the wire.

**Workaround.** After processing the SLO response, redirect the user to
Zitadel's UI logout as a follow-on step:

```
https://<instance>.zitadel.cloud/ui/login/logout
```

This terminates the Zitadel session through its first-party UI flow,
which is the only path that reliably clears it.

---

## Asgardeo — "URL must be internet resolvable"

Asgardeo's console UI validates SLO URLs at save-time and rejects any
value that looks like `localhost` or a private IP. This blocks local
demo development against an Asgardeo tenant.

The REST API does not enforce the same validation. PATCHing the SAML
inbound protocol configuration accepts loopback and private URLs:

```
PATCH /api/server/v1/applications/{app-id}/inbound-protocols/saml/configuration
```

The relevant fields are:

- `manualConfiguration.singleLogoutProfile.logoutResponseUrl`
- `manualConfiguration.singleLogoutProfile.logoutRequestUrl`

**Caveat.** Once the bypass is used, future console "Update" clicks on
the SAML config tab will fail. The UI re-validates every field on the
form (including the ones the API bypass set), and the loopback URLs
re-trigger the rejection. The application becomes API-managed from that
point on.

**Recommended use.**
- **Local demo only.** Use the API bypass once, do not re-edit through
  the console.
- **Production.** Use a public URL, or a tunnel that fronts the local
  server with one (cloudflared, ngrok, tailscale funnel).

---

## Descope — Free tier has no `<SingleLogoutService>`

Descope's free tier does not expose a `<SingleLogoutService>` endpoint
in its published SAML metadata. There is no Redirect or POST SLO binding
to discover and no way to initiate SP-init SLO on the wire.

The demo handles this by falling back to a local-only logout: it clears
the SP session and redirects with a query parameter so the UI can show
an informational banner:

```
?msg=signed-out-locally-no-slo
```

To get real SLO with Descope, the SLO endpoint has to be added in the
flow-builder, which requires a paid plan.

The demo does not work around this — it documents the fallback and lets
the operator make the upgrade decision.

---

## FusionAuth — three non-spec quirks

FusionAuth's SAML emitter has three quirks that require per-provider
overrides in `ProviderConfig`. These are already documented inline in
`examples/demo/config/providers.toml`; the summary here is for
operators who need to integrate against a FusionAuth IdP without first
reading the demo source.

### 1. `idp_entity_id_override`

FusionAuth's metadata `entityID` differs from the value it places in the
`<Issuer>` element of signed assertions. Without an override, the SP
performs signature and issuer validation against the metadata
`entityID` and rejects FusionAuth's assertions.

Set `idp_entity_id_override` to the value FusionAuth actually emits in
`<Issuer>`.

### 2. `extra_signing_cert_paths`

FusionAuth rotates its signing certificate without bumping the
`<KeyDescriptor>` in published metadata. The metadata advertises one
public key while assertions are signed with another.

Seed an additional trust anchor (the rotated certificate) via
`extra_signing_cert_paths` so verification continues to succeed across
rotations. Treat this as a known operational tax for FusionAuth, not a
one-time fix.

### 3. `prefer_slo_binding`

FusionAuth's SLO endpoint advertises both HTTP-Redirect and HTTP-POST
bindings in metadata. In practice only POST works reliably; Redirect
SLO requests are accepted but the session is not consistently
invalidated.

Set `prefer_slo_binding` to force POST.

---

## Crate-side known limitations

These are limitations in the crate itself, not in any specific IdP. They
are deliberate defaults or scope decisions.

### Replay cache default is strict

All assertion IDs are rejected on second sight by default, even when
the assertion does not assert `<OneTimeUse/>`. The SAML 2.0 core
specification is more permissive: `<OneTimeUse/>` assertions MUST be
single-use, others SHOULD be, with caller discretion.

The crate's default is the strict reading because the safer mode is
the right default when the application cannot reason about its own
assertion-replay semantics. A tiered `ReplayMode::{All, OneTimeUseOnly,
Off}` opt-out is tracked in `ROADMAP.md`.

### `xs:dateTime` year range

`xs:dateTime` parsing is hardcoded to accept years in the range
`1..=9999`. This is defensive against pathological inputs and is
deliberate; SAML deployments do not need years outside this range.

### No SOAP / HoK / ECP / inclusive-C14N

The following bindings, profiles, and canonicalization variants are
out of scope for the current release and tracked in `ROADMAP.md`:

- SOAP binding (artifact resolution, backchannel SLO over SOAP)
- Holder-of-Key Web SSO profile
- Enhanced Client or Proxy (ECP) profile
- Inclusive Canonical XML (`xml-c14n`, non-exclusive)

The crate ships exclusive Canonical XML (`exc-c14n`), HTTP-Redirect,
HTTP-POST, and HTTP-Artifact (front-channel) only.
