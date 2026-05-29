# Keycloak metadata interop

Proves a real third-party SAML consumer (Keycloak 26.0) accepts the metadata
emitted by this crate's `ServiceProvider::metadata_xml` and
`IdentityProvider::metadata_xml`. This is a round-trip against an external
implementation, not our own parser.

## What is checked

1. Our **SP** metadata is fed to Keycloak's `client-description-converter`,
   then created as a SAML **client**. Keycloak must echo back our entityID,
   ACS URL, SLO URL, signing certificate, signature algorithm and NameID
   format.
2. Our **IdP** metadata is fed to Keycloak's
   `identity-provider/import-config`, then created as a SAML **identity
   provider instance**. Keycloak must echo back our entityID, SSO/SLO URLs,
   signing certificate, `wantAuthnRequestsSigned`, and NameID policy.

A non-2xx from any step, or a missing/garbled field on read-back, is a
failure.

## Run

```sh
# bring up only Keycloak (admin/admin, host port 8080)
docker compose -f examples/idps/docker-compose.yml up -d keycloak

# generate metadata + drive the Keycloak admin REST API
RUN_KEYCLOAK_INTEROP=1 ./examples/idps/keycloak_interop.sh

# tear down
docker compose -f examples/idps/docker-compose.yml down -v
```

The script is gated behind `RUN_KEYCLOAK_INTEROP=1` so it is a no-op unless you
explicitly opt in (Keycloak must already be reachable on `localhost:8080`).

## Last verified result (Keycloak 26.0, realm `saml-demo`)

| Step | Endpoint | Status |
| --- | --- | --- |
| SP descriptor -> client representation | `POST /client-description-converter` | 200 |
| Create SAML client | `POST /clients` | 201 |
| IdP descriptor -> config | `POST /identity-provider/import-config` | 200 |
| Create IdP instance | `POST /identity-provider/instances` | 201 |

No fields were rejected or warned about. Keycloak preserved:

- SP: `clientId=https://sp.example.com/saml/metadata`,
  `saml_assertion_consumer_url_post`, `saml_single_logout_service_url_redirect`,
  `saml.signature.algorithm=RSA_SHA256`,
  `saml_signature_canonicalization_method=http://www.w3.org/2001/10/xml-exc-c14n#`,
  `saml.signing.certificate`, `saml_name_id_format=persistent`.
- IdP: `idpEntityId=https://idp.example.com/saml/metadata`,
  `singleSignOnServiceUrl`, `singleLogoutServiceUrl`,
  `wantAuthnRequestsSigned=true`, `validateSignature=true`,
  `nameIDPolicyFormat=...:persistent`, `signingCertificate`.
