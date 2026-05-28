# examples/idps — local IdP stack

Three docker-compose services backing the three local IdPs the
[`examples/demo`](../demo) SP drives: Keycloak (`:8080`), FusionAuth
(`:9011`), Authentik (`:9000`).

Each IdP stack runs on its own bridge network with its own backing
store. Only the IdPs' HTTP ports are exposed on the host; Postgres and
Redis stay internal.

## Run

```sh
docker compose -f examples/idps/docker-compose.yml up -d
# Wait ~60-90s for migrations + bootstrap:
docker compose -f examples/idps/docker-compose.yml ps

cargo run -p saml-demo
# open http://localhost:3000
```

## Admin consoles

| IdP        | URL                        | Credentials                              |
| ---------- | -------------------------- | ---------------------------------------- |
| Keycloak   | http://localhost:8080      | `admin` / `admin`                        |
| FusionAuth | http://localhost:9011      | `admin@saml-demo.local` / `password`     |
| Authentik  | http://localhost:9000      | `akadmin` / `AuthentikDemo!42`           |

## Test user

All three IdPs are seeded with `alice@saml-demo.local` / `password` —
the same identity the per-IdP example crates used before
consolidation.

## Bootstrap files

| Path                                       | Source IdP | What it does                                    |
| ------------------------------------------ | ---------- | ----------------------------------------------- |
| `keycloak/realm-export.json`               | Keycloak   | Realm `saml-demo` with SAML client + Alice      |
| `fusionauth/kickstart/kickstart.json`      | FusionAuth | Application `saml-axum-demo` + SP cert + Alice  |
| `authentik/blueprints/saml-demo.yaml`      | Authentik  | SAML provider + application + Alice             |

## Wipe state

```sh
docker compose -f examples/idps/docker-compose.yml down -v
```

The `-v` flag removes all the named volumes, so the next `up -d`
re-applies the bootstrap files cleanly.

## Rotating the FusionAuth IdP keypair

`fusionauth/idp/cert.pem` and `fusionauth/idp/key.pem` are committed
fixtures the kickstart bootstrap reads on first boot. To rotate
locally (cert expiry, key compromise during testing, regenerating
after switching openssl versions) run
`./fusionauth/regen_cert.sh` — it writes a fresh RSA-2048 self-signed
keypair with the same `CN=saml-axum-demo-fa-idp` subject and a
10-year validity window. Don't commit the regenerated files; they
exist only so a clean clone can `docker compose up` without extra
setup.
