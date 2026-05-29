#!/usr/bin/env bash
# Round-trip this crate's emitted SAML metadata through a real Keycloak.
#
# Gated: set RUN_KEYCLOAK_INTEROP=1 to actually run. Keycloak must already be
# reachable at $KC_URL (default http://localhost:8080) with admin/admin, e.g.
#   docker compose -f examples/idps/docker-compose.yml up -d keycloak
#
# See examples/idps/KEYCLOAK_INTEROP.md.
set -euo pipefail

if [[ "${RUN_KEYCLOAK_INTEROP:-0}" != "1" ]]; then
  echo "skipped: set RUN_KEYCLOAK_INTEROP=1 to run (needs Keycloak on localhost:8080)"
  exit 0
fi

KC_URL="${KC_URL:-http://localhost:8080}"
REALM="${KC_REALM:-saml-demo}"
SP_XML="${SP_XML:-/tmp/saml_sp_metadata.xml}"
IDP_XML="${IDP_XML:-/tmp/saml_idp_metadata.xml}"

if [[ ! -f "$SP_XML" || ! -f "$IDP_XML" ]]; then
  echo "error: metadata not found at $SP_XML / $IDP_XML" >&2
  echo "generate them first, e.g.:" >&2
  echo "  cargo +1.95.0 test --test keycloak_dump -- --ignored --nocapture" >&2
  exit 1
fi

req() { # method path [curl-args...] -> prints HTTP code, body to stdout
  local method=$1 path=$2; shift 2
  curl -s -o /tmp/kc_body -w "%{http_code}" -X "$method" "$KC_URL$path" "$@"
}

echo "==> admin token"
TOKEN=$(curl -s -X POST "$KC_URL/realms/master/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=admin-cli -d username=admin -d password=admin \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
AUTH=(-H "Authorization: Bearer $TOKEN")

echo "==> SP: client-description-converter"
CODE=$(req POST "/admin/realms/$REALM/client-description-converter" \
  "${AUTH[@]}" -H "Content-Type: application/xml" --data-binary @"$SP_XML")
echo "    HTTP $CODE"; [[ "$CODE" == 200 ]] || { cat /tmp/kc_body; exit 1; }
cp /tmp/kc_body /tmp/kc_client_rep.json

echo "==> SP: create client"
CODE=$(req POST "/admin/realms/$REALM/clients" \
  "${AUTH[@]}" -H "Content-Type: application/json" --data-binary @/tmp/kc_client_rep.json)
echo "    HTTP $CODE"; [[ "$CODE" == 201 ]] || { cat /tmp/kc_body; exit 1; }

echo "==> IdP: import-config"
CODE=$(req POST "/admin/realms/$REALM/identity-provider/import-config" \
  "${AUTH[@]}" -F providerId=saml -F "file=@$IDP_XML;type=application/xml")
echo "    HTTP $CODE"; [[ "$CODE" == 200 ]] || { cat /tmp/kc_body; exit 1; }
python3 -c "import json;c=json.load(open('/tmp/kc_body'));json.dump({'alias':'saml-rs-idp','providerId':'saml','enabled':True,'config':c},open('/tmp/kc_idp_instance.json','w'))"

echo "==> IdP: create instance"
CODE=$(req POST "/admin/realms/$REALM/identity-provider/instances" \
  "${AUTH[@]}" -H "Content-Type: application/json" --data-binary @/tmp/kc_idp_instance.json)
echo "    HTTP $CODE"; [[ "$CODE" == 201 ]] || { cat /tmp/kc_body; exit 1; }

echo "==> OK: Keycloak accepted both SP client and IdP instance"
