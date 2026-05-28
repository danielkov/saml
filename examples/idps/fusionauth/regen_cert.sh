#!/usr/bin/env bash
# Regenerate the FusionAuth IdP signing keypair under examples/idps/fusionauth/idp/.
#
# RSA-2048, self-signed, 10-year validity. CN matches the issuer the
# FusionAuth kickstart bootstrap expects (`saml-axum-demo-fa-idp`),
# so the regenerated cert drops straight into the existing demo
# without further config changes.
#
# Do not commit the regenerated files — they are checked-in fixtures
# already; run this only when you need to rotate locally for testing.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$here/idp"
mkdir -p "$out"

cn="saml-axum-demo-fa-idp"
days=3650

openssl req \
  -x509 \
  -newkey rsa:2048 \
  -sha256 \
  -days "$days" \
  -nodes \
  -keyout "$out/key.pem" \
  -out "$out/cert.pem" \
  -subj "/CN=$cn"

chmod 600 "$out/key.pem"
chmod 644 "$out/cert.pem"

echo
echo "Wrote:"
echo "  $out/cert.pem"
echo "  $out/key.pem"
