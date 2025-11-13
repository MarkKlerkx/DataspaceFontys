#!/bin/bash

# Stop onmiddellijk bij fouten
set -e
set -o pipefail

# --- DEBUGGING: Print alle argumenten naar stderr ---
echo "--- Script get_access_token_oid4vp.sh gestart ---" >&2
echo "Debug: Argument 1 (Service URL): $1" >&2
echo "Debug: Argument 2 (VC-Token, ingekort): ${2:0:50}..." >&2
echo "Debug: Argument 3 (Scope): $3" >&2
echo "------------------------------------------------" >&2

echo "Debug: Stap 1 - Ophalen OIDC-configuratie van $1/.well-known/openid-configuration" >&2
token_endpoint=$(curl -s -X GET "$1/.well-known/openid-configuration" | jq -r '.token_endpoint')

if [ -z "$token_endpoint" ] || [ "$token_endpoint" == "null" ]; then
    echo "FOUT: Kon 'token_endpoint' niet vinden. Is de URL $1 correct?" >&2
    exit 1
fi
echo "Debug: Token Endpoint Gevonden: $token_endpoint" >&2

# --- START AANPASSING ---
# Verwijder de foute :8080 poort die door de OIDC-config wordt geadverteerd
# Dit zorgt ervoor dat we de Ingress (op poort 80) aanroepen, niet de interne service (op poort 8080)
token_endpoint=$(echo $token_endpoint | sed 's/:8080//')
echo "Debug: GECORRIGEERDE Token Endpoint: $token_endpoint" >&2
# --- EINDE AANPASSING ---

echo "Debug: Stap 2 - Lezen Holder DID van /fiware/wallet-identity/did.json" >&2
holder_did=$(cat /fiware/wallet-identity/did.json | jq '.id' -r)

if [ -z "$holder_did" ] || [ "$holder_did" == "null" ]; then
    echo "FOUT: Kon '.id' niet vinden in /fiware/wallet-identity/did.json." >&2
    exit 1
fi
echo "Debug: Holder DID Gevonden: $holder_did" >&2

echo "Debug: Stap 3 - Maken van Verifiable Presentation (VP)" >&2
verifiable_presentation="{
  \"@context\": [\"https://www.w3.org/2018/credentials/v1\"],
  \"type\": [\"VerifiablePresentation\"],
  \"verifiableCredential\": [
      \"$2\"
  ],
  \"holder\": \"${holder_did}\"
}"

echo "Debug: Stap 4 - Maken van VP-JWT (Header, Payload, Signature)" >&2
# Foutcorrectie: Gebruik ${holder_did} in payload, niet ${holder_die}
jwt_header=$(echo -n "{\"alg\":\"ES256\", \"typ\":\"JWT\", \"kid\":\"${holder_did}\"}"| base64 -w0 | sed s/\+/-/g | sed 's/\//_/g' | sed -E s/=+$//)
payload=$(echo -n "{\"iss\": \"${holder_did}\", \"sub\": \"${holder_did}\", \"vp\": ${verifiable_presentation}}" | base64 -w0 | sed s/\+/-/g |sed 's/\//_/g' |  sed -E s/=+$//)
signature=$(echo -n "${jwt_header}.${payload}" | openssl dgst -sha256 -binary -sign /fiware/wallet-identity/private-key.pem | base64 -w0 | sed s/\+/-/g | sed 's/\//_/g' | sed -E s/=+$//)
jwt="${jwt_header}.${payload}.${signature}"
echo "Debug: VP-JWT Aangemaakt (ingekort): ${jwt:0:50}..." >&2

echo "Debug: Stap 5 - Aanvragen Access Token bij $token_endpoint" >&2
final_response=$(curl -s -X POST $token_endpoint \
      --header 'Accept: */*' \
      --header 'Content-Type: application/x-www-form-urlencoded' \
      --data grant_type=vp_token \
      --data client_id=data-service \
      --data vp_token=${jwt} \
      --data scope=$3)

echo "Debug: Volledige response van server: $final_response" >&2

echo "Debug: Stap 6 - Extraheren 'access_token' uit response" >&2
access_token=$(echo $final_response | jq '.access_token' -r)

if [ -z "$access_token" ] || [ "$access_token" == "null" ]; then
    echo "FOUT: Kon 'access_token' niet vinden in server response." >&2
    echo "Controleer de 'Volledige response' hierboven voor foutmeldingen." >&2
    exit 1
fi

echo "Debug: Access Token succesvol verkregen!" >&2

# --- EINDE DEBUGGING ---

# De ENIGE output naar STDOUT. Dit wordt opgevangen door de variabele.
echo $access_token
