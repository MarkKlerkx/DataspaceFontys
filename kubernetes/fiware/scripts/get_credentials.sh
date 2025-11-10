#!/bin/bash

# -------------------------
# Script to fetch a VC credential from Keycloak
# Usage: ./get_credential.sh <keycloak_url> <credential_id>
# Example: ./get_credential.sh http://keycloak-consumer.127.0.0.1.nip.io user-credential
# -------------------------

set -e
set -o pipefail

# --- Configurable parameters ---
REALM="test-realm"
CLIENT_ID="test-cli"
USERNAME="test-user"
PASSWORD="test"
# -------------------------------

# Check arguments
if [[ -z "$1" || -z "$2" ]]; then
  echo "Error: Incorrect usage."
  echo "Usage: $0 <keycloak_url> <credential_id>"
  exit 1
fi

KEYCLOAK_URL="$1"
CREDENTIAL_ID="$2"

echo "=== STEP 1: Fetch Keycloak access token ==="
access_token=$(curl -s -X POST "$KEYCLOAK_URL/realms/$REALM/protocol/openid-connect/token" \
  -H 'Accept: */*' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "grant_type=password" \
  -d "client_id=$CLIENT_ID" \
  -d "username=$USERNAME" \
  -d "password=$PASSWORD" \
  -d "scope=openid" | jq -r '.access_token')

if [[ -z "$access_token" || "$access_token" == "null" ]]; then
  echo "Error: Failed to obtain access_token"
  exit 1
fi
echo "Access token obtained successfully."

echo "=== STEP 2: Fetch credential-offer URI ==="
offer_uri_json=$(curl -s -X GET "$KEYCLOAK_URL/realms/$REALM/protocol/oid4vc/credential-offer-uri?credential_configuration_id=$CREDENTIAL_ID" \
  -H "Authorization: Bearer $access_token")

issuer=$(echo "$offer_uri_json" | jq -r '.issuer')
nonce=$(echo "$offer_uri_json" | jq -r '.nonce')

if [[ -z "$issuer" || -z "$nonce" ]]; then
  echo "Error: Failed to fetch credential-offer URI"
  echo "Response: $offer_uri_json"
  exit 1
fi

offer_uri="${issuer}${nonce}"
echo "Offer URI obtained: $offer_uri"

echo "=== STEP 3: Fetch pre-authorized code ==="
pre_authorized_code=$(curl -s -X GET "$offer_uri" \
  -H "Authorization: Bearer $access_token" | jq -r '.grants."urn:ietf:params:oauth:grant-type:pre-authorized_code"."pre-authorized_code"')

if [[ -z "$pre_authorized_code" || "$pre_authorized_code" == "null" ]]; then
  echo "Error: Failed to fetch pre-authorized code"
  exit 1
fi
echo "Pre-authorized code obtained successfully."

echo "=== STEP 4: Fetch credential access token ==="
credential_access_token=$(curl -s -X POST "$KEYCLOAK_URL/realms/$REALM/protocol/openid-connect/token" \
  -H 'Accept: */*' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code" \
  -d "pre-authorized_code=$pre_authorized_code" | jq -r '.access_token')

if [[ -z "$credential_access_token" || "$credential_access_token" == "null" ]]; then
  echo "Error: Failed to fetch credential access token"
  exit 1
fi
echo "Credential access token obtained successfully."

echo "=== STEP 5: Fetch the actual credential ==="
USER_CREDENTIAL=$(curl -s -X POST "$KEYCLOAK_URL/realms/$REALM/protocol/oid4vc/credential" \
  -H 'Accept: */*' \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $credential_access_token" \
  -d "{\"credential_identifier\":\"$CREDENTIAL_ID\", \"format\":\"jwt_vc\"}" | jq -r '.credential')

if [[ -z "$USER_CREDENTIAL" || "$USER_CREDENTIAL" == "null" ]]; then
  echo "Error: Failed to fetch USER_CREDENTIAL"
  exit 1
fi

export USER_CREDENTIAL
echo "USER_CREDENTIAL successfully obtained and exported."
echo "Credential preview: ${USER_CREDENTIAL:0:50}... (truncated)"
