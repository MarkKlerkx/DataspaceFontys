#!/bin/bash

# Stuur alle standaard output (debug info) naar stderr (scherm)
# zodat het niet in variabelen terechtkomt.
exec 3>&1
exec 1>&2

echo "--- START get_credential.sh ---"
echo "URL: $1 | Config: $2"

# 1. Access Token ophalen
access_token=$(curl -s -k -X POST "$1/realms/test-realm/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=test-cli -d username=test-user -d password=test | jq -r '.access_token // empty')

# 2. Offer URI ophalen
resp_offer=$(curl -s -k -X GET "$1/realms/test-realm/protocol/oid4vc/credential-offer-uri?credential_configuration_id=$2" \
  --header "Authorization: Bearer ${access_token}")

# Samengestelde URI
offer_uri=$(echo "$resp_offer" | jq -r '.issuer + .nonce' 2>/dev/null)

# 3. Pre-authorized code ophalen
pre_authorized_code=$(curl -s -k -L -X GET "${offer_uri}" \
  --header "Authorization: Bearer ${access_token}" | jq -r '.grants."urn:ietf:params:oauth:grant-type:pre-authorized_code"."pre-authorized_code" // empty')

# 4. Credential Access Token ophalen (Token Wissel)
# Opmerking: client_id weggelaten zoals verzocht
resp_cred_token=$(curl -s -k -X POST "$1/realms/test-realm/protocol/openid-connect/token" \
  --data grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code \
  --data pre-authorized_code="${pre_authorized_code}")

credential_access_token=$(echo "$resp_cred_token" | jq -r '.access_token // empty')

# 5. Het uiteindelijke Credential ophalen
final_resp=$(curl -s -k -X POST "$1/realms/test-realm/protocol/oid4vc/credential" \
  --header 'Content-Type: application/json' \
  --header "Authorization: Bearer ${credential_access_token}" \
  --data "{\"credential_identifier\":\"$2\", \"format\":\"jwt_vc\"}")

# Herstel stdout voor het eindresultaat
exec 1>&3

# Print alleen de token naar stdout
echo "$final_resp" | jq -r '.credential // empty'
