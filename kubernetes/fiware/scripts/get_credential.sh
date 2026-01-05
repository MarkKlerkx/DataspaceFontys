#!/bin/bash

# --- START DEBUGGING get_credential.sh ---
echo "Arg 1 (Base URL): $1"
echo "Arg 2 (Config ID): $2"

# 1. Access Token ophalen (Gebruikerstoken)
echo -e "\n[Stap 1] Ophalen User Access Token..."
# -k toegevoegd voor SSL bypass
resp_token=$(curl -s -k -X POST "$1/realms/test-realm/protocol/openid-connect/token" \
  --header 'Content-Type: application/x-www-form-urlencoded' \
  --data grant_type=password \
  --data client_id=test-cli \
  --data username=test-user \
  --data scope=openid \
  --data password=test)

echo "Raw Response Stap 1: $resp_token"
access_token=$(echo "$resp_token" | jq -r '.access_token // "FAIL"')
echo "Gevonden Access Token: ${access_token:0:20}..."

# 2. Offer URI ophalen
echo -e "\n[Stap 2] Ophalen Credential Offer URI..."
resp_offer=$(curl -s -k -X GET "$1/realms/test-realm/protocol/oid4vc/credential-offer-uri?credential_configuration_id=$2" \
  --header "Authorization: Bearer ${access_token}")

echo "Raw Response Stap 2: $resp_offer"
# We gebruiken + om de strings veilig aan elkaar te plakken zonder dubbele slashes te riskeren
offer_uri=$(echo "$resp_offer" | jq -r '.issuer + .nonce' 2>/dev/null || echo "FAIL")
echo "Samengestelde Offer URI: $offer_uri"

# 3. Pre-authorized code ophalen uit de URI
echo -e "\n[Stap 3] Ophalen Pre-authorized code uit URI..."
if [[ "$offer_uri" != "FAIL" && -n "$offer_uri" ]]; then
    # -L voor redirects, -k voor SSL
    resp_preauth=$(curl -s -k -L -X GET "${offer_uri}" \
      --header "Authorization: Bearer ${access_token}")
    echo "Raw Response Stap 3: $resp_preauth"
    
    export pre_authorized_code=$(echo "$resp_preauth" | jq -r '.grants."urn:ietf:params:oauth:grant-type:pre-authorized_code"."pre-authorized_code" // "FAIL"')
else
    echo "FOUT: offer_uri is leeg of ongeldig."
    pre_authorized_code="FAIL"
fi
echo "Pre-authorized code: $pre_authorized_code"

# 4. Credential Access Token ophalen (Token Wissel)
echo -e "\n[Stap 4] Inwisselen code voor Credential Access Token..."
# Hier sturen we de client_id (DID) mee om clientId=null in Keycloak te voorkomen
resp_cred_token=$(curl -s -k -X POST "$1/realms/test-realm/protocol/openid-connect/token" \
  --header 'Content-Type: application/x-www-form-urlencoded' \
  --data grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code \
  --data client_id="did:key:zDnaeWfLgffWDkUxX4kzNSnSZSZSL8nbQ2ncepu4yzguX2e6n" \
  --data pre-authorized_code="${pre_authorized_code}")

echo "Raw Response Stap 4: $resp_cred_token"
credential_access_token=$(echo "$resp_cred_token" | jq -r '.access_token // "FAIL"')
echo "Credential Access Token: ${credential_access_token:0:20}..."

# 5. Het uiteindelijke Verifiable Credential ophalen
echo -e "\n[Stap 5] Ophalen van het Credential..."
final_resp=$(curl -s -k -X POST "$1/realms/test-realm/protocol/oid4vc/credential" \
  --header 'Content-Type: application/json' \
  --header "Authorization: Bearer ${credential_access_token}" \
  --data "{\"credential_identifier\":\"$2\", \"format\":\"jwt_vc\"}")

echo "Raw Response Stap 5: $final_resp"
echo -e "\n--- RESULTAAT ---"
# De uiteindelijke output die in de variabele USER_CREDENTIAL komt
echo "$final_resp" | jq -r '.credential // empty'
echo "--- EINDE DEBUGGING ---"
