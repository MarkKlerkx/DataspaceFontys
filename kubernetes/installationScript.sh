#!/bin/bash
set -e

# ==============================================================================
# FIWARE INSTALLER - VERSION 25 (ROBUST IP & FULL POLICY)
# Fixes: IP Detection (hostname -I), PAP HTTP 500 (Full JSON), Time Sync
# ==============================================================================

# --- 1. DETECT ROBUST IP (CRITICAL FIX) ---
# We doen dit direct aan het begin.
echo "--- DETECTING IP ---"
CURRENT_IP=$(hostname -I | awk '{print $1}')

# Fallback als hostname -I faalt
if [ -z "$CURRENT_IP" ]; then
    CURRENT_IP=$(ip route get 1.1.1.1 | awk '{print $7}')
fi

# Hard fail als het nog steeds leeg is
if [ -z "$CURRENT_IP" ]; then
    echo "ERROR: Could not detect IP address! installation aborted."
    exit 1
fi

export INTERNAL_IP=$CURRENT_IP
echo "DETECTED IP: $INTERNAL_IP"

# --- DETECT REAL USER ---
if [ $SUDO_USER ]; then
    REAL_USER=$SUDO_USER
    REAL_HOME=$(getent passwd $SUDO_USER | cut -d: -f6)
else
    REAL_USER=$(whoami)
    REAL_HOME=$HOME
fi

LOG_FILE="$(pwd)/install_fiware.log"
exec > >(tee -i "$LOG_FILE") 2>&1

# --- COLORS ---
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[1;36m' 
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# --- WAIT FUNCTIONS ---
wait_for_ready() {
    local NAMESPACE=$1
    local TIMEOUT_SECS=$2
    local START_TIME=$(date +%s)
    echo -e "${BLUE}[WAIT] Watching namespace '$NAMESPACE'...${NC}"
    while true; do
        local CURRENT_TIME=$(date +%s)
        local ELAPSED=$((CURRENT_TIME - START_TIME))
        if [ $ELAPSED -gt $TIMEOUT_SECS ]; then
            log_error "Timeout '$NAMESPACE'!"
            return 1
        fi
        local PENDING=$(kubectl get pods -n $NAMESPACE --no-headers | grep -v -E "Running|Completed|Error" | wc -l)
        if [ "$PENDING" -eq 0 ]; then
            local HEALTHY=$(kubectl get pods -n $NAMESPACE --no-headers | grep -E "Running|Completed" | wc -l)
            if [ "$HEALTHY" -gt 0 ]; then
                log_success "Namespace '$NAMESPACE' active!"
                return 0
            fi
        fi
        sleep 5
    done
}

wait_for_api() {
    local URL=$1
    local TIMEOUT_SECS=600 
    local START_TIME=$(date +%s)
    echo -ne "${BLUE}[WAIT] API: $URL ...${NC}"
    while true; do
        local CURRENT_TIME=$(date +%s)
        local ELAPSED=$((CURRENT_TIME - START_TIME))
        if [ $ELAPSED -gt $TIMEOUT_SECS ]; then
            echo "" ; log_error "API Timeout!" ; return 1
        fi
        local STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 "$URL" || echo "000")
        if [[ "$STATUS" -ge 200 && "$STATUS" -lt 500 ]]; then
            echo -e " ${GREEN}[OK] ($STATUS)${NC}" ; return 0
        fi
        echo -ne "." ; sleep 5
    done
}

register_did() {
    local URL=$1 ; local DID=$2 ; local CRED=$3
    local ATTEMPT=1 ; local MAX=20
    echo -e "${BLUE}[ACTION] Registering DID: $DID ...${NC}"
    until [ $ATTEMPT -ge $MAX ]; do
        RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$URL" --header 'Content-Type: application/json' --data "{\"did\": \"$DID\", \"credentials\": $CRED}")
        HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
        if [[ "$HTTP_CODE" -ge 200 && "$HTTP_CODE" -lt 300 ]]; then
            log_success "Registered!" ; return 0
        elif [[ "$RESPONSE" == *"already exists"* ]]; then
             log_warn "Already registered." ; return 0
        else
            echo -ne "${YELLOW}   -> Retry $ATTEMPT/$MAX ($HTTP_CODE)...${NC}\r" ; sleep 5
        fi
        ATTEMPT=$((ATTEMPT+1))
    done
    log_error "Registration failed." ; return 1
}

# ==============================================================================
# 0. TIME SYNC FIX
# ==============================================================================
echo -e "${BLUE}[INIT] Checking System Time...${NC}"
if command -v timedatectl &> /dev/null; then
    sudo timedatectl set-ntp on || true
    sudo systemctl restart systemd-timesyncd.service || true
    echo "Time sync triggered. Current date: $(date)"
else
    echo "timedatectl not found, skipping auto-sync."
fi

# ==============================================================================
# 1. SETUP
# ==============================================================================
echo -e "${BLUE}[INIT] System Check & Locks...${NC}"

if sudo lsof /var/lib/dpkg/lock-frontend >/dev/null 2>&1; then
    sudo fuser -vki /var/lib/dpkg/lock-frontend || true
    sudo rm -f /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock
    sudo dpkg --configure -a
fi

echo -e "${BLUE}[INIT] Installing dependencies (curl, jq, git, java)...${NC}"
sudo apt-get update
sudo apt-get install -y curl jq inetutils-ping git default-jdk wget nano

# HARDE CHECK OP JQ
hash -r 
if ! command -v jq &> /dev/null; then
    echo -e "${RED}[ERROR] 'jq' is niet correct geïnstalleerd.${NC}"
    exit 1
else
    JQ_VERSION=$(jq --version)
    log_success "Dependencies OK. ($JQ_VERSION)"
fi

clear
echo -e "${BLUE}Docker Hub Auth (Required for Rate Limits)${NC}"
if [ -t 0 ]; then
    read -p "Username: " MY_DOCKER_USER
    read -s -p "Token: " MY_DOCKER_PASS ; echo ""
    read -p "Email: " MY_DOCKER_EMAIL
else
    echo -e "${RED}Interactive mode required.${NC}" ; exit 1
fi

LOGIN_RESPONSE=$(curl -s -H "Content-Type: application/json" -X POST -d '{"username": "'${MY_DOCKER_USER}'", "password": "'${MY_DOCKER_PASS}'"}' https://hub.docker.com/v2/users/login)
if [[ $(echo $LOGIN_RESPONSE | jq -r .token) == "null" ]]; then
    echo -e "${RED}Login Failed.${NC}" ; exit 1
fi
log_success "Docker Login OK."

# ==============================================================================
# 2. K3S
# ==============================================================================
echo -e "${BLUE}--- STEP 1: K3S ---${NC}"
sudo mkdir -p /etc/rancher/k3s
sudo cat <<EOF > /etc/rancher/k3s/registries.yaml
configs:
  "docker.io": { auth: { username: "$MY_DOCKER_USER", password: "$MY_DOCKER_PASS" } }
EOF

if ! command -v k3s &> /dev/null; then
    curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--write-kubeconfig-mode 644" sh -
else
    log_info "K3s installed."
fi

mkdir -p "$REAL_HOME/.kube"
for i in {1..30}; do [ -f /etc/rancher/k3s/k3s.yaml ] && break; sleep 1; done
cp /etc/rancher/k3s/k3s.yaml "$REAL_HOME/.kube/config"
chown -R "$REAL_USER:$REAL_USER" "$REAL_HOME/.kube"
chmod 600 "$REAL_HOME/.kube/config"
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

log_info "Waiting for K3s..."
for i in {1..60}; do kubectl get nodes 2>/dev/null | grep -q "Ready" && break; sleep 2; done

# ==============================================================================
# 3. HELM
# ==============================================================================
echo -e "${BLUE}--- STEP 2: HELM ---${NC}"
if ! command -v helm &> /dev/null; then curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash; fi

mkdir -p /fiware/scripts /fiware/trust-anchor /fiware/consumer /fiware/provider /fiware/wallet-identity
chown -R "$REAL_USER:$REAL_USER" /fiware

setup_ns() {
    kubectl create ns "$1" --dry-run=client -o yaml | kubectl apply -f -
    kubectl create secret docker-registry regcred --docker-server=https://index.docker.io/v1/ --docker-username="$MY_DOCKER_USER" --docker-password="$MY_DOCKER_PASS" --docker-email="$MY_DOCKER_EMAIL" -n "$1" --dry-run=client -o yaml | kubectl apply -f -
    for i in {1..30}; do kubectl get sa default -n "$1" >/dev/null 2>&1 && break; sleep 2; done
    kubectl patch sa default -p '{"imagePullSecrets": [{"name": "regcred"}]}' -n "$1"
}

setup_ns "kube-system"
helm repo add headlamp https://kubernetes-sigs.github.io/headlamp/
helm repo update
helm upgrade --install my-headlamp headlamp/headlamp -n kube-system
kubectl patch service my-headlamp -n kube-system -p '{"spec":{"type":"NodePort"}}'

# ==============================================================================
# 4. SCRIPTS (TOKEN FIX) & BASHRC
# ==============================================================================
wget -qO /fiware/scripts/get_credential.sh https://raw.githubusercontent.com/wistefan/deployment-demo/main/scripts/get_credential.sh

# GENERATE FIXED TOKEN SCRIPT
cat << 'EOF' > /fiware/scripts/get_access_token_oid4vp.sh
#!/bin/bash
set -e
set -o pipefail

token_endpoint=$(curl -s -X GET "$1/.well-known/openid-configuration" | jq -r '.token_endpoint')

if [ -z "$token_endpoint" ] || [ "$token_endpoint" == "null" ]; then
    echo "FOUT: Kon 'token_endpoint' niet vinden. Is de URL $1 correct?" >&2
    exit 1
fi

# Fix poort 8080 bug
token_endpoint=$(echo $token_endpoint | sed 's/:8080//')

holder_did=$(cat /fiware/wallet-identity/did.json | jq '.id' -r)

if [ -z "$holder_did" ] || [ "$holder_did" == "null" ]; then
    echo "FOUT: Kon '.id' niet vinden in /fiware/wallet-identity/did.json." >&2
    exit 1
fi

verifiable_presentation="{
  \"@context\": [\"https://www.w3.org/2018/credentials/v1\"],
  \"type\": [\"VerifiablePresentation\"],
  \"verifiableCredential\": [
      \"$2\"
  ],
  \"holder\": \"${holder_did}\"
}"

# --- PAYLOAD MET CLAIMS (FIX VOOR LEGE RESPONSE) ---
now=$(date +%s)
exp=$(($now + 600))
jti="jwt_$(date +%s)_$RANDOM"

jwt_header=$(echo -n "{\"alg\":\"ES256\", \"typ\":\"JWT\", \"kid\":\"${holder_did}\"}"| base64 -w0 | sed s/\+/-/g | sed 's/\//_/g' | sed -E s/=+$//)
payload_json="{\"iss\": \"${holder_did}\", \"sub\": \"${holder_did}\", \"aud\": \"${token_endpoint}\", \"jti\": \"${jti}\", \"iat\": ${now}, \"exp\": ${exp}, \"vp\": ${verifiable_presentation}}"
payload=$(echo -n "${payload_json}" | base64 -w0 | sed s/\+/-/g |sed 's/\//_/g' |  sed -E s/=+$//)
signature=$(echo -n "${jwt_header}.${payload}" | openssl dgst -sha256 -binary -sign /fiware/wallet-identity/private-key.pem | base64 -w0 | sed s/\+/-/g | sed 's/\//_/g' | sed -E s/=+$//)

jwt="${jwt_header}.${payload}.${signature}"

# Request
final_response=$(curl -s -X POST "$token_endpoint" \
      --header 'Accept: application/json' \
      --header 'Content-Type: application/x-www-form-urlencoded' \
      --data-urlencode "grant_type=vp_token" \
      --data-urlencode "client_id=data-service" \
      --data-urlencode "vp_token=${jwt}" \
      --data-urlencode "scope=$3")

access_token=$(echo $final_response | jq '.access_token' -r)

if [ -z "$access_token" ] || [ "$access_token" == "null" ]; then
    echo "FOUT: Geen access_token. Server antwoord: $final_response" >&2
    exit 1
fi

# Output token
echo $access_token
EOF

chmod +x /fiware/scripts/*.sh
chown -R "$REAL_USER:$REAL_USER" /fiware/scripts

# INJECT DEBUGGING FUNCTION
if ! grep -q "refresh_demo_tokens" "$REAL_HOME/.bashrc"; then
    cat <<EOF >> "$REAL_HOME/.bashrc"
# Robust IP Detection
INTERNAL_IP=\$(hostname -I | awk '{print \$1}')
if [ -z "\$INTERNAL_IP" ]; then INTERNAL_IP=\$(ip route get 1.1.1.1 | awk '{print \$7}'); fi
export INTERNAL_IP

headlamp-token() { sudo kubectl create token my-headlamp --namespace kube-system; }
refresh_demo_tokens() {
  echo "--- REFRESHING TOKENS (V25) ---"
  echo "Current IP: \$INTERNAL_IP"
  
  export CONSUMER_DID=\$(cat /fiware/consumer-identity/did.json 2>/dev/null | jq '.id' -r || echo "N/A")
  export PROVIDER_DID=\$(cat /fiware/provider-identity/did.json 2>/dev/null | jq '.id' -r || echo "N/A")
  
  echo "Fetching User Credential (Consumer)..."
  export USER_CREDENTIAL=\$(/fiware/scripts/get_credential.sh http://keycloak-consumer.\${INTERNAL_IP}.nip.io user-credential 2>/dev/null)
  
  echo "Fetching User Credential (Provider)..."
  export USER_CREDENTIAL_PROVIDER=\$(/fiware/scripts/get_credential.sh http://keycloak-provider.\${INTERNAL_IP}.nip.io user-credential 2>/dev/null)
  
  if [ -n "\$USER_CREDENTIAL" ]; then
      echo "Fetching Access Token (Consumer)..."
      export ACCESS_TOKEN=\$(/fiware/scripts/get_access_token_oid4vp.sh http://mp-data-service.\${INTERNAL_IP}.nip.io "\$USER_CREDENTIAL" default 2>/dev/null)
      echo "TOKEN: \${ACCESS_TOKEN:0:20}..."
  fi
  
  if [ -n "\$USER_CREDENTIAL_PROVIDER" ]; then
      echo "Fetching Access Token (Provider)..."
      export PROVIDER_ACCESS_TOKEN=\$(/fiware/scripts/get_access_token_oid4vp.sh http://mp-data-service.\${INTERNAL_IP}.nip.io "\$USER_CREDENTIAL_PROVIDER" default 2>/dev/null)
      echo "TOKEN: \${PROVIDER_ACCESS_TOKEN:0:20}..."
  fi
  echo "--- DONE ---"
}
EOF
fi

# ==============================================================================
# 5. TRUST ANCHOR
# ==============================================================================
echo -e "${BLUE}--- STEP 3: TRUST ANCHOR ---${NC}"
setup_ns "trust-anchor"
helm repo add data-space-connector https://fiware.github.io/data-space-connector/
helm repo update
wget -qO /fiware/trust-anchor/values.yaml-template https://raw.githubusercontent.com/MarkKlerkx/DataspaceFontys/refs/heads/main/kubernetes/fiware/trust-anchor/values.yaml-template
sed -e "s|INTERNAL_IP|$INTERNAL_IP|g" -e "s|192.168.165.211|$INTERNAL_IP|g" /fiware/trust-anchor/values.yaml-template > /fiware/trust-anchor/values.yaml
helm upgrade --install trust-anchor data-space-connector/trust-anchor --version 0.2.1 -f /fiware/trust-anchor/values.yaml -n trust-anchor

wait_for_ready "trust-anchor" 600
wait_for_api "http://til.${INTERNAL_IP}.nip.io/v4/issuers"

# ==============================================================================
# 6. CONSUMER
# ==============================================================================
echo -e "${BLUE}--- STEP 4: CONSUMER ---${NC}"
setup_ns "consumer"
cd /fiware/consumer
mkdir -p /fiware/consumer-identity && cd /fiware/consumer-identity
openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem
openssl ec -in private-key.pem -pubout -out public-key.pem
openssl req -new -x509 -key private-key.pem -out cert.pem -days 3600 -subj "/CN=Consumer"
openssl pkcs12 -export -inkey private-key.pem -in cert.pem -out cert.pfx -name didPrivateKey -passout pass:test
wget -q https://github.com/wistefan/did-helper/releases/download/0.1.1/did-helper && chmod +x did-helper
./did-helper -keystorePath cert.pfx -keystorePassword=test -outputFile did.json
export CONSUMER_DID=$(cat did.json | jq .id -r)
chown -R "$REAL_USER:$REAL_USER" /fiware/consumer-identity
kubectl create secret generic consumer-identity --from-file=/fiware/consumer-identity/cert.pfx -n consumer --dry-run=client -o yaml | kubectl apply -f -
wget -qO /fiware/consumer/values.yaml-template https://raw.githubusercontent.com/MarkKlerkx/DataspaceFontys/refs/heads/main/kubernetes/fiware/consumer/values.yaml-template
sed -e "s|DID_CONSUMER|$CONSUMER_DID|g" -e "s|INTERNAL_IP|$INTERNAL_IP|g" -e "s|192.168.165.211|$INTERNAL_IP|g" /fiware/consumer/values.yaml-template > /fiware/consumer/values.yaml
helm upgrade --install consumer-dsc data-space-connector/data-space-connector --version 8.2.22 -f /fiware/consumer/values.yaml -n consumer

wait_for_ready "consumer" 600
wait_for_api "http://keycloak-consumer.${INTERNAL_IP}.nip.io/realms/master"
register_did "http://til.${INTERNAL_IP}.nip.io/issuer" "$CONSUMER_DID" "[]"

# ==============================================================================
# 7. PROVIDER (ZONDER APISIX)
# ==============================================================================
echo -e "${BLUE}--- STEP 5A: PROVIDER IDENTITY & DSC ---${NC}"
setup_ns "provider"

mkdir -p /fiware/provider-identity && cd /fiware/provider-identity
openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem
openssl ec -in private-key.pem -pubout -out public-key.pem
openssl req -new -x509 -key private-key.pem -out cert.pem -days 3600 -subj "/CN=Provider"
openssl pkcs12 -export -inkey private-key.pem -in cert.pem -out cert.pfx -name didPrivateKey -passout pass:test
cp ../consumer-identity/did-helper .
./did-helper -keystorePath cert.pfx -keystorePassword=test -outputFile did.json
export PROVIDER_DID=$(cat did.json | jq .id -r)
chown -R "$REAL_USER:$REAL_USER" /fiware/provider-identity
kubectl create secret generic provider-identity --from-file=/fiware/provider-identity/cert.pfx -n provider --dry-run=client -o yaml | kubectl apply -f -
wget -qO /fiware/provider/values.yaml-template https://raw.githubusercontent.com/MarkKlerkx/DataspaceFontys/refs/heads/main/kubernetes/fiware/provider/values.yaml-template
sed -e "s|DID_PROVIDER|$PROVIDER_DID|g" -e "s|DID_CONSUMER|$CONSUMER_DID|g" -e "s|INTERNAL_IP|$INTERNAL_IP|g" -e "s|192.168.165.211|$INTERNAL_IP|g" /fiware/provider/values.yaml-template > /fiware/provider/values.yaml
helm upgrade --install provider-dsc data-space-connector/data-space-connector --version 8.2.22 -f /fiware/provider/values.yaml -n provider

# CRITICAL WAIT: Wait for Provider Pods (Keycloak/DB) BEFORE APISIX
log_info "Waiting for Provider Core Services to be ready..."
wait_for_ready "provider" 1200
# CRITICAL WAIT: Wait for Provider Keycloak API to be reachable
wait_for_api "http://keycloak-provider.${INTERNAL_IP}.nip.io/realms/master"

# ==============================================================================
# 7B. APISIX & ROUTE LOADING
# ==============================================================================
echo -e "${BLUE}--- STEP 5B: APISIX GATEWAY ---${NC}"

log_info "Deploying APISIX Configs..."
mkdir -p /fiware/apisix && cd /fiware/apisix
wget -qO apisix-values.yaml-template https://raw.githubusercontent.com/MarkKlerkx/DataspaceFontys/refs/heads/main/kubernetes/fiware/apisix/apisix-values.yaml-template
wget -qO apisix-dashboard.yaml-template https://raw.githubusercontent.com/MarkKlerkx/DataspaceFontys/refs/heads/main/kubernetes/fiware/apisix/apisix-dashboard.yaml-template
wget -qO apisix-secret.yaml https://raw.githubusercontent.com/MarkKlerkx/DataspaceFontys/refs/heads/main/kubernetes/fiware/apisix/apisix-secret.yaml
wget -qO apisix-routes-job.yaml-template https://raw.githubusercontent.com/MarkKlerkx/DataspaceFontys/refs/heads/main/kubernetes/fiware/apisix/apisix-routes-job.yaml-template
wget -qO opa-configmaps.yaml https://raw.githubusercontent.com/MarkKlerkx/DataspaceFontys/refs/heads/main/kubernetes/fiware/apisix/opa-configmaps.yaml

# FIX V23: Added '-e' flags to prevent file not found errors
sed -e "s|INTERNAL_IP|$INTERNAL_IP|g" -e "s|192.168.165.211|$INTERNAL_IP|g" apisix-values.yaml-template > apisix-values.yaml
sed -e "s|INTERNAL_IP|$INTERNAL_IP|g" -e "s|192.168.165.211|$INTERNAL_IP|g" apisix-dashboard.yaml-template > apisix-dashboard.yaml
sed -e "s|INTERNAL_IP|$INTERNAL_IP|g" -e "s|192.168.165.211|$INTERNAL_IP|g" apisix-routes-job.yaml-template > apisix-routes-job.yaml

kubectl apply -f opa-configmaps.yaml -n provider
kubectl apply -f apisix-secret.yaml -n provider
helm repo add apisix https://charts.apiseven.com ; helm repo update
helm upgrade --install apisix apisix/apisix -f apisix-values.yaml -n provider
helm upgrade --install apisix-dashboard apisix/apisix-dashboard -f apisix-dashboard.yaml -n provider

# FIX DASHBOARD 404: Explicitly create Ingress for APISIX Dashboard
log_info "Creating Ingress for APISIX Dashboard..."
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: apisix-dashboard-ingress
  namespace: provider
spec:
  rules:
  - host: apisix-dashboard.${INTERNAL_IP}.nip.io
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: apisix-dashboard
            port:
              number: 80
EOF

wait_for_ready "provider" 600

log_info "Ensuring APISIX Routes are loaded (Deleting old job)..."
kubectl delete job apisix-route-importer -n provider --ignore-not-found
log_info "Applying Route Job..."
kubectl apply -f apisix-routes-job.yaml -n provider
log_info "Waiting for Route Job to complete..."
kubectl wait --for=condition=complete job/apisix-route-importer -n provider --timeout=300s || log_warn "Route job did not report complete (might be ok)."

# Verify Trust APIs
wait_for_api "http://til-provider.${INTERNAL_IP}.nip.io/issuer"

echo -e "${BLUE}[ACTION] Establishing Trust Relations...${NC}"
register_did "http://til.${INTERNAL_IP}.nip.io/issuer" "$PROVIDER_DID" "[]"
register_did "http://til-provider.${INTERNAL_IP}.nip.io/issuer" "$CONSUMER_DID" "[{\"credentialsType\": \"UserCredential\"}]"
register_did "http://til-provider.${INTERNAL_IP}.nip.io/issuer" "$PROVIDER_DID" "[{\"credentialsType\": \"UserCredential\"}]"

# ==============================================================================
# 8. WALLET
# ==============================================================================
echo -e "${BLUE}--- STEP 6: WALLET ---${NC}"
mkdir -p /fiware/wallet-identity
chmod o+rw /fiware/wallet-identity
sudo k3s crictl pull quay.io/wi_stefan/did-helper:0.1.1 || true
sudo k3s ctr run --rm --mount type=bind,src=/fiware/wallet-identity,dst=/cert,options=rbind quay.io/wi_stefan/did-helper:0.1.1 did-helper-wallet-job
chmod -R o+rw /fiware/wallet-identity/private-key.pem

# ==============================================================================
# 9. DATA (FIXED POLICY CREATION with FULL JSON TO PREVENT 500 ERROR)
# ==============================================================================
echo -e "${BLUE}--- STEP 7: DEMO DATA ---${NC}"

PAP_URL="http://pap-provider.${INTERNAL_IP}.nip.io/policy"

# 1. Wait for API Availability
wait_for_api "$PAP_URL"

# 2. Create Policy with FULL JSON STRUCTURE
echo -e "${BLUE}[ACTION] Creating ODRL Policy (Full JSON)...${NC}"

# We use cat <<EOF to handle quotes safely
cat <<EOF > /tmp/policy.json
{
  "@context": {
    "dc": "http://purl.org/dc/elements/1.1/",
    "dct": "http://purl.org/dc/terms/",
    "owl": "http://www.w3.org/2002/07/owl#",
    "odrl": "http://www.w3.org/ns/odrl/2/",
    "rdfs": "http://www.w3.org/2000/01/rdf-schema#",
    "skos": "http://www.w3.org/2004/02/skos/core#"
  },
  "@id": "https://mp-operation.org/policy/common/type",
  "@type": "odrl:Policy",
  "odrl:uid": "https://mp-operation.org/policy/common/type",
  "odrl:permission": {
    "odrl:assigner": {
      "@id": "https://www.mp-operation.org/"
    },
    "odrl:target": {
      "@type": "odrl:AssetCollection",
      "odrl:source": "urn:asset",
      "odrl:refinement": [
        {
          "@type": "odrl:Constraint",
          "odrl:leftOperand": "ngsi-ld:entityType",
          "odrl:operator": {
            "@id": "odrl:eq"
          },
          "odrl:rightOperand": "EnergyReport"
        }
      ]
    },
    "odrl:assignee": {
      "@id": "vc:any"
    },
    "odrl:action": {
      "@id": "odrl:read"
    }
  }
}
EOF

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$PAP_URL" \
    -H 'Content-Type: application/json' \
    -d @/tmp/policy.json)

if [[ "$HTTP_CODE" -ge 200 && "$HTTP_CODE" -lt 300 ]]; then
    log_success "Policy created successfully (HTTP $HTTP_CODE)."
elif [[ "$HTTP_CODE" -eq 409 ]]; then
    log_warn "Policy already exists (HTTP 409). Continuing."
else
    log_error "Failed to create policy! HTTP Code: $HTTP_CODE"
    echo "Check /tmp/policy.json for payload details."
    exit 1
fi

# 3. Verify Policy Existence
echo -e "${BLUE}[CHECK] Verifying Policy in PAP...${NC}"
POLICY_LIST=$(curl -s -X GET "$PAP_URL")

if echo "$POLICY_LIST" | grep -q "vc:any"; then
    log_success "Policy Verified: 'vc:any' rule found in PAP."
else
    log_error "Policy verification failed! Rule 'vc:any' not found in: $POLICY_LIST"
    exit 1
fi

echo -e "${BLUE}[WAIT] Waiting for Scorpio...${NC}"
for i in {1..30}; do
    kubectl port-forward -n provider svc/data-service-scorpio 9090:9090 > /dev/null 2>&1 &
    PF_PID=$! ; sleep 3
    if curl -s "http://localhost:9090/ngsi-ld/v1/entities" > /dev/null; then
        echo -e " ${GREEN}[OK] Scorpio Ready.${NC}" ; break
    else
        kill $PF_PID ; sleep 5 ; echo -n "."
    fi
done
curl -s -X POST "http://localhost:9090/ngsi-ld/v1/entities/" --header 'Content-Type: application/ld+json' --data-raw '{"id":"urn:ngsi-ld:EnergyReport:001","type":"EnergyReport","consumption":{"type":"Property","value":150.5,"unitCode":"KWH"},"@context":["https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld"]}'
kill $PF_PID

# ==============================================================================
# 10. COMPLETION
# ==============================================================================
HEADLAMP_PORT=$(kubectl get service -n kube-system my-headlamp -o jsonpath='{.spec.ports[0].nodePort}')
HEADLAMP_TOKEN=$(kubectl create token my-headlamp --namespace kube-system)
KC_CONSUMER_PASS=$(kubectl get secret issuance-secret -n consumer -o jsonpath='{.data.keycloak-admin}' | base64 --decode)
KC_PROVIDER_PASS=$(kubectl get secret issuance-secret -n provider -o jsonpath='{.data.keycloak-admin}' | base64 --decode)

echo ""
echo -e "${GREEN}================================================================${NC}"
echo -e "${GREEN}                  INSTALLATION SUCCESSFUL!                      ${NC}"
echo -e "${GREEN}================================================================${NC}"
echo -e "${BLUE}--- 1. DASHBOARD ACCESS (INFRASTRUCTURE) ---${NC}"
echo "URL:             http://$INTERNAL_IP:$HEADLAMP_PORT"
echo "Token:           $HEADLAMP_TOKEN"
echo -e "Command:         Type ${GREEN}headlamp-token${NC} in your terminal to generate a new token."
echo -e "\n${BLUE}--- 2. IDENTITY MANAGEMENT (KEYCLOAK) ---${NC}"
echo "Consumer URL:    http://keycloak-consumer.$INTERNAL_IP.nip.io/"
echo "Admin User:      keycloak-admin"
echo "Admin Password:  $KC_CONSUMER_PASS"
echo "----------------------------------------------------------------"
echo "Provider URL:    http://keycloak-provider.$INTERNAL_IP.nip.io/"
echo "Admin User:      keycloak-admin"
echo "Admin Password:  $KC_PROVIDER_PASS"
echo -e "\n${BLUE}--- 3. API GATEWAY (APISIX DASHBOARD) ---${NC}"
echo "URL:             http://apisix-dashboard.$INTERNAL_IP.nip.io/"
echo "User:            admin"
echo "Password:        admin"
echo -e "\n${BLUE}--- 4. NEXT STEPS ---${NC}"
echo "Run this command to check if everything works now:"
echo -e "  ${GREEN}refresh_demo_tokens${NC}"
echo -e "${GREEN}================================================================${NC}"
