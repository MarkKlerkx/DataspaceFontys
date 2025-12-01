#!/bin/bash
set -e

# ==============================================================================
# FIWARE INSTALLER - FIXED VERSION (DASHBOARD INGRESS FIX + JQ)
# ==============================================================================

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
# 1. SETUP & TOOLS INSTALLATION
# ==============================================================================
echo -e "${BLUE}[INIT] System Check...${NC}"

# --- FIX TIME SYNC (Prevent APT errors) ---
sudo timedatectl set-ntp off
sudo timedatectl set-ntp on

# Prevent apt locks issues
if sudo lsof /var/lib/dpkg/lock-frontend >/dev/null 2>&1; then
    sudo fuser -vki /var/lib/dpkg/lock-frontend || true
    sudo rm -f /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock
    sudo dpkg --configure -a
fi

echo -e "${BLUE}[INIT] Installing prerequisites...${NC}"
sudo apt-get update
sudo apt-get install -y curl jq inetutils-ping git default-jdk

# FIX: Refresh shell hash table to ensure 'jq' is found immediately
hash -r 

# FIX: Verify JQ installation
if ! command -v jq &> /dev/null; then
    log_warn "JQ not found after install. Retrying..."
    sudo apt-get install -y jq
    hash -r
fi
if ! command -v jq &> /dev/null; then
    log_error "Critical: 'jq' could not be installed. Exiting."
    exit 1
fi
log_success "Prerequisites installed (jq detected)."

clear
echo -e "${BLUE}Docker Hub Auth (Required for Rate Limits)${NC}"
if [ -t 0 ]; then
    read -p "Username: " MY_DOCKER_USER
    read -s -p "Token: " MY_DOCKER_PASS ; echo ""
    read -p "Email: " MY_DOCKER_EMAIL
else
    echo -e "${RED}Interactive mode required.${NC}" ; exit 1
fi

# Validation
LOGIN_RESPONSE=$(curl -s -H "Content-Type: application/json" -X POST -d '{"username": "'${MY_DOCKER_USER}'", "password": "'${MY_DOCKER_PASS}'"}' https://hub.docker.com/v2/users/login)
TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r .token 2>/dev/null)

if [[ "$TOKEN" == "null" || -z "$TOKEN" ]]; then
    echo -e "${RED}Login Failed. Check credentials.${NC}" 
    echo "Response: $LOGIN_RESPONSE"
    exit 1
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
# 4. SCRIPTS & BASHRC
# ==============================================================================
export INTERNAL_IP=$(ip route get 1.1.1.1 | awk '{print $7}')
wget -qO /fiware/scripts/get_credential.sh https://raw.githubusercontent.com/wistefan/deployment-demo/main/scripts/get_credential.sh
wget -qO /fiware/scripts/get_access_token_oid4vp.sh https://raw.githubusercontent.com/wistefan/deployment-demo/main/scripts/get_access_token_oid4vp.sh
chmod +x /fiware/scripts/*.sh
sed -i "s|did.json|did.json|g" /fiware/scripts/get_access_token_oid4vp.sh
chown -R "$REAL_USER:$REAL_USER" /fiware/scripts

# INJECT DEBUGGING FUNCTION
if ! grep -q "refresh_demo_tokens" "$REAL_HOME/.bashrc"; then
    cat <<EOF >> "$REAL_HOME/.bashrc"
export INTERNAL_IP=\$(ip route get 1.1.1.1 | awk '{print \$7}')
headlamp-token() { sudo kubectl create token my-headlamp --namespace kube-system; }
refresh_demo_tokens() {
  echo "--- REFRESHING TOKENS (VERBOSE MODE) ---"
  export INTERNAL_IP=\$(ip route get 1.1.1.1 | awk '{print \$7}')
  echo "IP: \$INTERNAL_IP"
  
  export CONSUMER_DID=\$(cat /fiware/consumer-identity/did.json 2>/dev/null | jq '.id' -r || echo "N/A")
  export PROVIDER_DID=\$(cat /fiware/provider-identity/did.json 2>/dev/null | jq '.id' -r || echo "N/A")
  
  echo "Fetching User Credential (Consumer)..."
  export USER_CREDENTIAL=\$(/fiware/scripts/get_credential.sh http://keycloak-consumer.\${INTERNAL_IP}.nip.io user-credential 2>/dev/null)
  echo " > Credential: \${USER_CREDENTIAL:0:50}..."

  echo "Fetching User Credential (Provider)..."
  export USER_CREDENTIAL_PROVIDER=\$(/fiware/scripts/get_credential.sh http://keycloak-provider.\${INTERNAL_IP}.nip.io user-credential 2>/dev/null)
  echo " > Credential: \${USER_CREDENTIAL_PROVIDER:0:50}..."
  
  if [ -n "\$USER_CREDENTIAL" ]; then
      echo "Fetching Access Token (Consumer)..."
      export ACCESS_TOKEN=\$(/fiware/scripts/get_access_token_oid4vp.sh http://mp-data-service.\${INTERNAL_IP}.nip.io "\$USER_CREDENTIAL" default 2>/dev/null)
      echo " > Access Token: \${ACCESS_TOKEN:0:50}..."
  else
      echo " [!] SKIP Consumer Token (No Credential)"
  fi
  
  if [ -n "\$USER_CREDENTIAL_PROVIDER" ]; then
      echo "Fetching Access Token (Provider)..."
      export PROVIDER_ACCESS_TOKEN=\$(/fiware/scripts/get_access_token_oid4vp.sh http://mp-data-service.\${INTERNAL_IP}.nip.io "\$USER_CREDENTIAL_PROVIDER" default 2>/dev/null)
      echo " > Provider Token: \${PROVIDER_ACCESS_TOKEN:0:50}..."
  else
      echo " [!] SKIP Provider Token (No Credential)"
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
sed "s|INTERNAL_IP|$INTERNAL_IP|g" /fiware/trust-anchor/values.yaml-template > /fiware/trust-anchor/values.yaml
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
sed -e "s|DID_CONSUMER|$CONSUMER_DID|g" -e "s|INTERNAL_IP|$INTERNAL_IP|g" /fiware/consumer/values.yaml-template > /fiware/consumer/values.yaml
helm upgrade --install consumer-dsc data-space-connector/data-space-connector --version 8.2.22 -f /fiware/consumer/values.yaml -n consumer

wait_for_ready "consumer" 600
wait_for_api "http://keycloak-consumer.${INTERNAL_IP}.nip.io/realms/master"
register_did "http://til.${INTERNAL_IP}.nip.io/issuer" "$CONSUMER_DID" "[]"

# ==============================================================================
# 7. PROVIDER & APISIX
# ==============================================================================
echo -e "${BLUE}--- STEP 5: PROVIDER & ROUTE LOADING ---${NC}"
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
sed -e "s|DID_PROVIDER|$PROVIDER_DID|g" -e "s|DID_CONSUMER|$CONSUMER_DID|g" -e "s|INTERNAL_IP|$INTERNAL_IP|g" /fiware/provider/values.yaml-template > /fiware/provider/values.yaml
helm upgrade --install provider-dsc data-space-connector/data-space-connector --version 8.2.22 -f /fiware/provider/values.yaml -n provider

# APISIX SETUP
log_info "Deploying APISIX Configs..."
mkdir -p /fiware/apisix && cd /fiware/apisix
wget -qO apisix-values.yaml-template https://raw.githubusercontent.com/MarkKlerkx/DataspaceFontys/refs/heads/main/kubernetes/fiware/apisix/apisix-values.yaml-template
# Dashboard Template is ignored, we generate it locally below to avoid map/string errors
wget -qO apisix-secret.yaml https://raw.githubusercontent.com/MarkKlerkx/DataspaceFontys/refs/heads/main/kubernetes/fiware/apisix/apisix-secret.yaml
wget -qO apisix-routes-job.yaml-template https://raw.githubusercontent.com/MarkKlerkx/DataspaceFontys/refs/heads/main/kubernetes/fiware/apisix/apisix-routes-job.yaml-template
wget -qO opa-configmaps.yaml https://raw.githubusercontent.com/MarkKlerkx/DataspaceFontys/refs/heads/main/kubernetes/fiware/apisix/opa-configmaps.yaml

sed "s|INTERNAL_IP|$INTERNAL_IP|g" apisix-values.yaml-template > apisix-values.yaml
sed "s|INTERNAL_IP|$INTERNAL_IP|g" apisix-routes-job.yaml-template > apisix-routes-job.yaml

# --- FIX: GENERATE DASHBOARD YAML (SIMPLIFIED FOR DEPRECATED CHART) ---
# We use simple string paths because the chart crashes on object maps
cat <<EOF > apisix-dashboard.yaml
image:
  repository: apache/apisix-dashboard
  tag: 3.0.1
  pullPolicy: IfNotPresent

ingress:
  enabled: true
  annotations:
    kubernetes.io/ingress.class: traefik
  hosts:
    - host: apisix-dashboard.${INTERNAL_IP}.nip.io
      paths:
        - /
EOF

kubectl apply -f opa-configmaps.yaml -n provider
kubectl apply -f apisix-secret.yaml -n provider

helm repo add apisix https://charts.apiseven.com ; helm repo update
helm upgrade --install apisix apisix/apisix -f apisix-values.yaml -n provider

# Install Dashboard with the locally generated CLEAN yaml file
helm upgrade --install apisix-dashboard apisix/apisix-dashboard \
  -f apisix-dashboard.yaml \
  -n provider

# CRITICAL WAIT: Wait for Provider Pods
wait_for_ready "provider" 1200

# --- FIX: CHECK APISIX ADMIN API AVAILABILITY BEFORE JOB ---
echo -e "${BLUE}[WAIT] Waiting for APISIX Admin API to respond...${NC}"
for i in {1..30}; do
    kubectl port-forward -n provider svc/apisix-admin 9180:9180 > /dev/null 2>&1 &
    PF_PID=$!
    sleep 2
    # Check for 401 Unauthorized (Good) or 200 (Good). 000 is Bad.
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 1 "http://localhost:9180/apisix/admin/routes" -H "X-API-KEY: edd1c9f034335f136f87ad84b625c8f1")
    kill $PF_PID >/dev/null 2>&1
    
    if [[ "$STATUS" != "000" ]]; then
       echo -e " ${GREEN}[OK] APISIX Admin Alive ($STATUS)${NC}"
       break
    fi
    echo -n "."
    sleep 5
done

log_info "Ensuring APISIX Routes are loaded (Deleting old job)..."
kubectl delete job apisix-route-importer -n provider --ignore-not-found
log_info "Applying Route Job..."
kubectl apply -f apisix-routes-job.yaml -n provider

# Wait longer for job
kubectl wait --for=condition=complete job/apisix-route-importer -n provider --timeout=300s || log_warn "Route job did not report complete immediately (check logs if tokens fail)."

# Verify Trust APIs
wait_for_api "http://til-provider.${INTERNAL_IP}.nip.io/issuer"
wait_for_api "http://keycloak-provider.${INTERNAL_IP}.nip.io/realms/master"

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
# 9. DATA
# ==============================================================================
echo -e "${BLUE}--- STEP 7: DEMO DATA ---${NC}"
wait_for_api "http://pap-provider.${INTERNAL_IP}.nip.io/policy"
curl -s -X 'POST' "http://pap-provider.${INTERNAL_IP}.nip.io/policy" -H 'Content-Type: application/json' -d '{"@context":{"odrl":"http://www.w3.org/ns/odrl/2/"},"@type":"odrl:Policy","odrl:permission":{"odrl:assignee":{"@id":"vc:any"},"odrl:action":{"@id":"odrl:read"}}}'

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
echo -e "\n${BLUE}--- 4. NEXT STEPS & HANDY COMMANDS ---${NC}"
echo "To check tokens and debug, run:"
echo -e "  ${GREEN}refresh_demo_tokens${NC}"
echo "(This will now show the actual token values)"
echo ""
echo "Logging saved to $LOG_FILE"
echo -e "${GREEN}================================================================${NC}"
