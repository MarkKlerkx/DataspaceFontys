#!/bin/bash
set -e # Exit immediately if a command exits with a non-zero status

# ==============================================================================
# FIWARE DATA SPACE CONNECTOR - CORRECTED INSTALLER
# Fixes:
#  1. Atomic K3s Install (Passing config flags during install)
#  2. Correct User Detection (Fixes permissions when running with sudo)
#  3. Robust Wait Loops
# ==============================================================================

# --- DETECT REAL USER (To avoid everything being owned by root) ---
if [ $SUDO_USER ]; then
    REAL_USER=$SUDO_USER
    REAL_HOME=$(getent passwd $SUDO_USER | cut -d: -f6)
else
    REAL_USER=$(whoami)
    REAL_HOME=$HOME
fi

# --- LOGGING SETUP ---
LOG_FILE="$(pwd)/install_fiware.log"
exec > >(tee -i "$LOG_FILE") 2>&1

# --- COLORS ---
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${RED}[WARN]${NC} $1"; }

echo -e "${BLUE}Running installation as: root (Target Owner: $REAL_USER)${NC}"

# ==============================================================================
# 1. CONFIGURATION: DOCKER HUB
# ==============================================================================
echo -e "${BLUE}--- CONFIGURATION ---${NC}"
echo "To prevent download errors (Rate Limits), please provide Docker Hub credentials."
# Check if running interactively
if [ -t 0 ]; then
    read -p "Docker Username: " DOCKER_USER
    read -p "Docker Access Token: " DOCKER_PASS
    read -p "Docker Email: " DOCKER_EMAIL
else
    # Fallback if specific vars not set (avoid script hanging in non-interactive mode)
    DOCKER_USER=${DOCKER_USER:-"placeholder"}
    DOCKER_PASS=${DOCKER_PASS:-"placeholder"}
    DOCKER_EMAIL=${DOCKER_EMAIL:-"placeholder@example.com"}
fi

# Function to apply Docker Secrets
setup_namespace_secrets() {
    local ns=$1
    log_info "Setting up namespace: $ns"
    kubectl create namespace "$ns" --dry-run=client -o yaml | kubectl apply -f -
    
    if [ "$DOCKER_USER" != "placeholder" ]; then
        kubectl create secret docker-registry regcred \
          --docker-server=https://index.docker.io/v1/ \
          --docker-username="$DOCKER_USER" \
          --docker-password="$DOCKER_PASS" \
          --docker-email="$DOCKER_EMAIL" \
          -n "$ns" --dry-run=client -o yaml | kubectl apply -f -
        
        kubectl patch serviceaccount default -p '{"imagePullSecrets": [{"name": "regcred"}]}' -n "$ns"
    fi
}

# ==============================================================================
# 2. OS & K3S INSTALLATION 
# ==============================================================================
echo -e "${BLUE}--- STEP 1: K3S INSTALLATION ---${NC}"
apt-get update && apt-get install -y inetutils-ping git jq default-jdk curl

if ! command -v k3s &> /dev/null; then
    log_info "Installing K3s with write-kubeconfig-mode 644..."
    # FIX: Pass the permission flag directly to the installer
    curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--write-kubeconfig-mode 644" sh -
else
    log_info "K3s already installed."
fi

log_info "Configuring Kubeconfig for user: $REAL_USER"
mkdir -p "$REAL_HOME/.kube"
cp /etc/rancher/k3s/k3s.yaml "$REAL_HOME/.kube/config"
chown -R "$REAL_USER:$REAL_USER" "$REAL_HOME/.kube"
chmod 600 "$REAL_HOME/.kube/config"

# Export KUBECONFIG for the current script session so kubectl works immediately
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

log_info "Waiting for K3s Storage Provisioner..."
for i in {1..60}; do
    if kubectl get pods -n kube-system | grep "local-path" | grep -q "Running"; then
        log_success "K3s Storage is Ready!"
        break
    fi
    echo -n "."
    sleep 5
done

# ==============================================================================
# 3. HELM & HEADLAMP 
# ==============================================================================
echo -e "${BLUE}--- STEP 2: HELM & HEADLAMP ---${NC}"
if ! command -v helm &> /dev/null; then
    curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
fi

# Setup Directories with correct ownership
mkdir -p /fiware/scripts /fiware/trust-anchor /fiware/consumer /fiware/provider /fiware/wallet-identity
chown -R "$REAL_USER:$REAL_USER" /fiware

# Headlamp
helm repo add headlamp https://kubernetes-sigs.github.io/headlamp/
helm repo update
helm upgrade --install my-headlamp headlamp/headlamp --namespace kube-system --create-namespace
kubectl patch service my-headlamp -n kube-system -p '{"spec":{"type":"NodePort"}}'

# ==============================================================================
# 4. PREPARE SCRIPTS & BASHRC 
# ==============================================================================
export INTERNAL_IP=$(ip route get 1.1.1.1 | awk '{print $7}')
wget -qO /fiware/scripts/get_credential.sh https://raw.githubusercontent.com/wistefan/deployment-demo/main/scripts/get_credential.sh
wget -qO /fiware/scripts/get_access_token_oid4vp.sh https://raw.githubusercontent.com/wistefan/deployment-demo/main/scripts/get_access_token_oid4vp.sh
chmod +x /fiware/scripts/*.sh
sed -i "s|did.json|did.json|g" /fiware/scripts/get_access_token_oid4vp.sh
# Fix permissions so regular user can run them
chown -R "$REAL_USER:$REAL_USER" /fiware/scripts

# Inject function into the REAL USER'S bashrc
if ! grep -q "refresh_demo_tokens" "$REAL_HOME/.bashrc"; then
    cat <<EOF >> "$REAL_HOME/.bashrc"

# --- FIWARE HELPERS ---
export INTERNAL_IP=\$(ip route get 1.1.1.1 | awk '{print \$7}')
headlamp-token() { sudo kubectl create token my-headlamp --namespace kube-system; }

refresh_demo_tokens() {
  export INTERNAL_IP=\$(ip route get 1.1.1.1 | awk '{print \$7}')
  export CONSUMER_DID=\$(cat /fiware/consumer-identity/did.json 2>/dev/null | jq '.id' -r || echo "N/A")
  export PROVIDER_DID=\$(cat /fiware/provider-identity/did.json 2>/dev/null | jq '.id' -r || echo "N/A")

  export USER_CREDENTIAL=\$(/fiware/scripts/get_credential.sh http://keycloak-consumer.\${INTERNAL_IP}.nip.io user-credential 2>/dev/null || echo "")
  export USER_CREDENTIAL_PROVIDER=\$(/fiware/scripts/get_credential.sh http://keycloak-provider.\${INTERNAL_IP}.nip.io user-credential 2>/dev/null || echo "")

  if [ -n "\$USER_CREDENTIAL" ]; then
      export ACCESS_TOKEN=\$(/fiware/scripts/get_access_token_oid4vp.sh http://mp-data-service.\${INTERNAL_IP}.nip.io "\$USER_CREDENTIAL" default 2>/dev/null || echo "")
  fi

  if [ -n "\$USER_CREDENTIAL_PROVIDER" ]; then
      export PROVIDER_ACCESS_TOKEN=\$(/fiware/scripts/get_access_token_oid4vp.sh http://mp-data-service.\${INTERNAL_IP}.nip.io "\$USER_CREDENTIAL_PROVIDER" default 2>/dev/null || echo "")
  fi
  
  echo "Tokens refreshed for IP: \$INTERNAL_IP"
}
EOF
fi

# ==============================================================================
# 5. TRUST ANCHOR [cite: 43]
# ==============================================================================
echo -e "${BLUE}--- STEP 3: TRUST ANCHOR ---${NC}"
setup_namespace_secrets "trust-anchor"

helm repo add data-space-connector https://fiware.github.io/data-space-connector/
helm repo update
wget -qO /fiware/trust-anchor/values.yaml-template https://raw.githubusercontent.com/MarkKlerkx/DataspaceFontys/refs/heads/main/kubernetes/fiware/trust-anchor/values.yaml-template
sed "s|INTERNAL_IP|$INTERNAL_IP|g" /fiware/trust-anchor/values.yaml-template > /fiware/trust-anchor/values.yaml

helm upgrade --install trust-anchor data-space-connector/trust-anchor --version 0.2.1 -f /fiware/trust-anchor/values.yaml --namespace trust-anchor

log_info "Waiting for Trust Anchor..."
kubectl wait --for=condition=ready pod --all -n trust-anchor --timeout=300s

# ==============================================================================
# 6. CONSUMER [cite: 50]
# ==============================================================================
echo -e "${BLUE}--- STEP 4: CONSUMER ---${NC}"
setup_namespace_secrets "consumer"

cd /fiware/consumer
mkdir -p /fiware/consumer-identity && cd /fiware/consumer-identity
# Keys
openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem
openssl ec -in private-key.pem -pubout -out public-key.pem
openssl req -new -x509 -key private-key.pem -out cert.pem -days 3600 -subj "/CN=Consumer"
openssl pkcs12 -export -inkey private-key.pem -in cert.pem -out cert.pfx -name didPrivateKey -passout pass:test
# DID
wget -q https://github.com/wistefan/did-helper/releases/download/0.1.1/did-helper && chmod +x did-helper
./did-helper -keystorePath cert.pfx -keystorePassword=test -outputFile did.json
export CONSUMER_DID=$(cat did.json | jq .id -r)

# Restore ownership to real user
chown -R "$REAL_USER:$REAL_USER" /fiware/consumer-identity

# Secrets & Config
kubectl create secret generic consumer-identity --from-file=/fiware/consumer-identity/cert.pfx -n consumer --dry-run=client -o yaml | kubectl apply -f -
wget -qO /fiware/consumer/values.yaml-template https://raw.githubusercontent.com/MarkKlerkx/DataspaceFontys/refs/heads/main/kubernetes/fiware/consumer/values.yaml-template
sed -e "s|DID_CONSUMER|$CONSUMER_DID|g" -e "s|INTERNAL_IP|$INTERNAL_IP|g" /fiware/consumer/values.yaml-template > /fiware/consumer/values.yaml

helm upgrade --install consumer-dsc data-space-connector/data-space-connector --version 8.2.22 -f /fiware/consumer/values.yaml --namespace consumer

log_info "Waiting for Consumer..."
kubectl wait --for=condition=ready pod --all -n consumer --timeout=300s

# Register
curl -X POST "http://til.${INTERNAL_IP}.nip.io/issuer" --header 'Content-Type: application/json' --data "{\"did\": \"$CONSUMER_DID\", \"credentials\": []}" || true

# ==============================================================================
# 7. PROVIDER & APISIX [cite: 54]
# ==============================================================================
echo -e "${BLUE}--- STEP 5: PROVIDER ---${NC}"
setup_namespace_secrets "provider"

# Pre-create Postgres ServiceAccount to fix Rate Limits
kubectl create serviceaccount postgresql -n provider --dry-run=client -o yaml | kubectl apply -f -
if [ "$DOCKER_USER" != "placeholder" ]; then
    kubectl patch serviceaccount postgresql -p '{"imagePullSecrets": [{"name": "regcred"}]}' -n provider
fi

mkdir -p /fiware/provider-identity && cd /fiware/provider-identity
# Keys
openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem
openssl ec -in private-key.pem -pubout -out public-key.pem
openssl req -new -x509 -key private-key.pem -out cert.pem -days 3600 -subj "/CN=Provider"
openssl pkcs12 -export -inkey private-key.pem -in cert.pem -out cert.pfx -name didPrivateKey -passout pass:test
cp ../consumer-identity/did-helper .
./did-helper -keystorePath cert.pfx -keystorePassword=test -outputFile did.json
export PROVIDER_DID=$(cat did.json | jq .id -r)

# Restore ownership
chown -R "$REAL_USER:$REAL_USER" /fiware/provider-identity

# Secrets & Config
kubectl create secret generic provider-identity --from-file=/fiware/provider-identity/cert.pfx -n provider --dry-run=client -o yaml | kubectl apply -f -
wget -qO /fiware/provider/values.yaml-template https://raw.githubusercontent.com/MarkKlerkx/DataspaceFontys/refs/heads/main/kubernetes/fiware/provider/values.yaml-template
sed -e "s|DID_PROVIDER|$PROVIDER_DID|g" -e "s|DID_CONSUMER|$CONSUMER_DID|g" -e "s|INTERNAL_IP|$INTERNAL_IP|g" /fiware/provider/values.yaml-template > /fiware/provider/values.yaml

helm upgrade --install provider-dsc data-space-connector/data-space-connector --version 8.2.22 -f /fiware/provider/values.yaml --namespace provider

# --- APISIX ---
log_info "Installing APISIX..."
mkdir -p /fiware/apisix && cd /fiware/apisix
wget -qO apisix-values.yaml-template https://raw.githubusercontent.com/MarkKlerkx/DataspaceFontys/refs/heads/main/kubernetes/fiware/apisix/apisix-values.yaml-template
wget -qO apisix-dashboard.yaml-template https://raw.githubusercontent.com/MarkKlerkx/DataspaceFontys/refs/heads/main/kubernetes/fiware/apisix/apisix-dashboard.yaml-template
wget -qO apisix-secret.yaml https://raw.githubusercontent.com/MarkKlerkx/DataspaceFontys/refs/heads/main/kubernetes/fiware/apisix/apisix-secret.yaml
wget -qO apisix-routes-job.yaml-template https://raw.githubusercontent.com/MarkKlerkx/DataspaceFontys/refs/heads/main/kubernetes/fiware/apisix/apisix-routes-job.yaml-template
wget -qO opa-configmaps.yaml https://raw.githubusercontent.com/MarkKlerkx/DataspaceFontys/refs/heads/main/kubernetes/fiware/apisix/opa-configmaps.yaml

sed "s|INTERNAL_IP|$INTERNAL_IP|g" apisix-values.yaml-template > apisix-values.yaml
sed "s|INTERNAL_IP|$INTERNAL_IP|g" apisix-dashboard.yaml-template > apisix-dashboard.yaml
sed "s|INTERNAL_IP|$INTERNAL_IP|g" apisix-routes-job.yaml-template > apisix-routes-job.yaml

kubectl apply -f opa-configmaps.yaml -n provider
kubectl apply -f apisix-secret.yaml -n provider

helm repo add apisix https://charts.apiseven.com
helm repo update
helm upgrade --install apisix apisix/apisix -f apisix-values.yaml -n provider
helm upgrade --install apisix-dashboard apisix/apisix-dashboard -f apisix-dashboard.yaml -n provider

log_info "Waiting for Provider & APISIX to start..."
kubectl wait --for=condition=ready pod --all -n provider --timeout=600s

kubectl apply -f apisix-routes-job.yaml -n provider

# Trust Relationships
curl -X POST "http://til.${INTERNAL_IP}.nip.io/issuer" --header 'Content-Type: application/json' --data "{\"did\": \"$PROVIDER_DID\", \"credentials\": []}"
sleep 2
curl -X POST "http://til-provider.${INTERNAL_IP}.nip.io/issuer" --header 'Content-Type: application/json' --data "{\"did\": \"$CONSUMER_DID\", \"credentials\": [{\"credentialsType\": \"UserCredential\"}]}"
curl -X POST "http://til-provider.${INTERNAL_IP}.nip.io/issuer" --header 'Content-Type: application/json' --data "{\"did\": \"$PROVIDER_DID\", \"credentials\": [{\"credentialsType\": \"UserCredential\"}]}"

# ==============================================================================
# 8. WALLET [cite: 59]
# ==============================================================================
echo -e "${BLUE}--- STEP 6: WALLET ---${NC}"
mkdir -p /fiware/wallet-identity
chmod o+rw /fiware/wallet-identity
k3s ctr images pull quay.io/wi_stefan/did-helper:0.1.1
k3s ctr run --rm --mount type=bind,src=/fiware/wallet-identity,dst=/cert,options=rbind quay.io/wi_stefan/did-helper:0.1.1 did-helper-wallet-job
chmod -R o+rw /fiware/wallet-identity/private-key.pem

# ==============================================================================
# 9. DEMO DATA & POLICY [cite: 64]
# ==============================================================================
echo -e "${BLUE}--- STEP 7: DEMO DATA ---${NC}"
sleep 5
# Policy
curl -s -X 'POST' "http://pap-provider.${INTERNAL_IP}.nip.io/policy" -H 'Content-Type: application/json' -d '{"@context":{"odrl":"http://www.w3.org/ns/odrl/2/"},"@type":"odrl:Policy","odrl:permission":{"odrl:assignee":{"@id":"vc:any"},"odrl:action":{"@id":"odrl:read"}}}'

# Data (Using Port Forward)
kubectl port-forward -n provider svc/data-service-scorpio 9090:9090 > /dev/null 2>&1 &
PF_PID=$!
sleep 5
curl -s -X POST "http://localhost:9090/ngsi-ld/v1/entities/" --header 'Content-Type: application/ld+json' --data-raw '{"id":"urn:ngsi-ld:EnergyReport:001","type":"EnergyReport","consumption":{"type":"Property","value":150.5,"unitCode":"KWH"},"@context":["https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld"]}'
kill $PF_PID

# ==============================================================================
# 10. COMPLETION
# ==============================================================================
# --- Fetch Dynamic Info ---
HEADLAMP_PORT=$(kubectl get service -n kube-system my-headlamp -o jsonpath='{.spec.ports[0].nodePort}')
HEADLAMP_TOKEN=$(kubectl create token my-headlamp --namespace kube-system)

# Fetch Keycloak Admin Passwords 
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
echo "To ensure your environment variables (like access tokens) are set correctly"
echo "in new terminal sessions, always run the following command first:"
echo -e "  ${GREEN}refresh_demo_tokens${NC}"
echo ""
echo "Logging saved to $LOG_FILE"
echo -e "${GREEN}================================================================${NC}"
