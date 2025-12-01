#!/bin/bash

# ==============================================================================
# FIWARE DATA SPACE CONNECTOR - DEFINITIVE INSTALLER (FULL & ROBUST)
# Based on CitizenCity / FiWare DSC Implementation Documentation
# ==============================================================================

# --- Colors for Output ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# --- Helper Functions ---
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

check_command() {
    if ! command -v "$1" &> /dev/null; then return 1; else return 0; fi
}

wait_for_pods() {
    local namespace=$1
    log_info "Waiting for pods in namespace '$namespace' to be ready..."
    # Wacht maximaal 300 seconden (5 minuten) tot alles groen is
    sudo kubectl wait --for=condition=ready pod --all -n "$namespace" --timeout=300s || log_warn "Proceeding, though some pods are still starting..."
}

# --- STORAGE FIX FUNCTION ---
# Deze functie lost het 'Pending' probleem op door de provisioner te herstarten
fix_stuck_storage() {
    local ns=$1
    log_info "Checking for stuck storage claims (PVCs) in namespace '$ns'..."
    
    # Check of er PVC's op Pending staan
    if sudo kubectl get pvc -n "$ns" | grep -q "Pending"; then
        log_warn "Detected stuck PVCs (Pending state). Applying auto-fix..."
        
        # 1. Schop tegen de provisioner
        sudo kubectl rollout restart deployment local-path-provisioner -n kube-system
        sleep 10
        
        # 2. Verwijder de hangende claims (Helm maakt ze direct opnieuw aan)
        sudo kubectl get pvc -n "$ns" | grep Pending | awk '{print $1}' | xargs -r sudo kubectl delete pvc -n "$ns"
        
        log_success "Stuck PVCs reset. Storage should bind shortly."
    else
        log_info "Storage looks healthy (No pending PVCs)."
    fi
}

# ==============================================================================
# 1. OS PREPARATION & TOOLS [Source: 36]
# ==============================================================================
echo -e "${YELLOW}--- STEP 1: OS PREPARATION ---${NC}"

log_info "Updating system packages..."
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get autoremove -y

log_info "Installing necessary tools (curl, git, jq, java)..."
sudo apt-get install -y inetutils-ping git jq default-jdk curl

# ==============================================================================
# 2. K3S INSTALLATION [Source: 36]
# ==============================================================================
echo -e "${YELLOW}--- STEP 2: K3S INSTALLATION ---${NC}"

if check_command "k3s"; then
    log_info "K3s is already installed."
else
    log_info "Installing K3s..."
    curl -sfL https://get.k3s.io | sh -
fi

log_info "Configuring K3s permissions..."
if ! grep -q "write-kubeconfig-mode" /etc/rancher/k3s/config.yaml 2>/dev/null; then
    echo "write-kubeconfig-mode: \"0644\"" | sudo tee -a /etc/rancher/k3s/config.yaml
    sudo systemctl restart k3s
fi

log_info "Setting up local kubeconfig..."
mkdir -p "$HOME/.kube"
sudo cp /etc/rancher/k3s/k3s.yaml "$HOME/.kube/config"
sudo chown $(id -u):$(id -g) "$HOME/.kube/config"
sudo chmod 644 /etc/rancher/k3s/k3s.yaml

# Check storage provisioner health BEFORE starting
log_info "Verifying Storage Provisioner status..."
sudo kubectl rollout restart deployment local-path-provisioner -n kube-system
sudo kubectl rollout status deployment local-path-provisioner -n kube-system --timeout=60s

# ==============================================================================
# 3. HELM & HEADLAMP [Source: 36]
# ==============================================================================
echo -e "${YELLOW}--- STEP 3: HELM & HEADLAMP SETUP ---${NC}"

if ! check_command "helm"; then
    log_info "Installing Helm..."
    curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
fi

log_info "Setting up /fiware directory..."
sudo mkdir -p /fiware
sudo chown -R "$USER:$USER" /fiware

log_info "Installing Headlamp (Dashboard)..."
helm repo add headlamp https://kubernetes-sigs.github.io/headlamp/
helm repo update
helm upgrade --install my-headlamp headlamp/headlamp --namespace kube-system --create-namespace

log_info "Patching Headlamp to NodePort..."
sudo kubectl patch service my-headlamp -n kube-system -p '{"spec":{"type":"NodePort"}}'

# ==============================================================================
# 4. ENVIRONMENT VARIABLES & SCRIPTS [Source: 36]
# ==============================================================================
echo -e "${YELLOW}--- STEP 4: ENVIRONMENT CONFIGURATION ---${NC}"

export INTERNAL_IP=$(ip route get 1.1.1.1 | awk '{print $7}')
log_info "Detected Internal IP: $INTERNAL_IP"

log_info "Downloading Helper Scripts..."
mkdir -p /fiware/scripts
wget -qO /fiware/scripts/get_credential.sh https://raw.githubusercontent.com/wistefan/deployment-demo/main/scripts/get_credential.sh
wget -qO /fiware/scripts/get_access_token_oid4vp.sh https://raw.githubusercontent.com/wistefan/deployment-demo/main/scripts/get_access_token_oid4vp.sh
chmod +x /fiware/scripts/*.sh

# Fix path in script
sed -i "s|did.json|did.json|g" /fiware/scripts/get_access_token_oid4vp.sh

# Add aliases to bashrc
if ! grep -q "refresh_demo_tokens" "$HOME/.bashrc"; then
    log_info "Adding helper functions to ~/.bashrc..."
    cat <<EOF >> "$HOME/.bashrc"

# --- FIWARE HELPERS ---
export INTERNAL_IP=\$(ip route get 1.1.1.1 | awk '{print \$7}')

headlamp-token() {
   sudo kubectl create token my-headlamp --namespace kube-system
}

refresh_demo_tokens() {
  export INTERNAL_IP=\$(ip route get 1.1.1.1 | awk '{print \$7}')
  export CONSUMER_DID=\$(cat /fiware/consumer-identity/did.json 2>/dev/null | jq '.id' -r || echo "N/A")
  export PROVIDER_DID=\$(cat /fiware/provider-identity/did.json 2>/dev/null | jq '.id' -r || echo "N/A")
  
  # Fetch Credentials
  export USER_CREDENTIAL=\$(/fiware/scripts/get_credential.sh http://keycloak-consumer.\${INTERNAL_IP}.nip.io user-credential || echo "")
  export USER_CREDENTIAL_PROVIDER=\$(/fiware/scripts/get_credential.sh http://keycloak-provider.\${INTERNAL_IP}.nip.io user-credential || echo "")
  
  # Fetch Tokens
  if [ -n "\$USER_CREDENTIAL" ]; then
      export ACCESS_TOKEN=\$(/fiware/scripts/get_access_token_oid4vp.sh http://mp-data-service.\${INTERNAL_IP}.nip.io "\$USER_CREDENTIAL" default || echo "")
  fi
  if [ -n "\$USER_CREDENTIAL_PROVIDER" ]; then
      export PROVIDER_ACCESS_TOKEN=\$(/fiware/scripts/get_access_token_oid4vp.sh http://mp-data-service.\${INTERNAL_IP}.nip.io "\$USER_CREDENTIAL_PROVIDER" default || echo "")
  fi
  echo "Tokens refreshed."
}
EOF
fi
source "$HOME/.bashrc"

# ==============================================================================
# 5. TRUST ANCHOR DEPLOYMENT [Source: 43]
# ==============================================================================
echo -e "${YELLOW}--- STEP 5: DEPLOYING TRUST ANCHOR ---${NC}"

helm repo add data-space-connector https://fiware.github.io/data-space-connector/
helm repo update
mkdir -p /fiware/trust-anchor

log_info "Configuring Trust Anchor..."
wget -qO /fiware/trust-anchor/values.yaml-template https://raw.githubusercontent.com/MarkKlerkx/DataspaceFontys/refs/heads/main/kubernetes/fiware/trust-anchor/values.yaml-template
sed "s|INTERNAL_IP|$INTERNAL_IP|g" /fiware/trust-anchor/values.yaml-template > /fiware/trust-anchor/values.yaml

log_info "Installing Trust Anchor..."
sudo kubectl create namespace trust-anchor --dry-run=client -o yaml | sudo kubectl apply -f -
helm upgrade --install trust-anchor data-space-connector/trust-anchor --version 0.2.1 -f /fiware/trust-anchor/values.yaml --namespace trust-anchor

# CRITICAL FIX: Check Storage immediately
sleep 15
fix_stuck_storage "trust-anchor"
wait_for_pods "trust-anchor"

# ==============================================================================
# 6. CONSUMER SETUP [Source: 50]
# ==============================================================================
echo -e "${YELLOW}--- STEP 6: SETUP CONSUMER ---${NC}"

mkdir -p /fiware/consumer /fiware/consumer-identity
cd /fiware/consumer-identity

log_info "Generating Consumer Keys & DID..."
openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem
openssl ec -in private-key.pem -pubout -out public-key.pem
openssl req -new -x509 -key private-key.pem -out cert.pem -days 3600 -subj "/CN=Consumer"
openssl pkcs12 -export -inkey private-key.pem -in cert.pem -out cert.pfx -name didPrivateKey -passout pass:test

# Download did-helper
wget -q https://github.com/wistefan/did-helper/releases/download/0.1.1/did-helper
chmod +x did-helper
./did-helper -keystorePath cert.pfx -keystorePassword=test -outputFile did.json
export CONSUMER_DID=$(cat did.json | jq .id -r)
log_success "Consumer DID: $CONSUMER_DID"

log_info "Deploying Consumer Secret..."
sudo kubectl create namespace consumer --dry-run=client -o yaml | sudo kubectl apply -f -
sudo kubectl create secret generic consumer-identity --from-file=/fiware/consumer-identity/cert.pfx -n consumer --dry-run=client -o yaml | sudo kubectl apply -f -

log_info "Configuring Consumer DSC..."
wget -qO /fiware/consumer/values.yaml-template https://raw.githubusercontent.com/MarkKlerkx/DataspaceFontys/refs/heads/main/kubernetes/fiware/consumer/values.yaml-template
sed -e "s|DID_CONSUMER|$CONSUMER_DID|g" -e "s|INTERNAL_IP|$INTERNAL_IP|g" /fiware/consumer/values.yaml-template > /fiware/consumer/values.yaml

# Dummy dir for provider to avoid errors
mkdir -p /fiware/provider-identity

log_info "Installing Consumer DSC..."
helm upgrade --install consumer-dsc data-space-connector/data-space-connector --version 8.2.22 -f /fiware/consumer/values.yaml --namespace consumer

# CRITICAL FIX: Check Storage
sleep 15
fix_stuck_storage "consumer"
wait_for_pods "consumer"

log_info "Registering Consumer at Trust Anchor..."
curl -X POST "http://til.${INTERNAL_IP}.nip.io/issuer" --header 'Content-Type: application/json' --data "{\"did\": \"$CONSUMER_DID\", \"credentials\": []}" || true

# ==============================================================================
# 7. PROVIDER SETUP & APISIX [Source: 54]
# ==============================================================================
echo -e "${YELLOW}--- STEP 7: SETUP PROVIDER ---${NC}"

mkdir -p /fiware/provider /fiware/provider-identity
cd /fiware/provider-identity

log_info "Generating Provider Keys & DID..."
openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem
openssl ec -in private-key.pem -pubout -out public-key.pem
openssl req -new -x509 -key private-key.pem -out cert.pem -days 3600 -subj "/CN=Provider"
openssl pkcs12 -export -inkey private-key.pem -in cert.pem -out cert.pfx -name didPrivateKey -passout pass:test
cp ../consumer-identity/did-helper .
./did-helper -keystorePath cert.pfx -keystorePassword=test -outputFile did.json
export PROVIDER_DID=$(cat did.json | jq .id -r)
log_success "Provider DID: $PROVIDER_DID"

log_info "Deploying Provider Secret..."
sudo kubectl create namespace provider --dry-run=client -o yaml | sudo kubectl apply -f -
sudo kubectl create secret generic provider-identity --from-file=/fiware/provider-identity/cert.pfx -n provider --dry-run=client -o yaml | sudo kubectl apply -f -

log_info "Configuring Provider DSC..."
wget -qO /fiware/provider/values.yaml-template https://raw.githubusercontent.com/MarkKlerkx/DataspaceFontys/refs/heads/main/kubernetes/fiware/provider/values.yaml-template
sed -e "s|DID_PROVIDER|$PROVIDER_DID|g" -e "s|DID_CONSUMER|$CONSUMER_DID|g" -e "s|INTERNAL_IP|$INTERNAL_IP|g" /fiware/provider/values.yaml-template > /fiware/provider/values.yaml

log_info "Installing Provider DSC..."
helm upgrade --install provider-dsc data-space-connector/data-space-connector --version 8.2.22 -f /fiware/provider/values.yaml --namespace provider

# --- CRITICAL STAGE: Storage Fix for Provider ---
log_info "Checking Provider Storage stability (Crucial step)..."
sleep 20
fix_stuck_storage "provider"

# Wacht tot provider stabiel is VOOR we APISIX doen
wait_for_pods "provider"

# --- APISIX Setup ---
log_info "Setting up APISIX..."
mkdir -p /fiware/apisix
cd /fiware/apisix
wget -qO apisix-values.yaml-template https://raw.githubusercontent.com/MarkKlerkx/DataspaceFontys/refs/heads/main/kubernetes/fiware/apisix/apisix-values.yaml-template
wget -qO apisix-dashboard.yaml-template https://raw.githubusercontent.com/MarkKlerkx/DataspaceFontys/refs/heads/main/kubernetes/fiware/apisix/apisix-dashboard.yaml-template
wget -qO apisix-secret.yaml https://raw.githubusercontent.com/MarkKlerkx/DataspaceFontys/refs/heads/main/kubernetes/fiware/apisix/apisix-secret.yaml
wget -qO apisix-routes-job.yaml-template https://raw.githubusercontent.com/MarkKlerkx/DataspaceFontys/refs/heads/main/kubernetes/fiware/apisix/apisix-routes-job.yaml-template
wget -qO opa-configmaps.yaml https://raw.githubusercontent.com/MarkKlerkx/DataspaceFontys/refs/heads/main/kubernetes/fiware/apisix/opa-configmaps.yaml

# Generate Configs
sed "s|INTERNAL_IP|$INTERNAL_IP|g" apisix-values.yaml-template > apisix-values.yaml
sed "s|INTERNAL_IP|$INTERNAL_IP|g" apisix-dashboard.yaml-template > apisix-dashboard.yaml
sed "s|INTERNAL_IP|$INTERNAL_IP|g" apisix-routes-job.yaml-template > apisix-routes-job.yaml

# Apply ConfigMaps & Secrets
sudo kubectl apply -f opa-configmaps.yaml -n provider
sudo kubectl apply -f apisix-secret.yaml -n provider

# Install APISIX
helm repo add apisix https://charts.apiseven.com
helm repo update
helm upgrade --install apisix apisix/apisix -f apisix-values.yaml -n provider
helm upgrade --install apisix-dashboard apisix/apisix-dashboard -f apisix-dashboard.yaml -n provider

# Wacht op APISIX start
sleep 20
sudo kubectl apply -f apisix-routes-job.yaml -n provider

# --- TRUST CONFIGURATION ---
log_info "Configuring Trust Relationships..."
curl -X POST "http://til.${INTERNAL_IP}.nip.io/issuer" --header 'Content-Type: application/json' --data "{\"did\": \"$PROVIDER_DID\", \"credentials\": []}"
sleep 5
curl -X POST "http://til-provider.${INTERNAL_IP}.nip.io/issuer" --header 'Content-Type: application/json' --data "{\"did\": \"$CONSUMER_DID\", \"credentials\": [{\"credentialsType\": \"UserCredential\"}]}"
curl -X POST "http://til-provider.${INTERNAL_IP}.nip.io/issuer" --header 'Content-Type: application/json' --data "{\"did\": \"$PROVIDER_DID\", \"credentials\": [{\"credentialsType\": \"UserCredential\"}]}"

# ==============================================================================
# 8. WALLET IDENTITY [Source: 59]
# ==============================================================================
echo -e "${YELLOW}--- STEP 8: WALLET IDENTITY ---${NC}"

mkdir -p /fiware/wallet-identity
sudo chmod o+rw /fiware/wallet-identity

log_info "Generating Wallet Keys (via Docker/Container)..."
sudo k3s ctr images pull quay.io/wi_stefan/did-helper:0.1.1
sudo k3s ctr run --rm \
  --mount type=bind,src=/fiware/wallet-identity,dst=/cert,options=rbind \
  quay.io/wi_stefan/did-helper:0.1.1 did-helper-wallet-job

sudo chmod -R o+rw /fiware/wallet-identity/private-key.pem

# ==============================================================================
# 9. DEMO DATA & POLICY INJECTION [Source: 64]
# ==============================================================================
echo -e "${YELLOW}--- STEP 9: INJECTING DEMO DATA & POLICY ---${NC}"

log_info "Waiting for PAP Service to be ready..."
sleep 15

log_info "Pushing ODRL Policy to allow access..."
curl -s -X 'POST' "http://pap-provider.${INTERNAL_IP}.nip.io/policy" \
  -H 'Content-Type: application/json' \
  -d '{
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
            "odrl:assigner": { "@id": "https://www.mp-operation.org/" },
            "odrl:target": {
              "@type": "odrl:AssetCollection",
              "odrl:source": "urn:asset",
              "odrl:refinement": [{
                  "@type": "odrl:Constraint",
                  "odrl:leftOperand": "ngsi-ld:entityType",
                  "odrl:operator": { "@id": "odrl:eq" },
                  "odrl:rightOperand": "EnergyReport"
              }]
            },
            "odrl:assignee": { "@id": "vc:any" },
            "odrl:action": { "@id": "odrl:read" }
          }
      }'
log_success "ODRL Policy created."

log_info "Injecting 'EnergyReport' demo data..."
sudo kubectl port-forward -n provider svc/data-service-scorpio 9090:9090 > /dev/null 2>&1 &
PF_PID=$!
sleep 5
curl -s -X POST "http://localhost:9090/ngsi-ld/v1/entities/" \
  --header 'Content-Type: application/ld+json' \
  --data-raw '{
    "id": "urn:ngsi-ld:EnergyReport:001",
    "type": "EnergyReport",
    "consumption": { "type": "Property", "value": 150.5, "unitCode": "KWH" },
    "dateObserved": { "type": "Property", "value": "2025-11-18T12:00:00Z" },
    "@context": ["https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld"]
}'
kill $PF_PID
log_success "Demo Data injected."

# ==============================================================================
# 10. COMPLETION
# ==============================================================================
echo -e "${BLUE}==============================================================================${NC}"
echo -e "                   ${GREEN}FIWARE DSC ENVIRONMENT READY${NC}"
echo -e "${BLUE}==============================================================================${NC}"
echo ""
echo "Your Internal IP: $INTERNAL_IP"
echo ""
echo -e "${YELLOW}User Actions Required Now:${NC}"
echo "1. Run command: source ~/.bashrc"
echo "2. Run command: refresh_demo_tokens"
echo ""
echo -e "${YELLOW}Access URLs:${NC}"
echo " * Headlamp:          http://$INTERNAL_IP:30201"
echo "   (Get token via 'headlamp-token' command)"
echo " * Keycloak Consumer: http://keycloak-consumer.$INTERNAL_IP.nip.io"
echo " * APISIX Dashboard:  http://apisix-dashboard.$INTERNAL_IP.nip.io"
echo ""
echo -e "${BLUE}==============================================================================${NC}"
