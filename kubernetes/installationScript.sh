#!/bin/bash

# ==============================================================================
# FIWARE DATA SPACE CONNECTOR - PRO INSTALLER
# Features:
#  - Auto-Logging to file
#  - Docker Hub Authentication (prevents Rate Limits)
#  - Storage Deadlock Auto-Fix
# ==============================================================================

# --- 1. SETUP LOGGING ---
# Log alles naar install_fiware.log in dezelfde map, maar toon het ook op scherm.
LOG_FILE="$(pwd)/install_fiware.log"
if [ ! -f "$LOG_FILE" ]; then touch "$LOG_FILE"; fi
exec > >(tee -i "$LOG_FILE") 2>&1

echo "=========================================================="
echo " LOGGING ENABLED: Output wordt bewaard in:"
echo " $LOG_FILE"
echo "=========================================================="

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# --- Variables for Docker Auth ---
USE_DOCKER_AUTH=false
DOCKER_USER=""
DOCKER_PASS=""
DOCKER_EMAIL=""

# --- Helper Functions ---
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
check_command() { if ! command -v "$1" &> /dev/null; then return 1; else return 0; fi; }

wait_for_pods() {
    local namespace=$1
    log_info "Wachten tot pods in '$namespace' gestart zijn (max 5 min)..."
    sudo kubectl wait --for=condition=ready pod --all -n "$namespace" --timeout=300s || log_warn "Doorgaan (sommige pods starten nog)..."
}

fix_stuck_storage() {
    local ns=$1
    if sudo kubectl get pvc -n "$ns" 2>/dev/null | grep -q "Pending"; then
        log_warn "Storage Deadlock gedetecteerd in '$ns'. Auto-fix gestart..."
        sudo kubectl rollout restart deployment local-path-provisioner -n kube-system
        sleep 10
        sudo kubectl get pvc -n "$ns" | grep Pending | awk '{print $1}' | xargs -r sudo kubectl delete pvc -n "$ns"
        log_success "Opslag reset uitgevoerd."
    fi
}

# --- NIEUWE FUNCTIE: Docker Auth Toepassen ---
apply_docker_secret() {
    local ns=$1
    if [ "$USE_DOCKER_AUTH" = true ]; then
        log_info "Docker Credentials toepassen op namespace '$ns'..."
        # 1. Maak de secret aan (onderdruk foutmelding als hij al bestaat)
        sudo kubectl create secret docker-registry regcred \
          --docker-server=https://index.docker.io/v1/ \
          --docker-username="$DOCKER_USER" \
          --docker-password="$DOCKER_PASS" \
          --docker-email="$DOCKER_EMAIL" \
          -n "$ns" --dry-run=client -o yaml | sudo kubectl apply -f -
        
        # 2. Patch de default serviceaccount zodat pods de secret gebruiken
        sudo kubectl patch serviceaccount default -p '{"imagePullSecrets": [{"name": "regcred"}]}' -n "$ns"
        log_success "Docker authenticatie actief voor '$ns'."
    fi
}

# ==============================================================================
# INPUT STAP: DOCKER HUB CREDENTIALS
# ==============================================================================
echo -e "${YELLOW}--- DOCKER HUB CONFIGURATIE ---${NC}"
echo "Om 'ImagePullBackOff' (rate limits) te voorkomen, kun je inloggen met Docker Hub."
# Gebruik /dev/tty om input te lezen ondanks de output redirection
read -p "Wil je Docker Hub credentials gebruiken? (y/n): " -r RESPONSE < /dev/tty
if [[ "$RESPONSE" =~ ^([yY][eE][sS]|[yY])+$ ]]; then
    USE_DOCKER_AUTH=true
    echo ""
    read -p "Docker Username: " -r DOCKER_USER < /dev/tty
    read -p "Docker Access Token (of wachtwoord): " -r DOCKER_PASS < /dev/tty
    read -p "Docker Email: " -r DOCKER_EMAIL < /dev/tty
    echo ""
    log_info "Credentials opgeslagen. Ze worden toegepast zodra de namespaces zijn aangemaakt."
else
    log_warn "Geen credentials opgegeven. Je loopt risico op download-limieten (100 pulls/6u)."
fi

# ==============================================================================
# 1. OS PREPARATION
# ==============================================================================
echo -e "${YELLOW}--- STAP 1: VOORBEREIDING ---${NC}"
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install -y inetutils-ping git jq default-jdk curl

# ==============================================================================
# 2. K3S INSTALLATIE
# ==============================================================================
echo -e "${YELLOW}--- STAP 2: K3S INSTALLATIE ---${NC}"
if check_command "k3s"; then
    log_info "K3s is al geïnstalleerd."
else
    curl -sfL https://get.k3s.io | sh -
fi

if ! grep -q "write-kubeconfig-mode" /etc/rancher/k3s/config.yaml 2>/dev/null; then
    echo "write-kubeconfig-mode: \"0644\"" | sudo tee -a /etc/rancher/k3s/config.yaml
    sudo systemctl restart k3s
fi

mkdir -p "$HOME/.kube"
sudo cp /etc/rancher/k3s/k3s.yaml "$HOME/.kube/config"
sudo chown $(id -u):$(id -g) "$HOME/.kube/config"
sudo chmod 644 /etc/rancher/k3s/k3s.yaml

log_info "Controleren Storage Provisioner..."
sudo kubectl rollout restart deployment local-path-provisioner -n kube-system
sudo kubectl rollout status deployment local-path-provisioner -n kube-system --timeout=60s

# ==============================================================================
# 3. HELM & HEADLAMP
# ==============================================================================
echo -e "${YELLOW}--- STAP 3: HELM & HEADLAMP ---${NC}"
if ! check_command "helm"; then
    curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
fi

sudo mkdir -p /fiware
sudo chown -R "$USER:$USER" /fiware

helm repo add headlamp https://kubernetes-sigs.github.io/headlamp/
helm repo update
helm upgrade --install my-headlamp headlamp/headlamp --namespace kube-system --create-namespace
sudo kubectl patch service my-headlamp -n kube-system -p '{"spec":{"type":"NodePort"}}'

# ==============================================================================
# 4. CONFIGURATIE & VARIABELEN
# ==============================================================================
echo -e "${YELLOW}--- STAP 4: CONFIGURATIE ---${NC}"
export INTERNAL_IP=$(ip route get 1.1.1.1 | awk '{print $7}')
mkdir -p /fiware/scripts
wget -qO /fiware/scripts/get_credential.sh https://raw.githubusercontent.com/wistefan/deployment-demo/main/scripts/get_credential.sh
wget -qO /fiware/scripts/get_access_token_oid4vp.sh https://raw.githubusercontent.com/wistefan/deployment-demo/main/scripts/get_access_token_oid4vp.sh
chmod +x /fiware/scripts/*.sh
sed -i "s|did.json|did.json|g" /fiware/scripts/get_access_token_oid4vp.sh

if ! grep -q "refresh_demo_tokens" "$HOME/.bashrc"; then
    cat <<EOF >> "$HOME/.bashrc"
export INTERNAL_IP=\$(ip route get 1.1.1.1 | awk '{print \$7}')
headlamp-token() { sudo kubectl create token my-headlamp --namespace kube-system; }
refresh_demo_tokens() {
  export INTERNAL_IP=\$(ip route get 1.1.1.1 | awk '{print \$7}')
  export CONSUMER_DID=\$(cat /fiware/consumer-identity/did.json 2>/dev/null | jq '.id' -r || echo "N/A")
  export PROVIDER_DID=\$(cat /fiware/provider-identity/did.json 2>/dev/null | jq '.id' -r || echo "N/A")
  export USER_CREDENTIAL=\$(/fiware/scripts/get_credential.sh http://keycloak-consumer.\${INTERNAL_IP}.nip.io user-credential || echo "")
  export USER_CREDENTIAL_PROVIDER=\$(/fiware/scripts/get_credential.sh http://keycloak-provider.\${INTERNAL_IP}.nip.io user-credential || echo "")
  if [ -n "\$USER_CREDENTIAL" ]; then
      export ACCESS_TOKEN=\$(/fiware/scripts/get_access_token_oid4vp.sh http://mp-data-service.\${INTERNAL_IP}.nip.io "\$USER_CREDENTIAL" default || echo "")
  fi
  if [ -n "\$USER_CREDENTIAL_PROVIDER" ]; then
      export PROVIDER_ACCESS_TOKEN=\$(/fiware/scripts/get_access_token_oid4vp.sh http://mp-data-service.\${INTERNAL_IP}.nip.io "\$USER_CREDENTIAL_PROVIDER" default || echo "")
  fi
  echo "Tokens ververst."
}
EOF
fi
source "$HOME/.bashrc"

# ==============================================================================
# 5. TRUST ANCHOR
# ==============================================================================
echo -e "${YELLOW}--- STAP 5: TRUST ANCHOR ---${NC}"
helm repo add data-space-connector https://fiware.github.io/data-space-connector/
helm repo update
mkdir -p /fiware/trust-anchor
wget -qO /fiware/trust-anchor/values.yaml-template https://raw.githubusercontent.com/MarkKlerkx/DataspaceFontys/refs/heads/main/kubernetes/fiware/trust-anchor/values.yaml-template
sed "s|INTERNAL_IP|$INTERNAL_IP|g" /fiware/trust-anchor/values.yaml-template > /fiware/trust-anchor/values.yaml

# Create namespace & Apply Docker Auth
sudo kubectl create namespace trust-anchor --dry-run=client -o yaml | sudo kubectl apply -f -
apply_docker_secret "trust-anchor"

helm upgrade --install trust-anchor data-space-connector/trust-anchor --version 0.2.1 -f /fiware/trust-anchor/values.yaml --namespace trust-anchor

sleep 15
fix_stuck_storage "trust-anchor"
wait_for_pods "trust-anchor"

# ==============================================================================
# 6. CONSUMER
# ==============================================================================
echo -e "${YELLOW}--- STAP 6: CONSUMER ---${NC}"
mkdir -p /fiware/consumer-identity
cd /fiware/consumer-identity
openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem
openssl ec -in private-key.pem -pubout -out public-key.pem
openssl req -new -x509 -key private-key.pem -out cert.pem -days 3600 -subj "/CN=Consumer"
openssl pkcs12 -export -inkey private-key.pem -in cert.pem -out cert.pfx -name didPrivateKey -passout pass:test
wget -q https://github.com/wistefan/did-helper/releases/download/0.1.1/did-helper && chmod +x did-helper
./did-helper -keystorePath cert.pfx -keystorePassword=test -outputFile did.json
export CONSUMER_DID=$(cat did.json | jq .id -r)

# Create namespace & Apply Docker Auth
sudo kubectl create namespace consumer --dry-run=client -o yaml | sudo kubectl apply -f -
apply_docker_secret "consumer"

sudo kubectl create secret generic consumer-identity --from-file=/fiware/consumer-identity/cert.pfx -n consumer --dry-run=client -o yaml | sudo kubectl apply -f -
mkdir -p /fiware/consumer
wget -qO /fiware/consumer/values.yaml-template https://raw.githubusercontent.com/MarkKlerkx/DataspaceFontys/refs/heads/main/kubernetes/fiware/consumer/values.yaml-template
sed -e "s|DID_CONSUMER|$CONSUMER_DID|g" -e "s|INTERNAL_IP|$INTERNAL_IP|g" /fiware/consumer/values.yaml-template > /fiware/consumer/values.yaml
mkdir -p /fiware/provider-identity # Placeholder

helm upgrade --install consumer-dsc data-space-connector/data-space-connector --version 8.2.22 -f /fiware/consumer/values.yaml --namespace consumer

sleep 15
fix_stuck_storage "consumer"
wait_for_pods "consumer"

curl -X POST "http://til.${INTERNAL_IP}.nip.io/issuer" --header 'Content-Type: application/json' --data "{\"did\": \"$CONSUMER_DID\", \"credentials\": []}" || true

# ==============================================================================
# 7. PROVIDER & APISIX
# ==============================================================================
echo -e "${YELLOW}--- STAP 7: PROVIDER & APISIX ---${NC}"
mkdir -p /fiware/provider-identity
cd /fiware/provider-identity
openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem
openssl ec -in private-key.pem -pubout -out public-key.pem
openssl req -new -x509 -key private-key.pem -out cert.pem -days 3600 -subj "/CN=Provider"
openssl pkcs12 -export -inkey private-key.pem -in cert.pem -out cert.pfx -name didPrivateKey -passout pass:test
cp ../consumer-identity/did-helper .
./did-helper -keystorePath cert.pfx -keystorePassword=test -outputFile did.json
export PROVIDER_DID=$(cat did.json | jq .id -r)

# Create namespace & Apply Docker Auth
sudo kubectl create namespace provider --dry-run=client -o yaml | sudo kubectl apply -f -
apply_docker_secret "provider"

sudo kubectl create secret generic provider-identity --from-file=/fiware/provider-identity/cert.pfx -n provider --dry-run=client -o yaml | sudo kubectl apply -f -
mkdir -p /fiware/provider
wget -qO /fiware/provider/values.yaml-template https://raw.githubusercontent.com/MarkKlerkx/DataspaceFontys/refs/heads/main/kubernetes/fiware/provider/values.yaml-template
sed -e "s|DID_PROVIDER|$PROVIDER_DID|g" -e "s|DID_CONSUMER|$CONSUMER_DID|g" -e "s|INTERNAL_IP|$INTERNAL_IP|g" /fiware/provider/values.yaml-template > /fiware/provider/values.yaml

helm upgrade --install provider-dsc data-space-connector/data-space-connector --version 8.2.22 -f /fiware/provider/values.yaml --namespace provider

log_info "Provider Storage controleren..."
sleep 20
fix_stuck_storage "provider"
wait_for_pods "provider"

# APISIX Setup
mkdir -p /fiware/apisix && cd /fiware/apisix
wget -qO apisix-values.yaml-template https://raw.githubusercontent.com/MarkKlerkx/DataspaceFontys/refs/heads/main/kubernetes/fiware/apisix/apisix-values.yaml-template
wget -qO apisix-dashboard.yaml-template https://raw.githubusercontent.com/MarkKlerkx/DataspaceFontys/refs/heads/main/kubernetes/fiware/apisix/apisix-dashboard.yaml-template
wget -qO apisix-secret.yaml https://raw.githubusercontent.com/MarkKlerkx/DataspaceFontys/refs/heads/main/kubernetes/fiware/apisix/apisix-secret.yaml
wget -qO apisix-routes-job.yaml-template https://raw.githubusercontent.com/MarkKlerkx/DataspaceFontys/refs/heads/main/kubernetes/fiware/apisix/apisix-routes-job.yaml-template
wget -qO opa-configmaps.yaml https://raw.githubusercontent.com/MarkKlerkx/DataspaceFontys/refs/heads/main/kubernetes/fiware/apisix/opa-configmaps.yaml

sed "s|INTERNAL_IP|$INTERNAL_IP|g" apisix-values.yaml-template > apisix-values.yaml
sed "s|INTERNAL_IP|$INTERNAL_IP|g" apisix-dashboard.yaml-template > apisix-dashboard.yaml
sed "s|INTERNAL_IP|$INTERNAL_IP|g" apisix-routes-job.yaml-template > apisix-routes-job.yaml

sudo kubectl apply -f opa-configmaps.yaml -n provider
sudo kubectl apply -f apisix-secret.yaml -n provider

helm repo add apisix https://charts.apiseven.com
helm repo update
helm upgrade --install apisix apisix/apisix -f apisix-values.yaml -n provider
helm upgrade --install apisix-dashboard apisix/apisix-dashboard -f apisix-dashboard.yaml -n provider

sleep 20
sudo kubectl apply -f apisix-routes-job.yaml -n provider

curl -X POST "http://til.${INTERNAL_IP}.nip.io/issuer" --header 'Content-Type: application/json' --data "{\"did\": \"$PROVIDER_DID\", \"credentials\": []}"
sleep 5
curl -X POST "http://til-provider.${INTERNAL_IP}.nip.io/issuer" --header 'Content-Type: application/json' --data "{\"did\": \"$CONSUMER_DID\", \"credentials\": [{\"credentialsType\": \"UserCredential\"}]}"
curl -X POST "http://til-provider.${INTERNAL_IP}.nip.io/issuer" --header 'Content-Type: application/json' --data "{\"did\": \"$PROVIDER_DID\", \"credentials\": [{\"credentialsType\": \"UserCredential\"}]}"

# ==============================================================================
# 8. WALLET & DATA
# ==============================================================================
echo -e "${YELLOW}--- STAP 8: WALLET & DEMO DATA ---${NC}"
mkdir -p /fiware/wallet-identity
sudo chmod o+rw /fiware/wallet-identity
sudo k3s ctr images pull quay.io/wi_stefan/did-helper:0.1.1
sudo k3s ctr run --rm --mount type=bind,src=/fiware/wallet-identity,dst=/cert,options=rbind quay.io/wi_stefan/did-helper:0.1.1 did-helper-wallet-job
sudo chmod -R o+rw /fiware/wallet-identity/private-key.pem

sleep 15
curl -s -X 'POST' "http://pap-provider.${INTERNAL_IP}.nip.io/policy" -H 'Content-Type: application/json' -d '{"@context":{"odrl":"http://www.w3.org/ns/odrl/2/"},"@type":"odrl:Policy","odrl:permission":{"odrl:assignee":{"@id":"vc:any"},"odrl:action":{"@id":"odrl:read"}}}'

sudo kubectl port-forward -n provider svc/data-service-scorpio 9090:9090 > /dev/null 2>&1 &
PF_PID=$!
sleep 5
curl -s -X POST "http://localhost:9090/ngsi-ld/v1/entities/" --header 'Content-Type: application/ld+json' --data-raw '{"id":"urn:ngsi-ld:EnergyReport:001","type":"EnergyReport","consumption":{"type":"Property","value":150.5,"unitCode":"KWH"},"@context":["https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld"]}'
kill $PF_PID

log_success "INSTALLATIE VOLTOOID!"
echo "Logbestand bewaard in: $LOG_FILE"
echo "Refresh tokens with: source ~/.bashrc && refresh_demo_tokens"
