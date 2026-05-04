#!/usr/bin/env bash
#
# One-shot migration/deploy helper:
# 1) Scan repository and report findings
# 2) Ask for explicit confirmation
# 3) Patch pom.xml for native host k3s (skip docker run/apply in k3s plugin)
# 4) Replace 127.0.0.1.nip.io with {INTERNAL_IP}.nip.io
# 5) Replace {INTERNAL_IP} with detected/provided server IP
# 6) Ensure native k3s is installed/running and kubeconfig is usable
# 7) Build/deploy and apply manifests with host kubectl
#
# Usage:
#   ./prepare-native-k3s-server.sh --repo /path/to/repo
#   ./prepare-native-k3s-server.sh --repo /path --ip 172.20.10.15 --yes
#
set -euo pipefail

REPO_ROOT="$(pwd)"
REPO_PROVIDED=0
FORCE_YES=0
INCLUDE_DOCS=0
SKIP_BUILD=0
SKIP_APPLY=0
SKIP_K3S_INSTALL=0
DO_CLONE=0
SKIP_HEADLAMP=0
DEPLOY_URL_PORTAL=1
PORTAL_REPO_URL="https://github.com/MarkKlerkx/DataspaceFontys.git"
PORTAL_DIR="$HOME/DataspaceFontys"
PORTAL_KUSTOMIZE_PATH="localDeployment/ingress-url-portal"
IP_ARG=""

POM_FILE=""
TARGET_IP=""
LOG_FILE=""
HEADLAMP_NODEPORT=""
HEADLAMP_URL=""

declare -a CANDIDATE_FILES=()
declare -a NIP_FILES=()
declare -a PLACEHOLDER_FILES=()

usage() {
  cat <<'EOF'
Usage:
  prepare-native-k3s-server.sh [options]

Options:
  --repo <path>       Repository root (default: current directory)
  --clone             Clone FIWARE/data-space-connector into --repo (or ./data-space-connector)
  --ip <address>      Internal server IP to materialize
  --yes               Skip confirmation prompt
  --include-docs      Also update doc/**/*.md and doc/**/*.drawio
  --skip-k3s-install  Do not install/start k3s automatically
  --skip-headlamp     Do not install/configure Headlamp UI
  --skip-url-portal   Do not deploy the DSC URL portal (DataspaceFontys)
  --skip-build        Do not run Maven build/deploy
  --skip-apply        Do not run kubectl apply for target/k3s manifests
  -h, --help          Show this help
EOF
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: missing required command '$1'" >&2
    exit 1
  fi
}

detect_ipv4() {
  local ip=""
  if [[ -n "$IP_ARG" ]]; then
    echo "$IP_ARG"
    return 0
  fi
  if [[ -n "${INTERNAL_IP:-}" ]]; then
    echo "${INTERNAL_IP}"
    return 0
  fi
  ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") { print $(i + 1); exit }}')"
  if [[ -n "$ip" ]]; then
    echo "$ip"
    return 0
  fi
  ip="$(hostname -I 2>/dev/null | awk '{ print $1; exit }')"
  if [[ -n "$ip" ]]; then
    echo "$ip"
    return 0
  fi
  echo "error: unable to detect internal IP; use --ip <address> or export INTERNAL_IP." >&2
  exit 1
}

discover_repo() {
  if [[ ! -d "$REPO_ROOT" ]]; then
    echo "error: repo path does not exist: $REPO_ROOT" >&2
    exit 1
  fi
  REPO_ROOT="$(cd "$REPO_ROOT" && pwd)"
  if [[ ! -f "$REPO_ROOT/pom.xml" ]]; then
    echo "error: no root pom.xml found in $REPO_ROOT" >&2
    exit 1
  fi
}

clone_repo_if_requested() {
  need_cmd git

  # If user didn't specify --repo, clone into a sensible default subfolder.
  if [[ "$REPO_PROVIDED" -eq 0 ]]; then
    REPO_ROOT="$(pwd)/data-space-connector"
  fi

  if [[ -d "$REPO_ROOT/.git" ]]; then
    echo "Repo already cloned at $REPO_ROOT (.git exists). Skipping clone."
    return 0
  fi
  if [[ -e "$REPO_ROOT" ]]; then
    echo "error: --clone target already exists but is not a git repo: $REPO_ROOT" >&2
    exit 1
  fi

  echo "Cloning FIWARE/data-space-connector into: $REPO_ROOT"
  git clone https://github.com/FIWARE/data-space-connector.git "$REPO_ROOT"
}

setup_logging() {
  LOG_FILE="$REPO_ROOT/build.log"
  : >"$LOG_FILE"
  exec > >(tee -a "$LOG_FILE") 2>&1
  echo "Logging to: $LOG_FILE"
  echo
}

discover_pom() {
  POM_FILE="$REPO_ROOT/pom.xml"
  if ! grep -q '<artifactId>k3s-maven-plugin</artifactId>' "$POM_FILE"; then
    echo "warning: k3s-maven-plugin not found in $POM_FILE (script continues)." >&2
  fi
}

collect_candidate_files() {
  CANDIDATE_FILES=()
  local f=""
  while IFS= read -r -d '' f; do CANDIDATE_FILES+=("$f"); done < <(
    find "$REPO_ROOT/k3s" -type f \( -name '*.yaml' -o -name '*.yml' \) -print0 2>/dev/null
  )
  while IFS= read -r -d '' f; do CANDIDATE_FILES+=("$f"); done < <(
    find "$REPO_ROOT/it/src/test/java" -type f -name '*.java' -print0 2>/dev/null
  )
  while IFS= read -r -d '' f; do CANDIDATE_FILES+=("$f"); done < <(
    find "$REPO_ROOT/doc/scripts" -type f -name '*.sh' -print0 2>/dev/null
  )
  if [[ "$INCLUDE_DOCS" -eq 1 ]]; then
    while IFS= read -r -d '' f; do CANDIDATE_FILES+=("$f"); done < <(
      find "$REPO_ROOT/doc" -type f \( -name '*.md' -o -name '*.drawio' \) -print0 2>/dev/null
    )
  fi
}

scan_findings() {
  NIP_FILES=()
  PLACEHOLDER_FILES=()
  local f=""
  for f in "${CANDIDATE_FILES[@]}"; do
    if grep -q '127\.0\.0\.1\.nip\.io' "$f" 2>/dev/null; then
      NIP_FILES+=("$f")
    fi
    if grep -q '{INTERNAL_IP}' "$f" 2>/dev/null; then
      PLACEHOLDER_FILES+=("$f")
    fi
  done
}

print_findings() {
  local has_skip_run="no"
  local has_skip_apply="no"
  grep -q '<k3s.skipRun>true</k3s.skipRun>' "$POM_FILE" && has_skip_run="yes"
  grep -q '<k3s.skipApply>true</k3s.skipApply>' "$POM_FILE" && has_skip_apply="yes"

  echo "=== Native k3s migration report ==="
  echo "Repo                : $REPO_ROOT"
  echo "POM                 : $POM_FILE"
  echo "Detected INTERNAL_IP: $TARGET_IP"
  echo "Candidate files     : ${#CANDIDATE_FILES[@]}"
  echo "Files with 127...   : ${#NIP_FILES[@]}"
  echo "Files with placeholder {INTERNAL_IP}: ${#PLACEHOLDER_FILES[@]}"
  echo "pom has k3s.skipRun : $has_skip_run"
  echo "pom has k3s.skipApply: $has_skip_apply"
  echo
  echo "Planned actions:"
  echo "1) Upsert <k3s.skipRun>true</k3s.skipRun> and <k3s.skipApply>true</k3s.skipApply> in pom.xml"
  echo "2) Replace 127.0.0.1.nip.io -> {INTERNAL_IP}.nip.io in candidate files"
  echo "3) Replace {INTERNAL_IP} -> $TARGET_IP in candidate files"
  echo "3b) Rewrite demo domains to internal nip.io hosts (keep did:web:* unchanged):"
  echo "    - verifier.mp-operations.org -> verifier.$TARGET_IP.nip.io"
  echo "    - mp-operations.org -> marketplace.$TARGET_IP.nip.io"
  echo "    - fancy-marketplace.biz -> fancy-marketplace.$TARGET_IP.nip.io"
  if [[ "$SKIP_K3S_INSTALL" -eq 1 ]]; then
    echo "4) Skip native k3s install/start (--skip-k3s-install set)"
  else
    echo "4) Ensure k3s is installed and running as system service"
    echo "   - install via: curl -sfL https://get.k3s.io | sh -   (when missing)"
    echo "   - ensure kubeconfig at \$HOME/.kube/config for current user"
  fi
  echo "5) Run: mvn -f \"$POM_FILE\" clean deploy -Plocal -Dhelm.version=3.20.2   (logs go to build.log)"
  if [[ "$SKIP_APPLY" -eq 1 ]]; then
    echo "6) Skip kubectl apply (--skip-apply set)"
  else
    echo "6) Run kubectl apply in target/k3s (ordered infra + full tree)"
  fi
  if [[ "$DEPLOY_URL_PORTAL" -eq 1 ]]; then
    echo "7) Deploy DSC URL portal (DataspaceFontys) and print portal URL"
  else
    echo "7) Skip DSC URL portal deployment (--skip-url-portal set)"
  fi
  echo "==================================="
}

confirm_or_exit() {
  if [[ "$FORCE_YES" -eq 1 ]]; then
    return 0
  fi
  local answer=""
  read -r -p "Proceed with these changes on the repository? [y/N]: " answer
  case "$answer" in
    y|Y|yes|YES) ;;
    *) echo "Cancelled by user."; exit 0 ;;
  esac
}

upsert_pom_property() {
  local key="$1"
  local value="$2"
  if grep -q "<${key}>.*</${key}>" "$POM_FILE"; then
    sed -i -E "s|<${key}>.*</${key}>|<${key}>${value}</${key}>|g" "$POM_FILE"
  else
    sed -i -E "0,/<\/properties>/s|</properties>|        <${key}>${value}</${key}>\n    </properties>|" "$POM_FILE"
  fi
}

rewrite_hosts() {
  local f=""
  for f in "${CANDIDATE_FILES[@]}"; do
    sed -i 's/127\.0\.0\.1\.nip\.io/{INTERNAL_IP}.nip.io/g' "$f"
    sed -i "s/{INTERNAL_IP}/$TARGET_IP/g" "$f"
  done
}

rewrite_demo_domains() {
  local f=""
  local marketplace_host="marketplace.${TARGET_IP}.nip.io"
  local verifier_host="verifier.${TARGET_IP}.nip.io"
  local fancy_host="fancy-marketplace.${TARGET_IP}.nip.io"

  # Protect did:web:* identifiers (they should remain stable).
  for f in "${CANDIDATE_FILES[@]}"; do
    sed -i 's/did:web:mp-operations\.org/did:web:__MP_OPS__/g' "$f"
    sed -i 's/did:web:fancy-marketplace\.biz/did:web:__FANCY__/g' "$f"

    # verifier.mp-operations.org
    sed -i "s#https://verifier\.mp-operations\.org#https://${verifier_host}#g" "$f"
    sed -i "s#http://verifier\.mp-operations\.org#http://${verifier_host}#g" "$f"
    sed -i "s/verifier\.mp-operations\.org/${verifier_host}/g" "$f"

    # mp-operations.org (marketplace host)
    sed -i "s#https://mp-operations\.org#https://${marketplace_host}#g" "$f"
    sed -i "s#http://mp-operations\.org#http://${marketplace_host}#g" "$f"
    sed -i "s/mp-operations\.org/${marketplace_host}/g" "$f"

    # fancy-marketplace.biz (consumer demo host)
    sed -i "s#https://fancy-marketplace\.biz#https://${fancy_host}#g" "$f"
    sed -i "s#http://fancy-marketplace\.biz#http://${fancy_host}#g" "$f"
    sed -i "s/fancy-marketplace\.biz/${fancy_host}/g" "$f"

    # Restore did:web:* identifiers.
    sed -i 's/did:web:__MP_OPS__/did:web:mp-operations.org/g' "$f"
    sed -i 's/did:web:__FANCY__/did:web:fancy-marketplace.biz/g' "$f"
  done
}

k3s_service_exists() {
  command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -q '^k3s\.service'
}

ensure_k3s_and_kubeconfig() {
  if [[ "$SKIP_K3S_INSTALL" -eq 1 ]]; then
    echo "Skipping k3s install/start checks (--skip-k3s-install)."
    return 0
  fi

  need_cmd curl
  need_cmd kubectl
  need_cmd sudo

  if ! k3s_service_exists; then
    echo "k3s.service not found. Installing native k3s..."
    curl -sfL https://get.k3s.io | sudo sh -
  fi

  echo "Ensuring k3s service is enabled and running..."
  sudo systemctl enable k3s >/dev/null 2>&1 || true
  sudo systemctl start k3s

  echo
  echo "=== k3s install/start status ==="
  sudo systemctl status k3s --no-pager || true

  if [[ ! -f /etc/rancher/k3s/k3s.yaml ]]; then
    echo "error: /etc/rancher/k3s/k3s.yaml not found after k3s start" >&2
    exit 1
  fi

  mkdir -p "$HOME/.kube"
  sudo cp /etc/rancher/k3s/k3s.yaml "$HOME/.kube/config"
  sudo chown "$USER:$USER" "$HOME/.kube/config"
  chmod 600 "$HOME/.kube/config"
  export KUBECONFIG="$HOME/.kube/config"

  # Persist kubeconfig for interactive kubectl usage after the script finishes.
  local bashrc="$HOME/.bashrc"
  local kc_marker_begin="# >>> kubectl-kubeconfig (added by prepare-native-k3s-server.sh) >>>"
  local kc_marker_end="# <<< kubectl-kubeconfig <<<"
  if [[ ! -f "$bashrc" ]]; then
    touch "$bashrc"
  fi
  if ! grep -qF "$kc_marker_begin" "$bashrc" 2>/dev/null; then
    cat >>"$bashrc" <<'EOF'

# >>> kubectl-kubeconfig (added by prepare-native-k3s-server.sh) >>>
export KUBECONFIG="$HOME/.kube/config"
# <<< kubectl-kubeconfig <<<
EOF
  fi

  echo
  echo "=== waiting for positive k3s readiness ==="
  local max_tries=18
  local try=1
  local ready=0
  while [[ "$try" -le "$max_tries" ]]; do
    if kubectl --kubeconfig="$KUBECONFIG" get nodes 2>/dev/null | awk 'NR>1 {if ($2=="Ready") ok=1} END {exit(ok?0:1)}'; then
      ready=1
      break
    fi
    echo "k3s not ready yet (attempt $try/$max_tries), retrying in 10s..."
    sleep 10
    try=$((try + 1))
  done

  if [[ "$ready" -ne 1 ]]; then
    echo "error: k3s did not become Ready in expected time." >&2
    echo "--- recent k3s logs ---"
    sudo journalctl -u k3s -n 80 --no-pager || true
    exit 1
  fi

  echo
  echo "=== positive k3s readiness confirmed ==="
  kubectl --kubeconfig="$KUBECONFIG" cluster-info
  kubectl --kubeconfig="$KUBECONFIG" get nodes
  echo
  echo "KUBECONFIG persisted in: $bashrc"
  echo "To activate in your current shell:"
  echo "  source $bashrc"
  echo "k3s is healthy. Continuing with Maven deploy and kubectl apply..."
}

install_headlamp() {
  if [[ "$SKIP_HEADLAMP" -eq 1 ]]; then
    echo "Skipping Headlamp install/config (--skip-headlamp)."
    return 0
  fi

  need_cmd helm
  need_cmd kubectl

  if [[ -z "${KUBECONFIG:-}" && -f "$HOME/.kube/config" ]]; then
    export KUBECONFIG="$HOME/.kube/config"
  fi
  if [[ -z "${KUBECONFIG:-}" ]]; then
    echo "error: KUBECONFIG is not set; cannot install Headlamp." >&2
    exit 1
  fi

  echo
  echo "=== Installing Headlamp (Kubernetes UI) ==="
  helm repo add headlamp https://kubernetes-sigs.github.io/headlamp/ >/dev/null 2>&1 || true
  helm repo update >/dev/null 2>&1 || true

  local release="my-headlamp"
  local ns="kube-system"

  # Use upgrade --install to be idempotent.
  helm upgrade --install "$release" headlamp/headlamp --namespace "$ns"

  # Ensure NodePort so it's reachable from outside the node.
  kubectl --kubeconfig="$KUBECONFIG" -n "$ns" patch service "$release" -p '{"spec":{"type":"NodePort"}}' >/dev/null

  # Ensure the serviceaccount exists and has permissions for UI access.
  if ! kubectl --kubeconfig="$KUBECONFIG" -n "$ns" get sa "$release" >/dev/null 2>&1; then
    kubectl --kubeconfig="$KUBECONFIG" -n "$ns" create serviceaccount "$release" >/dev/null
  fi
  kubectl --kubeconfig="$KUBECONFIG" create clusterrolebinding "${release}-admin" \
    --clusterrole=cluster-admin \
    --serviceaccount="${ns}:${release}" >/dev/null 2>&1 || true

  # Determine the chosen NodePort and print clear access instructions.
  local node_port=""
  node_port="$(kubectl --kubeconfig="$KUBECONFIG" -n "$ns" get svc "$release" -o jsonpath='{.spec.ports[0].nodePort}' 2>/dev/null || true)"
  HEADLAMP_NODEPORT="$node_port"
  if [[ -n "$HEADLAMP_NODEPORT" ]]; then
    HEADLAMP_URL="http://${TARGET_IP}:${HEADLAMP_NODEPORT}"
  else
    HEADLAMP_URL=""
  fi

  # Add convenience function to the user's interactive shell.
  local bashrc="$HOME/.bashrc"
  local fn_marker_begin="# >>> headlamp-token (added by prepare-native-k3s-server.sh) >>>"
  local fn_marker_end="# <<< headlamp-token <<<"
  if [[ ! -f "$bashrc" ]]; then
    touch "$bashrc"
  fi
  if ! grep -qF "$fn_marker_begin" "$bashrc" 2>/dev/null; then
    cat >>"$bashrc" <<EOF

$fn_marker_begin
headlamp-token() {
  KUBECONFIG="\${KUBECONFIG:-\$HOME/.kube/config}" kubectl create token ${release} --namespace ${ns}
}
$fn_marker_end
EOF
  else
    # If an older version was installed, update it in-place.
    sed -i -E "s|sudo[[:space:]]+kubectl[[:space:]]+create[[:space:]]+token[[:space:]]+${release}[[:space:]]+--namespace[[:space:]]+${ns}|KUBECONFIG=\"\\\${KUBECONFIG:-\\\$HOME/.kube/config}\" kubectl create token ${release} --namespace ${ns}|g" "$bashrc" >/dev/null 2>&1 || true
  fi

  echo
  echo "Headlamp is installed."
  if [[ -n "$HEADLAMP_NODEPORT" ]]; then
    echo "Headlamp NodePort: $HEADLAMP_NODEPORT"
    echo "Open: $HEADLAMP_URL"
  else
    echo "warning: could not determine Headlamp NodePort automatically. Run:"
    echo "  kubectl -n $ns get svc $release -o wide"
  fi
  echo
  echo "Headlamp token function added to: $bashrc"
  echo "To activate in your current shell (or open a new terminal):"
  echo "  source $bashrc"
  echo "Then get a token with:"
  echo "  headlamp-token"
  echo "========================================="
}

build_manifests() {
  if [[ "$SKIP_BUILD" -eq 1 ]]; then
    echo "Skipping Maven build (--skip-build)."
    return 0
  fi
  need_cmd mvn
  mvn -f "$POM_FILE" clean deploy -Plocal -Dhelm.version=3.20.2
}

apply_manifests() {
  if [[ "$SKIP_APPLY" -eq 1 ]]; then
    echo "Skipping kubectl apply (--skip-apply)."
    return 0
  fi
  need_cmd kubectl
  if [[ -z "${KUBECONFIG:-}" && -f "$HOME/.kube/config" ]]; then
    export KUBECONFIG="$HOME/.kube/config"
  fi
  if [[ -z "${KUBECONFIG:-}" ]]; then
    echo "error: KUBECONFIG is not set. Export KUBECONFIG or run without --skip-k3s-install." >&2
    exit 1
  fi
  kubectl --kubeconfig="$KUBECONFIG" cluster-info >/dev/null
  local k3s_dir="$REPO_ROOT/target/k3s"
  if [[ ! -d "$k3s_dir" ]]; then
    echo "error: $k3s_dir not found (build likely failed or was skipped)." >&2
    exit 1
  fi

  wait_for_crd_established() {
    local crd_name="$1"
    local timeout_sec="${2:-300}"
    local try=1
    local max_tries=30
    while [[ "$try" -le "$max_tries" ]]; do
      if kubectl --kubeconfig="$KUBECONFIG" get crd "$crd_name" >/dev/null 2>&1; then
        kubectl --kubeconfig="$KUBECONFIG" wait --for=condition=Established "crd/$crd_name" --timeout="${timeout_sec}s" >/dev/null
        return 0
      fi
      echo "Waiting for CRD $crd_name (attempt $try/$max_tries)..."
      sleep 5
      try=$((try + 1))
    done
    echo "error: CRD $crd_name not available in time" >&2
    return 1
  }

  wait_for_cert_manager_webhook() {
    echo "Waiting for cert-manager webhook deployment..."
    kubectl --kubeconfig="$KUBECONFIG" -n cert-manager wait deploy/cert-manager-webhook --for=condition=Available --timeout=300s
    local try=1
    local max_tries=30
    while [[ "$try" -le "$max_tries" ]]; do
      if kubectl --kubeconfig="$KUBECONFIG" -n cert-manager get endpoints cert-manager-webhook -o jsonpath='{.subsets[0].addresses[0].ip}' 2>/dev/null | grep -qE '^[0-9]'; then
        echo "cert-manager-webhook endpoints are available."
        return 0
      fi
      echo "Waiting for cert-manager-webhook endpoints (attempt $try/$max_tries)..."
      sleep 5
      try=$((try + 1))
    done
    echo "error: cert-manager-webhook has no endpoints in time" >&2
    return 1
  }

  retry_apply_tree() {
    local path="$1"
    local tries="${2:-3}"
    local n=1
    while [[ "$n" -le "$tries" ]]; do
      if kubectl --kubeconfig="$KUBECONFIG" apply -f "$path" --recursive; then
        return 0
      fi
      echo "kubectl apply failed for $path (attempt $n/$tries), retrying in 10s..."
      sleep 10
      n=$((n + 1))
    done
    return 1
  }

  kubectl --kubeconfig="$KUBECONFIG" apply -f "$k3s_dir/namespaces" --recursive
  kubectl --kubeconfig="$KUBECONFIG" apply -f "$k3s_dir/infra/mongo-operator" --recursive
  if [[ -f "$k3s_dir/infra/operatorconfigurations.yaml" ]]; then
    kubectl --kubeconfig="$KUBECONFIG" apply -f "$k3s_dir/infra/operatorconfigurations.yaml"
  fi
  kubectl --kubeconfig="$KUBECONFIG" apply -f "$k3s_dir/infra/postgres-operator" --recursive
  wait_for_crd_established "postgresqls.acid.zalan.do" 300
  kubectl --kubeconfig="$KUBECONFIG" apply -f "$k3s_dir/infra/cert-manager" --recursive
  wait_for_crd_established "certificates.cert-manager.io" 300
  wait_for_cert_manager_webhook
  retry_apply_tree "$k3s_dir" 3
}

fix_marketplace_did_ingress_conflict() {
  # After rewriting mp-operations.org -> marketplace.<IP>.nip.io, the DID helper ingress may collide
  # with the marketplace root (both using host marketplace.* and path /). Ensure DID only serves
  # /.well-known/* so the marketplace portal remains reachable at /.
  if [[ "$SKIP_APPLY" -eq 1 ]]; then
    return 0
  fi
  need_cmd kubectl
  if [[ -z "${KUBECONFIG:-}" && -f "$HOME/.kube/config" ]]; then
    export KUBECONFIG="$HOME/.kube/config"
  fi
  if [[ -z "${KUBECONFIG:-}" ]]; then
    return 0
  fi

  local ns="provider"
  local did_ing="provider-did"
  local host path
  host="$(kubectl --kubeconfig="$KUBECONFIG" -n "$ns" get ingress "$did_ing" -o jsonpath='{.spec.rules[0].host}' 2>/dev/null || true)"
  path="$(kubectl --kubeconfig="$KUBECONFIG" -n "$ns" get ingress "$did_ing" -o jsonpath='{.spec.rules[0].http.paths[0].path}' 2>/dev/null || true)"
  if [[ -z "$host" || -z "$path" ]]; then
    return 0
  fi

  if [[ "$host" == marketplace.* && "$path" == "/" ]]; then
    echo
    echo "=== Fixing marketplace ingress conflict (provider-did) ==="
    echo "Detected $ns/$did_ing at host=$host path=/; patching to /.well-known/ ..."
    kubectl --kubeconfig="$KUBECONFIG" -n "$ns" patch ingress "$did_ing" --type=json \
      -p='[{"op":"replace","path":"/spec/rules/0/http/paths/0/path","value":"/.well-known/"}]' >/dev/null
    echo "Patched $ns/$did_ing to path /.well-known/."
  fi
}

fix_vcverifier_no_proxy_for_marketplace() {
  # The demo enables a Squid proxy for verifier egress to support did:web resolution for
  # "real" domains. In the internal nip.io setup, the verifier must fetch the request object
  # from the marketplace host directly (request_uri=https://marketplace.<IP>.nip.io/auth/vc/request.jwt).
  # If the proxy is used, the CONNECT may be blocked or resolution may fail.
  if [[ "$SKIP_APPLY" -eq 1 ]]; then
    return 0
  fi
  need_cmd kubectl
  if [[ -z "${KUBECONFIG:-}" && -f "$HOME/.kube/config" ]]; then
    export KUBECONFIG="$HOME/.kube/config"
  fi
  if [[ -z "${KUBECONFIG:-}" ]]; then
    return 0
  fi

  local ns="provider"
  local deploy="verifier"
  if ! kubectl --kubeconfig="$KUBECONFIG" -n "$ns" get deploy "$deploy" >/dev/null 2>&1; then
    return 0
  fi

  local marketplace_host="marketplace.${TARGET_IP}.nip.io"
  local current_np
  current_np="$(kubectl --kubeconfig="$KUBECONFIG" -n "$ns" get deploy "$deploy" -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="NO_PROXY")].value}' 2>/dev/null || true)"
  if [[ "$current_np" == *"$marketplace_host"* ]]; then
    return 0
  fi

  local desired_np=""
  if [[ -n "$current_np" ]]; then
    desired_np="${current_np},${marketplace_host},.nip.io,${TARGET_IP}"
  else
    desired_np="credentials-config-service,w3.org,trusted-issuers-list,${marketplace_host},.nip.io,${TARGET_IP}"
  fi

  echo
  echo "=== Fixing verifier NO_PROXY for marketplace ==="
  echo "Ensuring $ns/$deploy bypasses proxy for: $marketplace_host"

  # Try to replace existing NO_PROXY first; if absent, append a new env var.
  if kubectl --kubeconfig="$KUBECONFIG" -n "$ns" get deploy "$deploy" -o json | grep -q '"name":"NO_PROXY"'; then
    kubectl --kubeconfig="$KUBECONFIG" -n "$ns" patch deploy "$deploy" --type=json \
      -p="[
        {\"op\":\"replace\",\"path\":\"/spec/template/spec/containers/0/env\",\"value\":$(kubectl --kubeconfig=\"$KUBECONFIG\" -n \"$ns\" get deploy \"$deploy\" -o jsonpath='{.spec.template.spec.containers[0].env}' | python3 -c 'import json,sys; env=json.loads(sys.stdin.read());\nfor e in env:\n  if e.get(\"name\")==\"NO_PROXY\":\n    e[\"value\"]=sys.argv[1]\nprint(json.dumps(env))' \"$desired_np\") }
      ]" >/dev/null 2>&1 || true
  else
    kubectl --kubeconfig="$KUBECONFIG" -n "$ns" set env deploy/"$deploy" NO_PROXY="$desired_np" >/dev/null 2>&1 || true
  fi

  kubectl --kubeconfig="$KUBECONFIG" -n "$ns" rollout restart deploy/"$deploy" >/dev/null 2>&1 || true
  echo "Verifier updated; it should now resolve request_uri without proxy issues."
}

deploy_url_portal() {
  if [[ "$DEPLOY_URL_PORTAL" -ne 1 ]]; then
    echo "Skipping DSC URL portal deployment (--skip-url-portal)."
    return 0
  fi
  need_cmd git
  need_cmd kubectl

  echo
  echo "=== Deploying DSC URL portal ==="
  if [[ -d "$PORTAL_DIR/.git" ]]; then
    (cd "$PORTAL_DIR" && git pull --ff-only) || true
  else
    git clone "$PORTAL_REPO_URL" "$PORTAL_DIR"
  fi

  local kpath="$PORTAL_DIR/$PORTAL_KUSTOMIZE_PATH"
  if [[ ! -d "$kpath" ]]; then
    echo "error: portal kustomize path not found: $kpath" >&2
    return 1
  fi
  kubectl apply -k "$kpath"
  kubectl -n kube-system rollout status deploy/ingress-url-portal --timeout=180s || true
  echo "Portal URL: http://${TARGET_IP}:30091/"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo)
      [[ $# -gt 1 ]] || { echo "error: --repo requires a value" >&2; exit 1; }
      REPO_ROOT="$2"
      REPO_PROVIDED=1
      shift 2
      ;;
    --clone) DO_CLONE=1; shift ;;
    --ip)
      [[ $# -gt 1 ]] || { echo "error: --ip requires a value" >&2; exit 1; }
      IP_ARG="$2"
      shift 2
      ;;
    --yes) FORCE_YES=1; shift ;;
    --include-docs) INCLUDE_DOCS=1; shift ;;
    --skip-k3s-install) SKIP_K3S_INSTALL=1; shift ;;
    --skip-headlamp) SKIP_HEADLAMP=1; shift ;;
    --skip-url-portal) DEPLOY_URL_PORTAL=0; shift ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    --skip-apply) SKIP_APPLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "error: unknown option $1" >&2
      usage
      exit 1
      ;;
  esac
done

# Convenience: if run without --repo in a directory without pom.xml, auto-clone.
if [[ "$DO_CLONE" -ne 1 && "$REPO_PROVIDED" -eq 0 && ! -f "$REPO_ROOT/pom.xml" ]]; then
  DO_CLONE=1
fi

if [[ "$DO_CLONE" -eq 1 ]]; then
  clone_repo_if_requested
fi

discover_repo
setup_logging
discover_pom
collect_candidate_files
scan_findings
TARGET_IP="$(detect_ipv4)"
print_findings
confirm_or_exit

cp "$POM_FILE" "$POM_FILE.bak.$(date +%Y%m%d%H%M%S)"
upsert_pom_property "k3s.skipRun" "true"
upsert_pom_property "k3s.skipApply" "true"
rewrite_hosts
rewrite_demo_domains
ensure_k3s_and_kubeconfig
install_headlamp
build_manifests
apply_manifests
fix_marketplace_did_ingress_conflict
fix_vcverifier_no_proxy_for_marketplace
deploy_url_portal

echo
echo "Done."
echo "Native k3s migration/deploy actions completed for: $REPO_ROOT"
if [[ -n "${HEADLAMP_URL:-}" ]]; then
  echo
  echo "========================================="
  echo "HEADLAMP URL"
  echo "$HEADLAMP_URL"
  echo "Token (after: source ~/.bashrc): headlamp-token"
  echo "========================================="
fi

if [[ "$DEPLOY_URL_PORTAL" -eq 1 ]]; then
  echo
  echo "========================================="
  echo "DSC URL PORTAL"
  echo "http://${TARGET_IP}:30091/"
  echo "========================================="
fi

echo
echo "========================================="
echo "TLS TRUST (recommended for browsers)"
echo "This deployment uses a local self-signed CA via cert-manager."
echo "Export the CA cert on the k3s node:"
echo "  kubectl -n cert-manager get secret ca-secret -o jsonpath='{.data.tls\\.crt}' | base64 -d > dsconnector-ca.crt"
echo
echo "Install CA cert on your client machine to avoid 'Failed to fetch' / ERR_CERT_AUTHORITY_INVALID:"
echo "- Linux (Debian/Ubuntu): sudo cp dsconnector-ca.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates"
echo "- Windows (Admin PowerShell/CMD): certutil -addstore -f Root dsconnector-ca.crt"
echo "========================================="
