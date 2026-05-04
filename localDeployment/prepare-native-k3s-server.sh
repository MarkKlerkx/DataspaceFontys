#!/usr/bin/env bash
#
# One-shot migration/deploy helper:
# 1) Scan repository and report findings
# 2) Ask for explicit confirmation
# 3) Patch pom.xml for native host k3s (skip docker run/apply in k3s plugin)
# 4) Replace 127.0.0.1.nip.io with {INTERNAL_IP}.nip.io
# 5) Replace {INTERNAL_IP} with detected/provided server IP
# 6) Build/deploy and apply manifests with host kubectl
#
# Usage:
#   ./prepare-native-k3s-server.sh --repo /path/to/repo
#   ./prepare-native-k3s-server.sh --repo /path --ip 172.20.10.15 --yes
#
set -euo pipefail

REPO_ROOT="$(pwd)"
FORCE_YES=0
INCLUDE_DOCS=0
SKIP_BUILD=0
SKIP_APPLY=0
IP_ARG=""

POM_FILE=""
TARGET_IP=""

declare -a CANDIDATE_FILES=()
declare -a NIP_FILES=()
declare -a PLACEHOLDER_FILES=()

usage() {
  cat <<'EOF'
Usage:
  prepare-native-k3s-server.sh [options]

Options:
  --repo <path>       Repository root (default: current directory)
  --ip <address>      Internal server IP to materialize
  --yes               Skip confirmation prompt
  --include-docs      Also update doc/**/*.md and doc/**/*.drawio
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
  echo "4) Run: mvn -f \"$POM_FILE\" clean package -Plocal"
  if [[ "$SKIP_APPLY" -eq 1 ]]; then
    echo "5) Skip kubectl apply (--skip-apply set)"
  else
    echo "5) Run kubectl apply in target/k3s (ordered infra + full tree)"
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

build_manifests() {
  if [[ "$SKIP_BUILD" -eq 1 ]]; then
    echo "Skipping Maven build (--skip-build)."
    return 0
  fi
  need_cmd mvn
  mvn -f "$POM_FILE" clean deploy -Plocal -Dhelm.version=3.20.2 2>&1 | tee "$REPO_ROOT/build.log"
}

apply_manifests() {
  if [[ "$SKIP_APPLY" -eq 1 ]]; then
    echo "Skipping kubectl apply (--skip-apply)."
    return 0
  fi
  need_cmd kubectl
  local k3s_dir="$REPO_ROOT/target/k3s"
  if [[ ! -d "$k3s_dir" ]]; then
    echo "error: $k3s_dir not found (build likely failed or was skipped)." >&2
    exit 1
  fi
  kubectl apply -f "$k3s_dir/namespaces" --recursive
  kubectl apply -f "$k3s_dir/infra/mongo-operator" --recursive
  if [[ -f "$k3s_dir/infra/operatorconfigurations.yaml" ]]; then
    kubectl apply -f "$k3s_dir/infra/operatorconfigurations.yaml"
  fi
  kubectl apply -f "$k3s_dir/infra/postgres-operator" --recursive
  kubectl apply -f "$k3s_dir/infra/cert-manager" --recursive
  kubectl apply -f "$k3s_dir" --recursive
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo)
      [[ $# -gt 1 ]] || { echo "error: --repo requires a value" >&2; exit 1; }
      REPO_ROOT="$2"
      shift 2
      ;;
    --ip)
      [[ $# -gt 1 ]] || { echo "error: --ip requires a value" >&2; exit 1; }
      IP_ARG="$2"
      shift 2
      ;;
    --yes) FORCE_YES=1; shift ;;
    --include-docs) INCLUDE_DOCS=1; shift ;;
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

discover_repo
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
build_manifests
apply_manifests

echo
echo "Done."
echo "Native k3s migration/deploy actions completed for: $REPO_ROOT"
