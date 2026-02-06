#!/usr/bin/env bash

if [ -z "${BASH_VERSION:-}" ]; then
  echo "ERROR: this script must be run with bash (e.g. ./socnet/start_socnet.sh)." >&2
  exit 1
fi
if [ "${BASH_VERSINFO[0]:-0}" -lt 4 ]; then
  echo "ERROR: bash 4+ is required. Detected: ${BASH_VERSION}." >&2
  exit 1
fi

set -eu
set -o pipefail

export PATH="/opt/fabric-dev/tools-fabric-3/fabric-samples/bin:$PATH"
export FABRIC_CFG_PATH="/opt/fabric-dev/config"
export CORE_PEER_TLS_ENABLED=true

# -----------------------------
# Config (edit if needed)
# -----------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOCNET_DIR="$SCRIPT_DIR"
COMPOSE_DIR="$SOCNET_DIR/compose"
CONFIGTX_DIR="$SOCNET_DIR/configtx"
CONFIGTX_FILE="$CONFIGTX_DIR/configtx.yaml"
CC_DIR="$SOCNET_DIR/chaincode/lognotary"

CHANNEL="soclogs"
CC_NAME="lognotary"
CC_LABEL="lognotary_1.0"
CC_VERSION="1.0"
CC_SEQUENCE="1"
INIT_REQUIRED="false"
CC_IMAGE="lognotary-ccaas:1.0"
CC_CONTAINER="lognotary-ccaas"
CC_LISTEN_ADDR="0.0.0.0:9999"
CC_PEER_ADDR="${CC_CONTAINER}:9999"

PKG_DIR="$SOCNET_DIR/ccaas-pkg/$CC_NAME"
PKG_FILE="$PKG_DIR/$CC_LABEL.tgz"
CODE_TAR="$PKG_DIR/code.tar.gz"

FABRIC_DEV_ROOT="$(cd "$SOCNET_DIR/.." && pwd)"
FABRIC_BIN_DIR="/opt/fabric-dev/tools-fabric-3/fabric-samples/bin"

NETWORK="socnet"

CRYPTO_ROOT=""
ORG1_TLS_CA=""
ORG2_TLS_CA=""
ORG2_PEER_TLS_ROOTCERT_FILE="/opt/fabric-dev/socnet/crypto-config/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt"
CONFIGTX_RUNTIME_DIR=""
CHANNEL_PROFILE="SocChannel"

# -----------------------------
# Helpers
# -----------------------------
log() { echo -e "\n[+] $*\n"; }

set_peer_org1() {
  export CORE_PEER_LOCALMSPID="Org1MSP"
  export CORE_PEER_MSPCONFIGPATH="/opt/fabric-dev/socnet/crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp"
  export CORE_PEER_ADDRESS="peer0.org1.example.com:7051"
  export CORE_PEER_TLS_ROOTCERT_FILE="/opt/fabric-dev/socnet/crypto-config/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
}

set_peer_org2() {
  export CORE_PEER_LOCALMSPID="Org2MSP"
  export CORE_PEER_MSPCONFIGPATH="/opt/fabric-dev/socnet/crypto-config/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp"
  export CORE_PEER_ADDRESS="peer0.org2.example.com:9051"
  export CORE_PEER_TLS_ROOTCERT_FILE="/opt/fabric-dev/socnet/crypto-config/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt"
}

fatal() {
  echo "ERROR: $*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || fatal "missing command: $1"
}

detect_crypto_root() {
  local global_crypto_root="/opt/fabric-dev/crypto-config"
  local repo_socnet_crypto_root="$FABRIC_DEV_ROOT/socnet/crypto-config"

  if [[ -d "$global_crypto_root" ]]; then
    CRYPTO_ROOT="$global_crypto_root"
  elif [[ -d "$repo_socnet_crypto_root" ]]; then
    CRYPTO_ROOT="$repo_socnet_crypto_root"
  else
    fatal "No crypto-config directory found. Checked '$global_crypto_root' and '$repo_socnet_crypto_root'. Run cryptogen or place crypto material in one of these locations."
  fi

  ORG1_TLS_CA="$CRYPTO_ROOT/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
  ORG2_TLS_CA="$CRYPTO_ROOT/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt"
  ORG2_PEER_TLS_ROOTCERT_FILE="$ORG2_TLS_CA"
}

ensure_hosts() {
  # Keep cert hostnames resolvable; only required for WSL-based local Docker usage.
  if ! grep -qi microsoft /proc/version 2>/dev/null; then
    return
  fi

  if grep -q "peer0.org1.example.com" /etc/hosts; then
    log "WSL hosts already configured"
    return
  fi

  log "WSL detected. Adding Fabric hostnames to /etc/hosts"
  local host_line="127.0.0.1 orderer.example.com peer0.org1.example.com peer0.org2.example.com"

  if [[ -w /etc/hosts ]]; then
    echo "$host_line" >> /etc/hosts
  elif command -v sudo >/dev/null 2>&1; then
    sudo bash -c "echo '$host_line' >> /etc/hosts"
  else
    echo "WARN: unable to update /etc/hosts automatically (no write permission and no sudo)."
  fi
}

start_fabric() {
  log "Starting Fabric containers (docker compose up -d)"
  cd "$COMPOSE_DIR"
  docker compose up -d
  docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Networks}}\t{{.Ports}}" | egrep "orderer\.example\.com|peer0\.org1\.example\.com|peer0\.org2\.example\.com" || true
}

source_org1() {
  set_peer_org1
  export ORDERER_CA="/opt/fabric-dev/socnet/crypto-config/ordererOrganizations/example.com/orderers/orderer.example.com/tls/ca.crt"
}

source_org2() {
  set_peer_org2
  export ORDERER_CA="/opt/fabric-dev/socnet/crypto-config/ordererOrganizations/example.com/orderers/orderer.example.com/tls/ca.crt"
}

get_pkg_id() {
  source_org1 >/dev/null 2>&1 || true
  peer lifecycle chaincode queryinstalled 2>/dev/null \
    | awk -v lbl="$CC_LABEL" '
      $0 ~ "Package ID:" && $0 ~ "Label: "lbl {
        sub(/^Package ID: /,"");
        split($0,a,",");
        print a[1];
        exit
      }'
}

package_chaincode() {
  mkdir -p "$PKG_DIR"
  tar -C "$PKG_DIR" -czf "$CODE_TAR" connection.json
  tar -C "$PKG_DIR" -czf "$PKG_FILE" metadata.json "$(basename "$CODE_TAR")"
}

is_installed_for_current_org() {
  peer lifecycle chaincode queryinstalled 2>/dev/null | grep -q "Label: $CC_LABEL"
}

install_for_current_org() {
  local output
  if output=$(peer lifecycle chaincode install "$PKG_FILE" 2>&1); then
    echo "$output"
    return 0
  fi

  if grep -q "already successfully installed" <<<"$output"; then
    echo "$output"
    return 0
  fi

  echo "$output"
  return 1
}

is_approved_for_current_org() {
  peer lifecycle chaincode queryapproved -C "$CHANNEL" -n "$CC_NAME" 2>/dev/null \
    | grep -q "sequence: $CC_SEQUENCE"
}

is_committed() {
  peer lifecycle chaincode querycommitted -C "$CHANNEL" -n "$CC_NAME" 2>/dev/null \
    | grep -q "Version: $CC_VERSION, Sequence: $CC_SEQUENCE"
}

ensure_peer_joined_channel() {
  local channel="$1"
  peer channel list | grep -q "$channel" || {
    echo "❌ Peer is NOT joined to channel '$channel'"
    peer channel list
    exit 1
  }
}

ensure_channel_soclogs() {
  local orderer_join_block="/tmp/${CHANNEL}.block"
  local peer_genesis_block="/tmp/soclogs_genesis.block"
  local orderer_tls_ca orderer_admin_tls_dir
  local admin_ready_attempts=30
  local admin_ready_sleep=2
  local channel_ready_attempts=20
  local channel_ready_sleep=2

  command -v configtxgen >/dev/null 2>&1 || fatal "configtxgen not found (Fabric binaries not installed or not in PATH)"
  command -v osnadmin >/dev/null 2>&1 || fatal "osnadmin not found (Fabric binaries not installed or not in PATH)"
  detect_crypto_root

  orderer_tls_ca="$CRYPTO_ROOT/ordererOrganizations/example.com/orderers/orderer.example.com/tls/ca.crt"
  orderer_admin_tls_dir="$CRYPTO_ROOT/ordererOrganizations/example.com/users/Admin@example.com/tls"

  [[ -f "$orderer_tls_ca" ]] || fatal "orderer TLS CA not found at $orderer_tls_ca"
  [[ -d "$orderer_admin_tls_dir" ]] || fatal "orderer admin TLS dir not found at $orderer_admin_tls_dir"

  if [[ ! -s "$orderer_join_block" ]]; then
    log "Generating orderer join block for $CHANNEL (profile SocGenesis)"
    configtxgen -profile SocGenesis -channelID "$CHANNEL" -outputBlock "$orderer_join_block" \
      || fatal "failed to generate orderer join block for '$CHANNEL'"
  fi

  cp "$orderer_admin_tls_dir/ca.crt" /tmp/orderer-admin-ca.crt
  cp "$orderer_admin_tls_dir/client.crt" /tmp/orderer-admin-client.crt
  cp "$orderer_admin_tls_dir/client.key" /tmp/orderer-admin-client.key

  log "Waiting for orderer admin API readiness on :7053"
  local admin_ready="false"
  for ((i=1; i<=admin_ready_attempts; i++)); do
    if osnadmin channel list \
      -o orderer.example.com:7053 \
      --ca-file /tmp/orderer-admin-ca.crt \
      --client-cert /tmp/orderer-admin-client.crt \
      --client-key /tmp/orderer-admin-client.key \
      >/tmp/orderer-admin-channels.txt 2>/dev/null; then
      admin_ready="true"
      break
    fi
    echo "  (retry $i/$admin_ready_attempts) orderer admin API not ready yet..."
    sleep "$admin_ready_sleep"
  done

  if [[ "$admin_ready" != "true" ]]; then
    fatal "orderer admin API did not become ready on :7053 in time"
  fi

  if grep -q "$CHANNEL" /tmp/orderer-admin-channels.txt; then
    log "[OK] Orderer already joined (channel '$CHANNEL' exists)"
  else
    log "[INFO] Joining orderer to $CHANNEL"
    osnadmin channel join \
      --channelID "$CHANNEL" \
      --config-block "$orderer_join_block" \
      -o orderer.example.com:7053 \
      --ca-file /tmp/orderer-admin-ca.crt \
      --client-cert /tmp/orderer-admin-client.crt \
      --client-key /tmp/orderer-admin-client.key
  fi

  log "Confirming orderer reports channel '$CHANNEL'"
  local channel_ready="false"
  for ((i=1; i<=channel_ready_attempts; i++)); do
    if osnadmin channel list \
      -o orderer.example.com:7053 \
      --ca-file /tmp/orderer-admin-ca.crt \
      --client-cert /tmp/orderer-admin-client.crt \
      --client-key /tmp/orderer-admin-client.key \
      >/tmp/orderer-admin-channels.txt 2>/dev/null \
      && grep -q "$CHANNEL" /tmp/orderer-admin-channels.txt; then
      channel_ready="true"
      break
    fi
    echo "  (retry $i/$channel_ready_attempts) channel '$CHANNEL' not visible on orderer yet..."
    sleep "$channel_ready_sleep"
  done

  if [[ "$channel_ready" != "true" ]]; then
    fatal "orderer did not report channel '$CHANNEL'; channel creation/join failed"
  fi

  set_peer_org1
  if peer channel list 2>/dev/null | grep -q "^soclogs$"; then
    echo "[OK] Org1 peer already joined soclogs"
  else
    echo "[INFO] Fetching genesis block for soclogs (Org1)"
    peer channel fetch 0 "$peer_genesis_block" \
      -o orderer.example.com:7050 \
      -c soclogs \
      --tls \
      --cafile /opt/fabric-dev/socnet/crypto-config/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem

    if [[ ! -s "$peer_genesis_block" ]]; then
      fatal "failed to fetch genesis block for soclogs from orderer"
    fi

    echo "[INFO] Joining Org1 peer to soclogs"
    peer channel join -b "$peer_genesis_block"
  fi

  set_peer_org2
  if peer channel list 2>/dev/null | grep -q "^soclogs$"; then
    echo "[OK] Org2 peer already joined soclogs"
  else
    echo "[INFO] Joining Org2 peer to soclogs"
    peer channel join -b "$peer_genesis_block"
  fi

  set_peer_org1
}

ensure_chaincode_lifecycle() {
  local pkg_id org1_tls_rootcert org2_tls_rootcert
  local init_args=()

  if [[ "$INIT_REQUIRED" == "true" ]]; then
    init_args+=(--init-required)
  fi

  package_chaincode

  source_org1
  if ! is_installed_for_current_org; then
    log "Installing chaincode package on Org1"
    install_for_current_org
  else
    log "Chaincode label $CC_LABEL already installed on Org1"
  fi

  pkg_id="$(get_pkg_id || true)"
  if [[ -z "$pkg_id" ]]; then
    echo "ERROR: failed to read package ID for label '$CC_LABEL' from Org1 after install." >&2
    exit 1
  fi

  if ! is_approved_for_current_org; then
    log "Approving $CC_NAME on Org1"
    peer lifecycle chaincode approveformyorg \
      -o orderer.example.com:7050 --tls --cafile "$ORDERER_CA" \
      --channelID "$CHANNEL" --name "$CC_NAME" --version "$CC_VERSION" \
      --sequence "$CC_SEQUENCE" --package-id "$pkg_id" \
      "${init_args[@]}"
  else
    log "Chaincode definition already approved on Org1"
  fi

  source_org2
  if ! is_installed_for_current_org; then
    log "Installing chaincode package on Org2"
    install_for_current_org
  else
    log "Chaincode label $CC_LABEL already installed on Org2"
  fi

  if ! is_approved_for_current_org; then
    log "Approving $CC_NAME on Org2"
    peer lifecycle chaincode approveformyorg \
      -o orderer.example.com:7050 --tls --cafile "$ORDERER_CA" \
      --channelID "$CHANNEL" --name "$CC_NAME" --version "$CC_VERSION" \
      --sequence "$CC_SEQUENCE" --package-id "$pkg_id" \
      "${init_args[@]}"
  else
    log "Chaincode definition already approved on Org2"
  fi

  source_org1
  ensure_peer_joined_channel "$CHANNEL"
  org1_tls_rootcert="$CORE_PEER_TLS_ROOTCERT_FILE"
  source_org2
  ensure_peer_joined_channel "$CHANNEL"
  org2_tls_rootcert="$CORE_PEER_TLS_ROOTCERT_FILE"
  source_org1
  ensure_peer_joined_channel "$CHANNEL"

  if ! is_committed; then
    log "Committing chaincode definition on channel $CHANNEL"
    peer lifecycle chaincode commit \
      -o orderer.example.com:7050 --tls --cafile "$ORDERER_CA" \
      --channelID "$CHANNEL" --name "$CC_NAME" --version "$CC_VERSION" \
      --sequence "$CC_SEQUENCE" "${init_args[@]}" \
      --peerAddresses peer0.org1.example.com:7051 --tlsRootCertFiles "$org1_tls_rootcert" \
      --peerAddresses peer0.org2.example.com:9051 --tlsRootCertFiles "$org2_tls_rootcert"
  else
    log "Chaincode definition already committed on channel $CHANNEL"
  fi
}

build_cc_image() {
  log "Building CCaaS image: $CC_IMAGE"
  cd "$CC_DIR"
  docker build -t "$CC_IMAGE" .
}

run_cc_container() {
  local pkg_id="$1"

  if [[ -z "${pkg_id}" ]]; then
    echo "ERROR: Could not detect Package ID for label '$CC_LABEL'."
    echo "Run: source $COMPOSE_DIR/env_org1.sh && peer lifecycle chaincode queryinstalled"
    exit 1
  fi

  log "Starting CCaaS container '$CC_CONTAINER' on network '$NETWORK' (CHAINCODE_ID=$pkg_id)"
  docker rm -f "$CC_CONTAINER" >/dev/null 2>&1 || true

  docker run -d --name "$CC_CONTAINER" --network "$NETWORK" \
    --network-alias "$CC_CONTAINER" \
    -e CHAINCODE_ID="$pkg_id" \
    -e CHAINCODE_SERVER_ADDRESS="$CC_LISTEN_ADDR" \
    -e CORE_CHAINCODE_LISTEN_ADDRESS="$CC_LISTEN_ADDR" \
    -e CORE_CHAINCODE_ADDRESS="$CC_PEER_ADDR" \
    "$CC_IMAGE" >/dev/null

  if [[ "$(docker inspect -f '{{.State.Running}}' "$CC_CONTAINER" 2>/dev/null || true)" != "true" ]]; then
    echo "ERROR: CCaaS container '$CC_CONTAINER' failed to start." >&2
    docker logs "$CC_CONTAINER" --tail 100 || true
    exit 1
  fi

  docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Networks}}\t{{.Ports}}" | egrep "$CC_CONTAINER|peer0|orderer" || true
  docker logs "$CC_CONTAINER" --tail 20 || true
}

probe_ccaas_local() {
  docker exec "$CC_CONTAINER" sh -lc '
    ss -lnt 2>/dev/null | grep -q ":9999" ||
    netstat -lnt 2>/dev/null | grep -q ":9999" ||
    grep -qi "270F" /proc/net/tcp
  '
}

wait_for_ccaas_ready() {
  local max_attempts="${1:-20}"
  local sleep_s="${2:-2}"

  log "Waiting for CCaaS readiness (container running + local listen check)"
  for ((i=1; i<=max_attempts; i++)); do
    if [[ "$(docker inspect -f '{{.State.Running}}' "$CC_CONTAINER" 2>/dev/null || true)" != "true" ]]; then
      echo "ERROR: CCaaS container '$CC_CONTAINER' is not running while waiting for readiness." >&2
      docker logs "$CC_CONTAINER" --tail 50 || true
      exit 1
    fi

    if probe_ccaas_local; then
      echo "[OK] CCaaS listening on 9999"
      return 0
    fi

    echo "  (retry $i/$max_attempts) CCaaS not reachable yet..."
    sleep "$sleep_s"
  done

  echo "ERROR: CCaaS container '$CC_CONTAINER' did not become reachable in time." >&2
  docker logs "$CC_CONTAINER" --tail 50 || true
  exit 1
}

dns_check_from_peers() {
  log "DNS check from peer containers -> lognotary-ccaas"
  docker exec peer0.org1.example.com sh -lc "getent hosts $CC_CONTAINER || true" || true
  docker exec peer0.org2.example.com sh -lc "getent hosts $CC_CONTAINER || true" || true
}

print_usage() {
  cat <<USAGE

Socnet is up. Next, use these convenience commands:

1) Load Org1 env in your CURRENT terminal:
   source $SOCNET_DIR/compose/env_org1.sh
   export PATH=$FABRIC_BIN_DIR:\$PATH

2) Invoke with both org peers + wait for commit (recommended):
   $SOCNET_DIR/start_socnet.sh invoke PutLog k3 v3

3) Query:
   $SOCNET_DIR/start_socnet.sh query GetLog k3

4) Org2 query:
   source $SOCNET_DIR/compose/env_org2.sh
   peer chaincode query -C $CHANNEL -n $CC_NAME -c '{"Args":["GetLog","k3"]}'

USAGE
}

invoke_both() {
  local fcn="$1"; shift
  local args_json
  # Build Args array: ["Fcn","a","b",...]
  args_json=$(python3 - "$fcn" "$@" <<'PY'
import json,sys
fcn=sys.argv[1]
rest=sys.argv[2:]
print(json.dumps({"Args":[fcn]+rest}))
PY
)

  source_org1
  detect_crypto_root
  if [[ ! -f "${CORE_PEER_TLS_ROOTCERT_FILE:-}" ]]; then
    fatal "Org1 TLS root cert not found at ${CORE_PEER_TLS_ROOTCERT_FILE:-<unset>}"
  fi
  if [[ ! -f "$ORG2_PEER_TLS_ROOTCERT_FILE" ]]; then
    fatal "Org2 TLS root cert not found at $ORG2_PEER_TLS_ROOTCERT_FILE"
  fi
  ensure_peer_joined_channel "$CHANNEL"
  peer chaincode invoke \
    -o orderer.example.com:7050 \
    --ordererTLSHostnameOverride orderer.example.com \
    --tls --cafile "$ORDERER_CA" \
    -C "$CHANNEL" -n "$CC_NAME" \
    --peerAddresses peer0.org1.example.com:7051 \
    --tlsRootCertFiles "$CORE_PEER_TLS_ROOTCERT_FILE" \
    --peerAddresses peer0.org2.example.com:9051 \
    --tlsRootCertFiles "$ORG2_PEER_TLS_ROOTCERT_FILE" \
    --waitForEvent --waitForEventTimeout 60s \
    -c "$args_json"
}

query_simple() {
  local fcn="$1"; shift
  local args_json
  args_json=$(python3 - "$fcn" "$@" <<'PY'
import json,sys
fcn=sys.argv[1]
rest=sys.argv[2:]
print(json.dumps({"Args":[fcn]+rest}))
PY
)

  source_org1
  ensure_peer_joined_channel "$CHANNEL"
  peer chaincode query -C "$CHANNEL" -n "$CC_NAME" -c "$args_json"
}

# -----------------------------
# Main
# -----------------------------
need_cmd docker
need_cmd awk
need_cmd grep
need_cmd python3

case "${1:-up}" in
  up)
    log "Step 1/5: validating local host mappings"
    ensure_hosts
    log "Step 2/5: starting Fabric containers (Compose-managed network)"
    start_fabric
    log "Step 3/6: ensuring channel '$CHANNEL' exists and peers have joined"
    if ! ensure_channel_soclogs; then
      echo "ERROR: channel setup failed; aborting lifecycle + CCaaS startup." >&2
      exit 1
    fi

    log "Step 4/6: building chaincode service image"
    build_cc_image

    log "Step 5/6: ensuring chaincode lifecycle (package/install/approve/commit)"
    ensure_chaincode_lifecycle

    log "Step 6/6: detecting Package ID for label: $CC_LABEL"
    pkg_id=""
    for i in 1 2 3 4 5; do
      pkg_id="$(get_pkg_id || true)"
      [[ -n "$pkg_id" ]] && break
      echo "  (retry $i/5) package id not found yet..."
      sleep 2
    done

    run_cc_container "$pkg_id"
    wait_for_ccaas_ready 20 2
    dns_check_from_peers
    print_usage
    ;;

  invoke)
    shift
    if [[ $# -lt 1 ]]; then
      echo "Usage: $0 invoke <Fcn> [args...]"
      exit 1
    fi
    invoke_both "$@"
    ;;

  query)
    shift
    if [[ $# -lt 1 ]]; then
      echo "Usage: $0 query <Fcn> [args...]"
      exit 1
    fi
    query_simple "$@"
    ;;

  logs)
    docker logs "$CC_CONTAINER" --tail 200
    ;;

  status)
    docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Networks}}\t{{.Ports}}" | egrep "orderer\.example\.com|peer0\.org1\.example\.com|peer0\.org2\.example\.com|$CC_CONTAINER" || true
    ;;

  *)
    echo "Usage:"
    echo "  $0 up        # start everything (fabric + ccaaS)"
    echo "  $0 status    # show container status"
    echo "  $0 logs      # show ccaaS logs"
    echo "  $0 invoke <Fcn> [args...]   # invoke with both peers + wait"
    echo "  $0 query  <Fcn> [args...]   # query (org1)"
    exit 1
    ;;
esac
