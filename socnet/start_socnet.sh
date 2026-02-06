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

# -----------------------------
# Config (edit if needed)
# -----------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export FABRIC_CFG_PATH="$SCRIPT_DIR/configtx"
SOCNET_DIR="$SCRIPT_DIR"
COMPOSE_DIR="$SOCNET_DIR/compose"
CONFIGTX_DIR="$SOCNET_DIR/configtx"
CC_DIR="$SOCNET_DIR/chaincode/lognotary"

CHANNEL="soclogs"
CC_NAME="lognotary"
CC_LABEL="lognotary_1.0"
CC_VERSION="1.0"
CC_SEQUENCE="1"
INIT_REQUIRED="false"
CC_IMAGE="lognotary-ccaas:1.0"
CC_CONTAINER="lognotary-ccaas"
CC_ADDR="0.0.0.0:9999"

PKG_DIR="$SOCNET_DIR/ccaas-pkg/$CC_NAME"
PKG_FILE="$PKG_DIR/$CC_LABEL.tgz"
CODE_TAR="$PKG_DIR/code.tar.gz"

FABRIC_DEV_ROOT="$(cd "$SOCNET_DIR/.." && pwd)"
FABRIC_BIN_DIR="$FABRIC_DEV_ROOT/bin"

NETWORK="socnet"

ORG1_TLS_CA="$SOCNET_DIR/crypto-config/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
ORG2_TLS_CA="$SOCNET_DIR/crypto-config/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt"
CHANNEL_ARTIFACTS_DIR="$SOCNET_DIR/channel-artifacts"
CHANNEL_TX_FILE="$CHANNEL_ARTIFACTS_DIR/${CHANNEL}.tx"
CHANNEL_BLOCK_FILE="$CHANNEL_ARTIFACTS_DIR/${CHANNEL}.block"
CHANNEL_PROFILE="SocChannel"

# -----------------------------
# Helpers
# -----------------------------
log() { echo -e "\n[+] $*\n"; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "ERROR: missing command: $1"; exit 1; }
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
  export PATH="$FABRIC_BIN_DIR:$PATH"
  # shellcheck disable=SC1090
  source "$COMPOSE_DIR/env_org1.sh"
}

source_org2() {
  export PATH="$FABRIC_BIN_DIR:$PATH"
  # shellcheck disable=SC1090
  source "$COMPOSE_DIR/env_org2.sh"
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

current_peer_has_channel() {
  peer channel list 2>/dev/null | grep -Eq "(^|[[:space:]])${CHANNEL}([[:space:]]|$)"
}

ensure_channel_soclogs() {
  local had_org1=0 had_org2=0

  need_cmd configtxgen
  mkdir -p "$CHANNEL_ARTIFACTS_DIR"

  source_org1
  if current_peer_has_channel; then
    had_org1=1
  fi

  source_org2
  if current_peer_has_channel; then
    had_org2=1
  fi

  if [[ "$had_org1" -eq 1 && "$had_org2" -eq 1 ]]; then
    log "Channel $CHANNEL already joined on Org1 and Org2 peers"
    return 0
  fi

  if [[ ! -f "$CHANNEL_TX_FILE" ]]; then
    log "Generating create-channel transaction for $CHANNEL (profile $CHANNEL_PROFILE)"
    configtxgen -profile "$CHANNEL_PROFILE" -outputCreateChannelTx "$CHANNEL_TX_FILE" -channelID "$CHANNEL"
  else
    log "Using existing create-channel transaction: $CHANNEL_TX_FILE"
  fi

  if [[ ! -s "$CHANNEL_TX_FILE" ]]; then
    echo "ERROR: channel transaction file is missing or empty: $CHANNEL_TX_FILE" >&2
    exit 1
  fi

  source_org1
  if peer channel fetch 0 "$CHANNEL_BLOCK_FILE" \
    -o orderer.example.com:7050 \
    --ordererTLSHostnameOverride orderer.example.com \
    -c "$CHANNEL" \
    --tls --cafile "$ORDERER_CA" >/dev/null 2>&1; then
    log "Channel $CHANNEL already exists on the orderer"
  else
    log "Creating channel $CHANNEL"
    source_org1
    peer channel create \
      -o orderer.example.com:7050 \
      --ordererTLSHostnameOverride orderer.example.com \
      -c "$CHANNEL" \
      -f "$CHANNEL_TX_FILE" \
      --outputBlock "$CHANNEL_BLOCK_FILE" \
      --tls --cafile "$ORDERER_CA"
  fi

  source_org1
  if current_peer_has_channel; then
    log "Org1 peer already joined channel $CHANNEL"
  else
    log "Joining Org1 peer to channel $CHANNEL"
    peer channel join -b "$CHANNEL_BLOCK_FILE"
  fi

  source_org2
  if current_peer_has_channel; then
    log "Org2 peer already joined channel $CHANNEL"
  else
    log "Joining Org2 peer to channel $CHANNEL"
    peer channel join -b "$CHANNEL_BLOCK_FILE"
  fi

  source_org1
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
  org1_tls_rootcert="$CORE_PEER_TLS_ROOTCERT_FILE"
  source_org2
  org2_tls_rootcert="$CORE_PEER_TLS_ROOTCERT_FILE"
  source_org1

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
    -e CHAINCODE_SERVER_ADDRESS="$CC_ADDR" \
    -e CHAINCODE_ID="$pkg_id" \
    "$CC_IMAGE" >/dev/null

  docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Networks}}\t{{.Ports}}" | egrep "$CC_CONTAINER|peer0|orderer" || true
  docker logs "$CC_CONTAINER" --tail 20 || true
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
  peer chaincode invoke \
    -o orderer.example.com:7050 \
    --ordererTLSHostnameOverride orderer.example.com \
    --tls --cafile "$ORDERER_CA" \
    -C "$CHANNEL" -n "$CC_NAME" \
    --peerAddresses peer0.org1.example.com:7051 \
    --tlsRootCertFiles "$ORG1_TLS_CA" \
    --peerAddresses peer0.org2.example.com:9051 \
    --tlsRootCertFiles "$ORG2_TLS_CA" \
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
