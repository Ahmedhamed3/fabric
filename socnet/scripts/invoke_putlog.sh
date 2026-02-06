#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <evidence_id> <manifest_json>" >&2
  exit 1
fi

EVIDENCE_ID="$1"
MANIFEST_JSON="$2"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOCNET_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${SOCNET_DIR}/.." && pwd)"

export PATH="${REPO_ROOT}/bin:${PATH}"
export FABRIC_CFG_PATH="${REPO_ROOT}/config"

# shellcheck disable=SC1091
source "${SOCNET_DIR}/compose/env_org1.sh"

# Normalize env files that may still point at /opt/fabric-dev.
CORE_PEER_MSPCONFIGPATH="${CORE_PEER_MSPCONFIGPATH/\/opt\/fabric-dev/${REPO_ROOT}}"
CORE_PEER_TLS_ROOTCERT_FILE="${CORE_PEER_TLS_ROOTCERT_FILE/\/opt\/fabric-dev/${REPO_ROOT}}"
ORDERER_CA="${ORDERER_CA/\/opt\/fabric-dev/${REPO_ROOT}}"
FABRIC_CFG_PATH="${FABRIC_CFG_PATH/\/opt\/fabric-dev/${REPO_ROOT}}"

required_vars=(
  CORE_PEER_LOCALMSPID
  CORE_PEER_MSPCONFIGPATH
  CORE_PEER_ADDRESS
  ORDERER_CA
  FABRIC_CFG_PATH
)

for required_var in "${required_vars[@]}"; do
  if [[ -z "${!required_var:-}" ]]; then
    echo "ERROR: required environment variable ${required_var} is not set" >&2
    exit 1
  fi
done

if [[ ! -f "$ORDERER_CA" ]]; then
  echo "ERROR: ORDERER_CA file not found: $ORDERER_CA" >&2
  exit 1
fi

CC_INPUT_FILE="$(mktemp /tmp/cc_input.XXXXXX.json)"
cleanup() {
  rm -f "$CC_INPUT_FILE"
}
trap cleanup EXIT

python3 - "$EVIDENCE_ID" "$MANIFEST_JSON" "$CC_INPUT_FILE" <<'PY'
import json
import sys

_, evidence_id, manifest_json, output_path = sys.argv
payload = {"Args": ["PutLog", evidence_id, manifest_json]}
with open(output_path, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, ensure_ascii=False)
PY

set +e
OUTPUT="$(peer chaincode invoke \
  -C soclogs \
  -n lognotary \
  -o orderer.example.com:7050 \
  --tls \
  --cafile "$ORDERER_CA" \
  --ordererTLSHostnameOverride orderer.example.com \
  --peerAddresses peer0.org1.example.com:7051 \
  --tlsRootCertFiles "$CORE_PEER_TLS_ROOTCERT_FILE" \
  --peerAddresses peer0.org2.example.com:9051 \
  --tlsRootCertFiles "${SOCNET_DIR}/crypto-config/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt" \
  --waitForEvent --waitForEventTimeout 60s \
  -c "$(cat "$CC_INPUT_FILE")" 2>&1)"
STATUS=$?
set -e

printf '%s\n' "$OUTPUT"
if [[ $STATUS -ne 0 ]]; then
  exit $STATUS
fi

TX_ID="$(printf '%s' "$OUTPUT" | sed -n 's/.*[Tt]x[Ii][Dd][ :=]\([A-Za-z0-9]\+\).*/\1/p' | head -n1)"
if [[ -z "$TX_ID" ]]; then
  TX_ID="submitted"
fi

printf 'txid:%s\n' "$TX_ID"
