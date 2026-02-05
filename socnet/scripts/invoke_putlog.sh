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
ROOT_DIR="$(cd "${SOCNET_DIR}/.." && pwd)"

export PATH="${ROOT_DIR}/bin:${PATH}"
export FABRIC_CFG_PATH="${ROOT_DIR}/config"

# shellcheck disable=SC1091
source "${SOCNET_DIR}/compose/env_org1.sh"

# Normalize env files that may contain /opt/fabric-dev defaults.
CORE_PEER_MSPCONFIGPATH="${CORE_PEER_MSPCONFIGPATH/\/opt\/fabric-dev/${ROOT_DIR}}"
CORE_PEER_TLS_ROOTCERT_FILE="${CORE_PEER_TLS_ROOTCERT_FILE/\/opt\/fabric-dev/${ROOT_DIR}}"
ORDERER_CA="${ORDERER_CA/\/opt\/fabric-dev/${ROOT_DIR}}"

ARGS_JSON="$(python3 - "$EVIDENCE_ID" "$MANIFEST_JSON" <<'PY'
import json
import sys

print(json.dumps({"Args": ["PutLog", sys.argv[1], sys.argv[2]]}))
PY
)"

set +e
OUTPUT="$(peer chaincode invoke \
  -o orderer.example.com:7050 \
  --ordererTLSHostnameOverride orderer.example.com \
  --tls --cafile "$ORDERER_CA" \
  -C soclogs -n lognotary \
  --peerAddresses peer0.org1.example.com:7051 \
  --tlsRootCertFiles "$CORE_PEER_TLS_ROOTCERT_FILE" \
  --peerAddresses peer0.org2.example.com:9051 \
  --tlsRootCertFiles "${SOCNET_DIR}/crypto-config/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt" \
  --waitForEvent --waitForEventTimeout 60s \
  -c "$ARGS_JSON" 2>&1)"
STATUS=$?
set -e

echo "$OUTPUT"

if [[ $STATUS -ne 0 ]]; then
  exit $STATUS
fi

TX_ID="$(printf '%s' "$OUTPUT" | sed -n 's/.*[Tt]x[Ii][Dd][ :=]\([A-Za-z0-9]\+\).*/\1/p' | head -n1)"
if [[ -z "$TX_ID" ]]; then
  TX_ID="submitted"
fi

echo "txid:${TX_ID}"
