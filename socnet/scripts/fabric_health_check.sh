#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOCNET_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${SOCNET_DIR}/.." && pwd)"

export PATH="${REPO_ROOT}/bin:${PATH}"
export FABRIC_CFG_PATH="${REPO_ROOT}/config"

# shellcheck disable=SC1091
source "${SOCNET_DIR}/compose/env_org1.sh"

CORE_PEER_MSPCONFIGPATH="${CORE_PEER_MSPCONFIGPATH/\/opt\/fabric-dev/${REPO_ROOT}}"
CORE_PEER_TLS_ROOTCERT_FILE="${CORE_PEER_TLS_ROOTCERT_FILE/\/opt\/fabric-dev/${REPO_ROOT}}"
ORDERER_CA="${ORDERER_CA/\/opt\/fabric-dev/${REPO_ROOT}}"
FABRIC_CFG_PATH="${FABRIC_CFG_PATH/\/opt\/fabric-dev/${REPO_ROOT}}"

required_vars=(CORE_PEER_LOCALMSPID CORE_PEER_MSPCONFIGPATH CORE_PEER_ADDRESS ORDERER_CA FABRIC_CFG_PATH)
for required_var in "${required_vars[@]}"; do
  if [[ -z "${!required_var:-}" ]]; then
    echo "ERROR: required environment variable ${required_var} is not set" >&2
    exit 1
  fi
done

CHANNEL_OUTPUT="$(peer channel list 2>&1)"
CHAINCODE_OUTPUT="$(peer lifecycle chaincode querycommitted -C soclogs 2>&1)"

CHANNEL_OK=false
CHAINCODE_OK=false
if printf '%s' "$CHANNEL_OUTPUT" | grep -Eq '(^|[[:space:]])soclogs($|[[:space:]])'; then
  CHANNEL_OK=true
fi
if printf '%s' "$CHAINCODE_OUTPUT" | grep -q 'Name: lognotary'; then
  CHAINCODE_OK=true
fi

cat <<JSON
{
  "channel_ok": ${CHANNEL_OK},
  "chaincode_ok": ${CHAINCODE_OK},
  "channel_list": $(python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))' <<<"$CHANNEL_OUTPUT"),
  "querycommitted": $(python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))' <<<"$CHAINCODE_OUTPUT")
}
JSON
