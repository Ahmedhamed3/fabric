#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOCNET_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

export PATH=/opt/fabric-dev/bin:${PATH}
export FABRIC_CFG_PATH=/opt/fabric-dev/config

CHANNEL="${CHANNEL:-soclogs}"
CC_NAME="${CC_NAME:-lognotary}"
CC_VERSION="${CC_VERSION:-1.0}"
CC_SEQUENCE="${CC_SEQUENCE:-1}"
INIT_REQUIRED="${INIT_REQUIRED:-false}"
ORDERER_ADDRESS="${ORDERER_ADDRESS:-orderer.example.com:7050}"

CC_LABEL="${CC_NAME}_${CC_VERSION}"
PKG_DIR="${SOCNET_DIR}/ccaas-pkg/${CC_NAME}"
PKG_FILE="${PKG_DIR}/${CC_LABEL}.tgz"
CODE_TAR="${PKG_DIR}/code.tar.gz"

set_org1() {
  # shellcheck disable=SC1091
  source "${SCRIPT_DIR}/env_org1.sh"
}

set_org2() {
  # shellcheck disable=SC1091
  source "${SCRIPT_DIR}/env_org2.sh"
}

install_chaincode() {
  local output
  if output=$(peer lifecycle chaincode install "${PKG_FILE}" 2>&1); then
    echo "${output}"
    return 0
  fi

  if grep -q "already successfully installed" <<<"${output}"; then
    echo "${output}"
    echo "Chaincode package already installed on this peer; continuing."
    return 0
  fi

  echo "${output}"
  return 1
}

mkdir -p "${PKG_DIR}"
tar -C "${PKG_DIR}" -czf "${CODE_TAR}" connection.json

tar -C "${PKG_DIR}" -czf "${PKG_FILE}" metadata.json "$(basename "${CODE_TAR}")"
PACKAGE_ID="$(peer lifecycle chaincode calculatepackageid "${PKG_FILE}")"

set_org1

committed_info="$(peer lifecycle chaincode querycommitted -C "${CHANNEL}" -n "${CC_NAME}" 2>/dev/null || true)"
if [[ -n "${committed_info}" ]]; then
  committed_sequence="$(sed -n 's/.*Sequence: \([0-9]\+\),.*/\1/p' <<<"${committed_info}" | head -n1)"
  committed_version="$(sed -n 's/.*Version: \([^,]*\), Sequence.*/\1/p' <<<"${committed_info}" | head -n1)"
  committed_init_required="$(sed -n 's/.*InitRequired: \([^,]*\).*/\1/p' <<<"${committed_info}" | head -n1)"

  if [[ "${committed_sequence:-}" == "${CC_SEQUENCE}" && "${committed_version:-}" == "${CC_VERSION}" && "${committed_init_required:-}" == "${INIT_REQUIRED}" ]]; then
    echo "Requested definition already committed; skipping lifecycle approval/commit."
    echo "CHANNEL=${CHANNEL}"
    echo "CC_NAME=${CC_NAME}"
    echo "CC_VERSION=${CC_VERSION}"
    echo "CC_SEQUENCE=${CC_SEQUENCE}"
    echo "INIT_REQUIRED=${INIT_REQUIRED}"
    echo "PACKAGE_ID=${PACKAGE_ID}"
    exit 0
  fi
fi

echo "CHANNEL=${CHANNEL}"
echo "CC_NAME=${CC_NAME}"
echo "CC_VERSION=${CC_VERSION}"
echo "CC_SEQUENCE=${CC_SEQUENCE}"
echo "INIT_REQUIRED=${INIT_REQUIRED}"
echo "PACKAGE_ID=${PACKAGE_ID}"


INIT_ARGS=()
if [[ "${INIT_REQUIRED}" == "true" ]]; then
  INIT_ARGS+=(--init-required)
fi

set_org1
install_chaincode
peer lifecycle chaincode approveformyorg \
  -o "${ORDERER_ADDRESS}" --tls --cafile "${ORDERER_CA}" \
  --channelID "${CHANNEL}" --name "${CC_NAME}" --version "${CC_VERSION}" \
  --sequence "${CC_SEQUENCE}" --package-id "${PACKAGE_ID}" \
  "${INIT_ARGS[@]}"

set_org2
install_chaincode
peer lifecycle chaincode approveformyorg \
  -o "${ORDERER_ADDRESS}" --tls --cafile "${ORDERER_CA}" \
  --channelID "${CHANNEL}" --name "${CC_NAME}" --version "${CC_VERSION}" \
  --sequence "${CC_SEQUENCE}" --package-id "${PACKAGE_ID}" \
  "${INIT_ARGS[@]}"

set_org1
ORG1_TLS_ROOTCERT="${CORE_PEER_TLS_ROOTCERT_FILE}"
set_org2
ORG2_TLS_ROOTCERT="${CORE_PEER_TLS_ROOTCERT_FILE}"
set_org1

peer lifecycle chaincode commit \
  -o "${ORDERER_ADDRESS}" --tls --cafile "${ORDERER_CA}" \
  --channelID "${CHANNEL}" --name "${CC_NAME}" --version "${CC_VERSION}" \
  --sequence "${CC_SEQUENCE}" "${INIT_ARGS[@]}" \
  --peerAddresses peer0.org1.example.com:7051 --tlsRootCertFiles "${ORG1_TLS_ROOTCERT}" \
  --peerAddresses peer0.org2.example.com:9051 --tlsRootCertFiles "${ORG2_TLS_ROOTCERT}"

if [[ "${INIT_REQUIRED}" == "true" ]]; then
  init_payload='{"Args":["Init"]}'
  init_output="$(peer chaincode invoke \
    -o "${ORDERER_ADDRESS}" --tls --cafile "${ORDERER_CA}" \
    -C "${CHANNEL}" -n "${CC_NAME}" --isInit -c "${init_payload}" \
    --peerAddresses peer0.org1.example.com:7051 --tlsRootCertFiles "${ORG1_TLS_ROOTCERT}" \
    --peerAddresses peer0.org2.example.com:9051 --tlsRootCertFiles "${ORG2_TLS_ROOTCERT}" 2>&1 || true)"

  if grep -qi "already initialized\|duplicate\|status:500" <<<"${init_output}"; then
    echo "Init invoke returned a non-fatal response (likely already initialized):"
    echo "${init_output}"
  else
    echo "${init_output}"
  fi
fi

echo "Deployment complete."
