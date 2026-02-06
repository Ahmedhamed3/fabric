#!/usr/bin/env bash

if [ -z "${BASH_VERSION:-}" ]; then
  echo "[fabric-ui] ERROR: this script must be run with bash (e.g. ./fabric-ui/run.sh)." >&2
  exit 1
fi
if [ "${BASH_VERSINFO[0]:-0}" -lt 4 ]; then
  echo "[fabric-ui] ERROR: bash 4+ is required. Detected: ${BASH_VERSION}." >&2
  exit 1
fi

set -eu
set -o pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$ROOT_DIR/.." && pwd)"
SOCNET_DIR="${SOCNET_DIR:-$REPO_ROOT/socnet}"
START_SCRIPT="${START_SCRIPT:-$SOCNET_DIR/start_socnet.sh}"

ensure_wsl_hosts() {
  if ! grep -qi microsoft /proc/version 2>/dev/null; then
    return
  fi

  if grep -q "peer0.org1.example.com" /etc/hosts; then
    echo "[fabric-ui] Step 1/4: WSL hosts already configured"
    return
  fi

  echo "[fabric-ui] Step 1/4: WSL detected, adding Fabric hostnames to /etc/hosts"
  local host_line="127.0.0.1 orderer.example.com peer0.org1.example.com peer0.org2.example.com"

  if [ -w /etc/hosts ]; then
    echo "$host_line" >> /etc/hosts
  elif command -v sudo >/dev/null 2>&1; then
    sudo bash -c "echo '$host_line' >> /etc/hosts"
  else
    echo "[fabric-ui] ERROR: cannot update /etc/hosts (no write permission and no sudo)." >&2
    exit 1
  fi
}

if [ ! -x "$START_SCRIPT" ]; then
  echo "[fabric-ui] ERROR: start script not found or not executable: $START_SCRIPT" >&2
  exit 1
fi

ensure_wsl_hosts

echo "[fabric-ui] Step 2/4: starting Fabric network + CCaaS"
bash "$START_SCRIPT" up

echo "[fabric-ui] Step 3/4: installing/updating UI dependencies"
cd "$ROOT_DIR"
npm install

echo "[fabric-ui] Step 4/4: starting Fabric UI backend + frontend"
FABRIC_ENV_SCRIPT="${SOCNET_DIR}/compose/env_org1.sh" \
FABRIC_ENV_SCRIPT_ORG2="${SOCNET_DIR}/compose/env_org2.sh" \
FABRIC_BIN_DIR="/opt/fabric-dev/tools-fabric-3/fabric-samples/bin" \
FABRIC_CFG_PATH="${REPO_ROOT}/config" \
npm run dev
