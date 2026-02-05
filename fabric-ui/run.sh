#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOCNET_DIR="${SOCNET_DIR:-/opt/fabric-dev/socnet}"
START_SCRIPT="${START_SCRIPT:-$SOCNET_DIR/start_socnet.sh}"

ensure_wsl_hosts() {
  if ! grep -qi microsoft /proc/version 2>/dev/null; then
    return
  fi

  if grep -q "peer0.org1.example.com" /etc/hosts; then
    return
  fi

  echo "[fabric-ui] WSL detected; adding Fabric hostnames to /etc/hosts"
  local line="127.0.0.1 orderer.example.com peer0.org1.example.com peer0.org2.example.com"
  if [ -w /etc/hosts ]; then
    echo "$line" >> /etc/hosts
  elif command -v sudo >/dev/null 2>&1; then
    sudo bash -c "echo '$line' >> /etc/hosts"
  else
    echo "[fabric-ui] warning: unable to update /etc/hosts without sudo"
  fi
}

echo "[fabric-ui] Starting Fabric network and CCaaS"
ensure_wsl_hosts
bash "$START_SCRIPT" up

echo "[fabric-ui] Installing dependencies"
cd "$ROOT_DIR"
npm install

echo "[fabric-ui] Starting backend + frontend"
npm run dev
