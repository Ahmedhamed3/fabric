#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOCNET_DIR="${ROOT_DIR}/socnet"
EVIDENCE_API_DIR="${ROOT_DIR}/services/evidence-api"
OCSF_DIR="${ROOT_DIR}/ocsf-workspace"
FABRIC_UI_DIR="${ROOT_DIR}/fabric-ui"
RUN_DIR="${ROOT_DIR}/.run"
LOG_DIR="${RUN_DIR}/logs"
PID_DIR="${RUN_DIR}/pids"

mkdir -p "${LOG_DIR}" "${PID_DIR}"

ensure_deps() {
  if [[ ! -d "${EVIDENCE_API_DIR}/node_modules" ]]; then
    (cd "${EVIDENCE_API_DIR}" && npm install)
  fi
  if [[ ! -d "${FABRIC_UI_DIR}/node_modules" ]]; then
    (cd "${FABRIC_UI_DIR}" && npm install)
  fi
}

stop_background() {
  for svc in evidence-api ocsf-ui fabric-ui; do
    local pid_file="${PID_DIR}/${svc}.pid"
    if [[ -f "${pid_file}" ]]; then
      local pid
      pid="$(cat "${pid_file}")"
      if kill -0 "${pid}" >/dev/null 2>&1; then
        kill "${pid}" >/dev/null 2>&1 || true
      fi
      rm -f "${pid_file}"
    fi
  done
}

start_background() {
  local name="$1"
  local workdir="$2"
  local cmd="$3"
  local logfile="${LOG_DIR}/${name}.log"

  nohup bash -lc "cd '${workdir}' && ${cmd}" >"${logfile}" 2>&1 &
  echo $! >"${PID_DIR}/${name}.pid"
  echo "[run.sh] started ${name} (pid $(cat "${PID_DIR}/${name}.pid"))"
}

start_stack() {
  echo "[run.sh] Starting socnet"
  bash "${SOCNET_DIR}/start_socnet.sh" up

  echo "[run.sh] Deploying lognotary chaincode"
  bash "${SOCNET_DIR}/compose/deploy_lognotary_ccaas.sh"

  echo "[run.sh] Ensuring CCaaS container is running"
  docker start lognotary-ccaas >/dev/null 2>&1 || true

  ensure_deps
  stop_background

  echo "[run.sh] Starting evidence-api on :4100"
  start_background "evidence-api" "${EVIDENCE_API_DIR}" "npm start"

  echo "[run.sh] Starting ocsf-workspace UI on :8000"
  start_background "ocsf-ui" "${OCSF_DIR}" "python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000"

  echo "[run.sh] Starting fabric-ui"
  start_background "fabric-ui" "${FABRIC_UI_DIR}" "npm run dev"

  echo "[run.sh] Stack started. Logs in ${LOG_DIR}"
}

fresh_wipe() {
  echo "[run.sh] Dev wipe: stopping background apps"
  stop_background

  echo "[run.sh] Dev wipe: bringing down socnet"
  if (cd "${SOCNET_DIR}/compose" && docker compose down --volumes --remove-orphans); then
    echo "[run.sh] Dev wipe: socnet docker compose down completed"
  else
    echo "[run.sh] Dev wipe: docker compose down failed, falling back to explicit container/volume removal"
    docker rm -f orderer.example.com peer0.org1.example.com peer0.org2.example.com lognotary-ccaas >/dev/null 2>&1 || true
    docker volume rm orderer_data peer0org1_data peer0org2_data >/dev/null 2>&1 || true
  fi

  echo "[run.sh] Dev wipe: clearing evidence-api storage"
  rm -rf "${EVIDENCE_API_DIR}/storage"/*
}

case "${1:-up}" in
  up)
    start_stack
    ;;
  fresh)
    fresh_wipe
    start_stack
    ;;
  *)
    echo "Usage: $0 [up|fresh]"
    exit 1
    ;;
esac
