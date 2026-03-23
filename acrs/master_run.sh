#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${ROOT_DIR}/.venv"
LOG_DIR="${ROOT_DIR}/logs"
BACKEND_PORT="${BACKEND_PORT:-8000}"
FRONTEND_PORT="${FRONTEND_PORT:-5173}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
BACKEND_RELOAD="${BACKEND_RELOAD:-0}"

BACKEND_PID=""
FRONTEND_PID=""
FRONTEND_MODE="vite"
BACKEND_MODE="uvicorn"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Error: required command not found: $1"
    exit 1
  fi
}

python_has_modules() {
  local python_exec="$1"
  shift
  "${python_exec}" - "$@" <<'PY' >/dev/null 2>&1
import importlib.util
import sys

modules = sys.argv[1:]
missing = [m for m in modules if importlib.util.find_spec(m) is None]
raise SystemExit(1 if missing else 0)
PY
}

wait_for_http_ok() {
  local python_exec="$1"
  local url="$2"
  local attempts="$3"
  local delay="$4"
  local i
  for ((i = 1; i <= attempts; i++)); do
    if "${python_exec}" - "$url" <<'PY' >/dev/null 2>&1
import sys
from urllib.request import urlopen

url = sys.argv[1]
with urlopen(url, timeout=1.5) as resp:
    raise SystemExit(0 if 200 <= resp.status < 300 else 1)
PY
    then
      return 0
    fi
    sleep "${delay}"
  done
  return 1
}

kill_pids() {
  local pids="$1"
  local reason="$2"
  if [[ -n "${pids}" ]]; then
    echo "Stopping ${reason}: ${pids}"
    kill ${pids} >/dev/null 2>&1 || true
    sleep 1
    kill -9 ${pids} >/dev/null 2>&1 || true
  fi
}

kill_by_port() {
  local port="$1"
  local pids
  pids="$(lsof -ti "tcp:${port}" || true)"
  kill_pids "${pids}" "processes on port ${port}"
}

cleanup_started_processes() {
  if [[ -n "${BACKEND_PID}" ]] && kill -0 "${BACKEND_PID}" >/dev/null 2>&1; then
    kill "${BACKEND_PID}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${FRONTEND_PID}" ]] && kill -0 "${FRONTEND_PID}" >/dev/null 2>&1; then
    kill "${FRONTEND_PID}" >/dev/null 2>&1 || true
  fi
}

kill_from_pidfile() {
  local pidfile="$1"
  if [[ -f "${pidfile}" ]]; then
    local pid
    pid="$(cat "${pidfile}" 2>/dev/null || true)"
    if [[ -n "${pid}" ]] && kill -0 "${pid}" >/dev/null 2>&1; then
      kill "${pid}" >/dev/null 2>&1 || true
      sleep 1
      kill -9 "${pid}" >/dev/null 2>&1 || true
    fi
    rm -f "${pidfile}"
  fi
}

trap cleanup_started_processes EXIT INT TERM

require_cmd "${PYTHON_BIN}"
require_cmd npm
require_cmd lsof

echo "Cleaning up previous SNSX CRS processes..."
mkdir -p "${LOG_DIR}"
kill_from_pidfile "${LOG_DIR}/backend.pid"
kill_from_pidfile "${LOG_DIR}/frontend.pid"
kill_by_port "${BACKEND_PORT}"
kill_by_port "${FRONTEND_PORT}"

echo "Preparing Python environment..."
if [[ ! -d "${VENV_DIR}" ]]; then
  "${PYTHON_BIN}" -m venv "${VENV_DIR}"
fi

if ! python_has_modules "${VENV_DIR}/bin/python" fastapi uvicorn pydantic networkx numpy; then
  echo "Installing core Python dependencies..."
  if ! "${VENV_DIR}/bin/pip" --disable-pip-version-check install fastapi uvicorn pydantic networkx numpy; then
    echo "Python dependency installation failed."
    echo "If internet access is restricted, pre-install dependencies or run where package indexes are reachable."
    exit 1
  fi
else
  echo "Python dependencies already satisfied; skipping install."
fi

if ! python_has_modules "${VENV_DIR}/bin/python" z3; then
  echo "Installing optional symbolic execution dependency (z3-solver)..."
  "${VENV_DIR}/bin/pip" --disable-pip-version-check install z3-solver || \
    echo "Warning: z3-solver install failed; symbolic execution will run in placeholder mode."
fi

if [[ "${INSTALL_HEAVY_ML:-0}" == "1" ]] && ! python_has_modules "${VENV_DIR}/bin/python" torch; then
  echo "Installing optional ML dependency (torch)..."
  "${VENV_DIR}/bin/pip" --disable-pip-version-check install torch || \
    echo "Warning: torch install failed; heuristic predictor will still run."
fi

echo "Preparing frontend dependencies..."
cd "${ROOT_DIR}/dashboard/frontend"
if [[ ! -f "${ROOT_DIR}/dashboard/frontend/node_modules/vite/bin/vite.js" ]]; then
  echo "Installing frontend dependencies (including dev dependencies)..."
  if ! npm install --include=dev --fetch-retries=0 --fetch-timeout=10000 --no-audit --no-fund; then
    echo "Warning: frontend dependency installation failed."
    echo "Falling back to lightweight static dashboard server."
    FRONTEND_MODE="fallback"
  fi
else
  echo "Frontend dependencies already satisfied; skipping install."
fi

if [[ ! -f "${ROOT_DIR}/dashboard/frontend/node_modules/vite/bin/vite.js" ]]; then
  FRONTEND_MODE="fallback"
fi

echo "Starting backend on port ${BACKEND_PORT}..."
cd "${ROOT_DIR}"
rm -f "${LOG_DIR}/backend.log"
reload_args=()
if [[ "${BACKEND_RELOAD}" == "1" ]]; then
  reload_args+=(--reload)
fi
"${VENV_DIR}/bin/python" -m uvicorn api.main:app --host 127.0.0.1 --port "${BACKEND_PORT}" "${reload_args[@]}" \
  >"${LOG_DIR}/backend.log" 2>&1 &
BACKEND_PID=$!
echo "${BACKEND_PID}" > "${LOG_DIR}/backend.pid"

echo "Starting frontend on port ${FRONTEND_PORT}..."
if [[ "${FRONTEND_MODE}" == "vite" ]]; then
  cd "${ROOT_DIR}/dashboard/frontend"
  npm run dev -- --host 127.0.0.1 --port "${FRONTEND_PORT}" \
    >"${LOG_DIR}/frontend.log" 2>&1 &
else
  cd "${ROOT_DIR}/dashboard/fallback"
  "${VENV_DIR}/bin/python" -m http.server "${FRONTEND_PORT}" --bind 127.0.0.1 \
    >"${LOG_DIR}/frontend.log" 2>&1 &
fi
FRONTEND_PID=$!
echo "${FRONTEND_PID}" > "${LOG_DIR}/frontend.pid"

if ! wait_for_http_ok "${VENV_DIR}/bin/python" "http://127.0.0.1:${BACKEND_PORT}/health" 12 1; then
  if [[ "${BACKEND_RELOAD}" == "1" ]]; then
    echo "Uvicorn failed with reload enabled. Retrying backend without reload..."
    kill "${BACKEND_PID}" >/dev/null 2>&1 || true
    sleep 1
    "${VENV_DIR}/bin/python" -m uvicorn api.main:app --host 127.0.0.1 --port "${BACKEND_PORT}" \
      >>"${LOG_DIR}/backend.log" 2>&1 &
    BACKEND_PID=$!
    echo "${BACKEND_PID}" > "${LOG_DIR}/backend.pid"
  fi
fi

if ! wait_for_http_ok "${VENV_DIR}/bin/python" "http://127.0.0.1:${BACKEND_PORT}/health" 6 1; then
  echo "Warning: uvicorn backend failed to start. Falling back to lightweight backend server."
  BACKEND_MODE="fallback"
  cd "${ROOT_DIR}"
  kill "${BACKEND_PID}" >/dev/null 2>&1 || true
  sleep 1
  "${VENV_DIR}/bin/python" -m api.fallback_server --host 127.0.0.1 --port "${BACKEND_PORT}" \
    >>"${LOG_DIR}/backend.log" 2>&1 &
  BACKEND_PID=$!
  echo "${BACKEND_PID}" > "${LOG_DIR}/backend.pid"
  if ! wait_for_http_ok "${VENV_DIR}/bin/python" "http://127.0.0.1:${BACKEND_PORT}/health" 6 1; then
    echo "Backend failed to start in both uvicorn and fallback mode. Check ${LOG_DIR}/backend.log"
    exit 1
  fi
fi
if ! kill -0 "${FRONTEND_PID}" >/dev/null 2>&1; then
  echo "Frontend failed to start. Check ${LOG_DIR}/frontend.log"
  exit 1
fi

echo "SNSX CRS is running:"
echo "- Backend:  http://127.0.0.1:${BACKEND_PORT} (${BACKEND_MODE})"
echo "- Frontend: http://127.0.0.1:${FRONTEND_PORT} (${FRONTEND_MODE})"
echo "- Logs:     ${LOG_DIR}/backend.log, ${LOG_DIR}/frontend.log"
echo "Press Ctrl+C to stop both services."

wait "${BACKEND_PID}" "${FRONTEND_PID}"
