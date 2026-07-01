#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST="${DEMO_HOST:-127.0.0.1}"
PORT="${DEMO_PORT:-8088}"
BASE_URL="http://${HOST}:${PORT}"

cd "${ROOT_DIR}"
export UV_CACHE_DIR="${UV_CACHE_DIR:-${ROOT_DIR}/.uv-cache}"

echo "Starting DSO Report Reviewer demo agent on ${BASE_URL}"
uv run python demo_agent.py --host "${HOST}" --port "${PORT}" &
SERVER_PID="$!"

cleanup() {
  kill "${SERVER_PID}" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

for _ in $(seq 1 30); do
  if curl -fsS "${BASE_URL}/healthz" >/dev/null 2>&1; then
    echo
    echo "Demo agent is ready."
    echo "Customer pitch : ${BASE_URL}/customer-pitch.html"
    echo "Operator UI    : ${BASE_URL}/ui/index.html"
    echo "MVP runbook    : ${BASE_URL}/docs/MVP-DEMO-RUNBOOK.html"
    echo
    echo "Press Ctrl-C to stop the demo agent."
    wait "${SERVER_PID}"
    exit $?
  fi
  sleep 0.3
done

echo "Demo agent did not become healthy on ${BASE_URL}/healthz" >&2
exit 1
