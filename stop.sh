#!/usr/bin/env bash
# Uso: ./stop.sh — para o dashboard do claude-guardian
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; RESET='\033[0m'

ok()   { echo -e "${GREEN}✓${RESET} $*"; }
info() { echo -e "${CYAN}→${RESET} $*"; }
warn() { echo -e "${YELLOW}⚠${RESET} $*"; }
die()  { echo -e "${RED}✗ $*${RESET}" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="${SCRIPT_DIR}/.dashboard.pid"

if [[ ! -f "${PID_FILE}" ]]; then
  warn "PID file não encontrado — o dashboard pode não estar rodando."
  exit 0
fi

PID="$(cat "${PID_FILE}")"

if ! kill -0 "${PID}" 2>/dev/null; then
  warn "Processo ${PID} não está ativo — limpando PID file."
  rm -f "${PID_FILE}"
  exit 0
fi

info "Encerrando dashboard (PID ${PID})…"
kill -TERM "${PID}" 2>/dev/null || true

WAITED=0
while kill -0 "${PID}" 2>/dev/null; do
  if (( WAITED >= 10 )); then
    warn "Processo não encerrou graciosamente — forçando (SIGKILL)…"
    kill -KILL "${PID}" 2>/dev/null || true
    sleep 0.3
    break
  fi
  sleep 0.5
  (( WAITED++ ))
done

rm -f "${PID_FILE}"

if kill -0 "${PID}" 2>/dev/null; then
  die "Não foi possível encerrar o processo ${PID}."
fi

ok "Dashboard encerrado com sucesso."
