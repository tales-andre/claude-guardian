#!/usr/bin/env bash
# install-agent.sh — instala o agente claude-guardian em uma máquina de
# desenvolvedor e o conecta ao servidor central da empresa.
#
# Uso:
#   bash enterprise/install-agent.sh --server https://guardian.empresa.com --key <GUARDIAN_AGENT_KEY>
#
# O que faz:
#   1. Verifica Node.js >= 22.6
#   2. Instala dependências npm
#   3. Instala gitleaks (opcional, com degradação graciosa)
#   4. Registra os hooks no Claude Code e grava a config apontando para o
#      servidor central (centralUrl + centralApiKey)
#
# Diferente do init.sh (modo local), este script NÃO sobe dashboard local:
# os incidentes são reportados ao dashboard central do administrador.
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

ok()   { echo -e "${GREEN}✓${RESET} $*"; }
info() { echo -e "${CYAN}→${RESET} $*"; }
warn() { echo -e "${YELLOW}⚠${RESET} $*"; }
die()  { echo -e "${RED}✗ $*${RESET}" >&2; exit 1; }
header() { echo -e "\n${BOLD}$*${RESET}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLI="node --experimental-strip-types ${SCRIPT_DIR}/src/cli/index.ts"

SERVER_URL="${GUARDIAN_CENTRAL_URL:-}"
AGENT_KEY="${GUARDIAN_CENTRAL_KEY:-}"

usage() {
  echo "Uso: $0 --server <url-do-servidor-central> --key <chave-de-agente>"
  echo ""
  echo "  --server   URL do dashboard central (ex.: https://guardian.empresa.com)"
  echo "  --key      Chave de agente (GUARDIAN_AGENT_KEY definida no servidor)"
  echo ""
  echo "Também aceita as variáveis GUARDIAN_CENTRAL_URL e GUARDIAN_CENTRAL_KEY."
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --server) SERVER_URL="${2:-}"; shift 2 ;;
    --key)    AGENT_KEY="${2:-}";  shift 2 ;;
    -h|--help) usage ;;
    *) die "Argumento desconhecido: $1" ;;
  esac
done

[[ -n "${SERVER_URL}" ]] || usage
[[ -n "${AGENT_KEY}"  ]] || usage

# ── 1. Node.js ────────────────────────────────────────────────────────────────
header "1/4  Verificando Node.js"

if ! command -v node &>/dev/null; then
  die "Node.js não encontrado. Instale Node.js >= 22.6.0: https://nodejs.org"
fi

NODE_VERSION="$(node -e 'process.stdout.write(process.version)')"
NODE_MAJOR="${NODE_VERSION#v}"; NODE_MAJOR="${NODE_MAJOR%%.*}"
if (( NODE_MAJOR < 22 )); then
  die "Node.js ${NODE_VERSION} detectado — versão mínima exigida: 22.6.0"
fi
ok "Node.js ${NODE_VERSION}"

# ── 2. Dependências npm ───────────────────────────────────────────────────────
header "2/4  Instalando dependências npm"

cd "${SCRIPT_DIR}"
if [[ -d node_modules && node_modules -nt package.json ]]; then
  ok "node_modules já atualizado (pulando npm install)"
else
  info "Executando npm install…"
  npm install --silent
  ok "Dependências instaladas"
fi

# ── 3. Gitleaks (opcional) ────────────────────────────────────────────────────
header "3/4  Verificando Gitleaks"

if command -v gitleaks &>/dev/null; then
  ok "Gitleaks já instalado: $(gitleaks version 2>/dev/null || echo 'versão desconhecida')"
else
  warn "Gitleaks não encontrado — o guardian funciona sem ele (degradação graciosa)."
  warn "Para instalar depois, rode: bash ${SCRIPT_DIR}/init.sh"
fi

# ── 4. Conectividade + init ───────────────────────────────────────────────────
header "4/4  Conectando ao servidor central"

if command -v curl &>/dev/null; then
  if curl -sf --max-time 5 "${SERVER_URL%/}/health" &>/dev/null; then
    ok "Servidor central acessível: ${SERVER_URL}"
  else
    warn "Não foi possível alcançar ${SERVER_URL%/}/health agora."
    warn "A instalação continua — os eventos ficam em fila local até o servidor responder."
  fi
fi

info "Registrando hooks no Claude Code e gravando config…"
${CLI} init --central-url "${SERVER_URL}" --central-key "${AGENT_KEY}"
ok "Agente configurado"

# ── Resumo ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}══════════════════════════════════════════${RESET}"
echo -e "${BOLD}  claude-guardian (agente enterprise) pronto${RESET}"
echo -e "${BOLD}══════════════════════════════════════════${RESET}"
echo ""
echo -e "  Servidor central:  ${CYAN}${SERVER_URL}${RESET}"
echo -e "  Incidentes e aprovações são gerenciados pelo administrador"
echo -e "  no dashboard central."
echo ""
echo -e "  ${YELLOW}Reinicie o Claude Code para ativar os hooks.${RESET}"
echo ""
