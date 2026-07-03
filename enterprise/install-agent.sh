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
INSTALL_SERVICE=1

usage() {
  echo "Uso: $0 --server <url-do-servidor-central> --key <chave-de-agente> [--no-service]"
  echo ""
  echo "  --server      URL do dashboard central (ex.: https://guardian.empresa.com)"
  echo "  --key         Chave de agente (GUARDIAN_AGENT_KEY definida no servidor)"
  echo "  --no-service  Não instala o daemon local como serviço (systemd/launchd)"
  echo ""
  echo "Também aceita as variáveis GUARDIAN_CENTRAL_URL e GUARDIAN_CENTRAL_KEY."
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --server) SERVER_URL="${2:-}"; shift 2 ;;
    --key)    AGENT_KEY="${2:-}";  shift 2 ;;
    --no-service) INSTALL_SERVICE=0; shift ;;
    -h|--help) usage ;;
    *) die "Argumento desconhecido: $1" ;;
  esac
done

[[ -n "${SERVER_URL}" ]] || usage
[[ -n "${AGENT_KEY}"  ]] || usage

# ── 1. Node.js ────────────────────────────────────────────────────────────────
header "1/5  Verificando Node.js"

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
header "2/5  Instalando dependências npm"

cd "${SCRIPT_DIR}"
if [[ -d node_modules && node_modules -nt package.json ]]; then
  ok "node_modules já atualizado (pulando npm install)"
else
  info "Executando npm install…"
  npm install --silent
  ok "Dependências instaladas"
fi

# ── 3. Gitleaks (opcional) ────────────────────────────────────────────────────
header "3/5  Verificando Gitleaks"

if command -v gitleaks &>/dev/null; then
  ok "Gitleaks já instalado: $(gitleaks version 2>/dev/null || echo 'versão desconhecida')"
else
  warn "Gitleaks não encontrado — o guardian funciona sem ele (degradação graciosa)."
  warn "Para instalar depois, rode: bash ${SCRIPT_DIR}/init.sh"
fi

# ── 4. Conectividade + init ───────────────────────────────────────────────────
header "4/5  Conectando ao servidor central"

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

# ── 5. Daemon local como serviço ──────────────────────────────────────────────
# A extensão de navegador é fail-closed: sem o daemon respondendo em
# 127.0.0.1:7734, os sites de IA ficam bloqueados. Por isso o daemon precisa
# sobreviver a reboot — systemd no Linux/WSL, launchd no macOS.
header "5/5  Instalando o daemon local como serviço"

NODE_BIN="$(command -v node)"
SERVICE_TPL_DIR="${SCRIPT_DIR}/enterprise/service"

install_systemd_service() {
  local unit_src="${SERVICE_TPL_DIR}/claude-guardian.service.tpl"
  local unit_dst="/etc/systemd/system/claude-guardian.service"
  local run_user="${SUDO_USER:-$(id -un)}"

  if [[ ! -d /run/systemd/system ]]; then
    warn "systemd não está ativo nesta máquina."
    if grep -qi microsoft /proc/version 2>/dev/null; then
      warn "WSL sem systemd: rode o daemon no Windows (enterprise/install-agent.ps1)"
      warn "e os hooks desta distro alcançam ele via http://localhost:7734."
    fi
    return 1
  fi

  local tmp_unit
  tmp_unit="$(mktemp)"
  sed -e "s|__NODE__|${NODE_BIN}|g" \
      -e "s|__REPO__|${SCRIPT_DIR}|g" \
      -e "s|__USER__|${run_user}|g" \
      "${unit_src}" > "${tmp_unit}"

  if [[ $(id -u) -eq 0 ]]; then
    install -m 0644 "${tmp_unit}" "${unit_dst}"
    systemctl daemon-reload
    systemctl enable --now claude-guardian.service
  else
    info "Privilégios de root necessários para registrar o serviço systemd…"
    sudo install -m 0644 "${tmp_unit}" "${unit_dst}"
    sudo systemctl daemon-reload
    sudo systemctl enable --now claude-guardian.service
  fi
  rm -f "${tmp_unit}"
  ok "Serviço systemd claude-guardian ativo (reinicia sozinho após reboot)"
}

install_launchd_service() {
  local plist_src="${SERVICE_TPL_DIR}/claude-guardian.launchd.plist.tpl"
  local plist_dst="${HOME}/Library/LaunchAgents/com.claude-guardian.daemon.plist"
  if [[ $(id -u) -eq 0 ]]; then
    plist_dst="/Library/LaunchAgents/com.claude-guardian.daemon.plist"
  fi

  mkdir -p "$(dirname "${plist_dst}")"
  sed -e "s|__NODE__|${NODE_BIN}|g" \
      -e "s|__REPO__|${SCRIPT_DIR}|g" \
      "${plist_src}" > "${plist_dst}"
  launchctl unload "${plist_dst}" 2>/dev/null || true
  launchctl load -w "${plist_dst}"
  ok "LaunchAgent com.claude-guardian.daemon carregado (inicia no login)"
}

if [[ ${INSTALL_SERVICE} -eq 1 ]]; then
  case "$(uname -s)" in
    Linux)
      install_systemd_service || warn "Serviço não instalado — suba manualmente com: npm run serve"
      ;;
    Darwin)
      install_launchd_service || warn "Serviço não instalado — suba manualmente com: npm run serve"
      ;;
    *)
      warn "SO não reconhecido para instalação de serviço — suba manualmente com: npm run serve"
      ;;
  esac
else
  info "--no-service: daemon não instalado como serviço (suba com npm run serve)"
fi

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
