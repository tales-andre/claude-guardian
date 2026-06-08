#!/usr/bin/env bash
# init.sh — instala dependências, gitleaks e sobe o dashboard do claude-guardian
set -euo pipefail

# ── Cores ─────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

ok()   { echo -e "${GREEN}✓${RESET} $*"; }
info() { echo -e "${CYAN}→${RESET} $*"; }
warn() { echo -e "${YELLOW}⚠${RESET} $*"; }
die()  { echo -e "${RED}✗ $*${RESET}" >&2; exit 1; }
header() { echo -e "\n${BOLD}$*${RESET}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLI="node --experimental-strip-types ${SCRIPT_DIR}/src/cli/index.ts"
DASHBOARD_PORT=7734
PID_FILE="${SCRIPT_DIR}/.dashboard.pid"
LOG_FILE="${SCRIPT_DIR}/.dashboard.log"

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

# ── 3. Gitleaks ───────────────────────────────────────────────────────────────
header "3/4  Instalando Gitleaks"

if command -v gitleaks &>/dev/null; then
  ok "Gitleaks já instalado: $(gitleaks version 2>/dev/null || echo 'versão desconhecida')"
else
  info "Gitleaks não encontrado — instalando…"

  INSTALL_DIR="/usr/local/bin"
  # Fallback para ~/.local/bin se não tiver permissão de escrita em /usr/local/bin
  if [[ ! -w "${INSTALL_DIR}" ]]; then
    INSTALL_DIR="${HOME}/.local/bin"
    mkdir -p "${INSTALL_DIR}"
    warn "Sem permissão em /usr/local/bin — instalando em ${INSTALL_DIR}"
    warn "Certifique-se de que ${INSTALL_DIR} está no seu PATH"
  fi

  if ! command -v curl &>/dev/null; then
    die "curl não encontrado. Instale curl para continuar."
  fi

  # Detecta OS e arquitetura para montar o nome do asset do GitHub Releases
  GL_OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
  GL_ARCH="$(uname -m)"
  case "${GL_ARCH}" in
    x86_64)        GL_ARCH="x64"   ;;
    aarch64|arm64) GL_ARCH="arm64" ;;
    armv7*)        GL_ARCH="armv7" ;;
    i?86)          GL_ARCH="x32"   ;;
  esac

  info "Buscando versão mais recente do Gitleaks…"
  GL_VERSION="$(curl -sf https://api.github.com/repos/gitleaks/gitleaks/releases/latest \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['tag_name'].lstrip('v'))")" \
    || die "Não foi possível consultar a API do GitHub. Verifique sua conexão."

  GL_URL="https://github.com/gitleaks/gitleaks/releases/download/v${GL_VERSION}/gitleaks_${GL_VERSION}_${GL_OS}_${GL_ARCH}.tar.gz"
  info "Baixando Gitleaks v${GL_VERSION} (${GL_OS}/${GL_ARCH})…"

  GL_TMP="$(mktemp -d)"
  trap 'rm -rf "${GL_TMP}"' EXIT

  curl -sSfL "${GL_URL}" | tar -xz -C "${GL_TMP}" gitleaks \
    || die "Falha no download: ${GL_URL}"

  mv "${GL_TMP}/gitleaks" "${INSTALL_DIR}/gitleaks"
  chmod +x "${INSTALL_DIR}/gitleaks"
  trap - EXIT

  # Garante que o diretório de install está no PATH desta sessão
  export PATH="${INSTALL_DIR}:${PATH}"

  if command -v gitleaks &>/dev/null; then
    ok "Gitleaks v${GL_VERSION} instalado em ${INSTALL_DIR}"
  else
    warn "Binário salvo em ${INSTALL_DIR}/gitleaks mas não está no PATH desta sessão."
    warn "Adicione ao seu shell: export PATH=\"${INSTALL_DIR}:\$PATH\""
    warn "O claude-guardian funcionará sem ele (degradação graciosa)."
  fi
fi

# ── 4. claude-guardian init ───────────────────────────────────────────────────
header "4/4  Inicializando claude-guardian"

info "Criando config, banco de dados e registrando hooks no Claude Code…"
${CLI} init --show-token
ok "claude-guardian inicializado"

# ── Dashboard ─────────────────────────────────────────────────────────────────
header "     Subindo dashboard"

# Para instância anterior se existir
if [[ -f "${PID_FILE}" ]]; then
  OLD_PID="$(cat "${PID_FILE}")"
  if kill -0 "${OLD_PID}" 2>/dev/null; then
    info "Encerrando instância anterior (PID ${OLD_PID})…"
    kill "${OLD_PID}" 2>/dev/null || true
    sleep 0.5
  fi
  rm -f "${PID_FILE}"
fi

# Verifica se a porta já está em uso (por outro processo)
if command -v ss &>/dev/null; then
  PORT_IN_USE="$(ss -tlnH sport = "${DASHBOARD_PORT}" 2>/dev/null || true)"
elif command -v lsof &>/dev/null; then
  PORT_IN_USE="$(lsof -ti tcp:"${DASHBOARD_PORT}" 2>/dev/null || true)"
else
  PORT_IN_USE=""
fi

if [[ -n "${PORT_IN_USE}" ]]; then
  warn "Porta ${DASHBOARD_PORT} já em uso — o dashboard pode já estar rodando."
  warn "Para forçar reinício: kill \$(lsof -ti tcp:${DASHBOARD_PORT}) && bash init.sh"
else
  nohup ${CLI} serve \
    > "${LOG_FILE}" 2>&1 &
  DASHBOARD_PID=$!
  echo "${DASHBOARD_PID}" > "${PID_FILE}"

  # Aguarda o servidor aceitar conexões (até 5s)
  READY=0
  for i in $(seq 1 10); do
    sleep 0.5
    if curl -sf "http://127.0.0.1:${DASHBOARD_PORT}/health" &>/dev/null; then
      READY=1; break
    fi
  done

  if (( READY )); then
    ok "Dashboard iniciado (PID ${DASHBOARD_PID})"
  else
    warn "Dashboard iniciado mas ainda não respondeu em 5s."
    warn "Verifique os logs: tail -f ${LOG_FILE}"
  fi
fi

# ── Resumo ────────────────────────────────────────────────────────────────────
CONFIG_FILE="${HOME}/.config/claude-guardian/config.json"
TOKEN=""
if [[ -f "${CONFIG_FILE}" ]] && command -v node &>/dev/null; then
  TOKEN="$(node -e "
    try {
      const c = JSON.parse(require('fs').readFileSync('${CONFIG_FILE}','utf8'));
      process.stdout.write(c.dashboardToken || '');
    } catch {}
  " 2>/dev/null || true)"
fi

echo ""
echo -e "${BOLD}══════════════════════════════════════════${RESET}"
echo -e "${BOLD}  claude-guardian pronto${RESET}"
echo -e "${BOLD}══════════════════════════════════════════${RESET}"
echo ""
echo -e "  Dashboard:  ${CYAN}http://localhost:${DASHBOARD_PORT}/dashboard${RESET}"
[[ -n "${TOKEN}" ]] && echo -e "  Token:      ${TOKEN}"
echo ""
echo -e "  Logs:       tail -f ${LOG_FILE}"
[[ -f "${PID_FILE}" ]] && echo -e "  Parar:      kill \$(cat ${PID_FILE})"
echo ""
echo -e "  ${YELLOW}Reinicie o Claude Code para ativar os hooks.${RESET}"
echo ""
