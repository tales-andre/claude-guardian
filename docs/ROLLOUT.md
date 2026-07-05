# Plano de rollout — deploy interno em frota

Plano faseado para implantar o claude-guardian em centenas de máquinas com
control-plane no EKS. Cada fase tem **critério de saída** — não avance sem
cumpri-lo. Princípio geral: superfícies maduras primeiro; o componente que
cria risco novo (proxy HTTPS MITM) por último.

## Fase 1 — Control-plane + agentes Claude Code (modo observação)

**Escopo**

- Servidor central no EKS: Helm chart (`deploy/helm/claude-guardian`) +
  Postgres gerenciado (RDS/Aurora). Ver `docs/EKS-DEPLOY.md`.
- Dashboard atrás de SSO corporativo: `ingress.oidc.*` no chart
  (ALB + OIDC — ver `docs/ENTERPRISE.md`).
- Backup: snapshot automático do RDS habilitado (retenção >= 7 dias).
- Agentes nas máquinas: `enterprise/install-agent.sh --server <url>
  --enroll-token <segredo>` (Linux/macOS) ou `install-agent.ps1
  -EnrollToken` (Windows). Cada máquina recebe **chave individual
  revogável** (`/api/agent-keys` no dashboard).
- Hooks do Claude Code + proxy MCP (Claude Desktop/Kiro) — ambos entram
  juntos: o proxy MCP não depende de CA nem de rede, só do `init`.

**Modo observação (2 semanas)**: políticas de PII/medium em `redact` (ou
`allow` + auditoria), mantendo `block` apenas para segredos critical/high.
Objetivo: medir falso positivo real da frota antes de bloquear gente.

**Critério de saída**

- Taxa de falso positivo aceitável nos incidentes do período (analisar por
  detector no dashboard; ajustar allowlist/política antes de endurecer).
- `tests/corpus.test.ts` verde após qualquer ajuste de detector.
- Frota visível em `/api/fleet` com heartbeats regulares (sem `stale`
  sistemático).
- Chave legada desligada: `GUARDIAN_ALLOW_LEGACY_AGENT_KEY=false` após
  100% das máquinas migradas para enrollment.

## Fase 2 — Extensão de navegador

**Pré-requisito: definição de MDM** (Intune/Jamf/GPO). A distribuição muda
de desenho conforme a resposta:

- **Com MDM**: force-install da extensão + configuração via
  `chrome.storage.managed` (a página de opções fica somente leitura).
  Políticas por canal compiladas por `emit-managed-settings
  --extension-id` (Linux JSON, Windows `.reg`, macOS `.mobileconfig`,
  Firefox `policies.json`).
- **Sem MDM**: instalação assistida pelo instalador + monitoração de
  remoção via heartbeat — extensão silenciosa com máquina viva aparece
  como `tampered` em `/api/fleet`. Aceitar que o controle é detectivo,
  não preventivo.

**Escopo de providers**: somente os validados com tráfego real —
claude.ai, ChatGPT e Gemini. Copilot/Mistral/Adapta ficam fora até
passarem pela validação de `docs/ADAPTER-VALIDATION.md` (adapter não
validado em fail-closed = falso bloqueio para a frota inteira).

**Critério de saída**

- Extensão presente e pingando em >= 95% das máquinas com navegador.
- `extractFailures` por provider estável (~zero) por 2 semanas — é o
  sinal de drift de endpoint dos sites.

## Fase 3 — Proxy HTTPS MITM (Claude Desktop)

Último componente por decisão: é o único que **cria risco novo** — uma CA
confiada pela máquina. Não iniciar antes de:

1. **Modelo de CA decidido e documentado**: a CA é **por máquina**
   (`<db-dir>/guardian-ca.crt|key`, gerada localmente) — comprometimento
   fica confinado ao próprio host. A instalação da confiança é local
   (não há "uma CA da frota" para distribuir por MDM).
2. **Proteção da chave da CA**: permissões restritas ao usuário do
   daemon; a chave nunca sai da máquina.
3. **Tamper heartbeat implementado**: proxy desligado/contornado precisa
   aparecer no fleet como `tampered` (hoje o heartbeat cobre agente e
   extensão; falta o sinal específico do proxy).

**Critério de saída**: prompts/anexos do Claude Desktop aparecem como
incidentes `DesktopPrompt`/`DesktopUpload` nas máquinas-piloto, sem
quebra de conectividade reportada, antes de expandir para a frota.

## Fora de escopo (decidido)

- Shadow AI (bloqueio de IAs não aprovadas): já coberto pelo firewall
  corporativo.
- Prompt injection / sanitização de resposta (ingresso): o produto é DLP
  de egresso por design.
