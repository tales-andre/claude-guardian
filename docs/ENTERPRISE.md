# claude-guardian — Modo Enterprise

O claude-guardian tem dois modos de operação. **Nada muda no modo local** — o
modo enterprise é 100% aditivo.

| | Modo local | Modo enterprise |
|---|---|---|
| Instalação | `bash init.sh` | Servidor: Docker/EKS · Máquinas: `enterprise/install-agent.sh` |
| Dashboard | Local (`localhost:7734`) | Central, um para toda a empresa |
| Banco | SQLite local | PostgreSQL (RDS/Aurora) |
| Decisão de bloqueio | Local | Local (mesma latência) |
| Aprovações | Admin local | Admin no dashboard central |

## Arquitetura

```
┌─────────────────────┐         ┌──────────────────────────────┐
│ Máquina do dev       │         │ Servidor central (EKS/Docker) │
│                      │  HTTPS  │                              │
│ Claude Code          │ ──────▶ │  Dashboard do administrador  │
│  └─ hooks guardian   │         │  POST /api/agent/ingest      │
│      ├─ scan local   │         │  GET  /api/agent/approvals   │
│      ├─ SQLite local │         │           │                  │
│      └─ outbox ──────┘         │      PostgreSQL (RDS)        │
└─────────────────────┘         └──────────────────────────────┘
```

- **A decisão continua local**: os hooks escaneiam e bloqueiam na máquina, com
  a mesma latência de hoje. O servidor central é observabilidade + governança.
- **Store-and-forward**: cada incidente é gravado num *outbox* em disco e um
  processo em background faz o envio. Servidor fora do ar não trava ninguém —
  os eventos ficam em fila e são reenviados depois.
- **Segredos nunca saem da máquina**: o payload enviado ao central contém só
  metadados (tipo, severidade, snippet mascarado) — nunca o `rawValue`.
- **Aprovações centralizadas**: quando uma política dispara
  `require-approval` (ou o dev usa `[request-exception: motivo]`), a
  solicitação aparece no dashboard central. Depois que o admin aprova, o hook
  da máquina consulta o central e libera automaticamente.
- **Audit trail central**: o servidor mantém sua própria cadeia hash
  (SHA-256 encadeado) verificável em `/api/audit/verify`.

## 1. Subindo o servidor central

### Opção A — Docker Compose (avaliação / empresas pequenas)

```bash
cp deploy/docker.env.example .guardian.env
# edite .guardian.env — gere chaves com: openssl rand -hex 24
docker compose --env-file .guardian.env up -d
```

Dashboard: `http://<host>:7734/dashboard` (use o `GUARDIAN_DASHBOARD_TOKEN`).

### Opção B — EKS com Helm (produção)

1. Build e push da imagem:

```bash
docker build -t <conta>.dkr.ecr.<região>.amazonaws.com/claude-guardian:1.0.0 .
docker push <conta>.dkr.ecr.<região>.amazonaws.com/claude-guardian:1.0.0
```

2. Instale o chart (com RDS Postgres já provisionado):

```bash
helm install guardian deploy/helm/claude-guardian \
  --set image.repository=<conta>.dkr.ecr.<região>.amazonaws.com/claude-guardian \
  --set image.tag=1.0.0 \
  --set database.url="postgres://guardian:SENHA@meu-rds.amazonaws.com:5432/guardian" \
  --set auth.dashboardToken="$(openssl rand -hex 24)" \
  --set auth.agentKey="$(openssl rand -hex 24)" \
  --set ingress.enabled=true \
  --set ingress.host=guardian.minhaempresa.com
```

Para não passar credenciais na linha de comando, use Secrets existentes:

```bash
kubectl create secret generic guardian-auth \
  --from-literal=GUARDIAN_DASHBOARD_TOKEN=... \
  --from-literal=GUARDIAN_AGENT_KEY=...
kubectl create secret generic guardian-db \
  --from-literal=DATABASE_URL=postgres://...

helm install guardian deploy/helm/claude-guardian \
  --set auth.existingSecret=guardian-auth \
  --set database.existingSecret=guardian-db \
  --set ingress.enabled=true --set ingress.host=guardian.minhaempresa.com
```

O Ingress traz anotações de exemplo para o AWS Load Balancer Controller
(`values.yaml → ingress.annotations`). Exponha via HTTPS (ACM) — os agentes
enviam a chave em header.

### Variáveis de ambiente do servidor

| Variável | Função |
|---|---|
| `DATABASE_URL` / `GUARDIAN_DATABASE_URL` | Postgres; vazio = SQLite local |
| `GUARDIAN_DASHBOARD_TOKEN` | Token do admin no dashboard |
| `GUARDIAN_AGENT_KEY` | Chave compartilhada dos agentes (sem ela, ingestão desabilitada — fail-closed) |
| `GUARDIAN_BIND_HOST` | Bind address (`0.0.0.0` em container) |
| `GUARDIAN_PORT` | Porta (padrão 7734) |
| `GUARDIAN_DB_PATH` | Caminho do SQLite (só sem `DATABASE_URL`) |

## 2. Instalando o agente nas máquinas

Em cada máquina de desenvolvedor (ou via MDM/Ansible/Intune):

```bash
git clone https://github.com/<org>/claude-guardian.git
cd claude-guardian
bash enterprise/install-agent.sh \
  --server https://guardian.minhaempresa.com \
  --key <GUARDIAN_AGENT_KEY>
```

O script registra os hooks no Claude Code, grava `centralUrl`/`centralApiKey`
na config (`~/.config/claude-guardian/config.json`) e instala o **daemon local
como serviço** (passo 5). Reinicie o Claude Code.

No Windows, use o equivalente PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File enterprise\install-agent.ps1 `
  -Server https://guardian.minhaempresa.com -Key <GUARDIAN_AGENT_KEY>
```

Equivalente manual:

```bash
npm install
node --experimental-strip-types src/cli/index.ts init \
  --central-url https://guardian.minhaempresa.com \
  --central-key <GUARDIAN_AGENT_KEY>
```

### 2.1 Daemon local como serviço

A extensão de navegador (`extension/`) é **fail-closed**: se o daemon local não
responder em `http://127.0.0.1:7734`, o envio nos sites de IA é bloqueado. Por
isso o daemon precisa sobreviver a reboot/logon — o instalador cuida disso:

| Plataforma | Mecanismo | Instalado por |
|---|---|---|
| Linux (com systemd) | unit `claude-guardian.service` (`Restart=always`) | `install-agent.sh` |
| macOS | LaunchAgent `com.claude-guardian.daemon` (`KeepAlive`) | `install-agent.sh` |
| Windows | tarefa agendada `ClaudeGuardianDaemon` no logon | `install-agent.ps1` |

Os templates ficam em `enterprise/service/`. Use `--no-service` / `-NoService`
para pular (ex.: máquina que só usa hooks de CLI e não navega).

### 2.2 WSL

Cenário recomendado: **daemon no Windows** (via `install-agent.ps1`) servindo
os dois lados —

- a extensão dos browsers do Windows fala com `http://127.0.0.1:7734`;
- os hooks dentro da distro WSL2 alcançam o mesmo daemon via
  `http://localhost:7734` (encaminhamento de localhost do WSL2).

Se a distro tem systemd habilitado (`systemd=true` no `wsl.conf`), o
`install-agent.sh` também consegue instalar o serviço dentro do WSL; nesse caso
o daemon atende só os hooks da distro — browsers do Windows continuam
precisando do daemon Windows. **Valide o encaminhamento de localhost no piloto**
(há configurações de rede WSL, como `networkingMode=mirrored`, que mudam o
comportamento).

## 3. Fluxo de exceção no modo enterprise

1. Dev é bloqueado e recebe o link `https://guardian.minhaempresa.com/request-approval/<incidente>`
   (ou usa `[request-exception: motivo]` no prompt).
2. A solicitação aparece como *pending* no dashboard central.
3. Admin aprova com TTL.
4. No próximo prompt, o hook da máquina consulta o central
   (`GET /api/agent/approvals/active`) e libera — sem nenhuma ação manual na
   máquina do dev.

A consulta ao central tem timeout de 1,5 s e fallback silencioso: se o servidor
estiver indisponível, vale o comportamento local fail-safe (bloqueia).

## 4. Segurança

- **Autenticação em duas camadas**: `X-Guardian-Token` (admin/dashboard) e
  `X-Guardian-Agent-Key` (máquinas). Endpoints `/api/agent/*` são fail-closed:
  sem `GUARDIAN_AGENT_KEY` configurada no servidor, nada é aceito.
- **`rawValue` nunca é transmitido**: o servidor ainda descarta o campo por
  defesa em profundidade caso receba payload de um cliente antigo.
- **Idempotência**: reentregas do outbox não duplicam incidentes
  (upsert por id).
- **Outbox com teto** (500 eventos) para nunca encher o disco do funcionário.
- Rode o dashboard sempre atrás de TLS (ALB + ACM no EKS).
