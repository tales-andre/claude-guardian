# Evoluir o claude-guardian para plataforma de governança de frota (multi-tool, anti-adulteração)

## Papel

Você é engenheiro(a) sênior trabalhando no repositório `claude-guardian` (DLP que integra com agentes de código via hooks). Implemente a evolução abaixo de forma incremental, mantendo o modo local atual 100% funcional e sem regressões. Node >= 22.6.0, TypeScript executado direto (sem build), testes em vitest, lint/format Biome. Rode `npm run ci` ao final de cada fase.

## Contexto do que já existe (não reconstruir)

- Engine de scan agnóstico: `src/engine/` (`scan`/`scanSync`, dedup em duas passagens, allowlist) e detectores em `src/engine/detectors/` implementando a interface `Detector`.
- Três hooks acoplados ao Claude Code em `src/hooks/` (`pre-tool-use.ts`, `post-tool-use.ts`, `user-prompt-submit.ts`): leem JSON do stdin, rodam `scanSync` dentro de `engineTimeoutMs` (500 ms, fail-closed), `exit 2` bloqueia.
- Policy engine `src/lib/policy.ts`, approval `src/lib/approval.ts`, audit hash-chain `src/lib/audit.ts`, config Zod `src/config/`.
- Modo enterprise aditivo: central server (`src/server/`, `GuardianStore` com `SqliteStore`/`PgStore`), cliente com outbox em `src/lib/central.ts`, deploy Docker/Helm.

## Objetivo

Adicionar, de forma aditiva: (1) suporte multi-tool (Claude Code + Kiro) via adaptador; (2) anti-adulteração baseada em managed settings + detecção; (3) detector de evasão por troca de provider; (4) detecção tiered (regex sync no bloqueio, ML/verificação/LLM no caminho async/central); (5) control-plane que compila e distribui managed settings + fleet dashboard. **Modelo de ameaça honesto: tamper-evidente/resistente/auto-revertido, NÃO tamper-proof — devs têm admin local.** Não prometer prevenção absoluta em nenhuma mensagem, log ou doc.

## Fases (implementar e validar uma por vez, com testes antes do código)

**Fase 1 — HostAdapter (multi-tool).**
- Criar `src/hosts/` com interface `HostAdapter` que normaliza o payload de hook de cada ferramenta para um tipo interno único (`tool`, `toolInput`, `cwd`, `transcript`, etc.) e mapeia o resultado de volta (exit code / JSON de bloqueio).
- Implementar `claude.ts` (extrair a lógica de parse hoje embutida em `src/hooks/`) e `kiro.ts` (Kiro usa o mesmo contrato PreToolUse/PostToolUse com `exit 2`; matchers por nomes canônicos `fs_read`, `fs_write`, `execute_bash`, `use_aws` e aliases `read`/`write`/`shell`/`aws` — normalizar para os nomes que o policy engine já espera).
- Os 3 hooks passam a detectar o host (via env/flag/forma do payload) e delegar ao adapter. Engine, policy, audit permanecem intactos.

**Fase 2 — Detector de evasão + ConfigChange.**
- Novo detector/checagem que sinaliza presença de `ANTHROPIC_BASE_URL` ou `CLAUDE_CODE_USE_BEDROCK|VERTEX|FOUNDRY|MANTLE|ANTHROPIC_AWS` no ambiente do hook — provider-switch bypassa managed settings, então é evento de evasão: registrar no audit e enviar ao central como incidente de alta severidade (não bloqueia o fluxo do dev, mas é visível).
- Implementar handler de `ConfigChange` hook (contrato do Claude Code) que loga/encaminha mudanças de configuração ao central.

**Fase 3 — Detecção tiered.**
- Caminho síncrono (PreToolUse): manter só regex/entropia rápidos dentro do orçamento de 500 ms.
- Caminho assíncrono (PostToolUse + central): adicionar detectores pesados como `extraDetector`s rodando fora do bloqueio — NER/PII estilo Presidio, verificação ao-vivo de credencial estilo TruffleHog, e o analisador LLM-based já existente. Nenhum modelo pesado pode entrar no caminho síncrono. Decisão de rodar local vs central deve ser configurável.

**Fase 4 — Control-plane (estende o central existente).**
- No central server: autoria de política/allowlist que **compila** dois artefatos de managed settings: (a) payload server-managed (para o console claude.ai) e (b) arquivo endpoint-managed (`managed-settings.json` + `managed-mcp.json`) para distribuição via MDM. Incluir nas saídas: `allowManagedHooksOnly: true`, `forceRemoteSettingsRefresh: true`, registro do hook do guardian, e a allowlist MCP (`allowedMcpServers`/`deniedMcpServers` no server; `managed-mcp.json` no endpoint).
- Fleet dashboard: cada máquina envia heartbeat (versão do guardian, hash da config managed efetiva, status, incidentes). Dashboard lista máquinas como healthy/stale/tampered (hash diferente do esperado = tampered). Endpoint de ingestão autenticado pela chave de agente já existente.

## Regras

- Tudo aditivo: com os novos campos de config vazios, o comportamento local atual é idêntico. Nenhuma regressão nos testes existentes.
- Hooks nunca usam a camada async `GuardianStore`. Caminho síncrono continua fail-closed em timeout.
- Valores crus de segredo nunca são persistidos nem enviados ao central (só metadata: `dataType`, `severity`, `snippet`).
- Não distribuir config diretamente pelo guardian: o control-plane gera o artefato; quem empurra é o console/MDM.
- TDD: escreva o teste primeiro, veja falhar, implemente. Cada detector novo tem teste hermético.
- Siga o estilo do código existente (Biome, convenções dos detectores/adapters). `npm run ci` verde ao fim de cada fase.

## Critérios de qualidade

- Kiro e Claude passam pelo mesmo engine sem código duplicado de scan.
- Mensagens ao usuário e docs descrevem o guarantee como detecção+reversão contra dev admin, nunca como prevenção absoluta.
- Latência do PreToolUse não aumenta (modelo pesado fica no async).
- Cobertura de teste para: adapter Kiro, detector de evasão, compilação dos artefatos de managed settings, e cálculo de status tampered no fleet.

## Edge cases

- Payload de hook de host desconhecido → fail-closed com erro claro, nunca allow silencioso.
- WSL lendo só `/etc/claude-code` por padrão → documentar `wslInheritsWindowsSettings: true` quando a policy vem do Windows.
- `managed-mcp.json` não pode ir via server-managed → garantir que a compilação coloca a allowlist MCP nas chaves certas por canal.
- Central indisponível → cliente segue em modo local (timeout 1.5 s, fallback silencioso), heartbeat vai pro outbox.
