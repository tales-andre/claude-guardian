# Guardian GUI Gateway — bloqueio DLP no Claude Desktop e Kiro IDE

**Data:** 2026-07-04
**Status:** design aprovado, aguardando plano de implementação

## Problema

Hoje o `claude-guardian` bloqueia efetivamente em três superfícies:

- **Claude Code CLI** (incl. WSL) — via hooks `PreToolUse`/`PostToolUse`/`UserPromptSubmit`.
- **Kiro CLI** — via `HostAdapter` (`src/hosts/index.ts`) sobre o mesmo contrato de hook.
- **Browsers** (claude.ai, ChatGPT, Gemini…) — via extensão MV3 que faz hook de `fetch`/XHR.

Duas superfícies GUI ficam **descobertas**: **Claude Desktop** e **Kiro IDE**. Elas não expõem o ciclo de hooks bloqueante (`exit 2`) que o Claude Code oferece:

- O **Claude Desktop** é um app Electron que manda prompt e anexos direto para `api.anthropic.com` por HTTPS, e só acessa arquivos locais via **MCP servers**. Não há hook local de prompt nem de leitura de arquivo.
- O **Kiro IDE** acessa recursos via MCP e (possivelmente) via o mesmo agente do kiro-cli.

O objetivo é **paridade de comportamento de bloqueio** com o que já existe no CLI e na extensão: barrar secrets/PII no **prompt do usuário** e no **envio de arquivos** (uploads/anexos), nessas duas superfícies.

## Princípio de design

**Nenhum engine novo.** O daemon local existente ganha dois novos *adaptadores de ingresso*. Ambos alimentam exatamente o mesmo pipeline já usado por hooks e extensão:

```
scanSync() → evaluatePolicy() → audit(hash-chain) → central(outbox)
```

Assim o comportamento de bloqueio é idêntico nas cinco superfícies, e detectores/políticas/allowlist/aprovações valem para todas sem duplicação.

## Arquitetura

```
                 ┌───────────────── daemon local (já existe) ─────────────────┐
Claude Desktop ──┤  :PROXY  HTTPS seletivo (MITM só p/ hosts Anthropic)        │
              ──►┤            └─ buffer request → gui-scan → policy            │──► api.anthropic.com
                 │                                                             │      (se allow)
Claude Desktop ──┤  :MCP    proxy dos MCP servers (stdio + http)              │──► MCP servers reais
Kiro IDE      ──►┤            └─ JSON-RPC tools/call args+results → scan       │      (se allow)
                 │                                                             │
                 │  scanSync ─ evaluatePolicy ─ audit(hash-chain) ─ central ───┘
                 └─────────────────────────────────────────────────────────────┘
```

### Ponto-chave: MITM seletivo

O proxy HTTPS opera em modo **passthrough por padrão** (túnel CONNECT puro, sem tocar no TLS) e só faz **interceptação (MITM) nos hosts da Anthropic** — `api.anthropic.com` e o endpoint de Files. Todo o resto do tráfego da máquina passa intocado. Isso:

- reduz o blast-radius de um eventual cert pinning a um único vendor;
- evita quebrar aplicações não relacionadas;
- mantém o escopo do que é escaneado alinhado ao DLP (só tráfego de IA).

Decisão explícita de escopo: **o Kiro IDE NÃO é interceptado na rede.** Ele é coberto por proxy MCP + tentativa de hook. Endpoints AWS (bedrock/q/codewhisperer) ficam fora do MITM por serem mais frágeis (SigV4/pinning).

## Componentes novos

Tudo em Node, sem etapa de build (mantém o padrão `--experimental-strip-types`).

| Componente | Arquivo | Papel |
|---|---|---|
| Proxy HTTPS seletivo | `src/proxy/https-proxy.ts` | Servidor de proxy que trata CONNECT. Passthrough por padrão; nos hosts Anthropic, termina o TLS com a CA do guardian, bufferiza o body da request, chama `gui-scan`, e conforme a policy **bloqueia (4xx sintético, nunca encaminha)** / **redige (reescreve o body)** / **encaminha**. |
| Proxy MCP | `src/proxy/mcp-proxy.ts` | Shim que envolve cada MCP server configurado. Para servers stdio, faz spawn do binário real e senta no meio do stream JSON-RPC; para servers HTTP, encaminha. Escaneia `tools/call` params (egress) e results (ingress) e bloqueia com erro JSON-RPC. |
| Adaptador de scan GUI | `src/lib/gui-scan.ts` | Espelho de `src/lib/web-scan.ts`. Traduz a request da Anthropic e as chamadas MCP em **tools virtuais** — `DesktopPrompt`, `DesktopUpload`, `McpToolCall` — e roda o pipeline. Findings chegam sem `rawValue` ao serem persistidos, como no resto do sistema. |
| Artefatos MDM de CA/proxy | `src/lib/browser-policies.ts` / `src/lib/managed-settings.ts` | Passam a emitir a **CA do guardian** (geração + fingerprint), o payload de *trust* dessa CA e a configuração de proxy do SO por canal: `.mobileconfig` (macOS), `.reg` (Windows), JSON de policy (Linux). |
| Instalação | `src/cli/commands/init.ts`, `enterprise/install-agent.sh`, `enterprise/install-agent.ps1` | Sobem os dois listeners, apontam o proxy do SO para o daemon, e **reescrevem** `claude_desktop_config.json` e o `mcp.json` do Kiro para rotear cada MCP server pelo shim. Idempotente e reversível (guarda backup do config original). |
| Detecção de host | `src/hosts/index.ts` | Ganha `claude-desktop` e `kiro-ide` no `detectHost` + normalização de payload dessas origens. |
| Fleet/tamper | reuso de `machines` + `POST /api/extension/heartbeat` | O proxy reporta heartbeat: listeners vivos, CA presente no trust store, interceptação ativa. Ausência/adulteração → status `tampered` (via `computeMachineStatus`, já existente). |

## Fluxo de dados (idêntico ao caminho web existente)

1. Cliente (Desktop/Kiro IDE) faz a request → chega ao listener (HTTPS ou MCP).
2. Adaptador bufferiza e traduz para tool virtual + texto a escanear (`gui-scan`).
3. `scanSync` roda todos os detectores; dedup e allowlist aplicados como sempre.
4. `evaluatePolicy(findings, tool, rules)` retorna a ação de maior prioridade.
5. Ação:
   - **block** → resposta de erro sintética (HTTP 4xx com corpo explicativo / erro JSON-RPC). A request **nunca** chega ao upstream.
   - **require-approval** → cria `Approval` com escopo `tool:dataTypes`; bloqueia com URL do dashboard; libera nas próximas chamadas se houver aprovação ativa (checa central com timeout 1.5 s, fallback local).
   - **redact** → reescreve o body/params removendo os valores sensíveis e encaminha.
   - **allow** → encaminha intocado.
6. Incidente persistido (sem `rawValue`) → audit hash-chain → outbox central (store-and-forward).

## Cobertura por superfície (matriz final)

| Superfície | Prompt | Envio de arquivo | Tools/MCP | Mecanismo novo |
|---|---|---|---|---|
| Claude Code CLI (WSL) | ✅ já | ✅ já | ✅ já | — |
| **Claude Desktop** | 🆕 HTTPS MITM | 🆕 HTTPS MITM (anexo + Files API) | 🆕 proxy MCP | ✅ |
| Kiro CLI | ✅ já | ✅ já | ✅ já | — |
| **Kiro IDE** | 🆕 hook *se* aceitar | 🆕 hook / proxy MCP | 🆕 proxy MCP | ✅ |
| Browsers | ✅ já | ✅ já | — | — |

Kiro IDE não recebe MITM: o prompt fica coberto **apenas se** o IDE aceitar o contrato de hook do kiro-cli (validado no spike da Fase 1). Isso é uma limitação aceita conscientemente.

## Fases de entrega

- **Fase 0 — Spike de pinning (bloqueante).** Subir um MITM de teste e confirmar que o Claude Desktop aceita a CA do guardian sem cert pinning. **Nenhum MITM vai a produção antes deste passo passar.** Se pinar: fallback para injeção no renderer Electron só para o prompt (abordagem documentada como plano B, fora do escopo default).
- **Fase 1 — Proxy MCP (sem CA).** Cobre acesso a arquivos e tools via MCP no Claude Desktop e no Kiro IDE. Inclui o spike "Kiro IDE aceita o hook do kiro-cli?". Valor imediato, zero dependência de CA.
- **Fase 2 — Proxy HTTPS + CA/MDM.** Fecha a paridade de **prompt + anexo** no Claude Desktop. Geração de CA, distribuição de trust + proxy via MDM, reescrita do proxy do SO.
- **Fase 3 — Fleet/tamper.** Heartbeat do proxy (listeners vivos, CA presente, interceptação ativa) → status `tampered` no fleet existente.

## Riscos

| Risco | Mitigação |
|---|---|
| **Cert pinning no Claude Desktop** quebra o MITM | Spike bloqueante na Fase 0; MITM seletivo limita o dano; plano B (injeção no renderer) documentado. |
| **CA não confiada** pelo app Electron | Electron costuma usar o cert store do SO; validado no spike; distribuição via MDM que já existe. |
| **Updates do Desktop** revertem config de proxy/MCP | Instalação idempotente + heartbeat de tamper detecta e o fleet sinaliza. |
| **Latência** do buffer de request | DLP tolera; scan é `scanSync` (<500 ms, mesmo orçamento dos hooks); só hosts Anthropic são interceptados. |
| **Kiro IDE sem hook** deixa prompt descoberto | Aceito conscientemente; proxy MCP ainda cobre arquivos/tools; reavaliar MITM AWS se necessário no futuro. |

## Testes

- **Unit:** parsers de `gui-scan` e `mcp-proxy` com fixtures de request real da Anthropic (prompt, anexo base64, Files API) e de mensagens JSON-RPC MCP.
- **Integração:** upstream fake para provar block/redact/allow ponta-a-ponta no proxy HTTPS; server MCP fake para o shim.
- **Reuso:** suites existentes de engine/policy/audit valem sem alteração (o pipeline é o mesmo).

## Fora de escopo (YAGNI)

- MITM de endpoints AWS/Bedrock para o Kiro IDE.
- Scan da **resposta** do modelo (output) — pode virar audit-only opcional depois; foco atual é egress (prompt + arquivo).
- Injeção no renderer Electron — só como plano B se o pinning inviabilizar o MITM.
- Suporte a outros desktops de IA (ChatGPT desktop etc.) — a arquitetura de proxy seletivo já generaliza, mas cada host entra sob demanda.
