# Unificar as linhagens do claude-guardian e materializar o DLP organizacional (extensão gerenciada + MDM multi-OS)

## Papel

Você é engenheiro(a) sênior trabalhando no repositório `claude-guardian` (DLP para agentes de IA), branch `enterprise`. Node >= 22.6.0, TypeScript executado direto (sem build), testes em vitest, lint/format Biome. Rode `npm run ci` ao final de cada fase e não avance com CI vermelho.

## Contexto — duas linhagens divergentes

- **Branch `enterprise` (este working tree, fonte de verdade):** engine de scan (`src/engine/`), hooks Claude Code + Kiro via HostAdapter (`src/hosts/`), detecção de evasão de provider (`src/lib/evasion.ts`), hook ConfigChange, detecção tiered (`src/engine/detectors/async.ts`), central server (`src/server/`, SQLite/Postgres, Docker/Helm), compilador de managed settings (`src/lib/managed-settings.ts` + CLI), fleet health (`src/lib/fleet.ts`, `computeMachineStatus`), instalador `enterprise/install-agent.sh`. Grande parte está NÃO COMMITADA.
- **Zip `claude-guardian.zip` (na raiz do repo, fork lateral com 1 commit):** extensão de navegador MV3 em `extension/` (manifest.json + manifest.firefox.json; 6 providers: claude.ai, chatgpt.com/chat.openai.com, gemini.google.com, copilot.microsoft.com, chat.mistral.ai, adapta.one/app.adapta.one; hook de `fetch` e `XMLHttpRequest` via registry `ADAPTERS` em `injected.js`; interceptação de upload em `content.js`; `background.js` fala com o daemon local; fail-closed), backend `src/lib/web-scan.ts` (tools virtuais `WebPrompt`/`WebUpload`, block de arquivo por nome) + rota `POST /api/scan-web` em `src/server/api.ts`, teste `tests/web-scan.test.ts`, e mudanças em `src/cli/commands/serve.ts` e `src/db/client.ts`. O zip NÃO contém nada do stack enterprise.

Modelo de ameaça honesto (já adotado no código): contra dev com admin local o sistema é tamper-evidente/resistente/auto-revertido via MDM — NUNCA descreva como "tamper-proof" ou prevenção absoluta em mensagem, log ou doc.

## Objetivo

Unificar as duas linhagens no branch `enterprise` e completar o que falta para rollout real em organização com Windows+Intune, macOS+Jamf/Kandji, Linux gerenciado e WSL: extensão force-installed e configurada por política, daemon local como serviço, políticas de browser compiladas pelo control-plane, e extensão visível no fleet.

Fora de escopo (NÃO implementar): detecção de prompt malicioso (regex de intenção, ML local, LLM juiz — inclusive o wiring de `prompts/dlp-detection-hook.md`), proxy/CASB, novos hosts CLI além de Claude/Kiro. Para apps desktop de IA sem hooks, apenas documentar a mitigação (bloqueio de app/domínio via MDM, fora do guardian).

## Fases (uma por vez, teste antes do código, `npm run ci` verde ao fim de cada)

**Fase 0 — Consolidar o branch.** Rode `npm run ci`; corrija o que falhar. Commite todo o trabalho solto do branch `enterprise` em commits coerentes por tema (hosts/evasão/config-change, managed-settings/fleet, detecção async). Não misture com o porte do zip.

**Fase 1 — Portar a linhagem do zip.** Extraia `claude-guardian.zip` para um diretório temporário. Porte cirurgicamente (não copie por cima): `extension/` inteiro, `src/lib/web-scan.ts`, `tests/web-scan.test.ts`, a rota `POST /api/scan-web` e ajustes correlatos de `api.ts`/`serve.ts`/`db/client.ts` — integrando com o `buildServer`/`GuardianStore` atuais do branch (o zip não conhece essa camada; a rota deve funcionar no modo local E no modo central). Preserve o comportamento fail-closed da extensão. Incidentes de `WebPrompt`/`WebUpload` devem fluir para o outbox/central como os demais. Ao final, apague o zip e o `claude-guardian.zip:Zone.Identifier` do repo (a linhagem passa a viver no branch).

**Fase 2 — Extensão enterprise-grade.** Adicione suporte a `chrome.storage.managed` (schema declarado no manifest): URL/porta do daemon e flags vêm da política quando presente; nesse modo, `options.html` exibe os valores como somente-leitura e ignora escrita. Sem política, comportamento atual (dev standalone) inalterado. Atualize `extension/README.md`.

**Fase 3 — Daemon como serviço.** Empacote o `serve` como serviço por plataforma: unit systemd (Linux e WSL com systemd habilitado), LaunchDaemon plist (macOS), serviço Windows (script PowerShell usando `sc.exe` ou tarefa agendada de logon — sem dependências novas). Estenda `enterprise/install-agent.sh` (e crie `enterprise/install-agent.ps1` para Windows) para instalar/registrar/iniciar o serviço. Documente no `docs/ENTERPRISE.md`: WSL usa o daemon do Windows via localhost (WSL2 encaminha) — hooks dentro da distro apontam para `http://localhost:<porta>`; marque como configuração a validar no piloto.

**Fase 4 — Control-plane compila políticas de browser.** Estenda `compileManagedSettings` (novo tipo de saída, aditivo) para emitir, a partir da org policy: (a) `ExtensionInstallForcelist` + política 3rdparty/managed storage da extensão para Chrome e Edge nos formatos registry `.reg`/valores para ADMX (Intune), (b) configuration profile `.mobileconfig`/plist (Jamf/Kandji), (c) JSON para `/etc/opt/chrome/policies/managed/` e equivalente Edge (Linux), (d) `ExtensionSettings` para Firefox via `policies.json`. O ID da extensão e a update URL são campos da org policy (a publicação — Web Store unlisted vs self-hosted — fica documentada como decisão de rollout, com os dois caminhos descritos). CLI `managed-settings` ganha as novas saídas em `managed-settings-out/`.

**Fase 5 — Extensão no fleet.** O daemon passa a registrar heartbeat da extensão: `background.js` faz ping periódico (ex.: a cada 5 min) num endpoint local novo (`POST /api/extension/heartbeat` com versão da extensão e contadores); o daemon inclui esses dados no heartbeat de máquina existente. No servidor central/`computeMachineStatus`: máquina com daemon saudável mas extensão silenciosa além da janela → status `tampered` (extensão removida/desabilitada é o análogo browser do provider-evasion). Adicione contador de falhas de `extractText` por provider (a extensão reporta no heartbeat); exponha no fleet dashboard como alerta de drift de endpoint — com fail-closed, drift precisa ser visível em horas.

**Fase 6 — Validação de adapters.** Verifique quais dos adapters em `injected.js` têm `// TODO: validar endpoint/body com tráfego real`. Não invente endpoints: mantenha os TODOs, gere `docs/ADAPTER-VALIDATION.md` com checklist de validação manual por provider (passos DevTools → Network, o que observar, como confirmar block e redaction) e liste no resumo final quais adapters seguem pendentes.

## Regras

- Tudo aditivo: com os novos campos de config/política vazios, o comportamento atual (local e enterprise) é idêntico. Nenhuma regressão nos testes existentes.
- Hooks nunca usam a camada async `GuardianStore`; caminho síncrono continua fail-closed em timeout.
- Valores crus de segredo nunca são persistidos nem enviados ao central (só `dataType`, `severity`, `snippet`).
- Control-plane compila artefatos; quem distribui é o MDM/console — o guardian nunca se autodistribui.
- TDD: teste primeiro, veja falhar, implemente. Compilação de políticas de browser, heartbeat de extensão e status `tampered` por extensão silenciosa têm testes herméticos.
- Extensão permanece JS puro sem build step e sem dependências novas.
- Siga o estilo existente (Biome, comentários em pt-BR com separadores `── … ─`, convenções dos módulos vizinhos).

## Critérios de qualidade

- `npm run ci` verde ao fim de cada fase; commits temáticos por fase.
- Um segredo conhecido digitado em qualquer provider suportado é bloqueado antes do request sair, com o daemon rodando como serviço iniciado por boot.
- Derrubar o daemon → extensão bloqueia envio com mensagem clara de fail-closed (não erro genérico).
- `managed-settings-out/` contém artefatos por canal (console, MDM endpoint, Intune, Jamf, Linux, Firefox) gerados de uma única org policy.
- Máquina com extensão desabilitada aparece `tampered` no fleet dashboard dentro da janela configurada.
- Nenhum texto do produto promete prevenção absoluta.

## Edge cases

- Rota `/api/scan-web` no modo central: scan continua 100% local (daemon); só metadados vão ao central via outbox; central indisponível não altera o veredito.
- `chrome.storage.managed` ausente (dev standalone) → options page editável, comportamento atual.
- WSL sem systemd → documentar fallback (daemon no Windows, hooks apontando para localhost).
- Provider muda endpoint (`isSendRequest` casa mas `extractText` falha) → bloqueia (fail-closed), incrementa contador de drift no heartbeat.
- Heartbeat de extensão sem daemon central configurado (modo local puro) → registra localmente, não tenta rede.
- Porte da Fase 1: `api.ts` do zip diverge do atual — reconcilie manualmente; qualquer rota existente do branch tem precedência em conflito.
