# Guardian GUI Gateway — Fase 2 (Proxy HTTPS + CA) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans. Steps use checkbox (`- [ ]`).

**Goal:** Barrar **prompt + anexo** no Claude Desktop interceptando o tráfego para `api.anthropic.com` num proxy HTTPS local com CA corporativa, reusando o mesmo engine/policy/audit.

**Architecture:** Proxy CONNECT local. Passthrough (túnel puro) por padrão; MITM só nos hosts da Anthropic — termina o TLS com um cert assinado pela CA do guardian, bufferiza o body, escaneia via `gui-scan` (espelha `scanWeb`), bloqueia com resposta sintética. CA + config de proxy distribuídas pelo MDM existente.

**Tech Stack:** Node `tls`/`http`/`net` (builtin). Geração de cert: `openssl` no spike; para produção, cert dinâmico por-SNI (decisão de dep na Task 2).

---

## Task 0 — Spike de pinning (BLOQUEANTE, roda na máquina do usuário)

**Nenhuma linha de proxy vai a produção antes deste passo passar.**

- [ ] Gerar CA + leaf cert para `api.anthropic.com` (openssl).
- [ ] Subir um MITM de teste que intercepta CONNECT p/ `api.anthropic.com` e faz passthrough do resto.
- [ ] Na máquina com Claude Desktop: confiar na CA, apontar o proxy do SO para o MITM, abrir o Desktop e mandar uma mensagem.
- [ ] **Resultado:**
  - Interceptou (proxy loga a request decodificada) e o Desktop funciona → **sem pinning, Fase 2 viável.** Seguir Task 1.
  - Desktop falha (TLS error / não conecta) → **pinning.** Fase 2 por rede inviável → cair para o Plano B (injeção no renderer Electron), fora deste plano.

Harness do spike entregue em `scratchpad`/`/mnt/c/.../guardian-pinning-spike` (throwaway).

---

## Task 1 — Geração da CA do guardian

**Files:** `src/lib/mitm-ca.ts`, `tests/mitm-ca.test.ts`

- [ ] `ensureCa(dir)`: cria (uma vez) `guardian-ca.key`/`guardian-ca.crt` no dir de config; idempotente. Retorna `{ caCertPem, caKeyPem, fingerprint }`.
- [ ] `issueLeaf(ca, host)`: assina um cert de servidor para `host` (SAN), TTL curto, cacheado em memória por host.
- [ ] Teste: a chain do leaf valida contra a CA; SAN bate com o host.

Decisão de dependência: usar `node-forge` (puro JS, portável Windows/Mac/Linux) para emissão X.509 — `openssl` não é garantido no Windows. Registrar no CLAUDE.md.

---

## Task 2 — Proxy HTTPS seletivo

**Files:** `src/proxy/https-proxy.ts`, `tests/https-proxy.test.ts`

- [ ] Servidor HTTP que trata `CONNECT host:port`.
- [ ] `MITM_HOSTS = [/(^|\.)anthropic\.com$/]` (Files API incluso). Fora disso: `net.connect` e pipe cru (passthrough).
- [ ] Para host MITM: `tls.createServer({ SNICallback: issueLeaf(ca, sni) })`, aceita a conexão do cliente, lê a request HTTP, bufferiza o body, chama `scanGui`, e:
  - **block** → responde 403 sintético (nunca conecta ao upstream);
  - **redact** → reescreve o body e encaminha;
  - **allow** → encaminha ao upstream real (TLS) e faz pipe da resposta.
- [ ] Teste (upstream FAKE local): passthrough para host não-alvo; block para host-alvo com secret no body; allow para body limpo. Sem depender do Anthropic real.

---

## Task 3 — `scanGui` (parser da request Anthropic)

**Files:** `src/lib/gui-scan.ts`, `tests/gui-scan.test.ts`

- [ ] Mapeia a request `/v1/messages` (ou `/completion`) → tools virtuais `DesktopPrompt` (texto) e `DesktopUpload` (anexos/`attachments[].extracted_content`, igual ao adapter do browser).
- [ ] Reusa `scanSync`/`evaluatePolicy`/`audit`/`central` como `scanWeb`/`scanMcp`.
- [ ] Fail-closed no timeout; anexo fail-closed offline (consistente com a extensão).
- [ ] Teste: prompt com segredo → block; anexo com segredo → block; limpo → allow.

---

## Task 4 — CA + proxy nos artefatos MDM

**Files:** `src/lib/browser-policies.ts` (estende), `tests`

- [ ] Emitir a CA do guardian e a config de proxy do SO por canal: `.mobileconfig` (macOS, payload de trust + proxy), `.reg` (Windows), policy JSON (Linux).
- [ ] Teste: os artefatos contêm o fingerprint da CA e o endereço do proxy.

---

## Task 5 — init/daemon: subir o proxy + escrever a CA

**Files:** `src/cli/commands/init.ts`, `src/cli/commands/serve.ts`

- [ ] `ensureCa()` no init; opção de subir o listener do proxy junto do daemon (`serve`).
- [ ] `GUARDIAN_PROXY_PORT` (default) + doc de rollback.

---

## Task 6 — Fleet/tamper (Fase 3 dobrada aqui)

- [ ] Heartbeat do proxy: listener vivo, CA presente no trust store, interceptação ativa → `computeMachineStatus` marca `tampered` se ausente/adulterado.

---

## Riscos
- **Pinning** (Task 0 gate). Se pinar: Plano B (injeção Electron), fora deste plano.
- **Dep node-forge** para emissão de cert (portabilidade Windows).
- **Validação real** só na máquina do usuário; testes aqui usam upstream fake.
