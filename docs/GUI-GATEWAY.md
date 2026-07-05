# Guardian GUI Gateway

Cobertura DLP para superfícies GUI que não têm o ciclo de hooks bloqueante do
Claude Code: **Claude Desktop** e **Kiro IDE**.

## Fase 1 — Proxy MCP (esta entrega)

O `init` envolve cada MCP server configurado com o shim `src/proxy/mcp-proxy.ts`.
Configs cobertas (por SO):

- **Claude Desktop:** `claude_desktop_config.json`
  - macOS: `~/Library/Application Support/Claude/`
  - Windows: `%APPDATA%/Claude/`
  - Linux: `~/.config/Claude/`
- **Kiro IDE:** `~/.kiro/settings/mcp.json` e `.kiro/settings/mcp.json` (workspace)

O cliente passa a spawnar o shim no lugar do server real; o shim faz spawn do
server real e senta no meio do stream JSON-RPC (newline-delimited), escaneando
`tools/call` (args = egress) e as respostas (result = ingress) via `scanMcp`
(`src/lib/mcp-scan.ts`, tools virtuais `McpToolCall`/`McpToolResult`), reusando
engine/policy/audit/central dos hooks. Scan roda **in-process** (sem depender do
daemon). Bloqueio = erro JSON-RPC `-32001` devolvido ao cliente; a request nunca
chega ao server real.

### Reescrita de config (idempotente e reversível)

`wrapMcpServers` troca cada entrada por:

```json
{
  "command": "node",
  "args": ["--experimental-strip-types", "<repo>/src/proxy/mcp-proxy.ts"],
  "env": {
    "GUARDIAN_MCP_NAME": "<nome>",
    "GUARDIAN_MCP_TARGET": "{\"command\":\"<orig>\",\"args\":[...],\"env\":{...}}"
  }
}
```

Reenvolver é no-op (detecta `isWrapped`). Antes da primeira reescrita, o arquivo
é copiado para `<arquivo>.guardian.bak`.

### Rollback manual

Restaure o backup: cada config vira `<arquivo>.guardian.bak`. Programaticamente,
`uninstallMcpProxy()` (em `src/lib/mcp-install.ts`) copia o `.bak` de volta.
Reinicie o cliente depois.

## Kiro IDE hook-compat (spike Task 0)

**Status: NÃO investigado nesta entrega.** A Fase 1 cobre o Kiro IDE via proxy
MCP de qualquer forma (arquivos/tools). Fica pendente confirmar se o Kiro IDE
aceita o mesmo contrato de hook do kiro-cli — se aceitar, ganharíamos cobertura
de prompt no Kiro IDE sem MITM. Anotar o resultado aqui quando validado.

## Fase 2 — Proxy HTTPS + CA (prompt + anexo no Claude Desktop)

**Spike de pinning: PASSOU.** Validado na máquina real — o Claude Desktop
**não faz cert pinning**: com a CA confiada e um cert de servidor válido, o
handshake TLS do MITM é aceito e o tráfego HTTP/2 (`a-api.anthropic.com`) é
decifrável. A interceptação por rede é viável.

Implementado (core):

- `src/lib/mitm-ca.ts` — CA do guardian (persistida em `<dir-do-db>/guardian-ca.crt`)
  + emissão de cert de servidor por-SNI, assinado pela CA (node-forge). O
  `fingerprint` SHA-256 é o que o MDM distribui como confiável.
- `src/proxy/https-proxy.ts` — proxy CONNECT seletivo. Passthrough por padrão;
  MITM só `*.anthropic.com`. Termina o TLS com cert dinâmico, lê a request
  (HTTP/2, ALPN=h2, fallback h1), escaneia o corpo e bloqueia (403) ou encaminha.
- `src/lib/gui-scan.ts` — parseia a request (prompt + `attachments[].extracted_content`,
  fallback corpo inteiro) e escaneia reusando o pipeline. Tools virtuais
  `DesktopPrompt`/`DesktopUpload`.

Como rodar (modo local):

```
GUARDIAN_PROXY_PORT=8890 claude-guardian serve
```

O `serve` sobe o proxy junto do dashboard, imprime o caminho da CA e o
fingerprint. **Distribua a CA (`guardian-ca.crt`) via MDM e confie nas máquinas**,
e aponte o proxy do SO (ou do cliente) para `host:8890`.

### Falta (próximos)
- Artefatos MDM da CA + config de proxy por canal (`.mobileconfig`/`.reg`/Linux).
- Heartbeat/tamper do proxy no fleet (listener vivo, CA presente).
- Validar o schema real do corpo do Desktop (hoje há fallback de corpo inteiro).

Design completo: `docs/superpowers/specs/2026-07-04-gui-gateway-design.md`.
Planos: `docs/superpowers/plans/2026-07-04-gui-gateway-phase1-mcp.md` e
`…-phase2-https.md`.
