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

## Fases futuras (planos separados)

- **Fase 2:** proxy HTTPS + CA/MDM para barrar **prompt + anexo** no Claude
  Desktop (o único chokepoint honesto para o prompt do Desktop).
- **Fase 3:** heartbeat/tamper do proxy no fleet.

Design completo: `docs/superpowers/specs/2026-07-04-gui-gateway-design.md`.
Plano da Fase 1: `docs/superpowers/plans/2026-07-04-gui-gateway-phase1-mcp.md`.
