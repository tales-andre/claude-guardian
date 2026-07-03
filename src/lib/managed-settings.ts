// ── Compilador de managed settings ────────────────────────────────────────────
// O control-plane autora a política da organização e compila os artefatos que
// travam o Claude Code/Kiro nas máquinas. Dois canais (a doc da Anthropic):
//   • server-managed: colado no console claude.ai (não aceita managed-mcp.json,
//     então a allowlist de MCP vai como chaves allowedMcpServers/deniedMcpServers).
//   • endpoint-managed: managed-settings.json + managed-mcp.json empurrados via MDM.
// Garantia honesta: contra dev admin isto é resistente + auto-revertido (o MDM
// reaplica) e detectável, NÃO à prova de adulteração.

export interface OrgPolicyInput {
  /** Comando que invoca o hook PreToolUse do guardian na máquina. */
  hookCommand: string;
  /** Comandos opcionais dos demais hooks (default: reutiliza hookCommand). */
  postToolUseCommand?: string;
  userPromptSubmitCommand?: string;
  configChangeCommand?: string;
  /** MCP servers que o usuário pode usar. */
  allowedMcpServers?: string[];
  /** MCP servers explicitamente bloqueados. */
  deniedMcpServers?: string[];
  /** Caminhos cuja leitura é negada (viram regras Read(...)). */
  denyReadPaths?: string[];
}

export interface CompiledManagedSettings {
  /** Cole no console: Admin Settings > Claude Code > Managed settings. */
  serverManaged: Record<string, unknown>;
  /** Arquivo managed-settings.json para distribuição via MDM. */
  endpointManagedSettings: Record<string, unknown>;
  /** Arquivo managed-mcp.json para distribuição via MDM. */
  managedMcp: Record<string, unknown>;
}

function hookEntry(command: string) {
  return [{ hooks: [{ type: "command", command }] }];
}

/** Compila os artefatos de managed settings a partir da política da org. */
export function compileManagedSettings(
  input: OrgPolicyInput,
): CompiledManagedSettings {
  const {
    hookCommand,
    postToolUseCommand = hookCommand,
    userPromptSubmitCommand = hookCommand,
    configChangeCommand = hookCommand,
    allowedMcpServers = [],
    deniedMcpServers = [],
    denyReadPaths = [],
  } = input;

  // Base comum aos dois canais: trava o hook do guardian, exige fetch da policy
  // no startup (fail-closed) e registra os hooks.
  const base: Record<string, unknown> = {
    allowManagedHooksOnly: true,
    forceRemoteSettingsRefresh: true,
    hooks: {
      PreToolUse: hookEntry(hookCommand),
      PostToolUse: hookEntry(postToolUseCommand),
      UserPromptSubmit: hookEntry(userPromptSubmitCommand),
      ConfigChange: hookEntry(configChangeCommand),
    },
  };

  if (denyReadPaths.length > 0) {
    base["permissions"] = { deny: denyReadPaths.map((p) => `Read(${p})`) };
  }

  // Canal server-managed: a allowlist de MCP vira chaves (managed-mcp.json não
  // pode ser distribuído por aqui).
  const serverManaged: Record<string, unknown> = { ...base };
  if (allowedMcpServers.length > 0) {
    serverManaged["allowedMcpServers"] = allowedMcpServers;
  }
  if (deniedMcpServers.length > 0) {
    serverManaged["deniedMcpServers"] = deniedMcpServers;
  }

  return {
    serverManaged,
    endpointManagedSettings: { ...base },
    managedMcp: {
      allowedMcpServers,
      deniedMcpServers,
    },
  };
}
