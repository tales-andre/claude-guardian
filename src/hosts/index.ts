// ── HostAdapter: suporte multi-ferramenta (Claude Code + Kiro) ────────────────
// Claude Code e Kiro usam contratos de hook quase idênticos (PreToolUse/
// PostToolUse, stdin JSON, exit 2 bloqueia). A diferença está nos NOMES das
// tools e em alguns campos do input. Este módulo normaliza o payload de cada
// host para o formato que os hooks já esperam (formato Claude), deixando o
// engine/policy/audit totalmente agnósticos.

export type Host = "claude" | "kiro" | "claude-desktop" | "kiro-ide";

// Nomes canônicos do Kiro (e aliases) → nomes de tool do guardian.
const TOOL_NAME_MAP: Record<string, string> = {
  fs_read: "Read",
  read: "Read",
  fs_write: "Write",
  write: "Write",
  execute_bash: "Bash",
  shell: "Bash",
  bash: "Bash",
  use_aws: "Bash",
  aws: "Bash",
};

/** Converte o nome de tool de qualquer host para o nome canônico do guardian. */
export function normalizeToolName(name: string): string {
  return TOOL_NAME_MAP[name] ?? name;
}

/** Descobre qual ferramenta está invocando o hook. */
export function detectHost(env: NodeJS.ProcessEnv = process.env): Host {
  const explicit = env["GUARDIAN_HOST"]?.toLowerCase();
  if (
    explicit === "kiro" ||
    explicit === "claude" ||
    explicit === "claude-desktop" ||
    explicit === "kiro-ide"
  ) {
    return explicit;
  }
  if (Object.keys(env).some((k) => k.startsWith("KIRO"))) return "kiro";
  return "claude";
}

export interface NormalizedHookInput {
  session_id?: string | undefined;
  transcript_path?: string | undefined;
  tool_name?: string | undefined;
  tool_input?: {
    file_path?: string | undefined;
    command?: string | undefined;
    content?: string | undefined;
    new_string?: string | undefined;
  };
}

interface RawHookInput {
  session_id?: string | undefined;
  transcript_path?: string | undefined;
  tool_name?: string | undefined;
  tool_input?: Record<string, unknown> | undefined;
}

function str(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

/** Normaliza o payload bruto do host para o formato (estilo Claude) dos hooks. */
export function normalizeHookInput(
  raw: RawHookInput,
  host: Host,
): NormalizedHookInput {
  if (host === "claude") return raw as NormalizedHookInput;

  const ti = raw.tool_input ?? {};
  return {
    session_id: raw.session_id,
    transcript_path: raw.transcript_path,
    tool_name: normalizeToolName(raw.tool_name ?? ""),
    tool_input: {
      // Kiro usa `path`/`text`; mapeamos para os campos que os hooks já leem.
      file_path: str(ti["file_path"]) ?? str(ti["path"]),
      command: str(ti["command"]),
      content: str(ti["content"]) ?? str(ti["text"]),
      new_string: str(ti["new_string"]) ?? str(ti["newText"]),
    },
  };
}
