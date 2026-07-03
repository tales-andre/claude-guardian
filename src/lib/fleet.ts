import { createHash } from "node:crypto";

// ── Saúde da frota ────────────────────────────────────────────────────────────
// Cada máquina-cliente envia heartbeat (versão do guardian + hash da config
// managed efetiva + timestamp). O servidor central compara com o hash esperado
// da política da organização e classifica a máquina. Como o dev pode ter admin,
// "tampered"/"stale" são sinais de DETECÇÃO — não impedem, mas tornam visível.

export type MachineStatus = "healthy" | "stale" | "tampered";

/** Janela padrão sem heartbeat até a máquina ser considerada "stale". */
const DEFAULT_STALE_AFTER_MS = 60 * 60_000; // 1 hora

interface MachineState {
  configHash: string;
  lastSeen: string;
}

interface StatusOptions {
  expectedConfigHash: string;
  now?: Date;
  staleAfterMs?: number;
}

/**
 * Classifica uma máquina. Prioridade: tampered > stale > healthy.
 * tampered  = hash da config diferente do esperado (alguém mexeu na policy).
 * stale     = parou de reportar dentro da janela (possível guardian desligado).
 */
export function computeMachineStatus(
  machine: MachineState,
  opts: StatusOptions,
): MachineStatus {
  if (machine.configHash !== opts.expectedConfigHash) return "tampered";

  const now = opts.now ?? new Date();
  const staleAfter = opts.staleAfterMs ?? DEFAULT_STALE_AFTER_MS;
  const lastSeenMs = new Date(machine.lastSeen).getTime();
  if (Number.isNaN(lastSeenMs) || now.getTime() - lastSeenMs > staleAfter) {
    return "stale";
  }

  return "healthy";
}

/** Hash canônico de um objeto de config (chaves ordenadas → estável). */
export function hashConfig(value: unknown): string {
  return createHash("sha256").update(canonical(value)).digest("hex");
}

function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map(canonical).join(",")}]`;
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(obj[k])}`).join(",")}}`;
}
