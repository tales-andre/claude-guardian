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
  /** Último ping da extensão de navegador (via daemon local). */
  extensionLastSeen?: string;
}

interface StatusOptions {
  expectedConfigHash: string;
  now?: Date;
  staleAfterMs?: number;
  /** Org exige a extensão de navegador: silêncio dela = tampered. */
  extensionRequired?: boolean;
  extensionStaleAfterMs?: number;
}

function olderThan(
  timestamp: string | undefined,
  now: Date,
  windowMs: number,
): boolean {
  if (!timestamp) return true;
  const ms = new Date(timestamp).getTime();
  return Number.isNaN(ms) || now.getTime() - ms > windowMs;
}

/**
 * Classifica uma máquina. Prioridade: tampered > stale > healthy.
 * tampered  = hash da config diferente do esperado (alguém mexeu na policy),
 *             ou máquina viva com a extensão exigida silenciosa/ausente
 *             (extensão removida/desabilitada é o análogo browser do
 *             provider-evasion).
 * stale     = a máquina inteira parou de reportar (guardian desligado) — nesse
 *             caso o silêncio da extensão é consequência, não tamper.
 */
export function computeMachineStatus(
  machine: MachineState,
  opts: StatusOptions,
): MachineStatus {
  if (machine.configHash !== opts.expectedConfigHash) return "tampered";

  const now = opts.now ?? new Date();
  const staleAfter = opts.staleAfterMs ?? DEFAULT_STALE_AFTER_MS;
  if (olderThan(machine.lastSeen, now, staleAfter)) {
    return "stale";
  }

  if (
    opts.extensionRequired &&
    olderThan(
      machine.extensionLastSeen,
      now,
      opts.extensionStaleAfterMs ?? staleAfter,
    )
  ) {
    return "tampered";
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
