#!/usr/bin/env -S node --experimental-strip-types

// Flusher do outbox — roda como processo destacado, disparado pelos hooks.
// Envia cada evento pendente ao servidor central e remove o arquivo quando o
// servidor confirma (2xx) ou rejeita definitivamente (4xx). Erros de rede
// mantêm o arquivo para retry no próximo hook — store-and-forward.

import { readdirSync, readFileSync, renameSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { loadConfig } from "../config/loader.ts";
import { centralEnabled, outboxDir } from "./central.ts";

const FETCH_TIMEOUT_MS = 5000;

async function main(): Promise<void> {
  const config = loadConfig();
  if (!centralEnabled(config)) return;

  const dir = outboxDir(config);
  let files: string[];
  try {
    files = readdirSync(dir)
      .filter((f) => f.endsWith(".json"))
      .sort();
  } catch {
    return;
  }

  const base = config.centralUrl.replace(/\/+$/, "");

  for (const file of files) {
    const path = join(dir, file);
    const claimed = `${path}.sending`;

    // rename é atômico: se outro flusher já pegou este arquivo, pulamos.
    try {
      renameSync(path, claimed);
    } catch {
      continue;
    }

    try {
      const body = readFileSync(claimed, "utf8");
      const res = await fetch(`${base}/api/agent/ingest`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Guardian-Agent-Key": config.centralApiKey,
        },
        body,
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });

      if (res.ok || res.status === 400) {
        // Entregue, ou payload malformado (poison) — descarta. 401/5xx ficam
        // para retry: pode ser chave em rotação ou servidor indisponível.
        unlinkSync(claimed);
      } else {
        renameSync(claimed, path);
      }
    } catch {
      // Servidor indisponível — devolve para retry futuro.
      try {
        renameSync(claimed, path);
      } catch {
        // best-effort
      }
    }
  }
}

main().catch(() => {});
