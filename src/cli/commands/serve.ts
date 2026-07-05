import { dirname, join } from "node:path";
import { expandHome } from "../../config/defaults.ts";
import { loadConfig } from "../../config/loader.ts";
import { getDb } from "../../db/client.ts";
import { scanGui } from "../../lib/gui-scan.ts";
import { ensureCa } from "../../lib/mitm-ca.ts";
import { createHttpsProxy } from "../../proxy/https-proxy.ts";
import { buildServer } from "../../server/api.ts";

// GUI Gateway Fase 2: sobe o proxy HTTPS local (opt-in via GUARDIAN_PROXY_PORT)
// que intercepta *.anthropic.com e escaneia prompt/anexo do Claude Desktop
// in-process. Só no modo local (SQLite) — usa o mesmo DB dos hooks.
function maybeStartHttpsProxy(
  config: ReturnType<typeof loadConfig>,
  host: string,
): void {
  const portStr = process.env["GUARDIAN_PROXY_PORT"];
  if (!portStr) return;
  if (config.databaseUrl) {
    console.log(
      "• GUARDIAN_PROXY_PORT ignorado no modo central (use o modo local).",
    );
    return;
  }
  const dbPath = expandHome(config.dbPath);
  const caDir = dirname(dbPath);
  const ca = ensureCa(caDir);
  const db = getDb(dbPath);
  const proxy = createHttpsProxy({
    ca,
    scan: (input) => {
      try {
        const r = scanGui(db, config, input);
        return {
          action: r.action,
          reason: r.reason,
          ...(r.substitutedText != null
            ? { rewrittenBody: r.substitutedText }
            : {}),
        };
      } catch {
        return {
          action: "block",
          reason: "erro interno do guardian (fail-closed)",
        };
      }
    },
  });
  proxy.listen(Number(portStr), host, () => {
    console.log(
      `claude-guardian HTTPS proxy on ${host}:${portStr} (MITM *.anthropic.com)`,
    );
    console.log(`  CA cert:        ${join(caDir, "guardian-ca.crt")}`);
    console.log(`  CA fingerprint: ${ca.fingerprint}`);
    console.log(
      "  Distribua a CA via MDM e confie nas máquinas; aponte o proxy do SO para este endereço.",
    );
  });
}

interface ServeOptions {
  port?: string;
  host?: string;
  config?: string;
}

export async function cmdServe(opts: ServeOptions): Promise<void> {
  const config = loadConfig(opts.config);
  const port = opts.port ? parseInt(opts.port, 10) : config.dashboardPort;
  // Em container (Docker/EKS) o servidor precisa escutar em 0.0.0.0; local
  // permanece restrito a loopback como sempre foi. GUARDIAN_BIND_HOST (e não
  // GUARDIAN_HOST, que identifica o host de hook claude/kiro) controla o bind.
  const host = opts.host ?? process.env["GUARDIAN_BIND_HOST"] ?? "127.0.0.1";

  const server = await buildServer(config);

  try {
    await server.listen({ port, host });
    const addr = server.server.address();
    const url = `http://${host}:${typeof addr === "object" && addr ? addr.port : port}/dashboard`;
    console.log(`claude-guardian dashboard running at ${url}`);
    if (config.databaseUrl) {
      console.log("storage: postgres (central mode)");
    }
    if (config.dashboardToken) {
      console.log(`Token: ${config.dashboardToken}`);
    }
    maybeStartHttpsProxy(config, host);
  } catch (err) {
    process.stderr.write(`Failed to start server: ${String(err)}\n`);
    process.exit(1);
  }
}
