import { loadConfig } from "../../config/loader.ts";
import { buildServer } from "../../server/api.ts";

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
  } catch (err) {
    process.stderr.write(`Failed to start server: ${String(err)}\n`);
    process.exit(1);
  }
}
