import { loadConfig } from "../../config/loader.ts";
import { buildServer } from "../../server/api.ts";

interface ServeOptions {
  port?: string;
  config?: string;
}

export async function cmdServe(opts: ServeOptions): Promise<void> {
  const config = loadConfig(opts.config);
  const port = opts.port ? parseInt(opts.port, 10) : config.dashboardPort;

  const server = buildServer(config);

  try {
    await server.listen({ port, host: "127.0.0.1" });
    const addr = server.server.address();
    const url = `http://127.0.0.1:${typeof addr === "object" && addr ? addr.port : port}/dashboard`;
    console.log(`claude-guardian dashboard running at ${url}`);
    if (config.dashboardToken) {
      console.log(`Token: ${config.dashboardToken}`);
    }
  } catch (err) {
    process.stderr.write(`Failed to start server: ${String(err)}\n`);
    process.exit(1);
  }
}
