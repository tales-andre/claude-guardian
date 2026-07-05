import http2 from "node:http2";
import net from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import tls from "node:tls";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ensureCa, issueLeaf } from "../src/lib/mitm-ca.ts";
import { createHttpsProxy, type ProxyScanFn } from "../src/proxy/https-proxy.ts";

const AUTHORITY = "a-api.anthropic.com";
let caDir: string;
let ca: ReturnType<typeof ensureCa>;
let upstream: http2.Http2SecureServer;
let upstreamPort: number;
let proxyPort: number;
let received: string[] = [];

// Bloqueia se o corpo tiver "AKIA".
const scan: ProxyScanFn = ({ bodyText }) =>
  bodyText.includes("AKIA")
    ? { action: "block", reason: "secret" }
    : { action: "allow", reason: "" };

function listen(server: { listen: (p: number, h: string, cb: () => void) => void }): Promise<number> {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      // @ts-expect-error address() existe em runtime
      resolve(server.address().port);
    });
  });
}

// Cliente: CONNECT -> TLS(confia na nossa CA) -> h2 -> request. Igual ao Desktop.
function mitmRequest(body: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const raw = net.connect(proxyPort, "127.0.0.1", () => {
      raw.write(`CONNECT ${AUTHORITY}:443 HTTP/1.1\r\nHost: ${AUTHORITY}:443\r\n\r\n`);
    });
    raw.once("data", (d) => {
      if (!/^HTTP\/1\.1 200/.test(d.toString("latin1"))) {
        return reject(new Error(`CONNECT falhou: ${d.toString("latin1").split("\r\n")[0]}`));
      }
      const tlsSock = tls.connect(
        { socket: raw, servername: AUTHORITY, ca: [ca.caCertPem], ALPNProtocols: ["h2"] },
        () => {
          const client = http2.connect(`https://${AUTHORITY}`, {
            createConnection: () => tlsSock,
          });
          client.on("error", reject);
          const req = client.request({ ":method": "POST", ":path": "/v1/messages" });
          let status = 0;
          const chunks: Buffer[] = [];
          req.on("response", (h) => {
            status = Number(h[":status"]);
          });
          req.on("data", (c: Buffer) => chunks.push(c));
          req.on("end", () => {
            client.close();
            resolve({ status, body: Buffer.concat(chunks).toString("utf8") });
          });
          req.on("error", reject);
          req.write(body);
          req.end();
        },
      );
      tlsSock.on("error", reject);
    });
    raw.on("error", reject);
  });
}

beforeAll(async () => {
  caDir = mkdtempSync(join(tmpdir(), "guardian-proxy-ca-"));
  ca = ensureCa(caDir);

  // Upstream fake: h2 server que registra o corpo recebido.
  const leaf = issueLeaf(ca, AUTHORITY);
  upstream = http2.createSecureServer({ key: leaf.keyPem, cert: leaf.certPem });
  upstream.on("stream", (stream, _headers) => {
    const chunks: Buffer[] = [];
    stream.on("data", (c: Buffer) => chunks.push(c));
    stream.on("end", () => {
      received.push(Buffer.concat(chunks).toString("utf8"));
      stream.respond({ ":status": 200, "content-type": "application/json" });
      stream.end('{"ok":true}');
    });
  });
  upstreamPort = await listen(upstream);

  const proxy = createHttpsProxy({
    ca,
    scan,
    upstreamResolver: () => ({ host: "127.0.0.1", port: upstreamPort }),
    upstreamTlsInsecure: true,
  });
  proxyPort = await listen(proxy);
});

afterAll(() => {
  upstream?.close();
  rmSync(caDir, { recursive: true, force: true });
});

describe("createHttpsProxy (MITM HTTP/2)", () => {
  it("bloqueia (403) request com segredo e NÃO encaminha ao upstream", async () => {
    received = [];
    const r = await mitmRequest(JSON.stringify({ prompt: "k=AKIAIOSFODNN7EXAMPLE" }));
    expect(r.status).toBe(403);
    expect(r.body).toContain("claude-guardian");
    expect(received).toHaveLength(0); // upstream real nunca recebeu
  });

  it("encaminha request limpa ao upstream (200)", async () => {
    received = [];
    const r = await mitmRequest(JSON.stringify({ prompt: "olá" }));
    expect(r.status).toBe(200);
    expect(r.body).toContain("ok");
    expect(received).toHaveLength(1); // upstream recebeu
    expect(received[0]).toContain("olá");
  });
});
