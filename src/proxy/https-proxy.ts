// Proxy HTTPS seletivo do GUI Gateway (Fase 2). Trata CONNECT: passthrough
// (túnel puro) por padrão; MITM só nos hosts da Anthropic — termina o TLS com um
// cert emitido pela CA do guardian (por-SNI), lê a request (HTTP/2 ou 1.1),
// escaneia o corpo e bloqueia (403) se houver segredo, senão encaminha ao
// upstream real. HTTP/2 porque é o que o Claude Desktop negocia (ALPN=h2).

import http from "node:http";
import http2 from "node:http2";
import net from "node:net";
import tls from "node:tls";
import { type GuardianCa, issueLeaf } from "../lib/mitm-ca.ts";

export interface ProxyScanInput {
  bodyText: string;
  host: string;
  path: string;
}
export interface ProxyScanResult {
  action: "allow" | "block" | "redact" | "require-approval" | "substitute";
  reason: string;
  /** Corpo reescrito com dados fictícios (ação substitute) — encaminhado no lugar do original. */
  rewrittenBody?: string;
}
export type ProxyScanFn = (input: ProxyScanInput) => ProxyScanResult;

export interface HttpsProxyOptions {
  ca: GuardianCa;
  scan: ProxyScanFn;
  /** Hosts a interceptar (MITM). Resto = passthrough. */
  mitmHosts?: RegExp;
  /** Redireciona o upstream (testes). Default: host:443 reais. */
  upstreamResolver?: (host: string) => { host: string; port: number };
  /** Ignora validação do cert do upstream (apenas testes). */
  upstreamTlsInsecure?: boolean;
}

const WRITE_METHODS = new Set(["POST", "PUT", "PATCH"]);

function blocked(res: ProxyScanResult): boolean {
  return res.action === "block" || res.action === "require-approval";
}

function upstreamHeaders(
  headers: http2.IncomingHttpHeaders,
): http2.OutgoingHttpHeaders {
  const out: http2.OutgoingHttpHeaders = {};
  for (const [k, v] of Object.entries(headers)) {
    if (k === "host" || k === "connection" || k.startsWith("proxy-")) continue;
    out[k] = v as string | string[];
  }
  return out;
}

function forwardH2(
  clientStream: http2.ServerHttp2Stream,
  headers: http2.IncomingHttpHeaders,
  bodyChunks: Buffer[],
  opts: HttpsProxyOptions,
): void {
  const authority = String(headers[":authority"] ?? "");
  const up = opts.upstreamResolver?.(authority) ?? {
    host: authority,
    port: 443,
  };
  const session = http2.connect(`https://${authority}`, {
    host: up.host,
    port: up.port,
    rejectUnauthorized: !opts.upstreamTlsInsecure,
  });
  session.on("error", () => {
    try {
      clientStream.respond({ ":status": 502 });
      clientStream.end("guardian: upstream error");
    } catch {
      /* stream já fechado */
    }
  });
  const upReq = session.request(upstreamHeaders(headers));
  for (const c of bodyChunks) upReq.write(c);
  upReq.end();
  upReq.on("response", (respHeaders) => {
    try {
      clientStream.respond(respHeaders);
    } catch {
      return;
    }
    upReq.pipe(clientStream);
  });
  upReq.on("error", () => {
    try {
      clientStream.close();
    } catch {}
  });
  clientStream.on("close", () => session.close());
}

function handleH2Stream(
  stream: http2.ServerHttp2Stream,
  headers: http2.IncomingHttpHeaders,
  opts: HttpsProxyOptions,
): void {
  const method = String(headers[":method"] ?? "GET").toUpperCase();
  const authority = String(headers[":authority"] ?? "");
  const path = String(headers[":path"] ?? "/");
  const chunks: Buffer[] = [];
  stream.on("data", (c: Buffer) => chunks.push(c));
  stream.on("error", () => {});
  stream.on("end", () => {
    const bodyText = Buffer.concat(chunks).toString("utf8");
    const decision =
      WRITE_METHODS.has(method) && bodyText
        ? opts.scan({ bodyText, host: authority, path })
        : { action: "allow" as const, reason: "" };
    if (blocked(decision)) {
      try {
        stream.respond({ ":status": 403, "content-type": "application/json" });
        stream.end(
          JSON.stringify({ error: `claude-guardian: ${decision.reason}` }),
        );
      } catch {
        /* stream fechado */
      }
      return;
    }
    // substitute: encaminha o corpo reescrito (fakes), com content-length novo.
    if (decision.action === "substitute" && decision.rewrittenBody != null) {
      const buf = Buffer.from(decision.rewrittenBody, "utf8");
      forwardH2(
        stream,
        { ...headers, "content-length": String(buf.length) },
        [buf],
        opts,
      );
      return;
    }
    forwardH2(stream, headers, chunks, opts);
  });
}

// Fallback HTTP/1.1 (raro no Desktop, mas o ALPN pode cair nisso).
function handleH1(
  req: http2.Http2ServerRequest,
  res: http2.Http2ServerResponse,
  opts: HttpsProxyOptions,
): void {
  // O servidor http2 (allowHTTP1) emite 'request' TAMBÉM para streams h2 (camada
  // de compat) — esses já foram tratados por handleH2Stream. Só tratamos h1 real.
  if (req.httpVersionMajor >= 2) return;
  const method = String(req.method ?? "GET").toUpperCase();
  const authority = String(req.headers.host ?? "");
  const path = req.url ?? "/";
  const chunks: Buffer[] = [];
  req.on("data", (c: Buffer) => chunks.push(c));
  req.on("end", () => {
    const bodyText = Buffer.concat(chunks).toString("utf8");
    const decision =
      WRITE_METHODS.has(method) && bodyText
        ? opts.scan({ bodyText, host: authority, path })
        : { action: "allow" as const, reason: "" };
    if (blocked(decision)) {
      res.writeHead(403, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: `claude-guardian: ${decision.reason}` }));
      return;
    }
    const up = opts.upstreamResolver?.(authority) ?? {
      host: authority,
      port: 443,
    };
    const outChunks =
      decision.action === "substitute" && decision.rewrittenBody != null
        ? [Buffer.from(decision.rewrittenBody, "utf8")]
        : chunks;
    const upReq = tls.connect(
      {
        host: up.host,
        port: up.port,
        servername: authority,
        rejectUnauthorized: !opts.upstreamTlsInsecure,
      },
      () => {
        upReq.write(
          `${method} ${path} HTTP/1.1\r\nhost: ${authority}\r\nconnection: close\r\n\r\n`,
        );
        for (const c of outChunks) upReq.write(c);
      },
    );
    upReq.on("error", () => {
      if (!res.headersSent) res.writeHead(502);
      res.end("guardian: upstream error");
    });
    // Repassa a resposta bruta (status line + headers + body) ao cliente.
    res.socket?.on("error", () => upReq.destroy());
    upReq.pipe(res.socket ?? res);
  });
}

/** Cria o proxy HTTPS (http.Server). Chame .listen(port, host). */
export function createHttpsProxy(opts: HttpsProxyOptions): http.Server {
  const mitm = opts.mitmHosts ?? /(^|\.)anthropic\.com$/i;

  const h2server = http2.createSecureServer({
    ALPNProtocols: ["h2", "http/1.1"],
    allowHTTP1: true,
    SNICallback: (servername, cb) => {
      try {
        const leaf = issueLeaf(opts.ca, servername);
        cb(
          null,
          tls.createSecureContext({ key: leaf.keyPem, cert: leaf.certPem }),
        );
      } catch (e) {
        cb(e as Error);
      }
    },
  });
  h2server.on("stream", (stream, headers) =>
    handleH2Stream(stream, headers, opts),
  );
  h2server.on("request", (req, res) => handleH1(req, res, opts));
  h2server.on("tlsClientError", () => {});
  h2server.on("error", () => {});

  const proxy = http.createServer((_req, res) => {
    res.writeHead(200);
    res.end("claude-guardian proxy\n");
  });
  proxy.on("connect", (req, clientSocket, head) => {
    const [host, portStr] = String(req.url ?? "").split(":");
    const port = Number(portStr) || 443;
    if (mitm.test(host ?? "")) {
      clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head?.length) clientSocket.unshift(head);
      h2server.emit("connection", clientSocket);
      return;
    }
    const up = net.connect(port, host, () => {
      clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head?.length) up.write(head);
      up.pipe(clientSocket);
      clientSocket.pipe(up);
    });
    up.on("error", () => clientSocket.destroy());
    clientSocket.on("error", () => up.destroy());
  });
  return proxy;
}
