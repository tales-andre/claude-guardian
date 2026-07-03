import type { DataType, Severity } from "../../types/index.ts";
import { awsAccessKeyDetector, awsSecretKeyDetector } from "./aws.ts";
import { githubPatDetector } from "./github.ts";
import { anthropicKeyDetector } from "./openai.ts";
import { privateKeyDetector } from "./private-key.ts";
import { type Detector, type DetectorFinding, makeFinding } from "./types.ts";

// ── Detector async-only: segredos escondidos em base64 ────────────────────────
// Decodifica blobs base64 e re-escaneia o conteúdo com detectores de alta
// confiança. É CARO (decode + N detectores por blob), então NÃO entra no
// caminho síncrono de bloqueio (orçamento de 500ms) — roda só no PostToolUse /
// central, onde latência não importa. Pega segredos que os detectores rápidos
// não veem porque estão codificados.

const INNER_DETECTORS: Detector[] = [
  awsAccessKeyDetector,
  awsSecretKeyDetector,
  githubPatDetector,
  privateKeyDetector,
  anthropicKeyDetector,
];

// Sequências base64 longas o suficiente para carregar um segredo real.
const BASE64_RE = /[A-Za-z0-9+/]{40,}={0,2}/g;

const meta: Omit<Detector, "scan"> = {
  id: "base64-embedded-secret",
  label: "Secret embedded in base64",
  dataType: "generic-secret" as DataType,
  severity: "critical" as Severity,
};

export const base64SecretDetector: Detector = {
  ...meta,
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];

    for (const match of text.matchAll(BASE64_RE)) {
      const blob = match[0];
      let decoded: string;
      try {
        decoded = Buffer.from(blob, "base64").toString("utf8");
      } catch {
        continue;
      }
      if (decoded.length === 0) continue;
      if (!INNER_DETECTORS.some((d) => d.scan(decoded).length > 0)) continue;

      const start = match.index ?? 0;
      // snippet só com o prefixo do blob (codificado) — nunca o segredo decodificado.
      findings.push(
        makeFinding(
          meta,
          blob,
          `${blob.slice(0, 12)}… (base64)`,
          start,
          start + blob.length,
          0.9,
        ),
      );
    }

    return findings;
  },
};
