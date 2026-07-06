import type { Detector, DetectorFinding } from "./types.ts";
import { makeFinding } from "./types.ts";

// ── Detecção de entidades (nomes/endereços) — "NER" leve, em processo ────────
// Recall de PII que o regex estruturado não pega: nomes de pessoa e endereços.
// É o PISO rápido e síncrono que cabe no orçamento do hook. Um modelo NER real
// (ONNX quantizado, multilíngue) é o passo seguinte e deve rodar no daemon
// persistente com o modelo "warm" — encaixá-lo aqui via a mesma interface
// Detector (dataType person-name/postal-address) mantém o resto do pipeline
// (dedup, policy, substitute) inalterado.
//
// Conservador de propósito: substituição falha ABERTA, então preferimos perder
// uma entidade duvidosa a poluir o prompt com falsos positivos. Ligado apenas
// quando `config.entityDetection` é true (extraDetector, como o gitleaks).

// Tokens capitalizados que costumam NÃO ser nomes de pessoa (reduz falso+).
const NON_NAMES = new Set([
  "O",
  "A",
  "Os",
  "As",
  "Um",
  "Uma",
  "Eu",
  "Ele",
  "Ela",
  "Você",
  "Nós",
  "Isso",
  "Este",
  "Esta",
  "Esse",
  "Essa",
  "Como",
  "Quando",
  "Onde",
  "Porque",
  "Segue",
  "Olá",
  "Oi",
  "Bom",
  "Boa",
  "Prezado",
  "Prezada",
  "Att",
  "Atenciosamente",
  "The",
  "This",
  "That",
  "Hello",
  "Hi",
  "Dear",
  "New",
  "San",
  "São",
]);

// Substantivos Titlecase comuns em texto técnico/documental (produtos de nuvem,
// infra, UI, quiz/prova) que praticamente nunca são nome/sobrenome real.
// Reprova o candidato INTEIRO se QUALQUER token estiver aqui — mata FPs como
// "Transit Gateway", "Network Manager", "Route Tables" sem perder recall de
// nomes reais (a lista não contém pré/sobrenomes plausíveis).
const TECH_TERMS = new Set([
  "access",
  "account",
  "accounts",
  "address",
  "analytics",
  "balancer",
  "batch",
  "bridge",
  "bucket",
  "cloud",
  "cluster",
  "compute",
  "config",
  "console",
  "container",
  "control",
  "data",
  "database",
  "deploy",
  "deployment",
  "directory",
  "egress",
  "engine",
  "explorer",
  "firewall",
  "function",
  "functions",
  "gateway",
  "identity",
  "ingress",
  "injection",
  "internet",
  "learning",
  "load",
  "machine",
  "management",
  "manager",
  "monitor",
  "network",
  "object",
  "organization",
  "organizations",
  "pipeline",
  "platform",
  "policy",
  "private",
  "public",
  "region",
  "registry",
  "resource",
  "resources",
  "route",
  "router",
  "runtime",
  "secret",
  "secrets",
  "security",
  "server",
  "serverless",
  "service",
  "services",
  "sharing",
  "stack",
  "storage",
  "subnet",
  "subnets",
  "system",
  "systems",
  "table",
  "tables",
  "transit",
  "virtual",
  "zone",
  // documento/quiz (pt)
  "aviso",
  "capítulo",
  "erro",
  "exemplo",
  "explicação",
  "item",
  "página",
  "pergunta",
  "questão",
  "resposta",
  "seção",
  "título",
  "total",
  "valor",
]);

function hasTechTerm(candidate: string, extra?: ReadonlySet<string>): boolean {
  return candidate.split(/\s+/).some((w) => {
    const t = w.toLowerCase();
    return TECH_TERMS.has(t) || (extra?.has(t) ?? false);
  });
}

// Sigla ALL-CAPS colada logo antes/depois ("AWS Network Manager", "Fault
// Injection Simulator FIS") indica nome de PRODUTO, não pessoa. Não atravessa
// pontuação de fim de frase — um nome real seguido de "... IBM ligou" não é
// penalizado.
function adjacentAcronym(text: string, start: number, end: number): boolean {
  const before = text.slice(Math.max(0, start - 16), start);
  const after = text.slice(end, end + 16);
  return (
    /(?:^|[^A-Za-zÀ-ÿ])[A-Z][A-Z0-9]{1,11}[\s("'-]*$/.test(before) ||
    /^[\s("'-]*[A-Z][A-Z0-9]{1,11}(?![a-zà-ÿ])/.test(after)
  );
}

// Frases/pronomes de apresentação que ancoram um nome logo à frente (alta conf).
const ANCHOR_RE =
  /\b(?:Sr\.?|Sra\.?|Dr\.?|Dra\.?|Senhor|Senhora|meu nome é|me chamo|chamo-me|nome(?: completo)?:?)\s+([A-ZÀ-Ý][a-zà-ÿ]{1,20}(?:\s+(?:d[aeo]s?\s+)?[A-ZÀ-Ý][a-zà-ÿ]{1,20}){1,3})/g;

// Sequência de 2 a 4 palavras capitalizadas (Nome Sobrenome …), com conectores
// pt (da/de/do/dos). Confiança menor — filtrada pela stoplist.
const FULLNAME_RE =
  /\b[A-ZÀ-Ý][a-zà-ÿ]{1,20}(?:\s+(?:d[aeo]s?\s+)?[A-ZÀ-Ý][a-zà-ÿ]{1,20}){1,3}\b/g;

function pushName(
  findings: DetectorFinding[],
  seen: Set<string>,
  detector: Omit<Detector, "scan">,
  raw: string,
  start: number,
  confidence: number,
  extraStopwords?: ReadonlySet<string>,
): void {
  const trimmed = raw.trim();
  if (trimmed.length < 3) return;
  const first = trimmed.split(/\s+/)[0] ?? "";
  if (NON_NAMES.has(first)) return;
  if (hasTechTerm(trimmed, extraStopwords)) return;
  if (seen.has(trimmed)) return;
  seen.add(trimmed);
  findings.push(
    makeFinding(
      detector,
      trimmed,
      "[name]",
      start,
      start + trimmed.length,
      confidence,
    ),
  );
}

function makePersonNameDetector(extraStopwords: ReadonlySet<string>): Detector {
  return {
    id: "entity-person-name",
    label: "Person Name",
    dataType: "person-name",
    severity: "medium",
    kind: "heuristic",
    description:
      "Heurística de nomes de pessoa: frases-âncora (Sr./Dra./“meu nome é” — alta confiança) e sequências de 2–4 palavras capitalizadas com conectores pt (da/de/do), filtradas por stoplist de pronomes, termos técnicos, stopwords da organização e siglas ALL-CAPS adjacentes (nomes de produto).",
    scan(text: string): DetectorFinding[] {
      const findings: DetectorFinding[] = [];
      const seen = new Set<string>();

      for (const m of text.matchAll(ANCHOR_RE)) {
        const name = m[1];
        if (!name) continue;
        const start = m.index + m[0].lastIndexOf(name);
        pushName(findings, seen, this, name, start, 0.8, extraStopwords);
      }
      for (const m of text.matchAll(FULLNAME_RE)) {
        // Caminho de baixa confiança: bigrama Titlecase encostado numa sigla
        // ALL-CAPS é nome de produto ("AWS Fault Injection"), não pessoa.
        if (adjacentAcronym(text, m.index, m.index + m[0].length)) continue;
        pushName(findings, seen, this, m[0], m.index, 0.5, extraStopwords);
      }
      return findings;
    },
  };
}

export const personNameDetector: Detector = makePersonNameDetector(new Set());

// Endereços (BR): logradouro + número. Bounded para evitar ReDoS.
const ADDRESS_RE =
  /\b(?:Rua|R\.|Avenida|Av\.?|Alameda|Al\.|Travessa|Praça|Rodovia|Estrada)\s+[A-Za-zÀ-ÿ][A-Za-zÀ-ÿ0-9.\s]{2,40}?,?\s*(?:n[º°.]?\s*)?\d{1,6}\b/g;

export const postalAddressDetector: Detector = {
  id: "entity-postal-address",
  label: "Postal Address",
  dataType: "postal-address",
  severity: "medium",
  kind: "heuristic",
  pattern: ADDRESS_RE.source,
  description:
    "Endereços postais BR: logradouro (Rua/Av./Alameda/Travessa/Praça/Rodovia/Estrada) + nome + número. Regex bounded (anti-ReDoS), confiança 0.6.",
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(ADDRESS_RE)) {
      const raw = m[0].trim();
      findings.push(
        makeFinding(this, raw, "[address]", m.index, m.index + raw.length, 0.6),
      );
    }
    return findings;
  },
};

// Reunidos para ligar de uma vez nas superfícies de egress (quando habilitado).
// As stopwords extras vêm de config.entityStopwords (gerenciáveis pelo
// dashboard) e valem só para o detector de nome.
export function buildEntityDetectors(
  stopwords: readonly string[] = [],
): readonly Detector[] {
  const extra = new Set(stopwords.map((s) => s.toLowerCase()));
  return [makePersonNameDetector(extra), postalAddressDetector];
}

export const entityDetectors: readonly Detector[] = buildEntityDetectors();
