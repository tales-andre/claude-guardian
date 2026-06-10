export interface GenerateResult {
  regex: string;
  explanation: string;
  confidence: "high" | "medium" | "low";
  matchCount: number;
  missCount: number;
  warning?: string;
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Splits into alternating [token, sep, token, sep, ...] preserving separator chars.
const SEP_SPLIT = /([-_/.:@])/;
const SEP_CHARS = /^[-_/.:@]$/;

function tokenize(s: string): string[] {
  return s.split(SEP_SPLIT).filter((p) => p !== "");
}

function classifySegment(values: string[]): string {
  const allDigits = values.every((v) => /^\d+$/.test(v));
  const allUpper = values.every((v) => /^[A-Z]+$/.test(v));
  const allLower = values.every((v) => /^[a-z]+$/.test(v));
  const allAlpha = values.every((v) => /^[A-Za-z]+$/.test(v));
  const allAlphaNum = values.every((v) => /^[A-Za-z0-9]+$/.test(v));

  const lengths = values.map((v) => v.length);
  const min = Math.min(...lengths);
  const max = Math.max(...lengths);
  const len = min === max ? `{${min}}` : `{${min},${max}}`;

  if (allDigits) return `\\d${len}`;
  if (allUpper) return `[A-Z]${len}`;
  if (allLower) return `[a-z]${len}`;
  if (allAlpha) return `[A-Za-z]${len}`;
  if (allAlphaNum) return `[A-Za-z0-9]${len}`;
  return `.${len}`;
}

function lenDescription(regexPart: string): string {
  const m = regexPart.match(/\{(\d+)(?:,(\d+))?\}$/);
  if (!m) return "";
  return m[2] ? `${m[1]} a ${m[2]}` : `exatamente ${m[1]}`;
}

function explainSegment(part: string): string | null {
  if (SEP_CHARS.test(part)) return null;
  if (!part.includes("\\") && !part.includes("[") && !part.includes(".")) {
    return `literal "${part}"`;
  }
  const len = lenDescription(part);
  if (part.startsWith("\\d")) return `${len} dígito(s)`;
  if (part.startsWith("[A-Z]")) return `${len} letra(s) maiúscula(s)`;
  if (part.startsWith("[a-z]")) return `${len} letra(s) minúscula(s)`;
  if (part.startsWith("[A-Za-z]{")) return `${len} letra(s)`;
  if (part.startsWith("[A-Za-z0-9]{"))
    return `${len} caractere(s) alfanumérico(s)`;
  if (part.startsWith(".{")) return `${len} caractere(s) quaisquer`;
  return null;
}

export function generateRegex(examples: string[]): GenerateResult {
  const cleaned = [
    ...new Set(examples.map((e) => e.trim()).filter((e) => e.length > 0)),
  ];

  if (cleaned.length === 0) {
    return {
      regex: ".+",
      explanation: "Sem exemplos válidos",
      confidence: "low",
      matchCount: 0,
      missCount: 0,
      warning: "Nenhum exemplo válido fornecido",
    };
  }

  if (cleaned.length === 1) {
    const ex = cleaned[0] as string;
    const lit = escapeRegex(ex);
    return {
      regex: `\\b${lit}\\b`,
      explanation: `Corresponde exatamente a "${ex}"`,
      confidence: "medium",
      matchCount: 1,
      missCount: 0,
      warning: "Apenas um exemplo — adicione mais para um padrão flexível",
    };
  }

  const tokenized = cleaned.map(tokenize);
  const numParts = (tokenized[0] as string[]).length;
  const structureConsistent = tokenized.every((t) => t.length === numParts);

  if (!structureConsistent) {
    return fallbackPrefixSuffix(cleaned);
  }

  const regexParts: string[] = [];
  const explainParts: string[] = [];
  let isConsistent = true;

  for (let i = 0; i < numParts; i++) {
    const colValues = tokenized.map((t) => t[i] ?? "");
    const allSame = colValues.every((v) => v === colValues[0]);
    const isSep = SEP_CHARS.test(colValues[0] ?? "");

    if (allSame && colValues[0] !== undefined) {
      regexParts.push(escapeRegex(colValues[0]));
      const exp = explainSegment(colValues[0]);
      if (exp) explainParts.push(exp);
    } else if (isSep) {
      const uniq = [...new Set(colValues)].map(escapeRegex).join("");
      regexParts.push(`[${uniq}]`);
      isConsistent = false;
    } else {
      const seg = classifySegment(colValues);
      regexParts.push(seg);
      const exp = explainSegment(seg);
      if (exp) explainParts.push(exp);
    }
  }

  const regexStr = `\\b${regexParts.join("")}\\b`;

  try {
    const re = new RegExp(regexStr);
    const matchCount = cleaned.filter((e) => re.test(e)).length;
    const missCount = cleaned.length - matchCount;

    if (missCount > 0) {
      const fallback = fallbackPrefixSuffix(cleaned);
      fallback.warning = `O padrão gerado não capturou ${missCount} exemplo(s). Usando padrão mais genérico.`;
      return fallback;
    }

    return {
      regex: regexStr,
      explanation:
        explainParts.length > 0
          ? `Captura: ${explainParts.join(", seguido de ")}`
          : "Corresponde ao padrão dos exemplos fornecidos",
      confidence: isConsistent ? "high" : "medium",
      matchCount,
      missCount,
    };
  } catch {
    return fallbackPrefixSuffix(cleaned);
  }
}

function fallbackPrefixSuffix(examples: string[]): GenerateResult {
  let prefix = examples[0] ?? "";
  let suffix = examples[0] ?? "";

  for (const ex of examples.slice(1)) {
    while (prefix && !ex.startsWith(prefix)) prefix = prefix.slice(0, -1);
    while (suffix && !ex.endsWith(suffix)) suffix = suffix.slice(1);
  }

  // Avoid prefix and suffix overlapping (when all examples are identical)
  if (prefix.length + suffix.length > (examples[0]?.length ?? 0)) {
    suffix = "";
  }

  const mid = examples.map((e) =>
    e.slice(
      prefix.length,
      suffix.length > 0 ? e.length - suffix.length : undefined,
    ),
  );
  const midLengths = mid.map((m) => m.length);
  const minLen = Math.min(...midLengths);
  const maxLen = Math.max(...midLengths);
  const midPattern =
    minLen === maxLen ? `.{${minLen}}` : `.{${minLen},${maxLen}}`;

  const parts = [
    prefix.length > 0 ? escapeRegex(prefix) : "",
    midPattern,
    suffix.length > 0 ? escapeRegex(suffix) : "",
  ].filter(Boolean);

  const regexStr = `\\b${parts.join("")}\\b`;

  try {
    const re = new RegExp(regexStr);
    const matchCount = examples.filter((e) => re.test(e)).length;
    const missCount = examples.length - matchCount;

    const expl = [
      prefix.length > 0 ? `começa com "${prefix}"` : "",
      `seguido de ${minLen === maxLen ? `exatamente ${minLen}` : `${minLen} a ${maxLen}`} caractere(s)`,
      suffix.length > 0 ? `terminando com "${suffix}"` : "",
    ]
      .filter(Boolean)
      .join(", ");

    const result: GenerateResult = {
      regex: regexStr,
      explanation: `Captura: ${expl}`,
      confidence: missCount === 0 ? "medium" : "low",
      matchCount,
      missCount,
    };
    if (prefix.length === 0 && suffix.length === 0) {
      result.warning =
        "Estrutura inconsistente — o padrão pode ser muito amplo. Considere criar regras separadas.";
    }
    return result;
  } catch {
    return {
      regex: ".+",
      explanation: "Padrão genérico (fallback)",
      confidence: "low",
      matchCount: examples.length,
      missCount: 0,
      warning:
        "Não foi possível gerar um padrão específico para esses exemplos.",
    };
  }
}
