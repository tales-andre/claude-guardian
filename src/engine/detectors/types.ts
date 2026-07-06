import type { DataType, DetectorFinding, Severity } from "../../types/index.ts";

export type { DetectorFinding };

export interface Detector {
  id: string;
  label: string;
  dataType: DataType;
  severity: Severity;
  /**
   * Fonte da regex primária usada pelo scan (sempre `X_RE.source` da MESMA
   * constante que o scan executa — nunca uma cópia manual, para o catálogo do
   * dashboard nunca divergir do que roda). Ausente em detectores heurísticos
   * ou externos.
   */
  pattern?: string;
  /** Como o detector funciona; ausente = "regex". */
  kind?: "regex" | "heuristic" | "external";
  /** Descrição do critério para detectores sem pattern (heuristic/external). */
  description?: string;
  scan(text: string): DetectorFinding[];
}

// Build a DetectorFinding from regex match metadata.
export function makeFinding(
  detector: Omit<Detector, "scan">,
  rawValue: string,
  snippet: string,
  start: number,
  end: number,
  confidence: number,
): DetectorFinding {
  return {
    detectorId: detector.id,
    label: detector.label,
    dataType: detector.dataType,
    severity: detector.severity,
    snippet,
    rawValue,
    position: { start, end },
    confidence,
  };
}
