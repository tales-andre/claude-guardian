import type { DataType, DetectorFinding, Severity } from "../../types/index.ts";

export type { DetectorFinding };

export interface Detector {
  id: string;
  label: string;
  dataType: DataType;
  severity: Severity;
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
