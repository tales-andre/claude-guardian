import type BetterSqlite3 from "better-sqlite3";
import type { Severity } from "../../types/index.ts";
import { makeFinding, type Detector } from "./types.ts";

interface CustomDetectorRow {
  id: string;
  name: string;
  regex: string;
  severity: string;
}

export function loadCustomDetectors(db: BetterSqlite3.Database): Detector[] {
  try {
    const rows = db
      .prepare("SELECT id, name, regex, severity FROM custom_detectors")
      .all() as CustomDetectorRow[];

    return rows.flatMap((row) => {
      let re: RegExp;
      try {
        re = new RegExp(row.regex, "g");
      } catch {
        return [];
      }

      const detector: Detector = {
        id: row.id,
        label: row.name,
        dataType: `custom:${row.id}`,
        severity: row.severity as Severity,
        scan(text: string) {
          const findings = [];
          const localRe = new RegExp(re.source, re.flags);
          let m: RegExpExecArray | null;
          while ((m = localRe.exec(text)) !== null) {
            const raw = m[0];
            if (!raw) break;
            findings.push(makeFinding(this, raw, raw, m.index, m.index + raw.length, 0.9));
          }
          return findings;
        },
      };
      return [detector];
    });
  } catch {
    return [];
  }
}
