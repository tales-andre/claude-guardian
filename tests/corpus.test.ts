import { describe, expect, it } from "vitest";
import { scanSync } from "../src/engine/index.ts";
import { negatives, positives } from "./corpus/corpus.ts";

// Portão de qualidade dos detectores antes de rollout em frota:
// recall mínimo nos positivos e zero falso positivo nos negativos.
// Se um detector novo/alterado quebrar este teste, ele NÃO está pronto
// para rodar em modo block em centenas de máquinas.
const MIN_RECALL = 0.95;

describe("corpus de detectores", () => {
  it(`recall >= ${MIN_RECALL * 100}% nos positivos`, () => {
    const misses = positives.filter(
      (sample) =>
        !scanSync(sample.text).findings.some(
          (f) => String(f.dataType) === sample.dataType,
        ),
    );
    const recall = (positives.length - misses.length) / positives.length;
    expect(
      misses.map((m) => m.name),
      `recall ${(recall * 100).toFixed(1)}% — amostras perdidas listadas acima`,
    ).toEqual([]);
    expect(recall).toBeGreaterThanOrEqual(MIN_RECALL);
  });

  it("zero detecções nos negativos (falso positivo)", () => {
    for (const sample of negatives) {
      const { findings } = scanSync(sample.text);
      expect(
        findings.map((f) => `${sample.name} → ${f.detectorId} (${f.snippet})`),
      ).toEqual([]);
    }
  });
});
