import { describe, expect, it } from "vitest";
import { computeMachineStatus, hashConfig } from "../src/lib/fleet.ts";

const NOW = new Date("2026-06-25T12:00:00Z");
const EXPECTED = "abc123";

function minsAgo(n: number): string {
  return new Date(NOW.getTime() - n * 60_000).toISOString();
}

describe("computeMachineStatus", () => {
  const opts = { expectedConfigHash: EXPECTED, now: NOW };

  it("is healthy with a matching config and a recent heartbeat", () => {
    expect(
      computeMachineStatus(
        { configHash: EXPECTED, lastSeen: minsAgo(5) },
        opts,
      ),
    ).toBe("healthy");
  });

  it("is tampered when the config hash does not match the org's expected hash", () => {
    expect(
      computeMachineStatus(
        { configHash: "different", lastSeen: minsAgo(1) },
        opts,
      ),
    ).toBe("tampered");
  });

  it("is stale when the last heartbeat is older than the threshold", () => {
    expect(
      computeMachineStatus(
        { configHash: EXPECTED, lastSeen: minsAgo(120) },
        opts,
      ),
    ).toBe("stale");
  });

  it("reports tampered even when also stale (tampering wins)", () => {
    expect(
      computeMachineStatus(
        { configHash: "different", lastSeen: minsAgo(999) },
        opts,
      ),
    ).toBe("tampered");
  });

  it("é tampered quando a extensão é exigida e nunca reportou", () => {
    expect(
      computeMachineStatus(
        { configHash: EXPECTED, lastSeen: minsAgo(5) },
        { ...opts, extensionRequired: true },
      ),
    ).toBe("tampered");
  });

  it("é tampered quando a extensão silenciou além da janela (máquina viva)", () => {
    expect(
      computeMachineStatus(
        {
          configHash: EXPECTED,
          lastSeen: minsAgo(5),
          extensionLastSeen: minsAgo(120),
        },
        { ...opts, extensionRequired: true },
      ),
    ).toBe("tampered");
  });

  it("é healthy quando a extensão exigida reportou dentro da janela", () => {
    expect(
      computeMachineStatus(
        {
          configHash: EXPECTED,
          lastSeen: minsAgo(5),
          extensionLastSeen: minsAgo(10),
        },
        { ...opts, extensionRequired: true },
      ),
    ).toBe("healthy");
  });

  it("máquina inteira parada fica stale, não tampered por extensão silenciosa", () => {
    expect(
      computeMachineStatus(
        {
          configHash: EXPECTED,
          lastSeen: minsAgo(999),
          extensionLastSeen: minsAgo(999),
        },
        { ...opts, extensionRequired: true },
      ),
    ).toBe("stale");
  });

  it("sem extensionRequired, extensão silenciosa não muda o status", () => {
    expect(
      computeMachineStatus(
        { configHash: EXPECTED, lastSeen: minsAgo(5) },
        opts,
      ),
    ).toBe("healthy");
  });
});

describe("hashConfig", () => {
  it("is deterministic for equal content regardless of key order", () => {
    expect(hashConfig({ a: 1, b: 2 })).toBe(hashConfig({ b: 2, a: 1 }));
  });

  it("changes when the content changes", () => {
    expect(hashConfig({ a: 1 })).not.toBe(hashConfig({ a: 2 }));
  });
});
