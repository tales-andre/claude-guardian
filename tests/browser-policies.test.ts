import { describe, expect, it } from "vitest";
import {
  CHROME_WEBSTORE_UPDATE_URL,
  compileBrowserPolicies,
} from "../src/lib/browser-policies.ts";

const EXT_ID = "abcdefghijklmnopabcdefghijklmnop";

function compile(overrides = {}) {
  return compileBrowserPolicies({ extensionId: EXT_ID, ...overrides });
}

describe("compileBrowserPolicies", () => {
  it("gera forcelist Chrome no formato <id>;<updateUrl> com Web Store default", () => {
    const p = compile();
    const chrome = p.chromeLinuxPolicy as {
      ExtensionInstallForcelist: string[];
    };
    expect(chrome.ExtensionInstallForcelist).toEqual([
      `${EXT_ID};${CHROME_WEBSTORE_UPDATE_URL}`,
    ]);
  });

  it("inclui managed storage (3rdparty) com endpoint default do daemon local", () => {
    const p = compile();
    const chrome = p.chromeLinuxPolicy as {
      "3rdparty": { extensions: Record<string, { endpoint: string }> };
    };
    expect(chrome["3rdparty"].extensions[EXT_ID]?.endpoint).toBe(
      "http://127.0.0.1:7734",
    );
  });

  it("propaga endpoint e token custom para Chrome e Edge", () => {
    const p = compile({
      guardianEndpoint: "http://127.0.0.1:9999",
      guardianToken: "tok-123",
    });
    for (const policy of [p.chromeLinuxPolicy, p.edgeLinuxPolicy]) {
      const cfg = (
        policy as {
          "3rdparty": {
            extensions: Record<string, { endpoint: string; token: string }>;
          };
        }
      )["3rdparty"].extensions[EXT_ID];
      expect(cfg?.endpoint).toBe("http://127.0.0.1:9999");
      expect(cfg?.token).toBe("tok-123");
    }
  });

  it("gera .reg com as chaves de política do Chrome e do Edge", () => {
    const p = compile({ guardianToken: "tok-reg" });
    expect(p.windowsRegistry).toContain(
      "Windows Registry Editor Version 5.00",
    );
    expect(p.windowsRegistry).toContain(
      `SOFTWARE\\Policies\\Google\\Chrome\\ExtensionInstallForcelist`,
    );
    expect(p.windowsRegistry).toContain(
      `SOFTWARE\\Policies\\Microsoft\\Edge\\ExtensionInstallForcelist`,
    );
    expect(p.windowsRegistry).toContain(
      `3rdparty\\extensions\\${EXT_ID}\\policy`,
    );
    expect(p.windowsRegistry).toContain('"token"="tok-reg"');
  });

  it("gera mobileconfig com payloads Chrome/Edge e managed storage", () => {
    const p = compile();
    expect(p.macMobileconfig).toContain("<?xml");
    expect(p.macMobileconfig).toContain("com.google.Chrome");
    expect(p.macMobileconfig).toContain("com.microsoft.Edge");
    expect(p.macMobileconfig).toContain(`com.google.Chrome.extensions.${EXT_ID}`);
    expect(p.macMobileconfig).toContain("ExtensionInstallForcelist");
    expect(p.macMobileconfig).toContain("http://127.0.0.1:7734");
  });

  it("gera policies.json do Firefox com force_installed quando há install_url", () => {
    const p = compile({
      firefoxExtensionId: "claude-guardian@junto.local",
      firefoxInstallUrl: "https://mdm.example.com/claude-guardian.xpi",
    });
    const ff = p.firefoxPolicies as {
      policies: {
        ExtensionSettings: Record<
          string,
          { installation_mode: string; install_url: string }
        >;
        "3rdparty": { Extensions: Record<string, { endpoint: string }> };
      };
    };
    const setting = ff.policies.ExtensionSettings["claude-guardian@junto.local"];
    expect(setting?.installation_mode).toBe("force_installed");
    expect(setting?.install_url).toBe(
      "https://mdm.example.com/claude-guardian.xpi",
    );
    expect(
      ff.policies["3rdparty"].Extensions["claude-guardian@junto.local"]
        ?.endpoint,
    ).toBe("http://127.0.0.1:7734");
  });

  it("sem install_url do Firefox, emite só o managed storage (sem force install)", () => {
    const p = compile({ firefoxExtensionId: "claude-guardian@junto.local" });
    const ff = p.firefoxPolicies as {
      policies: Record<string, unknown>;
    };
    expect(ff.policies["ExtensionSettings"]).toBeUndefined();
    expect(ff.policies["3rdparty"]).toBeDefined();
  });

  it("Edge aceita id e update_url próprios (loja da Microsoft)", () => {
    const p = compile({
      edgeExtensionId: "ponmlkjihgfedcbaponmlkjihgfedcba",
      edgeUpdateUrl: "https://edge.microsoft.com/extensionwebstorebase/v1/crx",
    });
    const edge = p.edgeLinuxPolicy as {
      ExtensionInstallForcelist: string[];
    };
    expect(edge.ExtensionInstallForcelist).toEqual([
      "ponmlkjihgfedcbaponmlkjihgfedcba;https://edge.microsoft.com/extensionwebstorebase/v1/crx",
    ]);
  });
});
