// Default configuration for the Claude Guardian extension.
// The options page can override `endpoint` and `token`, persisted in
// extension storage. Defaults assume the guardian server on localhost.
//
// Used in two contexts:
//  - content/background scripts (read overrides from storage)
//  - injected page script (uses these literals only — no extension APIs)
globalThis.GUARDIAN_CONFIG = {
  // Base URL of the local claude-guardian server (matches dashboardPort).
  endpoint: "http://127.0.0.1:7734",
  // Must match `dashboardToken` in claude-guardian.config.json (empty = no auth).
  token: "",
};
