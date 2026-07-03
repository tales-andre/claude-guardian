const api = globalThis.browser ?? globalThis.chrome;
const DEFAULTS = { endpoint: "http://127.0.0.1:7734", token: "" };

const $endpoint = document.getElementById("endpoint");
const $token = document.getElementById("token");
const $ok = document.getElementById("ok");

(async function load() {
  const s = await api.storage.local.get(["endpoint", "token"]);
  $endpoint.value = s.endpoint || DEFAULTS.endpoint;
  $token.value = s.token || "";
})();

document.getElementById("save").addEventListener("click", async () => {
  await api.storage.local.set({
    endpoint: ($endpoint.value || DEFAULTS.endpoint).trim(),
    token: $token.value.trim(),
  });
  $ok.style.display = "block";
  setTimeout(() => ($ok.style.display = "none"), 1500);
});
