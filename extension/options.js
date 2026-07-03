const api = globalThis.browser ?? globalThis.chrome;
const DEFAULTS = { endpoint: "http://127.0.0.1:7734", token: "" };

const $endpoint = document.getElementById("endpoint");
const $token = document.getElementById("token");
const $ok = document.getElementById("ok");
const $save = document.getElementById("save");
const $managed = document.getElementById("managed");

async function getManaged() {
  try {
    return (await api.storage.managed.get(["endpoint", "token"])) || {};
  } catch {
    return {};
  }
}

(async function load() {
  const managed = await getManaged();
  if (managed.endpoint) {
    // Configuração vem da política da organização: exibe somente-leitura.
    $endpoint.value = managed.endpoint;
    $token.value = managed.token ? "••••••••" : "";
    $endpoint.disabled = true;
    $token.disabled = true;
    $save.disabled = true;
    $managed.style.display = "block";
    return;
  }
  const s = await api.storage.local.get(["endpoint", "token"]);
  $endpoint.value = s.endpoint || DEFAULTS.endpoint;
  $token.value = s.token || "";
})();

$save.addEventListener("click", async () => {
  if ($save.disabled) return;
  await api.storage.local.set({
    endpoint: ($endpoint.value || DEFAULTS.endpoint).trim(),
    token: $token.value.trim(),
  });
  $ok.style.display = "block";
  setTimeout(() => ($ok.style.display = "none"), 1500);
});
