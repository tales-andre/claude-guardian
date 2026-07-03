# Claude Guardian — extensão de browser (multi-provider)

Estende a proteção DLP do `claude-guardian` para os principais chats de IA no
browser. A extensão é só "olho e mão": captura prompts e uploads e delega
**todo** o scan ao backend local (`POST /api/scan-web`). **Fail-closed**: se o
guardian estiver offline — ou se um envio for reconhecido mas o texto não puder
ser extraído — o envio é bloqueado.

## Sites suportados

| Provider | Hosts |
|---|---|
| Claude | `claude.ai` |
| ChatGPT | `chatgpt.com`, `chat.openai.com` |
| Gemini | `gemini.google.com` |
| Microsoft Copilot | `copilot.microsoft.com` |
| Mistral (Le Chat) | `chat.mistral.ai` |
| Adapta One | `adapta.one`, `app.adapta.one` |

**Fora de escopo:** Kiro (IDE desktop — fora do alcance de uma extensão de
browser; cobrir via hooks do próprio claude-guardian) e Perplexity.

## Pré-requisito: subir o backend

```bash
npm run serve   # sobe o guardian em http://127.0.0.1:7734
```

Se você definiu `dashboardToken` no `claude-guardian.config.json`, configure o
mesmo token na extensão (página de opções).

## Instalar (modo desenvolvedor)

### Chrome / Edge
1. Abra `chrome://extensions` (ou `edge://extensions`).
2. Ative **Modo desenvolvedor**.
3. **Carregar sem compactação** → selecione a pasta `extension/`.
4. (Opcional) abra as **opções** da extensão e ajuste endpoint/token.

### Firefox
1. Renomeie/aponte para o manifest do Firefox:
   ```bash
   cp extension/manifest.firefox.json extension/manifest.json   # ou use um link
   ```
   > No Firefox o `background` usa `scripts` em vez de `service_worker`.
2. Abra `about:debugging#/runtime/this-firefox`.
3. **Carregar extensão temporária** → selecione `extension/manifest.json`.
4. ⚠️ No Firefox a extensão temporária **some ao fechar o browser** — recarregue.

## Como funciona

- **Camada de rede (`injected.js`)**: intercepta `fetch` **e `XMLHttpRequest`**
  de envio de mensagem e segura até ter veredito. É o enforcement real. O
  conhecimento por site (qual request é "envio" e como extrair o texto) vive no
  registry `ADAPTERS` — um adapter por provider. Adicionar um site = um adapter
  novo + uma entrada de host nos dois manifests.
- **Camada de UI (`content.js`)**: overlay de feedback e interceptação de
  uploads (drag/drop, paste, file input) — agnóstica de site.
- **Background (`background.js`)**: único contexto que fala com `localhost`.

## Limitações conhecidas

- Os adapters dependem de superfícies **não-oficiais** de cada site
  (endpoint/formato de body podem mudar sem aviso). Quando mudam, o envio é
  bloqueado (fail-closed) até o adapter ser corrigido.
- Adapters marcados com `// TODO: validar ... com tráfego real` em
  `injected.js` (**Gemini, Copilot, Mistral, Adapta One**) foram escritos com o
  melhor palpite e **precisam ser validados** inspecionando o Network real do
  site. Claude e ChatGPT são os mais maduros.
- Envios via **WebSocket** ou `navigator.sendBeacon` não são cobertos (risco
  residual conhecido — ex.: alguns fluxos do Copilot).
- Conteúdo de **binários/PDF/imagem** não é escaneado — bloqueio por nome/extensão.
- Token fica na config da extensão (aceitável em localhost).
- Sem build step: arquivos `.js` carregam direto (sem TypeScript/esbuild).

## Testes manuais

| Caso | Esperado |
|---|---|
| Prompt limpo | passa |
| Prompt com `sk-ant-...` / AWS key | bloqueado (request rejeitado no Network) |
| Arrastar `.env` / `.pem` | bloqueado por nome |
| Guardian desligado | bloqueado (fail-closed) |
| Envio reconhecido mas texto não extraído | bloqueado (fail-closed) |

> Rode o caso "prompt com segredo" em **cada** site suportado e confirme no
> DevTools → Network que o request de envio foi rejeitado e o overlay apareceu.
