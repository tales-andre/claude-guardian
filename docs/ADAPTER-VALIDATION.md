# Validação manual dos adapters da extensão

Os adapters em `extension/injected.js` dependem de superfícies **não-oficiais**
de cada site (endpoint interno + formato do body). Antes de qualquer rollout,
cada adapter precisa ser validado contra o tráfego real — um adapter com
endpoint errado combinado com fail-closed **bloqueia o provider inteiro** para
a frota no dia 1.

## Status atual

| Provider | Adapter | Status | Observação |
|---|---|---|---|
| Claude (claude.ai) | `claudeAdapter` | ✅ maduro | `POST /(completion\|retry_completion\|append_message\|messages)`, body JSON `prompt`/`messages`; redaction in-place suportada |
| ChatGPT | `chatgptAdapter` | ✅ maduro | `POST /backend-api/(f/)?conversation`, `messages[].content.parts`; sem redaction (block) |
| Gemini | `geminiAdapter` | ✅ **validado com tráfego real** (2026-07-04) | Envio = XHR `POST …/assistant.lamda.BardFrontendService/StreamGenerate` com `f.req` urlencoded; extração decodifica todas as strings do envelope (nunca retorna vazio p/ corpo não-vazio). Bloqueio simula falha de rede (readyState 4 + error/loadend) — UI do Gemini não trava |
| Microsoft Copilot | `copilotAdapter` | ⚠️ **pendente** | Endpoints HTTP cobertos por palpite; **muitos fluxos usam WebSocket (gap residual conhecido, não coberto)** |
| Mistral (Le Chat) | `mistralAdapter` | ⚠️ **pendente** | Endpoint/body por palpite |
| Adapta One | `adaptaAdapter` | ⚠️ **pendente** | Endpoint/body por palpite |

Os pendentes estão marcados com `// TODO: validar ... com tráfego real` no
código. **Não remova o TODO sem completar o checklist abaixo.**

## Pré-requisitos

1. Daemon rodando: `npm run serve` (ou o serviço instalado).
2. Extensão carregada (modo dev ou force-installed) apontando para o daemon.
3. Uma conta no provider a validar.
4. Um segredo de teste que o engine detecta com certeza, por exemplo uma
   chave AWS sintética: `AKIAIOSFODNN7EXAMPLE` acompanhada de
   `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`.
   **Nunca use um segredo real.**

## Checklist por provider (repita para cada um)

### A. Mapear o tráfego real

1. Abra o site do provider, DevTools → **Network** → filtro `Fetch/XHR` + `WS`.
2. Envie uma mensagem inócua ("olá") e observe:
   - [ ] Qual request dispara no envio? (método, URL completa)
   - [ ] É `fetch`/XHR ou **WebSocket**? (WS = não coberto; anote como gap)
   - [ ] Qual o formato do body? (JSON puro, urlencoded `f.req`, FormData, protobuf)
   - [ ] Onde exatamente está o texto digitado dentro do body?
3. Teste também: **editar mensagem** e **retry/regenerate** — endpoints podem
   ser outros e precisam constar no `isSendRequest`.

### B. Corrigir o adapter

4. Ajuste `isSendRequest` para casar exatamente os endpoints observados (e não
   casar polls/telemetria — envio de "olá" não pode bloquear requests de
   telemetria por engano).
5. Ajuste `extractText` para o formato real do body.
6. Se o body for JSON reescrevível, implemente `injectRedaction`; senão,
   documente que redact vira block nesse provider.

### C. Validar o comportamento

7. [ ] **Prompt limpo passa**: "olá" chega ao provider normalmente.
8. [ ] **Segredo bloqueia**: prompt com a chave sintética → request de envio
       **não aparece** no Network (ou aparece abortado) e o overlay de block
       aparece.
9. [ ] **Upload bloqueia**: arrastar um `.env` de teste → bloqueado por nome.
10. [ ] **Fail-closed**: pare o daemon → qualquer envio no site é bloqueado
        com a mensagem de guardian offline.
11. [ ] **Sem falso positivo estrutural**: navegar, trocar de conversa e usar
        o site por ~5 min sem enviar segredo não dispara block nenhum.
12. [ ] **Drift zero**: `GET /api/fleet` (ou a aba Fleet) não mostra
        `extractFailures` crescendo para o host durante o uso normal — se
        cresce, o `extractText` está falhando em envios reconhecidos.

### D. Encerrar

13. Remova o `// TODO: validar ...` do adapter.
14. Atualize a tabela de status deste arquivo e o `extension/README.md`.
15. Commit: `fix(extension): valida adapter <provider> contra tráfego real`.

## Gaps residuais conhecidos (documentar, não esconder)

- **WebSocket / `navigator.sendBeacon`** não são interceptados — fluxos do
  Copilot que usam WS escapam da camada de rede (a camada de UI/upload ainda
  cobre parte). Mitigação honesta: documentar e monitorar drift no fleet.
- **Binários/PDF/imagem** em upload: decididos por nome/extensão, conteúdo não
  é escaneado.
- Sites mudam endpoint sem aviso: com fail-closed, a quebra aparece como
  bloqueio total do site + `extractFailures` subindo no fleet — trate como
  incidente de manutenção do adapter, não como bug do usuário.
