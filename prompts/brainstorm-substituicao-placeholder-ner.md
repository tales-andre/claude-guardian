# Tarefa: adicionar substituição por placeholders fictícios (egress, mão única) + detecção NER ao claude-guardian

## Papel
Você é engenheiro do `claude-guardian` (DLP para Claude Code, Node/TypeScript, sem build step — `node --experimental-strip-types`, Node ≥ 22.6). Conhece a arquitetura descrita em `CLAUDE.md`: hooks síncronos (`scanSync`, teto 500ms, fail-closed), engine de detectores, policy engine, audit hash-chain, daemon/servidor Fastify, proxy HTTPS/MCP e extensão de browser.

## Objetivo
Fazer o guardian, além de bloquear/mascarar, **reescrever o conteúdo de saída substituindo dados sensíveis por valores fictícios plausíveis** — para o prompt poder ser enviado com segurança usando dados falsos. Foco exclusivo em **egress (o que sai), mão única**: NÃO há restauração da resposta, NÃO há round-trip, NÃO há vault persistente. Também aumentar o recall de PII adicionando um detector **NER** que pegue entidades que o regex não pega (nomes, endereços).

## Contexto e restrições
- O dado que sai no Claude Code passa pelo **hook síncrono de 500ms** — essa é a superfície nº 1. NER não cabe confortavelmente nesse orçamento, então a detecção é **em camadas**.
- Substituição falha **aberta e silenciosa** (se o detector perde a entidade, o dado real vaza achando que foi trocado). Por isso todo timeout/erro no caminho de substituição deve **falhar fechado (bloquear)**, nunca deixar passar sem substituir.
- Enviar o dado a proteger para uma API de NER externa é auto-sabotagem: o modelo NER deve rodar **local** (ONNX quantizado / in-process ou daemon local). Nada de raw value saindo do processo para terceiros.

## Escopo (in)
1. **Nova ação de policy `substitute`** ao lado de `block | require-approval | redact | allow`. É opt-in por regra. Não sobrecarregar `redact` (que continua sendo masking destrutivo). Ordem de prioridade e short-circuit devem ser definidos de forma coerente com `src/lib/policy.ts` — justifique onde `substitute` entra no ranking.
2. **Detecção em camadas:**
   - regex + gitleaks continuam **síncronos in-process** como piso, sempre executados.
   - **Detector NER** (modelo pré-treinado ONNX quantizado, multilíngue PT/EN) adicionado como `extraDetector`, rodando no **daemon persistente com o modelo warm**. O hook chama o daemon com orçamento apertado.
   - **Timeout/erro do NER no caminho de substituição → fail-closed (bloqueia)**, nunca envia sem NER.
3. **Offsets nos findings:** os detectores passam a expor `start`/`end` do match (posição no texto), pois a substituição in-place exige a posição — snippet não basta. Adaptar `DetectorFinding`/`types.ts` e todos os detectores.
4. **Geradores de placeholder format-preserving e determinísticos:** substituto por `hash(rawValue + salt)` → mesmo valor real sempre vira o mesmo fake (integridade referencial dentro do prompt e entre turnos) sem armazenar nada. Um gerador por `dataType` (nome, email, CPF/CNPJ, telefone, cartão de crédito, API key, etc.), cada um produzindo valor com **formato válido mas fictício** (ex.: CPF com formato válido que não pertence a ninguém real). `dataType` sem gerador cai em **mask** como fallback.
5. **Aplicar substituição em todas as superfícies de egress, sempre mão única:** `UserPromptSubmit` (reescreve o prompt), proxy HTTPS (`gui-scan`), proxy MCP (`mcp-scan`), extensão/`web-scan`. Nenhuma restaura resposta.
6. **Config + schema Zod** da ação `substitute` (incluindo salt, orçamento de latência do NER, lista de dataTypes com gerador). Atualizar `DEFAULT_CONFIG` mantendo o modo local inalterado quando os campos novos estão vazios.
7. **Audit:** registrar eventos de substituição sem gravar o valor bruto — só metadados (`dataType`, `severity`, contagem, fake usado se não revelar o real).
8. **Testes vitest** cobrindo: detecção NER, offsets corretos, determinismo do gerador (mesmo input → mesmo fake), format-validity dos fakes, fail-closed no timeout do NER, integração da ação `substitute` no policy engine, e reescrita end-to-end em pelo menos uma superfície.

## Escopo (out)
- Restauração/round-trip da resposta do LLM; vault persistente.
- Treino de modelo próprio (usar pré-treinado).
- Substituição no browser para providers ainda não validados (ver `docs/ADAPTER-VALIDATION.md`).

## Processo
1. Primeiro **investigue e mapeie** os arquivos afetados (engine, `types.ts`, `policy.ts`, hooks, proxies, config, audit) e proponha o plano concreto antes de editar.
2. Resolva os **pontos em aberto** com uma recomendação fundamentada, marcando claramente o que assumiu:
   - modelo NER exato e se o hook fala com o daemon via localhost ou carrega WASM in-process;
   - quanto dos 500ms fica para o NER;
   - quais `dataTypes` ganham gerador sintético na v1 vs. caem no mask.
3. Implemente seguindo os padrões do repo (biome, sem build step). Rode `npm run ci` (typecheck + biome + vitest) e garanta verde.
4. Atualize `CLAUDE.md` e docs relevantes descrevendo a ação `substitute` e o detector NER.

## Formato de saída
- Plano inicial (arquivos + decisões dos pontos em aberto) antes de codar.
- Implementação com testes.
- Resumo final: o que mudou, decisões assumidas, resultado do `npm run ci`.

## Critérios de qualidade
- Piso regex/gitleaks nunca é enfraquecido; NER só soma.
- Nenhum raw value sai do processo para terceiros.
- Todo caminho de substituição é fail-closed em erro/timeout.
- Determinismo e format-validity dos placeholders comprovados por teste.
- Modo local existente permanece idêntico quando os campos novos estão vazios.

## Edge cases a tratar
- Entidade detectada por dois detectores (regex + NER) na mesma posição → uma única substituição (respeitar a dedup existente + offsets).
- Sobreposição parcial de spans de detectores diferentes.
- Mesma entidade repetida no prompt → mesmo fake em todas as ocorrências.
- `dataType` sem gerador → mask, não erro.
- Prompt sem findings → passa intacto, sem custo extra perceptível.
- NER indisponível/timeout → bloqueia, não envia.
