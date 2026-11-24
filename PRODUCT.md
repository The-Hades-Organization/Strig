# Product

<!-- impeccable:product-schema 1 -->

## Platform

desktop

App nativo em gpui (`gpui-pre =0.3.11` + `gpui-component =0.9.0`), Linux (Wayland e X11) e macOS. Não é web: a interface é desenhada em Rust, sem HTML/CSS no produto.

## Users

Dois públicos com o mesmo peso:

- **Quem integra a Strig**: escreve o catálogo, os papéis e os grants, e precisa entender por que uma decisão saiu permitida ou negada.
- **Quem audita**: revisa trilhas de auditoria em JSON Lines, confere a cadeia de hash e reavalia decisões passadas contra a política atual.

## Product Purpose

Tornar visível como a Strig decide. A partir de um cenário (spec + grants + tuplas + sujeitos + recursos) ou de uma trilha de auditoria, mostra a decisão e o rastro dela: overrides, o destino de cada grant (veredito, degrau, âncora) e a árvore das condições. Sucesso é a pessoa responder "por que isto foi permitido/negado?" e "este conjunto de grants daria acesso a X?" sem ler código.

## Positioning

É o visualizador do `Engine::explain` da Strig: o rastro vem do próprio motor, não de uma reimplementação, então o que a tela mostra é exatamente o que o motor decide. A simulação liga e desliga grants e compara com os originais; a auditoria reavalia registros antigos contra a política atual.

## Operating Context

Consulta pontual: a pessoa abre o app para responder uma dúvida e fecha. Os arquivos são recarregados sozinhos quando mudam no disco. Entrada por CLI (`--scenario`, `--audit`); o mesmo crate também responde no terminal (`explain`, `matrix`, `audit`).

## Capabilities and Constraints

- Abas: Avaliação (sujeito × permissão × recurso, com rastro), Matriz (permissões × sujeitos para um recurso, células que mudaram com a simulação marcadas) e Auditoria (lista de registros, estado da cadeia, reavaliação, rastro gravado, JSON).
- Simulação: ligar/desligar grants do cenário, adicionar grants, desfazer.
- Vocabulário do domínio: sujeito, permissão, recurso, grant, papel, relação, âncora, degrau, override, estratégia, veredito, cadeia de hash.
- Textos da interface em inglês (os comentários do código seguem em português).
- Crate opcional (`strig-inspect`), fora do `default-members` do workspace.

## Brand Commitments

Identidade visual própria e única: não herda da família Hades (Hades-UI, Cardinal). Nome do produto: Strig Inspect.

## Evidence on Hand

- Cenário de exemplo: `crates/strig-inspect/examples/scenario.json`.
- Não há trilha de auditoria de exemplo versionada.

## Product Principles

1. A decisão vem primeiro; o rastro explica a decisão, nunca a esconde.
2. O que aparece na tela é o que o motor decidiu: nenhuma regra reinterpretada na interface.
3. Permitido e negado se distinguem sem depender só da cor.
4. Simulação é sempre reversível e sempre comparada com o original.
