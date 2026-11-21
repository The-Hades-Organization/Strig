---
version: 1
slug: "crates-themis-inspect-src-gui-rs"
primary_target: "crates/themis-inspect/src/gui.rs"
related_targets: []
---

# Themis Inspect — janela gpui

Modo: operate. Público e produto em PRODUCT.md. Escolha feita em duas rodadas: o padrão da categoria, depois o acabamento "Legível e neutro" com a régua do GitHub Primer (também comparado a Linear, Vercel Geist e Raycast).

## Direction contract

THESIS: a avaliação lida como uma revisão de código: o veredito numa caixa com cabeçalho e selo, e os grants numa linha do tempo vertical em que cada destino tem seu ícone. Recusa o painel de cartões soltos com selos espalhados.

OWN-WORLD: fundo #FFFFFF, superfícies #F6F8FA, bordas #D1D9E0, tinta #1F2328, secundário #59636E, azul #0969DA para seleção e degrau decisivo, permitido #1A7F37, negado #CF222E; selos em pílula com ícone e palavra; caixas com cabeçalho cinza; mono para ids.

STORY: a pessoa escolhe sujeito, permissão e recurso, lê o veredito e o motivo, vê o degrau decisivo no caminho e desce a linha do tempo até o grant que explica a decisão, com a árvore da condição aberta.

FIRST VIEWPORT: cabeçalho de 56 px com marca, arquivo, abas com ícone e Recarregar; barra lateral de 300 px com Sujeito, Permissão, Recurso e Grants; à direita a caixa do veredito (selo Negado + pedido, motivo, nota de quem decidiria, fatos), a caixa do caminho do recurso com o degrau 3 em azul e a linha do tempo dos grants com o pro-export expandido.

FORM: acabamento Primer sobre o padrão da categoria, 3.º da lista de referências; seed:8381ed00f99db9ec

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
