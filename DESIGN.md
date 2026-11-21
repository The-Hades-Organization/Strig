---
name: Themis Inspect
description: Visualizador desktop do rastro de decisão da Themis, com acabamento GitHub Primer claro e neutro.
colors:
  bg: "#FFFFFF"
  surface: "#F6F8FA"
  surface2: "#EFF2F5"
  selected: "#E7ECF0"
  line: "#D1D9E0"
  line2: "#DFE4E9"
  ink: "#1F2328"
  mute: "#59636E"
  faint: "#818B98"
  accent: "#0969DA"
  accent_bg: "#DDF4FF"
  accent_line: "#B6E3FF"
  accent_ink: "#0550AE"
  accent_soft: "#F1F9FF"
  ok: "#1A7F37"
  ok_bg: "#DAFBE1"
  ok_line: "#8DDB9F"
  no: "#CF222E"
  no_bg: "#FFEBE9"
  no_line: "#FFCECB"
  warn: "#9A6700"
  warn_bg: "#FFF8C5"
  warn_line: "#D4A72C"
typography:
  headline:
    fontFamily: "Noto Sans"
    fontSize: "20px"
    fontWeight: 600
  title:
    fontFamily: "Noto Sans"
    fontSize: "16px"
    fontWeight: 600
  brand:
    fontFamily: "Noto Sans"
    fontSize: "15px"
    fontWeight: 600
  title-small:
    fontFamily: "Noto Sans"
    fontSize: "14px"
    fontWeight: 600
  body-medium:
    fontFamily: "Noto Sans"
    fontSize: "14px"
    fontWeight: 500
  body:
    fontFamily: "Noto Sans"
    fontSize: "14px"
    fontWeight: 400
  body-small:
    fontFamily: "Noto Sans"
    fontSize: "13px"
    fontWeight: 400
  label:
    fontFamily: "Noto Sans"
    fontSize: "12px"
    fontWeight: 500
  caption-strong:
    fontFamily: "Noto Sans"
    fontSize: "12px"
    fontWeight: 600
  caption:
    fontFamily: "Noto Sans"
    fontSize: "12px"
    fontWeight: 400
  mono-headline:
    fontFamily: "JetBrains Mono"
    fontSize: "17px"
    fontWeight: 600
  mono:
    fontFamily: "JetBrains Mono"
    fontSize: "12.5px"
    fontWeight: 400
  mono-small:
    fontFamily: "JetBrains Mono"
    fontSize: "12px"
    fontWeight: 400
  mono-time:
    fontFamily: "JetBrains Mono"
    fontSize: "11.5px"
    fontWeight: 400
  kbd:
    fontFamily: "JetBrains Mono"
    fontSize: "11px"
    fontWeight: 400
rounded:
  xs: "2px"
  sm: "4px"
  md: "6px"
  full: "9999px"
spacing:
  "2": "2px"
  "4": "4px"
  "6": "6px"
  "8": "8px"
  "10": "10px"
  "12": "12px"
  "14": "14px"
  "16": "16px"
  "24": "24px"
  "32": "32px"
components:
  app-header:
    backgroundColor: "{colors.bg}"
    height: "56px"
    padding: "0 24px"
  sidebar:
    backgroundColor: "{colors.surface}"
    width: "300px"
    padding: "12px"
  audit-list:
    backgroundColor: "{colors.surface}"
    width: "420px"
    padding: "12px"
  tab:
    textColor: "{colors.ink}"
    typography: "{typography.body}"
    rounded: "{rounded.md}"
    padding: "4px 8px"
  tab-hover:
    backgroundColor: "{colors.surface2}"
  tab-active:
    textColor: "{colors.ink}"
    typography: "{typography.title-small}"
  tab-active-underline:
    backgroundColor: "{colors.accent}"
    rounded: "{rounded.xs}"
    height: "2px"
  button-neutral:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    typography: "{typography.body-medium}"
    rounded: "{rounded.md}"
    padding: "0 12px"
    height: "32px"
  button-neutral-hover:
    backgroundColor: "{colors.surface2}"
  button-caution:
    backgroundColor: "{colors.warn_bg}"
    textColor: "{colors.warn}"
    typography: "{typography.body-medium}"
    rounded: "{rounded.md}"
    padding: "0 12px"
    height: "32px"
  button-caution-hover:
    backgroundColor: "{colors.surface2}"
  list-row:
    textColor: "{colors.ink}"
    typography: "{typography.body}"
    rounded: "{rounded.md}"
    padding: "0 8px"
    height: "30px"
  list-row-hover:
    backgroundColor: "{colors.surface2}"
  list-row-selected:
    backgroundColor: "{colors.selected}"
    typography: "{typography.title-small}"
  sidebar-title:
    textColor: "{colors.mute}"
    typography: "{typography.caption-strong}"
  sidebar-title-active:
    textColor: "{colors.accent_ink}"
  checkbox-on:
    backgroundColor: "{colors.accent}"
    textColor: "{colors.bg}"
    rounded: "{rounded.sm}"
    size: "16px"
  checkbox-off:
    backgroundColor: "{colors.bg}"
    rounded: "{rounded.sm}"
    size: "16px"
  label-allow:
    backgroundColor: "{colors.ok_bg}"
    textColor: "{colors.ok}"
    typography: "{typography.label}"
    rounded: "{rounded.full}"
    padding: "0 8px"
    height: "22px"
  label-deny:
    backgroundColor: "{colors.no_bg}"
    textColor: "{colors.no}"
    typography: "{typography.label}"
    rounded: "{rounded.full}"
    padding: "0 8px"
    height: "22px"
  label-caution:
    backgroundColor: "{colors.warn_bg}"
    textColor: "{colors.warn}"
    typography: "{typography.label}"
    rounded: "{rounded.full}"
    padding: "0 8px"
    height: "22px"
  label-accent:
    backgroundColor: "{colors.accent_bg}"
    textColor: "{colors.accent_ink}"
    typography: "{typography.label}"
    rounded: "{rounded.full}"
    padding: "0 8px"
    height: "22px"
  label-condition-false:
    backgroundColor: "{colors.bg}"
    textColor: "{colors.no}"
    typography: "{typography.label}"
    rounded: "{rounded.full}"
    padding: "0 8px"
    height: "22px"
  verdict-state-allow:
    backgroundColor: "{colors.ok}"
    textColor: "{colors.bg}"
    typography: "{typography.title-small}"
    rounded: "{rounded.full}"
    padding: "0 14px 0 12px"
    height: "32px"
  verdict-state-deny:
    backgroundColor: "{colors.no}"
    textColor: "{colors.bg}"
    typography: "{typography.title-small}"
    rounded: "{rounded.full}"
    padding: "0 14px 0 12px"
    height: "32px"
  verdict-header:
    backgroundColor: "{colors.surface}"
    padding: "10px 16px"
    height: "60px"
  box:
    backgroundColor: "{colors.bg}"
    rounded: "{rounded.md}"
  box-header:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    typography: "{typography.title-small}"
    padding: "0 16px"
    height: "44px"
  note-info:
    backgroundColor: "{colors.accent_soft}"
    textColor: "{colors.ink}"
    rounded: "{rounded.md}"
    padding: "10px 14px"
  note-caution:
    backgroundColor: "{colors.warn_bg}"
    textColor: "{colors.ink}"
    rounded: "{rounded.md}"
    padding: "10px 14px"
  note-allow:
    backgroundColor: "{colors.ok_bg}"
    textColor: "{colors.ink}"
    rounded: "{rounded.md}"
    padding: "10px 14px"
  note-deny:
    backgroundColor: "{colors.no_bg}"
    textColor: "{colors.ink}"
    rounded: "{rounded.md}"
    padding: "10px 14px"
  note-quiet:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.md}"
    padding: "10px 14px"
  path-crumb:
    backgroundColor: "{colors.bg}"
    textColor: "{colors.ink}"
    typography: "{typography.mono}"
    rounded: "{rounded.full}"
    padding: "0 10px 0 4px"
    height: "28px"
  path-crumb-hit:
    backgroundColor: "{colors.accent_soft}"
    textColor: "{colors.accent_ink}"
  path-rank:
    backgroundColor: "{colors.surface2}"
    textColor: "{colors.ink}"
    typography: "{typography.caption-strong}"
    rounded: "{rounded.full}"
    padding: "0 6px"
    height: "20px"
  path-rank-hit:
    backgroundColor: "{colors.accent}"
    textColor: "{colors.bg}"
  resource-chip:
    backgroundColor: "{colors.bg}"
    textColor: "{colors.ink}"
    typography: "{typography.mono}"
    rounded: "{rounded.full}"
    padding: "0 12px"
    height: "28px"
  resource-chip-selected:
    backgroundColor: "{colors.accent_soft}"
    textColor: "{colors.accent_ink}"
  resource-chip-hover:
    backgroundColor: "{colors.surface2}"
  file-pill:
    textColor: "{colors.mute}"
    typography: "{typography.mono}"
    rounded: "{rounded.full}"
    padding: "0 10px"
    height: "28px"
  timeline-badge-decisive-allow:
    backgroundColor: "{colors.ok}"
    textColor: "{colors.bg}"
    rounded: "{rounded.full}"
    size: "32px"
  timeline-badge-decisive-deny:
    backgroundColor: "{colors.no}"
    textColor: "{colors.bg}"
    rounded: "{rounded.full}"
    size: "32px"
  timeline-badge-candidate:
    backgroundColor: "{colors.accent_bg}"
    textColor: "{colors.accent}"
    rounded: "{rounded.full}"
    size: "32px"
  timeline-badge-explains:
    backgroundColor: "{colors.no}"
    textColor: "{colors.bg}"
    rounded: "{rounded.full}"
    size: "32px"
  timeline-badge-unresolved:
    backgroundColor: "{colors.warn}"
    textColor: "{colors.bg}"
    rounded: "{rounded.full}"
    size: "32px"
  timeline-badge-quiet:
    backgroundColor: "{colors.surface2}"
    textColor: "{colors.mute}"
    rounded: "{rounded.full}"
    size: "32px"
  timeline-badge-not-reached:
    backgroundColor: "{colors.surface2}"
    textColor: "{colors.faint}"
    rounded: "{rounded.full}"
    size: "32px"
  condition-header:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    typography: "{typography.body-small}"
    padding: "0 16px"
    height: "38px"
  condition-row:
    textColor: "{colors.ink}"
    typography: "{typography.mono}"
    padding: "0 16px"
    height: "34px"
  table-header:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.mute}"
    typography: "{typography.caption-strong}"
    padding: "0 16px"
    height: "40px"
  table-row:
    textColor: "{colors.ink}"
    padding: "0 16px"
    height: "44px"
  kbd:
    backgroundColor: "{colors.bg}"
    textColor: "{colors.mute}"
    typography: "{typography.kbd}"
    rounded: "{rounded.sm}"
    padding: "0 5px"
---

# Design System: Themis Inspect

## Overview

**Creative North Star: "A Revisão de Código"**

O Themis Inspect lê uma decisão de autorização do jeito que se lê um pull request no GitHub: o veredito fica numa caixa com cabeçalho cinza e um selo cheio, e os grants descem numa linha do tempo vertical em que cada destino tem o próprio ícone. A pessoa entra com uma dúvida ("por que isto foi negado?"), encontra a resposta no topo e desce até o grant que a explica, com a árvore da condição aberta logo abaixo dele.

O acabamento segue a régua do GitHub Primer em modo claro: fundo branco, superfícies em cinza muito leve, bordas de 1 px, tinta quase preta e um único azul para seleção, foco e degrau decisivo. Verde e vermelho ficam reservados ao efeito (permitido, negado) e o amarelo à simulação e ao que não pôde ser avaliado. A densidade é de ferramenta de leitura: corpo em 14 px, linhas de 30 a 44 px, nada de cartões soltos nem selos espalhados.

Não há sombra, animação ou gradiente. A profundidade vem do contraste entre o branco do conteúdo e o cinza dos cabeçalhos e barras laterais, sempre separados por uma borda. Identificadores do domínio (permissões, recursos, âncoras, expressões, horários, JSON, teclas) aparecem em monoespaçada; prosa, nomes de sujeitos e ids de grant em sans.

**Key Characteristics:**
- Caixas com cabeçalho cinza (#F6F8FA) e corpo branco, borda de 1 px e raio de 6 px.
- Selos em pílula com ícone e palavra; o efeito nunca depende só da cor.
- Um azul só (#0969DA) para seleção, foco por teclado, aba ativa e degrau decisivo.
- Linha do tempo vertical de grants com marcador circular de 32 px por destino.
- Zero sombras: profundidade por superfície e borda.
- Teclado de primeira classe: setas, Tab, Espaço e atalhos de aba, com anel de foco que só aparece quando o teclado está em uso.

## Colors

Paleta clara e neutra do Primer, com três famílias de estado (azul, verde/vermelho, amarelo) e cada família em quatro papéis: tinta forte, fundo, borda e, no azul, uma tinta escura para texto.

### Primary
- **Azul de Seleção** (`accent`): aba ativa (sublinhado de 2 px), check do item escolhido nas listas, checkbox ligado, anel de foco por teclado, degrau decisivo no caminho do recurso, marcador de grant candidato.
- **Azul Tinta** (`accent_ink`): texto sobre fundos azuis (selo "degrau N", crumb e chip selecionados) e título da lista ativa na barra lateral.
- **Azul Lavado** (`accent_bg`): fundo do selo azul e do marcador de candidato na linha do tempo.
- **Azul Névoa** (`accent_soft`): fundo da nota informativa ("quem teria permitido") e do crumb e chip selecionados.
- **Borda Azul** (`accent_line`): borda do selo azul, da nota informativa e do chip de recurso selecionado.

### Secondary
- **Verde Permitido** (`ok`), com `ok_bg` e `ok_line`: efeito allow, desfecho "aplicada"/"permitido", cadeia de hashes íntegra, folha verdadeira na árvore da condição, faixa "decidem igual" da reavaliação.
- **Vermelho Negado** (`no`), com `no_bg` e `no_line`: efeito deny, desfecho "recusada"/"negado", cadeia quebrada, folha falsa, erros de leitura de arquivo.

### Tertiary
- **Âmbar da Simulação** (`warn`), com `warn_bg` e `warn_line`: botão "Desfazer simulação", selos "simulado" e "desligado na simulação", nota "com os grants originais seria...", células da matriz que mudaram ("antes: sim"), condição ou sujeito não avaliável, avisos do motor, faixa "a decisão mudou".

### Neutral
- **Branco Papel** (`bg`): fundo da janela, corpo das caixas, cabeçalho do app, ícone sobre fundos cheios.
- **Cinza Cabeçalho** (`surface`): cabeçalho das caixas, barras laterais, cabeçalho da tabela, botão neutro, marca do app.
- **Cinza Hover** (`surface2`): hover de linhas, abas, botões e chips; fundo do número do degrau e dos marcadores neutros da linha do tempo.
- **Cinza Seleção** (`selected`): linha escolhida nas listas da barra lateral e na lista de registros.
- **Borda** (`line`): bordas de caixas, barras e controles; trilho do scrollbar e régua de profundidade na árvore da condição.
- **Divisória** (`line2`): divisórias internas (entre linhas da tabela, da árvore, abaixo do motivo) e o trilho vertical da linha do tempo.
- **Tinta** (`ink`): texto principal.
- **Tinta Secundária** (`mute`): rótulos, subtítulos, legendas, ícones das abas e dos botões neutros.
- **Tinta Apagada** (`faint`): setas entre identificadores, marcador de grant não alcançado, folha não avaliada, scrollbar em hover.

### Named Rules

**A Regra do Azul Único.** O azul marca onde a pessoa está e o que decidiu (seleção, foco, aba ativa, degrau decisivo, candidato). Nunca representa efeito: permitido é verde, negado é vermelho.

**A Regra do Efeito com Ícone.** Todo verde ou vermelho de efeito vem com ícone (check ou x) e palavra. Célula da matriz, selo, marcador da linha do tempo e folha da árvore seguem isso; cor sozinha não carrega veredito.

**A Regra do Âmbar da Simulação.** Amarelo é o tom do que foi alterado pela simulação ou não pôde ser avaliado. Não serve para destaque genérico.

## Typography

**Body Font:** Noto Sans (Regular, Medium, SemiBold e Italic embutidos no binário, OFL)
**Label/Mono Font:** JetBrains Mono (Regular e SemiBold embutidos, OFL)

Nenhuma fonte de fallback é declarada; as duas famílias são carregadas de `assets/fonts` no início e o gpui usa a do sistema se o carregamento falhar. Altura de linha não é definida em nenhum lugar: vale o padrão do gpui.

**Character:** Noto Sans neutra para a prosa em português, JetBrains Mono para tudo que é identificador do motor. A mono roda sempre um pouco menor que o corpo (12,5 contra 14 px) para não pesar nas linhas mistas.

### Hierarchy
- **Headline** (SemiBold 600, 20 px): o pedido no cabeçalho do veredito ("beto pede"), com a permissão em mono SemiBold de 17 px na mesma linha.
- **Title** (SemiBold 600, 16 px): títulos de seção fora de caixa ("Grants entregues pela fonte", "Rastro gravado na auditoria").
- **Brand** (SemiBold 600, 15 px): o nome "Themis Inspect" no cabeçalho.
- **Title small** (SemiBold 600, 14 px): título das caixas, aba ativa, item selecionado nas listas, ação do registro de auditoria, id do grant na linha do tempo, selo cheio do veredito.
- **Body medium** (Medium 500, 14 px): texto dos botões e valor dos fatos do veredito.
- **Body** (Regular 400, 14 px): base da janela inteira.
- **Body small** (Regular 400, 13 px): destino textual dos grants, ator do registro, "gravado"/"hoje", cabeçalho da árvore da condição (este em SemiBold), detalhe em itálico das folhas ("não avaliado: curto-circuito").
- **Label** (Medium 500, 12 px): texto dos selos em pílula.
- **Caption strong** (SemiBold 600, 12 px): título das listas da barra lateral, cabeçalho da tabela, palavra allow/deny nos grants da barra lateral, número do degrau.
- **Caption** (Regular 400, 12 px): nome dos fatos, dicas ("setas trocam o recurso"), atalhos de teclado no rodapé, "antes: sim".
- **Mono** (JetBrains Mono 400, 12,5 px): permissões, recursos, âncoras, alvos, estratégia, expressões de condição, arquivos abertos.
- **Mono small** (400, 12 px): JSON do registro e permissão sob cada grant na barra lateral.
- **Mono time** (400, 11,5 px): horário dos registros de auditoria.
- **Kbd** (400, 11 px): teclas dentro do componente de atalho.

### Named Rules

**A Regra do Mono para Identificadores.** Se o texto é algo que o motor reconhece por nome exato (permissão, recurso, âncora, estratégia, expressão, horário, nível, JSON, tecla), vai em JetBrains Mono. Nome de sujeito e id de grant ficam em sans.

**A Regra do Peso para Seleção.** Seleção sobe o peso para SemiBold (aba ativa, item escolhido) em vez de mudar a cor do texto.

## Layout

Janela desktop de 1360 × 860 px ao abrir, mínimo de 980 × 600 px. Não há breakpoints: a adaptação vem de `flex_wrap` nas linhas de fatos, no caminho do recurso, na identidade dos grants e no cabeçalho da reavaliação.

- **Cabeçalho do app:** 56 px de altura, 24 px de margem lateral, 16 px entre grupos. Da esquerda para a direita: marca (quadrado de 28 px + nome), pílula com os arquivos abertos, abas com ícone, espaço flexível, botões.
- **Avaliação:** barra lateral fixa de 300 px (fundo `surface`, 12 px de respiro, 6 px entre grupos) com Sujeito, Permissão, Recurso, Grants e o quadro de atalhos; à direita, área rolável com 32 px laterais e 24 px verticais.
- **Matriz:** sem barra lateral; seletor de recurso em chips no topo e tabela com primeira coluna de 300 px e colunas de sujeito de 150 px.
- **Auditoria:** lista de registros de 420 px à esquerda (2 px entre itens), detalhe rolável à direita com os mesmos 32/24 px.
- **Ritmo:** 16 px entre caixas e seções; 12 px de gap entre colunas da linha do tempo; 8 px entre ícone e texto; 6 px entre selos e itens pequenos; 4 px dentro de selos. Fatos do veredito com 32 px entre colunas e 10 px entre linhas.
- **Linha do tempo:** 4 px de recuo, trilho vertical de 2 px em `line2` centrado nos marcadores (left 19 px), marcador de 32 px, coluna de número de 16 px, identidade flexível, destino alinhado à direita. A árvore da condição entra recuada 84 px.
- **Árvore da condição:** cada nível de profundidade acrescenta uma régua vertical de 1 px em `line` com 11 px de margem.
- **Rolagem:** barras sempre visíveis, trilho transparente, polegar `line` e `faint` em hover.

## Elevation & Depth

O sistema é plano: não existe nenhuma sombra no código. A profundidade vem de camadas tonais, com o branco do conteúdo sobre o cinza `surface` das barras laterais e dos cabeçalhos de caixa, sempre separados por uma borda de 1 px em `line`. Divisões internas usam `line2`, um tom mais claro, para não competir com a borda externa.

### Named Rules

**A Regra do Plano.** Nenhuma superfície flutua. Uma caixa se distingue pelo cabeçalho cinza e pela borda, nunca por sombra. Estado (hover, seleção, foco) muda fundo ou borda, não a elevação.

## Shapes

Quatro raios no total. 6 px (`md`) é o padrão de tudo que contém conteúdo: caixas, botões, linhas das listas, notas, legenda da aba, marca do app. 4 px (`sm`) fica para os elementos pequenos e quadrados (checkbox, tecla). 2 px (`xs`) só no sublinhado da aba ativa. Pílula (`full`) para tudo que é estado ou identificador avulso: selos, selo do veredito, marcadores da linha do tempo, crumbs do caminho, número do degrau, chips de recurso, pílula de arquivos.

Bordas são de 1 px, exceto o anel de foco das listas e o contorno dos marcadores da linha do tempo, que usam 2 px. Os ícones são SVG próprios em grade de 24, traço de 2 (2,5 em check e x), pontas e junções arredondadas, tingidos pela cor do texto; aparecem em 12, 14 e 16 px.

## Components

### Buttons
Contidos e discretos, como os botões secundários do Primer.
- **Shape:** cantos levemente curvos (6 px), 32 px de altura, 12 px laterais, borda de 1 px, ícone de 16 px a 8 px do texto.
- **Neutro ("Recarregar"):** fundo `surface`, texto `ink` em Medium, borda `line`, ícone em `mute`.
- **Âmbar ("Desfazer simulação"):** fundo `warn_bg`, texto e ícone `warn`, borda `warn_line`. Só aparece enquanto há simulação.
- **Hover:** o fundo vai para `surface2` em qualquer tom. Sem foco por teclado: os botões respondem a Ctrl+R e Ctrl+Z (⌘ no macOS).

### Selos (labels em pílula)
A unidade básica de estado.
- **Style:** pílula de 22 px, 8 px laterais, borda de 1 px, ícone de 12 px opcional a 4 px do texto, Medium 12 px.
- **Tons:** permitido (`ok` sobre `ok_bg`, borda `ok_line`), negado (`no` / `no_bg` / `no_line`), âmbar (`warn` / `warn_bg` / `warn_line`), azul para "degrau N" e "candidato" (`accent_ink` / `accent_bg` / `accent_line`).
- **Variante "condição falsa":** texto e borda em `no` sobre fundo branco, mais forte que o selo negado comum.
- **Na matriz:** a célula alterada pela simulação troca a borda por `warn_line` e ganha "antes: sim/não" em `warn`; hover da célula pinta a borda de `accent`.

### Caixas com cabeçalho
O contêiner de toda informação agrupada.
- **Corner Style:** 6 px, conteúdo cortado no raio.
- **Background:** corpo `bg`, cabeçalho `surface` com borda inferior `line`.
- **Shadow Strategy:** nenhuma (ver Elevation & Depth).
- **Border:** 1 px `line`.
- **Internal Padding:** cabeçalho com 44 px de altura mínima e 16 px laterais; título SemiBold seguido de subtítulo em `mute` alinhados pela linha de base, 8 px entre eles. Corpo com 16 px laterais e 12 a 16 px verticais.

### Caixa do veredito
A caixa mais importante da tela.
- **Cabeçalho:** 60 px de altura mínima, 10 px verticais, 16 px laterais, 12 px de gap. À esquerda o selo cheio do veredito (pílula de 32 px com fundo `ok` ou `no`, texto e ícone brancos, SemiBold, 12 px à esquerda e 14 px à direita); ao lado o pedido em Headline com a permissão em mono.
- **Linha do motivo:** "Motivo" em `mute` e a razão em `ink`, divisória `line2` abaixo. Quando um grant teria permitido, uma nota azul entra na mesma linha, com 260 a 520 px de largura.
- **Fatos:** pares nome (Caption, `mute`) e valor (Body medium, `ink`) com 2 px entre eles.

### Notas em faixa
- **Style:** 10 px verticais, 14 px laterais, raio de 6 px, borda de 1 px e fundo do tom, texto sempre em `ink`, ícone de 16 px na cor forte do tom.
- **Tons:** informativa (`accent` / `accent_soft` / `accent_line`), âmbar, permitido, negado e neutra (`mute` / `surface` / `line`, usada quando não há cadeia de hashes).

### Navegação (abas)
- **Style:** abas com ícone de 16 px em `mute` e legenda em `ink`, 10 px laterais, ocupando toda a altura do cabeçalho.
- **Hover:** fundo `surface2` só na legenda (4 × 8 px, raio de 6 px).
- **Ativa:** legenda em SemiBold e sublinhado de 2 px em `accent` com raio de 2 px, recuado 8 px de cada lado e assentado sobre a borda do cabeçalho.
- **Teclado:** Ctrl+1, Ctrl+2 e Ctrl+3 (⌘ no macOS).

### Listas da barra lateral
- **Linha:** 30 px de altura, 8 px laterais, raio de 6 px, texto `ink`. Sujeitos em sans, permissões e recursos em mono.
- **Hover:** fundo `surface2`.
- **Selecionada:** fundo `selected`, SemiBold e check de 16 px em `accent` à direita.
- **Título da lista:** Caption strong com 10 px acima e 4 px abaixo; em `accent_ink` quando é a lista que recebe as setas, em `mute` nas outras. Subtítulo após " · " em `mute`.
- **Grants:** checkbox de 16 px (raio de 4 px; ligado em `accent` com check branco de 12 px, desligado em branco com borda `line`), palavra do efeito em Caption strong na cor do efeito, id do grant e a permissão em mono small embaixo. Grant desligado cai para 60% de opacidade.

### Foco por teclado
- **Anel:** todas as linhas navegáveis reservam uma borda de 2 px transparente; ela vira `accent` na linha ativa da lista que recebe as setas.
- **Quando aparece:** só depois de uma ação de teclado, com a janela focada. Um clique do mouse apaga o anel.
- **Chips de recurso da matriz:** o anel usa a borda de 1 px do próprio chip.
- **Mapa de teclas** (contexto `ThemisInspect`): ↑/↓ escolhem na lista, Tab e Shift+Tab trocam de lista, Espaço liga ou desliga o grant, Ctrl/⌘+1/2/3 trocam de aba, Ctrl/⌘+R recarrega, Ctrl/⌘+Z desfaz a simulação.

### Kbd (dica de atalho)
- **Style:** fundo `bg`, borda 1 px `line`, raio de 4 px, 5 px laterais, JetBrains Mono 11 px em `mute`. O modificador é escrito como a plataforma escreve: "Ctrl+" no Linux, "⌘" no macOS. Fica no rodapé da barra lateral sob o título "Teclado".

### Caminho do recurso
- **Crumb:** pílula de 28 px com borda `line` e fundo branco, número do degrau numa pílula interna de 20 px (`surface2`, Caption strong) e a âncora em mono. Setas de 14 px em `faint` entre os crumbs.
- **Degrau decisivo:** crumb com borda `accent`, fundo `accent_soft` e texto `accent_ink`; o número vira pílula `accent` com texto branco.

### Linha do tempo dos grants (componente assinatura)
Cada grant é uma linha com marcador circular de 32 px (borda de 2 px em `bg`, que recorta o trilho), número em `mute`, identidade (id SemiBold, selo do efeito, permissão em mono, seta, sujeito e alvo, selo "degrau N" quando há) e destino à direita.
- **Decisivo:** marcador cheio na cor do efeito com check ou x branco; destino é o selo "decisivo".
- **Candidato:** ponto `accent` sobre `accent_bg`; destino é selo azul.
- **Condição falsa que explica a negação:** x branco sobre `no`. Condição falsa comum: x `mute` sobre `surface2`.
- **Não avaliável:** alerta branco sobre `warn`; selo âmbar.
- **Não alcançado:** ponto `faint` sobre `surface2`. Demais destinos: barra cortada `mute` sobre `surface2` e o texto do destino em Body small `mute`.
- **Desligado na simulação:** mesma linha a 60% de opacidade, no lugar e com o número originais, com selo âmbar.
- Identidade de grant que não pesa na decisão vai em `mute`; a que pesa, em `ink`.

### Árvore da condição
Caixa recuada sob o grant: cabeçalho de 38 px com chevron de 14 px e "Árvore da condição" em 13 px SemiBold; linhas de 34 px com ícone de 14 px (check `ok`, x `no`, alerta `warn`, ponto `faint`), expressão em mono e, quando há, o detalhe em itálico de 13 px `mute`. Folha não avaliada tem a expressão em `mute`.

### Tabela da matriz
Dentro de uma caixa: cabeçalho de 40 px em `surface` (Caption strong, `mute`), linhas de 44 px com divisória `line2`, permissão em mono `ink` e um selo sim/não por célula. Clicar numa célula abre a Avaliação daquele sujeito e permissão.

### Registros de auditoria
Linha com 7 px verticais, 8 px laterais e raio de 6 px: selo do desfecho, ação em SemiBold, horário em mono time à direita; embaixo, ator em Body small `mute`, seta `faint` e o objeto em mono `ink` cortado com reticências. Selecionado em `selected`, hover em `surface2`.

### Estado vazio
Mensagem centralizada em `mute` com 24 px de respiro, sempre dizendo como sair do vazio ("Abra um cenário com --scenario para avaliar.").

## Do's and Don'ts

### Do:
- **Do** usar a caixa com cabeçalho `surface` e corpo `bg`, borda de 1 px `line` e raio de 6 px para qualquer grupo novo de informação.
- **Do** acompanhar todo verde ou vermelho de efeito com o ícone check ou x e a palavra.
- **Do** reservar `accent` para seleção, foco por teclado, aba ativa, degrau decisivo e candidato.
- **Do** escrever identificadores do motor em JetBrains Mono 12,5 px e prosa em Noto Sans 14 px.
- **Do** reservar a borda de 2 px transparente em toda linha navegável por teclado, para o anel em `accent` não deslocar o layout.
- **Do** mostrar o que a simulação mudou no lugar original, em âmbar e com o valor anterior ("antes: sim").
- **Do** usar 60% de opacidade para grant desligado, sem tirá-lo da lista.

### Don't:
- **Don't** usar sombra para separar superfícies; o sistema é plano.
- **Don't** usar azul para indicar permitido ou negado.
- **Don't** usar âmbar como destaque decorativo; ele significa simulação ou avaliação impossível.
- **Don't** espalhar cartões soltos com selos avulsos; o veredito vai numa caixa com cabeçalho e os grants na linha do tempo.
- **Don't** escrever cor literal fora da paleta de tokens.

## Marca do repositório (banner do README)

O banner `assets/banner.svg` é a marca da biblioteca e não segue o estilo Primer do Themis Inspect: cada um tem identidade própria.

- **Ideia:** a balança da Themis mostra como o motor decide. No degrau decisivo o `deny` vence, então o prato da negação fica mais baixo e é o único dourado.
- **Cores:** bronze com pátina como fundo inteiro (`#1F5C51`; no tema escuro `#14302A`, claro o bastante para o cartão aparecer sobre o `#0D1117` do GitHub), tinta osso `#F1E7CF` para o nome, a frase e a marca, verde claro `#C6DCD1` (escuro `#9FC0B2`) para a linha técnica, e um único dourado `#E3B04B`, reservado ao prato que decide.
- **Tipos:** nome em capitulares Marcellus (106 px, espaçamento de inscrição de 0,06 em); frase e linha técnica em Hanken Grotesk 500 e 400. As duas são OFL e vão em contorno no SVG, que assim não depende de fonte instalada.
- **Formato:** SVG de 960×240 com raio de 16, autocontido, sem script nem referência externa. O tema escuro troca só o fundo e o verde claro; a marca fica idêntica nos dois.
- **Regras:** o dourado só aparece no prato que decide; o travessão fica inclinado 9°, com o lado da negação para baixo; o texto do banner é em inglês.
