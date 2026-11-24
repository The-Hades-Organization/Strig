---
name: Strig Inspect
description: Visualizador desktop do rastro de decisão da Strig, com a paleta e a tipografia da marca em tema claro e escuro.
colors:
  bg: "#FFFFFF"
  panel: "#F8F6F6"
  sunk: "#F1EEEE"
  line: "#E4DEDE"
  line_strong: "#CFC5C5"
  ink: "#111111"
  mute: "#5C4A4A"
  comment: "#665252"
  accent: "#7D4A4A"
  accent_bg: "#F3E6E6"
  ornament: "#996C6C"
  brand: "#B01030"
  deny: "#B01030"
  deny_bg: "#FBE4E8"
  allow: "#1B6B3A"
  allow_bg: "#DDF1E4"
  caution_ink: "#6F5200"
  caution_bg: "#F5EBCB"
  err: "#7A35B5"
colors_dark:
  bg: "#0A0A0A"
  panel: "#141212"
  sunk: "#070707"
  line: "#2A2424"
  line_strong: "#3F3535"
  ink: "#F2F2F2"
  mute: "#BFAAAA"
  comment: "#B09A9A"
  accent: "#E0A8A8"
  accent_bg: "#2E1C1C"
  ornament: "#B88282"
  brand: "#FF5E70"
  deny: "#FF5E70"
  deny_bg: "#3A141A"
  allow: "#5FD08A"
  allow_bg: "#12301E"
  caution_ink: "#E3B04B"
  caution_bg: "#2E2410"
  err: "#C9A0F0"
typography:
  wordmark:
    fontFamily: "Cinzel"
    fontSize: "14px"
    fontWeight: 500
  headline:
    fontFamily: "Noto Sans"
    fontSize: "20px"
    fontWeight: 600
  verdict:
    fontFamily: "Noto Sans"
    fontSize: "26px"
    fontWeight: 600
  label-caps:
    fontFamily: "Noto Sans"
    fontSize: "12px"
    fontWeight: 600
  body:
    fontFamily: "Noto Sans"
    fontSize: "14px"
    fontWeight: 400
  body-small:
    fontFamily: "Noto Sans"
    fontSize: "13px"
    fontWeight: 400
  caption:
    fontFamily: "Noto Sans"
    fontSize: "12px"
    fontWeight: 400
  mono:
    fontFamily: "JetBrains Mono"
    fontSize: "12.5px"
    fontWeight: 400
rounded:
  r1: "4px"
  r2: "8px"
  r3: "14px"
  full: "9999px"
components:
  app-header:
    backgroundColor: "{colors.bg}"
    height: "56px"
    padding: "0 24px"
  brand-mark:
    textColor: "{colors.brand}"
    size: "28px"
  brand-name:
    textColor: "{colors.ink}"
    typography: "{typography.wordmark}"
  box:
    backgroundColor: "{colors.panel}"
    rounded: "{rounded.r3}"
  label-allow:
    backgroundColor: "{colors.allow_bg}"
    textColor: "{colors.allow}"
    typography: "{typography.caption}"
    rounded: "{rounded.full}"
    height: "22px"
  label-deny:
    backgroundColor: "{colors.deny_bg}"
    textColor: "{colors.deny}"
    typography: "{typography.caption}"
    rounded: "{rounded.full}"
    height: "22px"
  label-caution:
    backgroundColor: "{colors.caution_bg}"
    textColor: "{colors.caution_ink}"
    typography: "{typography.caption}"
    rounded: "{rounded.full}"
    height: "22px"
  label-accent:
    backgroundColor: "{colors.accent_bg}"
    textColor: "{colors.accent}"
    typography: "{typography.caption}"
    rounded: "{rounded.full}"
    height: "22px"
  code-well:
    backgroundColor: "{colors.sunk}"
    textColor: "{colors.ink}"
    typography: "{typography.mono}"
    rounded: "{rounded.r1}"
---

# Design System: Strig Inspect

## Overview

**Creative North Star: "O Corte"**

A marca da Strig é uma lua cheia mordida de cima para baixo, e as presas são a forma do pedaço que falta. O Inspect aplica a ideia ao que mostra: a decisão de autorização é uma lua inteira (permitido) ou uma lua mordida (negado), com a palavra ao lado e o ícone do efeito dentro, então o veredito nunca depende só da cor.

O uso é operar uma ferramenta de leitura: escolher um sujeito, uma permissão e um recurso, ler o veredito e descer até o grant que o explica. Por isso a interface é sóbria, em colunas fixas, com densidade de leitura e sem decoração que atrapalhe. A personalidade fica no símbolo do cabeçalho, no selo do veredito e no nome do produto em Cinzel.

A paleta vem de `brand/` do site de docs (rubi `#B01030` no fundo claro, rosa `#FF5E70` no escuro, apoio `#996C6C`, fundos `#FFFFFF` e `#0A0A0A`, tinta `#111111` e `#F2F2F2`). A janela segue a aparência do sistema, claro ou escuro, e troca de tema ao vivo.

**Key Characteristics:**
- Símbolo da marca de 28 px no cabeçalho, no tom da marca (`brand`), seguido do nome em Cinzel Medium.
- Selo do veredito em disco: inteiro com check no allow, mordido pela marca com x no deny.
- Neutros quentes, puxados para o rosa de apoio, em vez de cinzas frios.
- Cinco famílias de estado, cada uma com um papel e nenhuma dividindo matiz com outra: rubi (negado e marca), verde (permitido), rosa-cinza (estrutura, seleção, foco), âmbar (quem, onde, números, simulação) e violeta (defeito de leitura).
- Zero sombras: a profundidade vem de painel sobre fundo e de bordas de 1 px.
- Teclado de primeira classe, com anel de foco só quando o teclado está em uso.

## Colors

Cada papel vem em duas cores de tema. O contraste foi medido pela fórmula de luminância relativa do WCAG 2.x: texto pede 4,5:1; símbolo, ornamento e foco pedem 3:1.

### Marca e efeito
- **Rubi** (`brand`, `deny`; `#B01030` claro, `#FF5E70` escuro): o símbolo, o selo e o texto de negado, o x do deny e a folha falsa da árvore da condição. É a cor da marca e a do efeito negado porque a mordida é a recusa. O brand sheet pede o vermelho fora do texto corrido; aqui ele só vira texto como palavra de estado, sempre ao lado do ícone.
- **Verde** (`allow`; `#1B6B3A` claro, `#5FD08A` escuro): efeito permitido, folha verdadeira, a palavra `"allow"` no JSON.
- **Rosa-cinza de apoio** (`accent`; `#7D4A4A` claro, `#E0A8A8` escuro): estrutura, seleção, foco por teclado, chaves do JSON, candidato na linha do tempo. É a cor de apoio da marca (`#996C6C`) escurecida até passar 4,5:1 como texto. Nunca representa efeito.
- **Âmbar** (`caution_ink`; `#6F5200` claro, `#E3B04B` escuro): quem, onde e números, botão e selos de simulação, condição que não pôde ser avaliada.
- **Violeta** (`err`; `#7A35B5` claro, `#C9A0F0` escuro): defeito de leitura (nota de erro com ícone de exclamação). É o único matiz que nenhum efeito usa, para que erro e negado não se confundam.
- **Ornamento** (`ornament`; `#996C6C` claro, `#B88282` escuro): a cor de apoio da marca em estado puro, só para o sublinhado da aba ativa. Nunca é texto.

Cada família tem fundo tingido (`*_bg`) e borda derivada por mistura (`*_line`, 45% da cor forte sobre o fundo tingido); `accent_soft` mistura `accent_bg` a 45% sobre `panel`, e `err_bg` mistura `err` a 10% sobre `panel`.

### Neutros
- **Fundo** (`bg`) e **painel** (`panel`): página e cartões. No claro `#FFFFFF` e `#F8F6F6`; no escuro `#0A0A0A` e `#141212`.
- **Poço** (`sunk`): campo de código e marcadores neutros, um degrau abaixo do fundo (`#F1EEEE` claro, `#070707` escuro).
- **Borda** (`line`) e **borda forte** (`line_strong`): divisórias e contornos de controles.
- **Tinta** (`ink`): texto principal. **Tinta secundária** (`mute`): rótulos e legendas. **Comentário** (`comment`): texto de menor ênfase e grants não alcançados.

### Contraste medido

| Par | Claro | Escuro | Mínimo |
|---|---|---|---|
| `ink` sobre `bg` | 18,9 | 17,7 | 4,5 |
| `ink` sobre `sunk` | 16,4 | 18,0 | 4,5 |
| `mute` sobre `sunk` | 7,2 | 9,2 | 4,5 |
| `comment` sobre `caution_bg` | 6,1 | 5,8 | 4,5 |
| `accent` sobre `accent_bg` | 5,9 | 8,0 | 4,5 |
| `deny` sobre `deny_bg` | 5,9 | 5,5 | 4,5 |
| `allow` sobre `allow_bg` | 5,5 | 7,4 | 4,5 |
| `caution_ink` sobre `caution_bg` | 6,1 | 7,7 | 4,5 |
| `err` sobre o fundo tingido do erro | 5,6 | 7,4 | 4,5 |
| `bg` sobre `deny` (texto no selo cheio) | 7,1 | 6,7 | 4,5 |
| `bg` sobre `allow` (texto no selo cheio) | 6,5 | 10,3 | 4,5 |
| `ornament` sobre `bg` | 4,5 | 6,2 | 3 |

### Named Rules

**A Regra do Efeito com Ícone.** Todo verde ou rubi de efeito vem com ícone (check ou x) e palavra. Selo, marcador da linha do tempo, célula da matriz e folha da árvore seguem isso; cor sozinha não carrega veredito.

**A Regra do Matiz Único.** Rubi, verde, rosa-cinza, âmbar e violeta têm um papel cada. Rosa-cinza marca onde a pessoa está, nunca o efeito; violeta é só defeito de leitura.

**A Regra do Ornamento.** `ornament` não é texto. Se precisa ser lido, usa `accent`.

## Typography

**Nome do produto:** Cinzel Medium (500), a fonte do logotipo, embutida a partir de `brand/fonts` (OFL).
**Corpo e rótulos:** Noto Sans (Regular, Medium, SemiBold e Italic embutidos, OFL).
**Identificadores:** JetBrains Mono (Regular e SemiBold embutidos, OFL).

Nenhuma fonte de fallback é declarada; as famílias são carregadas de `assets/fonts` no início e o gpui usa a do sistema se o carregamento falhar.

**Character:** a Cinzel só aparece no nome do produto no cabeçalho, como manda a marca (Cinzel é a fonte do wordmark e não se troca por outra inscricional). O resto é Noto Sans neutra para a prosa em inglês e JetBrains Mono para tudo que é identificador do motor.

### Hierarchy
- **Wordmark** (Cinzel 500, 14 px, capitais espaçadas): o nome do produto no cabeçalho.
- **Verdict** (Noto Sans SemiBold, 26 px, capitais espaçadas): a palavra do veredito ao lado do selo.
- **Headline** (SemiBold, 20 px): o pedido no cabeçalho do veredito.
- **Label caps** (SemiBold, 12 px, capitais espaçadas): títulos de caixas e de seções.
- **Body** (Regular, 14 px): base da janela.
- **Body small** (Regular, 13 px) e **Caption** (Regular, 12 px): destinos, dicas, horários e selos em pílula (Medium).
- **Mono** (JetBrains Mono, 12,5 px): permissões, recursos, âncoras, expressões e JSON.

### Named Rules

**A Regra da Cinzel Única.** Cinzel só no nome do produto. Rótulo, título de caixa e veredito são Noto Sans; a inscricional não vira estilo de interface.

**A Regra do Mono para Identificadores.** Se o motor reconhece o texto por nome exato (permissão, recurso, âncora, estratégia, expressão, JSON, tecla), vai em JetBrains Mono. Nome de sujeito e id de grant ficam em sans.

## Layout

Janela desktop de 1360 × 860 px ao abrir, mínimo de 980 × 600 px. Sem breakpoints: a adaptação vem de `flex_wrap` nas linhas de fatos, no caminho do recurso e na identidade dos grants.

- **Cabeçalho do app:** 56 px de altura, 24 px de margem lateral, 16 px entre grupos: símbolo da marca de 28 px e nome, pílula com os arquivos abertos, abas com ícone, espaço flexível, botões.
- **Avaliação:** barra lateral fixa com Sujeito, Permissão, Recurso, Grants e atalhos; à direita, área rolável.
- **Matriz:** seletor de recurso em chips no topo e tabela de grants por sujeito.
- **Auditoria:** lista de registros à esquerda e detalhe rolável à direita.
- **Ritmo:** 16 px entre caixas e seções; 12 px entre colunas da linha do tempo; 8 px entre ícone e texto; 4 a 6 px dentro de selos.

## Elevation & Depth

O sistema é plano: nenhuma sombra no código. A profundidade vem do painel sobre o fundo e da borda de 1 px em `line`. Hover, seleção e foco mudam fundo ou borda, não a elevação.

## Shapes

Três raios e a pílula. 14 px (`r3`) para cartões e caixas, 8 px (`r2`) para controles, 4 px (`r1`) para código em linha e checkbox, pílula (`full`) para selos, crumbs e o selo do veredito. Bordas de 1 px, exceto o anel de foco e o contorno dos marcadores da linha do tempo, que usam 2 px.

Ícones são SVG próprios em grade de 24, traço de 2, pontas arredondadas, tingidos pela cor do texto. O símbolo da marca e os discos do selo são as formas de `brand/`, em máscara, tingidos pela cor do estado.

## Components

### Marca no cabeçalho
Símbolo de 28 px em `brand`, sem caixa ao redor, e o nome em Cinzel Medium com 8 px de intervalo. Abaixo de 24 px de altura a marca fica só no símbolo; o cabeçalho nunca desce disso.

### Selo do veredito
Disco de 48 px no tom do efeito: inteiro com check no allow, mordido pelas presas com x no deny, ícone em `bg`. Ao lado, a palavra em capitais espaçadas na cor do efeito.

### Selos (labels em pílula)
Pílula de 22 px, 8 px laterais, borda de 1 px, ícone de 12 px opcional, Medium 12 px. Tons: permitido, negado, âmbar e rosa-cinza (degrau e candidato). A variante "condição falsa" usa texto e borda `deny` sobre `bg`.

### Caixas com cabeçalho
Raio de 14 px, borda de 1 px em `line`, corpo em `panel`, cabeçalho com título em capitais espaçadas e subtítulo em `mute`.

### Navegação (abas)
Ícone de 16 px em `mute` e legenda em `ink`; a aba ativa sobe para SemiBold e ganha sublinhado de 2 px em `ornament`. Ctrl+1, Ctrl+2 e Ctrl+3 (⌘ no macOS).

### Árvore da condição
Folha verdadeira em `allow` com check, falsa em `deny` com x, não avaliável em `caution_ink` com alerta, curto-circuitada em `comment`, uma régua de 1 px por nível de profundidade.

### Rolagem
Barras sempre visíveis, trilho transparente, polegar em `line_strong` e `mute` em hover.

## Do's and Don'ts

### Do
- Dar a todo efeito ícone e palavra, além da cor.
- Usar `accent` para texto que precisa ser lido e `ornament` só para traço decorativo.
- Manter o tema escuro com `brand` em `#FF5E70` e o claro com `#B01030`, como o brand sheet.
- Deixar o símbolo sem sombra, brilho ou rotação.

### Don't
- Gotas, escorridos ou textura de sangue nas presas.
- Girar o símbolo ou virar as presas para baixo.
- Usar Cinzel fora do nome do produto, ou trocá-la por outra inscricional parecida.
- Pintar `ornament` ou `brand` como texto de corpo.
- Usar violeta para outra coisa que não defeito de leitura.
