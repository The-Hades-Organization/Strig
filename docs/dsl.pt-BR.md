# A linguagem de políticas

As políticas da Themis são dados: um catálogo de permissões, papéis, atribuições, concessões e regras. Você pode
montar uma em Rust ou carregá-la de JSON, e também pode escrevê-la como texto. Este guia trata da forma em texto,
chamada de linguagem de políticas ou DSL. Ela exige a feature `dsl` do `themis-auth`; ler e gravar arquivos exige
também `dsl-fs`.

```toml
themis-auth = { version = "0.4", features = ["dsl", "dsl-fs"] }
```

O texto é só uma maneira de escrever a política. Ao ler o texto você obtém o mesmo valor `Policy`, e dali em diante
valida, serializa para JSON ou monta um motor, exatamente como numa política montada em código.

## Três sintaxes, uma política

A linguagem tem três sintaxes, chamadas de tipos. Elas descrevem a mesma política. Escolha a que fica mais legível
para quem mantém o arquivo:

- **blocks** é explícita e regular, com um bloco por declaração e campos `chave = valor`. Serve para arquivos
  gerados e políticas grandes.
- **rules** é uma instrução por linha, escrita para ser lida em voz alta. Serve para políticas curtas e para revisão.
- **actors** agrupa a política por quem age: um título nomeia um papel, usuário ou principal, e as linhas abaixo dizem
  o que esse ator pode fazer. Serve para responder "o que um editor pode fazer?".

Aqui está um cenário nos três tipos. Um projeto tem pastas e documentos; leitores leem, editores editam, gerentes
herdam de editores, e duas pessoas têm papéis em um projeto.

Blocks:

```themis
// Documents of an organization: who may read, edit and manage them.
language blocks

target_kinds = [project, folder, document]
broad_targets = [org]

permission project.view {
  label = "View project"
  targets = [project]
}

// Reading a document follows from viewing its project.
permission document.view {
  targets = [project, folder, document]
  implied_by = [project.view]
}

permission document.edit {
  targets = [project, folder, document]
  depends_on = [document.view]  // never alone
}

role viewer {
}

role editor {
  inherits = [viewer]
}

role manager {
  inherits = [editor]
}

// Ana runs the project.
subject user:ana {
  assign manager {
    scope = project:apollo
  }
}

subject user:bruno {
  assign editor {
    scope = project:apollo
  }
}

grant g-view {
  effect = allow
  subject = role viewer
  permission = project.view
  target = project
  scope = org:acme
}

grant g-edit {
  effect = allow
  subject = role editor
  permission = document.edit
  target = project
  scope = org:acme
}
```

Rules:

```themis
// Documents of an organization: who may read, edit and manage them.
language rules

kinds document, folder, project
broad org

permission project.view on project label "View project"
// Reading a document follows from viewing its project.
permission document.view on project, folder, document implied by project.view
permission document.edit on project, folder, document needs document.view
  // never alone

role editor inherits viewer
role manager inherits editor
role viewer

// Ana runs the project.
user:ana has role manager in project:apollo
user:bruno has role editor in project:apollo

g-view: allow role viewer to project.view on project in org:acme
g-edit: allow role editor to document.edit on project in org:acme
```

Actors:

```themis
// Documents of an organization: who may read, edit and manage them.
language actors

role editor inherits viewer

role manager inherits editor

role viewer
  in org:acme
    allow project.view on project as g-view

role editor
  in org:acme
    allow document.edit on project as g-edit

// Ana runs the project.
subject user:ana
  role manager in project:apollo

subject user:bruno
  role editor in project:apollo

catalog
  kinds document, folder, project
  broad org
  project.view on project label "View project"
  // Reading a document follows from viewing its project.
  document.view on project, folder, document implied by project.view
  document.edit on project, folder, document needs document.view
    // never alone
```

Os três geram políticas equivalentes. `Policy::equivalent` as compara, e `convert` (abaixo) reescreve um tipo em
outro.

## A declaração language

A primeira linha que não seja vazia nem comentário de todo texto nomeia o seu tipo:

```text
language blocks
language rules
language actors
```

Sem ela, o parser para na linha 1 e diz como corrigir. Um nome desconhecido lista os três válidos:

```text
c.themis:1:1: a source starts by declaring its language
  hint: write on the first line: language blocks
d.themis:1:10: unknown language `prose`
  hint: expected one of: blocks, rules, actors
```

## Um arquivo, um tipo

Um arquivo tem uma linha `language` e usa essa sintaxe até o fim. Uma segunda linha `language` é erro, mesmo com o
mesmo tipo, então um arquivo não troca de sintaxe no meio.

Uma política ainda pode ocupar vários arquivos e vários tipos. Adicione cada texto a um `Project` e monte:

```rust
use themis::dsl::Project;

let mut project = Project::new();
project.add_source("catalog.themis", "language rules\n\nkinds doc\npermission doc.read on doc\n")?;
project.add_source("people.themis", "language blocks\n\ntarget_kinds = [org]\nrole viewer {\n}\n")?;
let built = project.build()?;
let policy = built.policy;
# Ok::<(), Box<dyn std::error::Error>>(())
```

`add_source` devolve o tipo que detectou. `build` junta os textos numa política só, e `origins` no resultado diz de
que arquivo veio cada elemento.

A junção recusa uma declaração repetida. O erro mostra os dois lugares, para você remover um:

```text
two.themis:3:1: the kind `doc` is listed in target_kinds twice (also at one.themis:3:1)
  hint: list each kind in one source only
two.themis:4:6: the role `viewer` is declared twice (also at one.themis:4:6)
  hint: declare each role in one source only
```

## Leitura e escrita de arquivos

Com `dsl-fs`, `themis::dsl::fs` lê e grava arquivos de política:

```rust
use themis::dsl::{Language, fs};

let policy = fs::read_file("policies/main.themis")?.policy;
let project = fs::read_dir("policies")?;      // every *.themis in the directory
fs::write_file("policies/out.themis", &policy, Language::Rules)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

- `read_file` lê um arquivo.
- `read_dir` monta um `Project` com os arquivos `*.themis` diretamente dentro de um diretório. Não desce em
  subdiretórios e ignora links simbólicos. Lê no máximo 1024 arquivos.
- `write_file` grava num arquivo ao lado do destino e o renomeia por cima dele, então um leitor nunca vê uma política
  pela metade.

Essas funções não existem em `wasm`.

## Conversão entre tipos

`convert` recebe o texto e devolve a mesma política escrita em outro tipo:

```rust
use themis::dsl::{Language, convert};

let actors = convert("language rules\n\nkinds doc\n// hi\nrole viewer\n", Language::Actors)?;
assert_eq!(actors, "language actors\n\n// hi\nrole viewer\n\ncatalog\n  kinds doc\n");
# Ok::<(), Box<dyn std::error::Error>>(())
```

`print(&policy, language)` faz o mesmo a partir de uma `Policy` que você já tem. A conversão falha com um
`ConvertError` quando o texto não é lido, ou quando a política não cabe no tipo de destino.

## Notas e reconstrução

Os comentários não se perdem. Cada comentário `//` vira uma nota com o texto, o elemento a que está ligado e o lugar:
nas linhas antes do elemento, depois dele ou na mesma linha. `parse` devolve as notas junto da política, e `print` e
`convert` as escrevem de volta ao lado do mesmo elemento na nova sintaxe, como mostra o `// hi` acima.

As notas pertencem ao texto, não à política. Não entram no JSON, então uma política carregada de JSON é impressa sem
comentários.

## O JSON validado é a fonte da verdade

O texto é validado ao ser lido, com as mesmas checagens de `Policy::validate`. O que você guarda, compara e entrega é o
JSON da política validada:

```rust
use themis::dsl::parse;

let parsed = parse("main.themis", source)?;
let json = parsed.policy.to_json()?;
let again = themis::dsl::Policy::from_json(&json)?;
assert!(parsed.policy.equivalent(&again));
# Ok::<(), Box<dyn std::error::Error>>(())
```

Dois arquivos de tipos diferentes que significam o mesmo dão o mesmo JSON. Trate o texto como o jeito de as pessoas
editarem a política e o JSON como o artefato que os serviços carregam. `Policy::engine_spec` transforma a política na
especificação com que se monta um motor.

## Macros

O crate `themis-macros` confere a política durante a compilação do seu programa, então uma política que não valida
não compila.

```toml
[dependencies]
themis-auth = { version = "0.4", features = ["dsl"] }
themis-macros = "0.4"
```

```rust
use themis_macros::{include_policy, policy};

let inline: themis::dsl::Policy = policy!(r#"
language blocks

target_kinds = [org]

permission org.read {
  targets = [org]
}
"#);

let from_file: themis::dsl::Policy = include_policy!("policies/main.themis");
```

- `policy!` recebe um literal de texto. Prefira uma string crua para várias linhas; o erro aponta para o literal, com
  `policy:linha:coluna` contado dentro do texto.
- `include_policy!` recebe um caminho relativo ao `CARGO_MANIFEST_DIR` de quem chama e acompanha o arquivo, então
  editá-lo recompila o crate. O arquivo precisa estar dentro do crate, fora de `target/` e de componentes de caminho
  ocultos, ser UTF-8 válido e ter no máximo 4 MiB.
- A expansão embute o JSON canônico da política validada. O texto nunca é lido em tempo de execução, mas o JSON é lido
  de volta a cada vez que a expansão roda, então guarde a política muito usada num `static` com `LazyLock`.

Não existe a feature `macros` no `themis-auth`. As macros rodam o parser durante a compilação, então o
`themis-macros` depende do `themis-auth`; reexportá-las atrás de uma feature criaria um ciclo de pacotes, que o Cargo
recusa. Dependa do `themis-macros` diretamente, como acima. Os dois crates têm a mesma versão fixada.

## Erros

Todo erro traz `arquivo:linha:coluna`, uma mensagem e, quando há uma correção provável, uma dica:

```text
a.themis:6:26: unknown permission `doc.write`
  hint: declare it as a permission block
b.themis:3:1: unknown statement `frobnicate`
  hint: expected one of: kinds, broad, strategy, depth, permission, role, subject, tuple, relation, relations, override, always
e.themis:5:3: unknown field `target` in permission
  hint: did you mean `targets`?
```

O parser continua depois do primeiro erro e relata até 100, depois "and N more". Um erro que envolve dois lugares
nomeia o segundo com "also at". As mensagens e as dicas ficam em inglês.

## Limites contra entrada hostil

A leitura é limitada, então texto não confiável não esgota a memória nem a pilha:

| Limite | Valor |
| --- | --- |
| Tamanho de um texto | 4 MiB (`MAX_SOURCE_BYTES`) |
| Textos num projeto | 10000 (`MAX_SOURCES`) |
| Tamanho total de um projeto | 64 MiB (`MAX_PROJECT_BYTES`) |
| Arquivos lidos de um diretório | 1024 |
| Aninhamento de condições e grupos | 64 |
| Diagnósticos relatados | 100 |

Um texto acima do limite de tamanho é recusado com a posição no início, antes de qualquer leitura.

## Referência da gramática

Comum aos três tipos:

- Comentários começam com `//` e vão até o fim da linha.
- Identificadores como permissões (`doc.read`), papéis e tipos são palavras soltas. Textos usam aspas duplas.
- Uma referência a recurso ou sujeito é `tipo:id`, por exemplo `project:apollo` ou `user:ana`.
- Datas são UTC: `2026-01-01` ou `2026-01-01T09:00:00Z`, com milissegundos opcionais.
- Matchers de sujeito: `anyone`, `role <nome>`, `user <id>`, `principal <id>`, `relation <nome>`.
- Condições usam `==`, `!=`, `<`, `<=`, `>`, `>=`, `in`, `and` (ou `&&`), `or` (ou `||`), `not` (ou `!`),
  `exists <atributo>`, `all(...)`, `any(...)` e `@funcao(argumentos)`. Atributos começam com `subject.`,
  `resource.` ou `env.`.
- Reescritas de relação: `this`, união `a | b`, interseção `a & b`, diferença `a - b`, caminhada `parent->relation` e
  as formas de função `union(...)`, `intersection(...)` e `exclusion(a, b)`. Não misture `|`, `&` e `-` sem
  parênteses.

### Blocks

Um texto é uma lista de declarações. As configurações de topo são `target_kinds`, `broad_targets`, `strategy`
(`most_specific`, `deny_overrides`, `permit_overrides` ou `first_applicable`) e `max_depth`. Os campos são
`nome = valor`, e as listas são `[a, b]`.

| Declaração | Campos |
| --- | --- |
| `permission <id> { }` | `label`, `description`, `targets` (obrigatório), `implied_by`, `depends_on`, `non_delegable`, `management_only`, `override_only`, `meta { k = "v" }` |
| `role <nome> { }` | `inherits` |
| `subject <tipo:id> { }` | `principals`, `attrs { }`, `assign <papel> { scope, valid_from, valid_until }` |
| `grant <id> { }` | `effect` (`allow` ou `deny`), `subject`, `permission`, `target`, `scope`, `when`, `valid_from`, `valid_until` |
| `relation <tipo#nome> { }` | `rewrite` |
| `relations = []` | declara que a política não usa relações |
| `tuples { }` | um `objeto#relação@sujeito` por linha |
| `override resource_owner { }` | `attr`, `except` |
| `override permission_holder { }` | `permission`, `except` |
| `invariant <tipo> { }` | depende do tipo, abaixo |

Tipos de invariante: `catalog_conformance`, `no_self_management`, `prerequisites`, `require_permission` (`permission`,
`resource`), `no_lockout` (`permissions`, `members`, `resource`, `reserve_role`, `reserve_scope`, `reserve_subjects`,
`reserve_from`, `reserve_until`), `non_delegable` (`manager`), `management_only` (`roles`), `no_escalation` (`bypass`,
`on`) e `forbid` (`subject`, `permissions`).

### Rules

Uma instrução por linha. Uma linha recuada mais que a de cima a continua.

| Instrução | Forma |
| --- | --- |
| `kinds` | `kinds a, b, c` |
| `broad` | `broad org` |
| `strategy` | `strategy <nome>` |
| `depth` | `depth <n>` |
| `permission` | `permission <id> on <tipos> [implied by <ids>] [needs <ids>] [label "..."] [about "..."] [non-delegable] [management-only] [override-only] [meta k = "v"]` |
| `role` | `role <nome> [inherits <nomes>]` |
| `subject` | `subject team:ops` declara um sujeito; `user:ana has role <nome> [in <escopo>] [from <data>] [until <data>]`, `user:ana has principal <id>` e `user:ana has attr <chave> = <valor>` o preenchem |
| `relations` | `relations none` declara que a política não usa relações |
| `relation` | `relation doc#viewer = this \| owner` |
| `tuple` | `tuple doc:d1#owner@user:bob` |
| concessão | `<id>: allow\|deny <matcher> to <permissão> on <alvo> [in <escopo>] [when <condição>] [from <data>] [until <data>]` |
| `override` | `override resource-owner <attr> [except <ids>]`, `override permission-holder <id> [except <ids>]` |
| `always` | `always <invariante> [campos]` |

As palavras de invariante são os nomes dos blocos com hífen: `catalog-conformance`, `no-self-management`,
`prerequisites`, `require-permission`, `no-lockout`, `non-delegable`, `management-only`, `no-escalation` e `forbid`.
Os campos vêm depois da palavra como pares `nome valor`, com listas entre colchetes.

### Actors

Os títulos começam na primeira coluna e as linhas abaixo são recuadas.

| Título | Linhas abaixo |
| --- | --- |
| `role <nome> [inherits <nomes>]` | `in <escopo>` e, sob ele ou direto, `allow\|deny <permissão> on <alvo> [when <condição>] [from <data>] [until <data>] as <id>` |
| `user <id>` ou `subject <tipo:id>` | `role <nome> [in <escopo>] [from <data>] [until <data>]`, `principal <id>`, `attr <chave> = <valor>` e as mesmas linhas `allow` e `deny` |
| `principal <id>`, `relation <nome>`, `anyone` | as linhas `allow` e `deny` |
| `catalog` | `kinds`, `broad`, depois cada permissão como em rules, sem a palavra `permission` |
| `relations` | `doc#viewer = this \| owner`, uma por linha |
| `tuples` | `doc:d1#owner@user:bob`, uma por linha |
| `engine` | `strategy`, `depth` e `override ...` |
| `governance` | as palavras de invariante, como em rules sem `always` |

Quando uma forma aqui não ficar clara, o corpus em `crates/themis/tests/dsl/corpus` tem um arquivo funcionando para
cada assunto nos três tipos: roles, governance, validity, conditions, relations, members, overrides.

## Governança do catálogo na linguagem

As marcas de governança e as invariantes fazem parte da linguagem, então um catálogo pode declarar as próprias regras.
Este texto, do corpus, usa `non_delegable`, `management_only`, `override_only`, os dois overrides e todos os tipos de
invariante:

```themis
language blocks

target_kinds = [org, doc]

permission doc.read {
  targets = [doc]
}

permission doc.edit {
  targets = [doc]
  implied_by = [doc.read]
  non_delegable = true
}

permission org.settings {
  targets = [org]
  management_only = true
}

permission doc.purge {
  label = "Purge for good"
  targets = [doc]
  override_only = true
  meta {
    risk = "high"
  }
}

role viewer {
}

subject user:bob {
  assign viewer {
  }
}

// The owner of a document may do anything to it.
override resource_owner {
  attr = "owner"
  except = [doc.purge]
}

override permission_holder {
  permission = doc.read
}

invariant no_self_management {
}

invariant catalog_conformance {
}

invariant require_permission {
  permission = doc.read
  resource = org:acme > doc
}

invariant no_lockout {
  permissions = [doc.read]
  members = [user:bob]
  resource = doc:d1
  reserve_role = viewer
  reserve_subjects = [user:bob]
}

invariant forbid {
  subject = anyone
  permissions = [doc.edit]
}
```

## Janelas de validade

`valid_from` e `valid_until` limitam uma atribuição ou uma concessão a uma janela, em UTC:

```themis
language blocks

target_kinds = [project]

permission project.view {
  targets = [project]
}

role auditor {
}

// A temporary assignment.
subject user:carla {
  assign auditor {
    scope = project:apollo
    valid_from = 2026-01-01
    valid_until = 2026-12-31T23:59:59Z
  }
}

grant g-window {
  effect = allow
  subject = role auditor
  permission = project.view
  target = project
  valid_from = 2026-03-01T08:30:00Z
  valid_until = 2026-06-30
}

grant g-open {
  effect = allow
  subject = user carla
  permission = project.view
  target = project:apollo
  valid_until = 2027-01-01  // renewed yearly
}
```

## Condições e relações

As condições leem atributos do sujeito e do recurso:

```themis
language blocks

target_kinds = [project, document]
strategy = deny_overrides

permission document.view {
  targets = [project, document]
}

permission document.edit {
  targets = [project, document]
  implied_by = [document.view]
}

role editor {
}

subject user:ana {
  attrs {
    dept = "legal"
    level = 3
    active = true
  }
  principals = [ana]
  assign editor {
  }
}

// Legal may edit what is theirs.
grant g-dept {
  effect = allow
  subject = role editor
  permission = document.edit
  target = document
  when = subject.dept == "legal" and subject.level >= 2
}

grant g-freeze {
  effect = deny
  subject = anyone
  permission = document.edit
  target = project:apollo
  when = subject.active == false
}

grant g-user {
  effect = allow
  subject = user ana
  permission = document.view
  target = document:spec  // one document
}

grant g-principal {
  effect = allow
  subject = principal ana
  permission = document.view
  target = project
}
```

As relações reescrevem uma relação em termos de outras, e as tuplas dão os fatos:

```themis
language blocks

target_kinds = [org, doc]
max_depth = 4

permission doc.read {
  targets = [doc]
}

role viewer {
}

// Owners and viewers of a document.
relation doc#owner {
  rewrite = this
}

relation doc#viewer {
  rewrite = this | owner
}

relation org#member {
  rewrite = this
}

tuples {
  doc:d1#owner@user:bob
  doc:d1#viewer@org:acme#member  // the whole organization
  org:acme#member@user:ana
}

grant g-read {
  effect = allow
  subject = relation viewer
  permission = doc.read
  target = doc
}
```
