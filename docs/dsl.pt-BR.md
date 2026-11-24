# A linguagem de políticas

As políticas da Themis são dados: um catálogo de permissões, papéis, atribuições, concessões e regras. Você pode
montar uma em Rust ou carregá-la de JSON, e também pode escrevê-la como texto. Este guia trata da forma em texto,
chamada de linguagem de políticas ou DSL. Ela exige a feature `dsl` do `themis-auth`; ler e gravar arquivos exige
também `dsl-fs`.

```toml
themis-auth = { version = "0.5", features = ["dsl", "dsl-fs"] }
```

Ler o texto produz uma `Policy`, o mesmo valor que você montaria em código.

A menor política declara um tipo e uma permissão:

```themis
language blocks

target_kinds = [org]

permission org.read {
  targets = [org]
}
```

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
permission document.edit on project, folder, document depends_on document.view
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
  document.edit on project, folder, document depends_on document.view
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
```

- `read_file` lê um arquivo.
- `read_dir` monta um `Project` com os arquivos `*.themis` diretamente dentro de um diretório. Não desce em
  subdiretórios e recusa um arquivo de política que seja link simbólico. Um diretório com mais de 1024 arquivos de
  política, ou com mais de 64 MiB no total, é um erro.
- `write_file` grava num arquivo ao lado do destino e o renomeia por cima dele, então um leitor nunca vê uma política
  pela metade.

Essas funções não existem em `wasm`.

## Conversão entre tipos

`convert` recebe o texto e devolve a mesma política escrita em outro tipo:

```rust
use themis::dsl::{Language, convert};

let actors = convert("language rules\n\nkinds doc\n// hi\nrole viewer\n", Language::Actors)?;
assert_eq!(actors, "language actors\n\n// hi\nrole viewer\n\ncatalog\n  kinds doc\n");
```

`print(&policy, language)` faz o mesmo a partir de uma `Policy` que você já tem. A conversão falha com um
`ConvertError` quando o texto não é lido, ou quando a política não cabe no tipo de destino.

## Formatação

`format` reescreve o texto no layout canônico do tipo que a linha `language` declara: o espaçamento, as linhas em
branco e a ordem que o `print` escreve, com os comentários preservados. Formatar o resultado de novo não muda nada.
`is_formatted` diz se o texto já está canônico sem guardar o texto novo. `file` só dá nome à fonte nas posições dos
erros.

```rust
use themis::dsl::{format, is_formatted};

let messy = "language rules\n\n\n\nkinds doc   // kinds\n";
assert!(!is_formatted("a.themis", messy)?);
assert_eq!(format("a.themis", messy)?, "language rules\n\nkinds doc  // kinds\n");
```

Um texto que não compila vira um `FormatError::Parse` com `arquivo:linha:coluna`. No terminal,
`themis-inspect fmt <arquivo|dir>` reescreve os arquivos `.themis` no lugar, e `themis-inspect fmt --check
<arquivo|dir>` não escreve nada, lista os arquivos que mudariam e sai com 1 (para CI). No Node,
`themis.format(text)` e `themis.isFormatted(text)` fazem o mesmo sobre texto.

## Notas e reconstrução

Os comentários não se perdem. Cada comentário `//` vira uma nota com o texto, o elemento a que está ligado e o lugar:
antes do elemento, depois dele, na mesma linha ou dentro dele. `parse` devolve as notas junto da política, e `print` e
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
```

Dois arquivos de tipos diferentes que significam o mesmo dão o mesmo JSON. Trate o texto como o jeito de as pessoas
editarem a política e o JSON como o artefato que os serviços carregam. `Policy::engine_spec` transforma a política na
especificação com que se monta um motor.

## Macros

O crate `themis-macros` confere a política durante a compilação do seu programa, então uma política que não valida
não compila.

```toml
[dependencies]
themis-auth = { version = "0.5", features = ["dsl"] }
themis-macros = "0.5"
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
| Arquivos de política num diretório | 1024 |
| Aninhamento de condições e grupos | 64 |
| Diagnósticos relatados | 100 |

Um texto acima do limite de tamanho é recusado com a posição no início, antes de qualquer leitura.

## Referência da gramática

Comum aos três tipos:

- Comentários começam com `//` e vão até o fim da linha.
- Identificadores como permissões (`doc.read`), papéis e tipos são palavras soltas. Textos usam aspas duplas.
- Uma referência a recurso ou sujeito é `tipo:id`, por exemplo `project:apollo` ou `user:ana`.
- Onde um campo recebe um recurso (`resource` e `on` nos invariantes), pode ser um caminho de passos ligados por `>`,
  como `org:acme > doc`. Cada passo é `tipo` ou `tipo:id`, e os passos ficam na ordem escrita, que é a ordem de
  `Resource::path`: o primeiro é o passo mais específico.
- Datas são UTC: `2026-01-01` ou `2026-01-01T09:00:00Z`, com milissegundos opcionais.
- Matchers de sujeito: `anyone`, `role <nome>`, `user <id>`, `principal <id>`, `relation <nome>`.
- Condições usam `==`, `!=`, `<`, `<=`, `>`, `>=`, `in`, `and` (ou `&&`), `or` (ou `||`), `not` (ou `!`),
  `exists <atributo>`, `all(...)`, `any(...)` e `@funcao(argumentos)`. Atributos começam com `subject.`,
  `resource.` ou `env.`. Os operadores de texto, conjunto e rede `starts_with`, `ends_with`, `contains`, `any_in`,
  `all_in` e `ip_in` ficam entre dois operandos (`a starts_with "x"`), e as condições de tempo são
  `time_between "HH:MM" "HH:MM"` e `weekday_in ["mon", ...]`, com os dias como texto; veja
  [Condições de texto, conjunto, rede e tempo](#condições-de-texto-conjunto-rede-e-tempo).
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
| `permission` | `permission <id> on <tipos> [implied by <ids>] [depends_on <ids>] [label "..."] [about "..."] [non-delegable] [management-only] [override-only] [meta k = "v"]` |
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

### Condições de texto, conjunto, rede e tempo

Além das comparações, uma condição pode testar texto, listas, endereços de rede e o instante da decisão. As três
sintaxes escrevem do mesmo jeito, e o `op` do JSON é o nome do operador.

| Condição | Vale quando |
| --- | --- |
| `a starts_with b`, `a ends_with b` | o texto `a` começa ou termina com o texto `b` |
| `a contains b` | o texto `a` tem `b` como trecho, ou a lista `a` tem `b` como elemento |
| `a any_in b` | a lista `a` tem ao menos um elemento que está na lista `b` |
| `a all_in b` | todo elemento da lista `a` está na lista `b` (um `a` vazio vale) |
| `a ip_in b` | o endereço IPv4 ou IPv6 `a` está dentro do CIDR `b`, ou de um CIDR da lista `b` |
| `time_between "09:00" "17:30"` | a hora do dia em UTC está em `[from, until)`; uma janela com `from` depois de `until` cruza a meia-noite, e limites iguais dão janela vazia |
| `weekday_in ["mon", "tue"]` | o dia da semana em UTC é um dos dias (`mon`, `tue`, `wed`, `thu`, `fri`, `sat`, `sun`) |

```themis
when = resource.name ends_with ".md" and subject.tags any_in ["docs", "ops"]
when = env.ip ip_in ["10.0.0.0/8", "2001:db8::/32"]
when = time_between "22:00" "06:00" and weekday_in ["mon", "tue", "wed", "thu", "fri"]
```

- Um endereço sem tamanho de prefixo vale como um único host, e um IPv4 escrito como IPv6 mapeado (`::ffff:10.1.2.3`)
  é comparado com os CIDRs IPv4.
- Não há condição com expressão regular.
- O validador recusa CIDR, hora do dia ou dia da semana ilegível, com posição e dica. As mesmas checagens valem para o
  JSON.
- Tipo errado ou operando ilegível é erro, como nas comparações: um `allow` com ele não vale e um `deny` com ele vale.
- As condições de tempo leem o instante da decisão, `Context::at` (`setNow` no binding Node), sempre em UTC. Sem
  instante não resolvem, então um grant que as usa nunca permite.
- Uma condição que lê atributo `resource.` não vira SQL: a listagem a mantém como resíduo, conferido linha a linha, e o
  `themis-postgres` nunca a transforma em allow.
- `DSL_SCHEMA` sobe de 1 para 2. Um leitor do schema 1 recusa a política que usa uma dessas condições, e a política sem
  elas lê como antes.

### Relações

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
