<p align="center">
  <img src="assets/banner.svg" alt="Strig: quem pode fazer o quê, e por quê. RBAC, ABAC e ReBAC num motor de decisão para Rust." width="100%">
</p>

# Strig

[![CI](https://github.com/The-Hades-Organization/Strig/actions/workflows/ci.yml/badge.svg)](https://github.com/The-Hades-Organization/Strig/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Rust 1.88+](https://img.shields.io/badge/rust-1.88%2B-orange.svg)
[![crates.io](https://img.shields.io/crates/v/strig.svg)](https://crates.io/crates/strig)
[![docs.rs](https://img.shields.io/docsrs/strig)](https://docs.rs/strig)
[![npm](https://img.shields.io/npm/v/@the-hades-organization/strig.svg)](https://www.npmjs.com/package/@the-hades-organization/strig)

[English](README.md) · **Português (Brasil)**

Strig é uma biblioteca de autorização em Rust. Você declara um catálogo de permissões, entrega seus grants ao motor e pergunta se um sujeito pode fazer algo num recurso. RBAC, ABAC e ReBAC são avaliados sobre os mesmos grants. As mudanças nos grants passam por regras de governança, ficam na auditoria e podem chegar em tempo real às outras instâncias e ao navegador.

O núcleo não faz IO, não precisa de runtime assíncrono e compila para WebAssembly. Tempo real, transportes e os bindings JavaScript ficam em crates separados e opcionais.

[Documentação](https://strig.vercel.app/docs) · [Playground](https://strig-playground.vercel.app) · [API no docs.rs](https://docs.rs/strig) · [Changelog](CHANGELOG.md)

> [!NOTE]
> A Strig ainda não chegou à 1.0: a API pode mudar entre versões menores. Até a 0.5.0 o projeto saiu com o nome Themis.

## Instalação

```sh
cargo add strig                             # Rust
cargo add strig --features dsl              # Rust, com a linguagem de políticas
npm install @the-hades-organization/strig   # Node, Bun e navegador
```

Features do crate `strig`:

| Feature | Padrão | Acrescenta |
|---|---|---|
| `audit` | sim | Trilha de auditoria das mudanças de grant e das decisões, com cadeia de hash |
| `exclusive` | não | Um detentor por recurso, com prioridade e preempção |
| `dsl` | não | A linguagem de políticas: parse, validação, conversão, formatação. Sem IO, funciona em wasm |
| `dsl-fs` | não | `dsl` mais leitura e escrita de arquivos e diretórios `.strig` |

## Primeiros passos

```rust
use strig::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let catalog = Catalog::builder()
        .target_kinds(["project", "doc_type", "document"])
        .broad_target("org")
        .permission(PermissionDef::new("document.export").targets(["project", "document"]))
        .permission(
            PermissionDef::new("document.invoice.export")
                .targets(["doc_type", "document"])
                .implied_by(["document.export"]),
        )
        .build()?;

    let engine = Engine::builder(catalog).build()?;

    let grants = vec![
        Grant::allow("g1", SubjectMatcher::role("member"), "document.export", TargetSelector::kind("org"))
            .scoped(Anchor::new("org", "acme")),
        Grant::deny("g2", SubjectMatcher::Any, "document.invoice.export", TargetSelector::exact("doc_type", "invoice")),
    ];

    let dave = Subject::user("dave").with_role_in("member", Anchor::new("org", "acme"));
    let invoice = Resource::new("document", "d1")
        .within("doc_type", "invoice")
        .within("project", "p1")
        .within("org", "acme");

    let ctx = Context::new(&grants);
    let export_invoice = engine.decide(&ctx, &Request::new(&dave, "document.invoice.export", &invoice));
    let export = engine.decide(&ctx, &Request::new(&dave, "document.export", &invoice));
    println!("{:?} {:?}", export_invoice.effect, export_invoice.reason);
    println!("{:?} {:?}", export.effect, export.reason);
    Ok(())
}
```

```text
Deny Grant { grant_id: "g2", permission: "document.invoice.export", rank: 1, strategy: "most_specific" }
Allow Grant { grant_id: "g1", permission: "document.export", rank: 3, strategy: "most_specific" }
```

O Dave exporta documentos em qualquer lugar de `acme` (`g1`), mas não faturas: `g2` está em `doc_type:invoice`, a um degrau do documento (`rank: 1`), e `g1` está em `org:acme`, a três degraus (`rank: 3`). O rank conta os degraus a partir do próprio recurso (rank 0), e a estratégia padrão deixa o menor rank decidir.

O mesmo motor roda no Node, no Bun e no navegador; veja [JavaScript](#javascript-node-bun-e-navegador).

O mesmo motor pode ser configurado em JSON, TOML ou YAML via `EngineSpec`, ou a partir de um arquivo `.strig` na [linguagem de políticas](#linguagem-de-políticas). `EngineSpec::builder()` devolve o `EngineBuilder`, para você acrescentar em código o que não serializa, como funções de condição.

Mais para rodar:

```sh
cargo run -p strig --example documents        # RBAC, ABAC e ReBAC num mesmo domínio
cargo run -p strig-axum --example server      # servidor de tempo real sobre SSE e WebSocket
```

## Crates

Todos os crates, menos `strig-inspect` e `strig-node`, estão no crates.io na mesma versão.

| Crate | Use para | Dependências principais |
|---|---|---|
| `strig` | Catálogo, motor de decisão, governança, auditoria, spec em JSON, linguagem de políticas | `serde`, `thiserror`; `sha2` com `audit` |
| `strig-sync` | Hub de mudanças, trait `Transport`, sessões SSE/WebSocket independentes de framework web, cache de capacidades | `tokio` |
| `strig-redis` | `Transport` sobre Redis pub/sub | `redis` |
| `strig-postgres` | `Transport` sobre Postgres `LISTEN/NOTIFY`, enviado dentro da sua transação | `tokio-postgres` |
| `strig-axum` | Rotas SSE e WebSocket do axum sobre as sessões do `strig-sync` | `axum` |
| `strig-server` | Servidor HTTP de decisão, e um cliente Rust que nega quando não recebe resposta | `axum`, `hyper-util` (cliente) |
| `strig-macros` | `policy!` e `include_policy!`: a política é validada em tempo de compilação | `strig` |
| `strig-node` | O pacote npm: módulo nativo (N-API) para Node e Bun, WebAssembly para navegador | `napi` ou `wasm-bindgen` |
| `strig-inspect` | Visualizador: rastro das decisões, simulação de grants, matriz de acesso, trilha de auditoria. Janela desktop e comandos de terminal | `gpui-pre`, `gpui-component` |

```toml
[dependencies]
strig = "0.6"
strig-sync = "0.6"
```

## Conceitos

| Conceito | Tipo | O que guarda |
|---|---|---|
| Catálogo | `Catalog`, `PermissionDef` | Chaves de permissão pontilhadas (`document.invoice.export`), os alvos que cada uma aceita, `implied_by`, metadados livres (`meta`). Exporta e importa JSON. |
| Recurso | `Resource`, `Anchor` | Caminho de degraus (âncoras) do mais específico ao mais amplo (`document:7 → doc_type:invoice → project:42 → org:9`), com um `global` implícito no fim, mais atributos. |
| Sujeito | `Subject` | Id, papéis (com escopo opcional), principais (`authenticated`, `anonymous` ou próprios), atributos. |
| Grant | `Grant` | Quem (`User`, `Role`, `Principal`, `Relation`, `Any`), qual permissão, em qual alvo (um tipo ou um degrau exato), permite ou nega, com escopo (uma âncora por onde o caminho do recurso tem de passar) e condição opcionais. |
| Motor | `Engine` | Decide. Devolve uma `Decision` com o efeito, o motivo, os grants casados e os avisos. |
| Governança | `Governance`, `Invariant` | Aplica uma mudança de grant só se todos os invariantes passarem, e audita o resultado. |

O catálogo é validado na construção. Ele recusa chave mal formada, duplicata, alvo não registrado, pai inexistente, ciclo e o que a sua `CatalogRule` rejeitar.

## Como a decisão é tomada

1. **Permissão desconhecida.** Nega com `Reason::UnknownPermission`.
2. **Overrides.** Rodam em ordem, e o primeiro que responde decide. `override_except` tira permissões, e as que elas implicam, do alcance de um override.
3. **Coleta.** Um grant é candidato quando tudo isto vale:
   - a permissão dele é a pedida, ou uma que a implica;
   - o escopo dele está no caminho do recurso;
   - o alvo dele casa com um degrau do caminho;
   - o sujeito dele casa;
   - a condição dele é verdadeira.
4. **Estratégia.** A estratégia escolhe o grant que decide. Sem candidato, nega.

Uma condição ou relação que não pode ser avaliada (atributo ausente, motor sem `TupleStore`) nunca abre acesso: o `allow` é descartado, o `deny` continua valendo, e o motivo vai para `Decision::warnings`.

| Estratégia | Regra |
|---|---|
| `MostSpecific` (padrão) | Decide o degrau mais específico que tem algum grant; nesse degrau, `deny` vence. |
| `DenyOverrides` | Qualquer `deny` vence. |
| `PermitOverrides` | Qualquer `allow` vence. |
| `FirstApplicable` | Decide o primeiro grant na ordem da fonte. |

## Os três modelos

### RBAC

`RoleGraph::builder().inherit("maintainer", "member")` dá a `maintainer` os grants de `member`. `Subject::with_role_in(role, anchor)` limita um papel aos recursos abaixo daquele degrau.

### ABAC

`Grant::when(condition)` anexa uma `Condition` serializável. Os operandos leem `subject.*`, `resource.*` e `env.*`.

| Operadores | Sobre |
|---|---|
| `eq`, `ne`, `lt`, `le`, `gt`, `ge`, `is_in`, `exists` | Qualquer valor |
| `starts_with`, `ends_with`, `contains` | Texto (`contains` também testa se um item está numa lista) |
| `any_in`, `all_in` | Listas |
| `ip_in` | Um endereço num CIDR ou numa lista de CIDRs |
| `time_between`, `weekday_in` | O instante da decisão, em UTC |
| `all`, `any`, `not` | Outras condições |
| `call` | Uma função sua, registrada com `ConditionRegistry::register` |

As condições de tempo leem o instante dado por `Context::at`; sem ele não dá para resolvê-las, então o `allow` não vale. Não existe condição de expressão regular. `Engine::validate_grant` confere se cada `call` aponta para uma função registrada.

### ReBAC

Guarde tuplas `object#relation@subject` num `TupleStore` e descreva cada tipo num `RelationSchema` com `This`, `Computed`, `TupleToUserset`, `Union`, `Intersection` e `Exclusion`. `user:*` vale para todo usuário.

Um grant com `SubjectMatcher::relation("editor")` vale para quem tem `editor` no degrau em que o alvo dele corresponde. A busca para em `max_relation_depth` (32 por padrão) e corta ciclos.

## Governança

`Governance` passa uma mudança de grant por uma lista de invariantes e só devolve o novo conjunto de grants se todos passarem. Persista o resultado no `Ok`; no `Err` vêm as violações.

Daqui em diante, os trechos reaproveitam o `engine`, os `grants` e os sujeitos dos exemplos anteriores; nomes como `actor`, `current` (os grants que você tem hoje) e `request_meta` representam valores seus. O argumento `None` é um `TupleStore` opcional para ReBAC, e `apply_with` é o `apply` com metadados da requisição para a auditoria.

```rust
let governance = Governance::new()
    .with(CatalogConformance)
    .with(RequirePermission::new("org.roles.edit", org_resource.clone()))
    .with(NoSelfManagement)
    .with(NoLockout::new(["org.invite"], members, org_resource))
    .with(Forbid::new(SubjectMatcher::principal(AUTHENTICATED), ["project.delete"]))
    .audited(auditor);

let next = governance.apply_with(&engine, &actor, &current, &Mutation::Add(grant), None, &request_meta)?;
// persista `next`
```

Atribuir ou revogar um papel passa pelos mesmos invariantes e vai para a auditoria como `role_assign` ou `role_revoke`. O conjunto de grants volta igual; o sujeito a persistir vem de `Mutation::subject_after`.

```rust
let change = Mutation::AssignRole { subject: bob, role: RoleAssignment::in_scope("editor", org) };
governance.apply_with(&engine, &actor, &current, &change, None, &request_meta)?;
let bob = change.subject_after().expect("role change"); // persista os papéis do bob
```

`Forbid` só se aplica a uma atribuição de papel quando ela é para um usuário, e ignora o escopo. Escreva sua própria regra implementando `Invariant`. A lista de invariantes também pode vir de JSON (`InvariantSpec`).

### Regras declaradas no catálogo

Algumas regras pertencem a uma permissão, então são declaradas no `PermissionDef` dela:

| Flag | Efeito |
|---|---|
| `depends_on` | Ter a permissão exige ter cada uma das listadas no mesmo recurso (conferido por `Prerequisites`). |
| `non_delegable` | Só um gestor a concede, não qualquer um que apenas a tenha. |
| `management_only` | Só pode ser concedida a papéis de gestão. |
| `override_only` | Só vale por um override; um grant comum dela não conta. |

`NoEscalation` impede alguém de conceder o que não tem: grants `allow` e atribuições de papel são recusados a menos que o autor tenha cada permissão que eles conferem, e cada permissão que essas implicam, onde quer que eles valham. Ter `org.roles.edit`, portanto, não serve para dar a alguém um papel mais forte que o seu.

```rust
let catalog = Catalog::builder()
    .target_kind("project")
    .permission(PermissionDef::new("project.view").targets(["project"]))
    .permission(PermissionDef::new("project.edit").targets(["project"]).depends_on(["project.view"]))
    .permission(PermissionDef::new("project.share").targets(["project"]).non_delegable())
    .permission(PermissionDef::new("project.purge").targets(["project"]).override_only())
    .build()?;
let engine = Engine::builder(catalog).build()?;

let governance = Governance::new()
    .with(CatalogConformance)
    .with(Prerequisites)
    .with(NoEscalation::new());

// `lead` só tem `project.edit`, então conceder `project.view` é escalada.
let current = vec![Grant::allow("l", SubjectMatcher::user("lead"), "project.edit", TargetSelector::kind("project"))];
let handout = Mutation::Add(Grant::allow("a", SubjectMatcher::user("ana"), "project.view", TargetSelector::kind("project")));
let refused = governance.apply(&engine, &Subject::user("lead"), &current, &handout, None).unwrap_err();
assert_eq!(refused[0].invariant, "no_escalation");
```

Mais duas ferramentas:

- **Reserva contra lockout.** `NoLockout::with_reserve` diz quem deve assumir uma permissão crítica. Quando uma mudança deixaria essa permissão sem ninguém, a `Violation` traz uma `Suggestion` com a atribuição de papel que resolve. Nada é aplicado; a sugestão também vai para o registro de auditoria.
- **Modelos de papel.** `RoleTemplate::materialize` transforma um modelo em grants comuns. O id e a versão do modelo vão nos metadados da mudança; os grants não guardam vínculo com o modelo.

## Auditoria

Com a feature `audit`, toda mudança que passa pela governança vira um `AuditRecord`, aplicada ou recusada. Registre tuplas ReBAC e atribuições de papel com `Auditor::tuple_change` e `Auditor::role_change`. Se o destino falha ao gravar, a governança recusa a mudança com a violação `audit`: sem registro, sem mudança.

```rust
let auditor = Arc::new(Auditor::new(AuditLevel::Standard, Arc::new(JsonLinesAudit::new(file))));
```

Os destinos prontos são `MemoryAuditLog` e `JsonLinesAudit`, que escreve em qualquer `io::Write`. Para mandar os registros a um banco, uma fila ou um SIEM, implemente `AuditSink`.

### O que cada nível guarda

Cada nível guarda tudo do nível acima. Os tamanhos são bytes de JSON compacto por linha de JSON Lines, sem compressão nem índices, medidos num registro de referência (`audit::reference_record`): um grant com escopo e condição de duas cláusulas, ids UUID, um autor com dois papéis e três metadados da requisição.

| Nível | Registros de mudança guardam | Bytes | Por 1 milhão |
|---|---|---:|---:|
| `minimal` | Quando, quem, ação, id do objeto, resultado | 175 | 175 MB |
| `standard` | + resumo do grant (permissão, sujeito, alvo, efeito, escopo, se tem condição) e os nomes dos invariantes que recusaram | 388 | 388 MB |
| `detailed` | + o grant inteiro com a condição, o autor completo, as mensagens das violações, os metadados da requisição | 1.097 | 1,10 GB |
| `forensic` | + digest SHA-256 do conjunto de grants antes e depois, e a cadeia de hash | 1.415 | 1,42 GB |

Decisões também podem ser auditadas: `Auditor::decide(&engine, &ctx, &request, &meta)` decide e registra. A decisão de referência (`audit::reference_decision_record`) tem três grants na fonte, um deles com condição, um recurso com três degraus, ids UUID e três metadados.

| Nível | Registros de decisão guardam | Bytes | Por 1 milhão |
|---|---|---:|---:|
| `minimal` | Quando, sujeito, `permission@resource`, permitido ou negado | 285 | 285 MB |
| `standard` | + o motivo (override, grant e degrau que decidiram, ou nenhum grant) e os grants casados | 669 | 669 MB |
| `detailed` | + o sujeito e o recurso completos, os avisos, os metadados da requisição. O bastante para reavaliar a decisão depois | 1.239 | 1,24 GB |
| `forensic` | + o rastro completo de `Engine::explain`, e a cadeia de hash | 3.582 | 3,58 GB |

Para projetar o seu volume, chame `AuditLevel::estimate_bytes(n)` para mudanças e `AuditLevel::estimate_decision_bytes(n)` para decisões; o tamanho forense da decisão cresce com o número de grants que a fonte devolve. Num banco, some o overhead por linha (cerca de 28 bytes no Postgres) e os seus índices.

Os números são conferidos: os testes `estimates_match_reference_records` e `decision_estimates_match_reference_records` falham se um tamanho medido se afastar mais de 10% da tabela, e `cargo run -p strig --example audit_storage` mede de novo.

### Cadeia de hash

No nível `forensic`, cada registro leva o hash do anterior. `audit::verify_chain` detecta um registro editado ou removido, e `Auditor::resume_chain` continua a cadeia depois de um reinício.

## Janelas de validade

`Grant::valid_between(from, until)` limita um grant no tempo; `valid_from` e `valid_until` definem uma ponta só.

- Os tempos são milissegundos desde a época Unix. A janela inclui `from` e exclui `until`.
- Quem chama fornece o instante: `Context::at(now)` nas decisões, `Governance::at(now)` nas mudanças.
- Sem instante, um grant com janela não vale, então relógio ausente nega.

```rust
let grant = Grant::allow("w", SubjectMatcher::user("ana"), "project.view", TargetSelector::kind("project"))
    .valid_between(1_000, 2_000);
let grants = vec![grant];
let ana = Subject::user("ana");
let project = Resource::new("project", "p1");
let request = Request::new(&ana, "project.view", &project);

assert!(engine.check(&Context::new(&grants).at(1_500), &request));
assert!(!engine.check(&Context::new(&grants).at(2_000), &request));
assert!(!engine.check(&Context::new(&grants), &request));
```

`CapabilityCache` expira as entradas no próximo limite de janela. Tirar do armazenamento os grants vencidos fica a cargo de um job seu.

## Consultas reversas e listagem filtrada

Pergunte quem pode fazer algo, ou o que um sujeito alcança, em vez de checar uma requisição. `QueryContext` leva os grants (e `.at(now)`), `QueryLimits` limita o trabalho e `PgTables` transforma as respostas em SQL.

```rust
let qctx = QueryContext::new(&grants).at(1_500);
let filter = engine.list(&qctx, &ana, "project.view", "project");
let who = engine.who_can(&qctx, "project.view");
assert_eq!(who, vec![SubjectRef::User { id: "ana".into() }]);
```

| Chamada | Devolve |
|---|---|
| `engine.list(&qctx, &subject, permission, kind)` | Um `AccessFilter` sobre os recursos daquele tipo que o sujeito alcança, pronto para virar uma cláusula `WHERE`. |
| `engine.who_can(&qctx, permission)` | Todos os nomeados por um grant `allow` da permissão, em qualquer lugar. Denies, overrides e condições não são avaliados. |
| `engine.who_can_on(..)` | O mesmo num recurso, com denies, overrides e condições avaliados. |
| `engine.access_of(..)` | Todos com acesso a um recurso, e as permissões de cada um. |
| `engine.check_for(..)` | Uma checagem por referência de sujeito: um `SubjectResolver` carrega o sujeito, e a resposta diz o caminho que decidiu. |

## Recurso exclusivo

Com a feature `exclusive`, um recurso pode ter um detentor por vez. `Terms::new(priority, ttl_ms)` define a força do pedido e quanto ele dura. Uma prioridade maior só toma o recurso quando quem pede também tem `exclusive.preempt`. Permissões e tempo são conferidos pelo mesmo motor de qualquer outra decisão.

```rust
let mut registry = ExclusiveRegistry::default();
let now = 0; // milissegundos desde a época Unix, passados por quem chama
let first = registry.acquire_checked(&engine, &ctx, &ana, &document, Terms::new(1, 60_000), now)?;
assert_eq!(first, Acquisition::Granted);

let second = registry.acquire_checked(&engine, &ctx, &bob, &document, Terms::new(9, 60_000), now + 10)?;
assert!(matches!(second, Acquisition::Preempted { .. }));
```

## Tempo real

```text
mudança de grant ──► Hub::publish ──► sessões locais (SSE/WebSocket) e CapabilityCache
                          │
                          └─► Transport (Redis, Postgres, o seu) ──► Hub nas outras instâncias
```

```rust
let hub = Hub::builder()
    .transport(RedisTransport::new("redis://127.0.0.1/", "strig:changes")?)
    .build();
let _relay = hub.spawn_relay();

let cache = Arc::new(CapabilityCache::new(Duration::from_secs(30), 10_000));
hub.on_change(cache.clone());
let provider = EngineProvider::new(engine, my_grant_loader).with_cache(cache);
let realtime = strig_axum::Realtime::new(hub).with_provider(Arc::new(provider));
// nas rotas: realtime.sse(subject, scopes) ou realtime.websocket(upgrade, subject, scopes)
```

O aviso de mudança (`Change`) diz o tipo de mudança e em qual degrau, sem os grants. Quem recebe recarrega da própria fonte, então qualquer transporte serve.

Uma sessão observa escopos, isto é, âncoras como `org:acme`. Com um `CapabilityProvider`, ela envia ao cliente as capacidades (as permissões que o sujeito tem) de cada escopo afetado, e mudanças que chegam juntas são recalculadas uma vez só. Quando o transporte cai e volta, ou um cliente fica para trás, o hub emite `Resync` e tudo é recarregado.

| Transporte | Crate | Observações |
|---|---|---|
| Redis | `strig-redis` | Pub/sub; a publicação reconecta sozinha. |
| Postgres | `strig-postgres` | `LISTEN/NOTIFY`. Chame `strig_postgres::notify(&tx, channel, &change)` dentro da transação que grava o grant, e o aviso só sai no commit. TLS via `PgTransport::with_tls`. |
| O seu | | NATS, Kafka ou qualquer broker: implemente `Transport` (`publish` e `subscribe`). |

O protocolo do cliente é JSON e igual em SSE e WebSocket. O servidor envia `hello`, `capabilities`, `change`, `resync`, `error` e `ping`; o cliente envia `watch`, `unwatch` e `refresh` (só WebSocket). Para um framework web que não seja o axum, repasse o stream de `Session::open` e escreva cada mensagem com `ServerMessage::to_sse` ou `to_json`.

## Servidor de decisão e cliente remoto

O `strig-server` responde decisões por HTTP, para serviços que não embutem o motor.

```rust
let source = Arc::new(MemorySource::new(Snapshot::new(Arc::new(engine), grants)));
let router = DecisionServer::new(source).router();
let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await?;
axum::serve(listener, router).await?;
```

O router atende `POST /v1/check`, `/v1/check/batch`, `/v1/list`, `/v1/who` e `/v1/access`, mais `GET /health/live` e `/health/ready`. Os grants vêm de uma `DecisionSource`; `MemorySource` guarda um `Snapshot` que você pode trocar com `replace`. As decisões usam o relógio do servidor. O contrato completo está em [`crates/strig-server/API.md`](crates/strig-server/API.md).

O cliente falha fechado. Só um `200` conta como resposta: timeout, conexão recusada, `503` ou corpo ilegível vira `ClientDecision::Denied` com o motivo, e um circuit breaker deixa de chamar um servidor que segue falhando.

```rust
let config = ClientConfig::default()
    .with_timeout(Duration::from_millis(250))
    .with_breaker(BreakerConfig::default().with_failure_threshold(5).with_open_for(Duration::from_secs(10)));
let client = Client::http("http://127.0.0.1:8080", config);

let request = CheckRequest::new(Subject::user("alice"), "document.view", Resource::new("document", "d1"));
if client.check(&request).await.is_allowed() {
    // serve o documento
}
```

## JavaScript: Node, Bun e navegador

```sh
npm install @the-hades-organization/strig
```

```js
import { load } from '@the-hades-organization/strig';
const { Engine, Context } = await load(); // nativo no Node/Bun, wasm no navegador

const engine = new Engine(spec); // o mesmo JSON de EngineSpec do Rust
const ctx = new Context({ grants });
engine.check(ctx, { subject, permission: 'document.view', resource });
engine.apply({ actor, current, mutation: { add: grant }, invariants, audit: { level: 'standard' } });
```

No Node e no Bun, `load()` tenta o módulo nativo e recorre ao wasm. Defina `STRIG_BACKEND=native` ou `STRIG_BACKEND=wasm` para forçar um deles.

O que o binding não faz: funções de condição próprias (`call`) e overrides próprios só existem em Rust. A spec JSON cobre os overrides prontos, `resource_owner` e `permission_holder`.

### No navegador

`PermissionClient` (`/client`) conecta por SSE ou WebSocket, guarda as capacidades de cada escopo e decide localmente com o mesmo motor. Use para moldar a interface; o servidor continua decidindo em toda operação.

```js
import { PermissionClient } from '@the-hades-organization/strig/client';
const client = new PermissionClient({ url: '/permissions/events', scopes, strig, engine }).connect();
client.on('capabilities', () => render());
client.can('document.edit', resource);
```

### Tempo real num backend JS

`/server` traz `Hub`, `openSession`, `sseResponse` (Fetch API: Bun.serve, Hono, Deno), `pipeSse` (`http` do Node) e três transportes: `redisTransport` (node-redis e o `RedisClient` do Bun), `ioredisTransport` e `pgTransport` (pacote `pg`). Os avisos usam o formato do `strig-sync`, então instâncias Rust e JS podem dividir o mesmo canal.

### Express, Fastify e NestJS

As três integrações recebem as mesmas opções e decidem em cada rota:

```js
import { load, scopeFromString } from '@the-hades-organization/strig';
import { authorize } from '@the-hades-organization/strig/express';

const { Engine, Context } = await load();
const options = {
  subject: (req) => (req.headers['x-user'] ? { kind: 'user', id: req.headers['x-user'] } : undefined),
  resource: (req) => scopeFromString(`document:${req.params.id}/org:o1`),
  local: { engine: new Engine(spec), context: new Context({ grants }), now: () => Date.now() },
};

app.get('/doc/:id', authorize({ ...options, permission: 'document.view' }), handler);
```

| Opção | Significado |
|---|---|
| `subject(req)` | O sujeito; não devolver nada responde `401`. |
| `resource(req)` | O recurso. |
| `local: { engine, context, now }` ou `remote: RemoteClient` | De onde vem a decisão. Passe exatamente um. |

A requisição só passa quando a decisão permite:

| Resultado | Status | Mude com |
|---|---|---|
| Sem sujeito | `401` | `unauthenticatedStatus` |
| Negado | `403` | `denyStatus` |
| Não foi possível decidir | `503` | `failureStatus` |
| Sua função `subject` ou `resource` lançou exceção | `500`, sem detalhe | `errorStatus`, `onError` |

- **Fastify** (`/fastify`): o mesmo `authorize`, mais um `plugin` que acrescenta `fastify.strigCan`.
- **NestJS** (`/nestjs`): `@Can('document.view')` num handler ou controller, com `new StrigGuard(options)` como guard.

Express, Fastify e NestJS são peer dependencies opcionais. Uma integração que você não importa não custa nada, e importar uma cujo peer falta lança `MissingPeerError`.

Para obter as decisões de um [servidor de decisão](#servidor-de-decisão-e-cliente-remoto), passe um `RemoteClient` (`/remote`) como `remote`. Ele tem timeout e breaker, e nega quando não há resposta:

```js
import { RemoteClient } from '@the-hades-organization/strig/remote';
const remote = new RemoteClient({ url: 'http://127.0.0.1:8080', timeoutMs: 250 });
const { allowed } = await remote.check({ subject, permission: 'document.view', resource });
```

### Tipos do catálogo para o frontend

Uma permissão pode levar o nome exibido e a descrição por locale (`labels` / `descriptions`, ao lado de `label` / `description`; em Rust `PermissionDef::localized_label("pt-BR", "Editar")`). São opcionais e não se declaram na linguagem de políticas, só no export do catálogo (JSON) ou no builder. O `strig-types` transforma um catálogo exportado num único `.ts` com a união `PermissionId`, a constante `PERMISSIONS` com os metadados e os helpers `isPermissionId`, `permissionLabel` e `permissionDescription` (locale com volta ao texto padrão). A saída é ordenada, então só muda quando o catálogo muda.

```sh
npx strig-types catalog.json -o src/permissions.generated.ts
```

```ts
import { generateTypes } from '@the-hades-organization/strig/types'; // o mesmo, como função
import { PermissionClient } from '@the-hades-organization/strig/client';
import type { PermissionId } from './permissions.generated';

const client = new PermissionClient<PermissionId>(/* ... */);
client.can('users:read', resource); // autocompleta os ids; qualquer outra string continua aceita (use isPermissionId para estreitar)
```

## Linguagem de políticas

Com a feature `dsl`, uma política pode ser escrita em texto em vez de JSON. A mesma política tem três sintaxes, Blocks, Rules e Actors, e `convert` passa de uma para outra. Todo erro traz posição e dica. O JSON validado continua sendo a fonte da verdade.

Experimente no [playground](https://strig-playground.vercel.app), que roda o motor de verdade compilado para WebAssembly. O [guia](docs/dsl.md) mostra as três sintaxes lado a lado e a gramática.

```rust
use strig::dsl::{self, Language};

const SOURCE: &str = "language blocks

target_kinds = [org]

permission org.read {
  targets = [org]
}
";

let parsed = dsl::parse("policy.strig", SOURCE)?;
let json = parsed.policy.to_json()?;
let as_rules = dsl::convert(SOURCE, Language::Rules)?;
```

`as_rules` fica com:

```text
language rules

kinds org

permission org.read on org
```

As condições de `when` se escrevem igual nas três sintaxes, por exemplo `a starts_with b`, `env.ip ip_in "10.0.0.0/8"`, `time_between "09:00" "17:30"` e `weekday_in ["mon", "tue"]`. O validador recusa CIDR, horário ou dia da semana que não consegue ler. Quando um nome está a um erro de digitação de uma permissão, papel ou pai declarado, a dica acrescenta ``did you mean `x`?``.

- **Formatação.** `strig::dsl::format` e `is_formatted` reescrevem uma fonte no layout canônico da sintaxe dela e mantêm os comentários. `strig-inspect fmt [--check] <arquivo|dir>` faz o mesmo com arquivos `.strig`; `--check` lista os que mudariam e sai com 1.
- **Arquivos.** Com `dsl-fs`, `strig::dsl::fs::read_dir` lê todos os `*.strig` de um diretório num `Project`, e `write_file` grava uma política de volta.

### No Node

O binding expõe a mesma linguagem, nativo e WebAssembly, atrás de `load()`. Uma política compilada é o JSON canônico, o mesmo para as três sintaxes, com os comentários em `notes`.

```js
import { load } from '@the-hades-organization/strig';
const strig = await load();

const source = `language blocks

target_kinds = [org]

permission org.read {
  targets = [org]
}
`;

const policy = strig.compile(source, { file: 'policy.strig' }); // JSON canônico
const rules = strig.print(policy, 'rules'); // 'blocks' | 'rules' | 'actors'
const actors = strig.convert(source, 'actors'); // texto para texto
const merged = strig.loadProject([
  { path: 'org.strig', text: source },
  { path: 'team.strig', text: strig.convert(source.replaceAll('org', 'team'), 'actors') },
]);
const fromDisk = strig.loadProjectDir?.('./policy'); // só no módulo nativo
```

- `format(source)` devolve a fonte no layout canônico da sintaxe dela; `isFormatted(source)` diz se ela já está assim.
- `loadProjectDir(dir)` só existe no módulo nativo, porque o WebAssembly não acessa arquivos. Ele lê os `*.strig` do diretório e recusa um arquivo de política que seja link simbólico. Passe só um `dir` de origem confiável.

Toda falha é um `Error` cujo `code` é o mesmo nos dois alvos:

| `code` | Causa |
|---|---|
| `DSL_PARSE` | O texto tem erro de sintaxe. |
| `DSL_VALIDATE` | A sintaxe está certa, mas a política é inválida. |
| `DSL_CONFLICT` | Duas fontes declaram a mesma coisa; as duas posições vêm no erro. |
| `DSL_UNREPRESENTABLE` | A sintaxe de destino não consegue expressar a política. |
| `DSL_UNSUPPORTED` | A sintaxe não existe neste build. |
| `DSL_LIMIT` | Um limite de tamanho ou de quantidade foi excedido. |
| `DSL_DUPLICATE_SOURCE` | O mesmo `path` aparece duas vezes em `loadProject`. |
| `DSL_IO` | Um arquivo ou link em `loadProjectDir`. A mensagem leva o caminho, então não a repasse a um cliente remoto. |

`error.diagnostics` lista até 100 entradas `{ file, line, column, message, hint, related? }`; quando houve mais, a última diz "and N more". `file`, `line` e `column` são `null` numa política que não veio de texto. `related` (`{ file, line, column }`) aparece num `DSL_CONFLICT`.

```js
try {
  strig.compile('language blocks\n\npermission {', { file: 'a.strig' });
} catch (error) {
  error.code; // 'DSL_PARSE'
  const [first] = error.diagnostics; // first.file === 'a.strig', first.line === 3
}
```

### Macros

`policy!` e `include_policy!`, do crate `strig-macros`, validam a política em tempo de compilação: política que não valida não compila. Elas ficam num crate próprio, e não atrás de uma feature do `strig`; o guia explica [por quê](docs/dsl.md#macros).

```rust
use strig_macros::{include_policy, policy};

let inline: strig::dsl::Policy = policy!(r#"
language blocks

target_kinds = [org]

permission org.read {
  targets = [org]
}
"#);
let from_file: strig::dsl::Policy = include_policy!("policies/main.strig");
```

## Visualizador (`strig-inspect`)

O `strig-inspect` mostra por que uma decisão saiu como saiu. Ele usa `Engine::explain`, que Rust e JS também chamam direto. Com o cenário de exemplo:

```sh
strig-inspect explain --scenario crates/strig-inspect/examples/scenario.json \
    --subject ben --permission document.view --resource secret
```

```text
DENIED — ben asks document.view on document:secret → project:roadmap → org:acme → global
reason: grant no-secret (document.view, step 0) chosen by strategy most_specific
permissions that grant: document.view, project.view
effective roles: member
override resource_owner: abstained
grants (5):
  + members-view allow project.view → role member on org [step 2]
      candidate
  - editors-edit allow project.edit → relation editor on project
      permission not related
  ★ no-secret deny document.view → any subject on document:secret [step 0]
      candidate
  - pro-export allow document.export → role member on org
      permission not related
  - no-invoice-export deny document.invoice.export → role member on doc_type:invoice
      permission not related
```

O crate não está no crates.io e fica fora dos `default-members` do workspace. Instale a partir de um clone:

```sh
cargo install --path crates/strig-inspect                          # janela e comandos de terminal
cargo install --path crates/strig-inspect --no-default-features    # só comandos de terminal, sem gpui
```

```sh
strig-inspect --scenario scenario.json --audit trail.jsonl          # janela
strig-inspect --scenario scenario.json --subject ben --permission document.export --resource invoice-7 \
               --disable pro-export --tab matrix                    # janela aberta numa seleção e aba
strig-inspect matrix --scenario scenario.json --resource secret --disable no-secret --add grant.json
strig-inspect audit  --audit trail.jsonl --scenario scenario.json
strig-inspect fmt [--check] <arquivo|dir>
```

Um cenário é um arquivo JSON com a política (`spec`, um `EngineSpec`), os dados (`grants`, `tuples`, `env`) e os sujeitos e recursos a examinar, por nome. O exemplo em `crates/strig-inspect/examples/` vem com uma trilha forense de seis decisões, `audit.jsonl`, gerada por:

```sh
cargo run -p strig-inspect --no-default-features --example trail -- \
    crates/strig-inspect/examples/scenario.json > crates/strig-inspect/examples/audit.jsonl
```

A janela tem três abas:

- **Evaluation:** escolha sujeito, permissão e recurso e veja a decisão, o motivo, o caminho do recurso com o degrau que decidiu, os papéis efetivos, cada override e por que cada grant valeu ou não, com a árvore da condição e os valores resolvidos.
- **Matrix:** toda permissão do catálogo para todo sujeito num recurso. Clique numa célula para abrir o rastro dela.
- **Audit:** lê uma trilha JSON Lines, confere a cadeia de hash dos registros `forensic`, mostra o rastro gravado e reavalia as decisões `detailed` e `forensic` contra a política atual, apontando as que mudariam.

A **simulação** vale para todas as abas: desligue ou ligue grants, ou acrescente com `--add`, e veja se o conjunto daria o acesso. Quando uma decisão muda, a decisão original aparece ao lado, e as células alteradas da matriz ficam marcadas.

Os arquivos recarregam quando mudam no disco. A janela segue o tema claro ou escuro do sistema, usa a paleta do playground e embute as fontes (Noto Sans e JetBrains Mono, OFL) e os ícones, então fica igual em qualquer máquina. A interface é em inglês.

## Pontos de extensão

| Trait | Implemente para |
|---|---|
| `GrantSource` | Ler grants de um banco, de um cache ou de várias fontes (tuplas `(A, B)` encadeiam). |
| `TupleStore` | Guardar tuplas ReBAC fora da memória. |
| `Override` | Decidir antes dos grants: dono, superadmin, conta suspensa, janela de manutenção. `FnOverride` recebe uma closure. |
| `Strategy` | Combinar grants com outra regra. |
| `Invariant` | Acrescentar uma regra para mudanças de grant. |
| `CatalogRule` | Validar o catálogo do seu jeito (`RequireMeta`, `FnRule`). |
| `AuditSink` | Mandar a trilha de auditoria para outro lugar. |
| `Transport` | Levar os avisos de mudança entre instâncias. |
| `CapabilityProvider`, `GrantLoader` | Controlar como uma sessão calcula as capacidades que envia. |
| `ChangeSink` | Reagir de forma síncrona a cada mudança (cache, métrica). |

## Desenvolvimento

```sh
cargo fmt --all --check
cargo clippy --workspace --exclude strig-inspect --all-targets -- -D warnings
cargo test --workspace --exclude strig-inspect
cargo test -p strig-inspect --no-default-features

# transportes contra servidores reais (pulados sem as variáveis)
STRIG_REDIS_URL=redis://127.0.0.1:6379/ STRIG_PG_URL=postgres://postgres:pw@127.0.0.1/postgres \
    cargo test --workspace --exclude strig-inspect
```

O pacote npm fica em `crates/strig-node/js`. `crates/strig-node/scripts/build.sh` gera o módulo nativo (`js/native/strig.<plataforma>-<arch>.node`) e o WebAssembly (`js/wasm/`); a parte wasm precisa do target `wasm32-unknown-unknown` e do `wasm-bindgen-cli` 0.2.130.

```sh
sh crates/strig-node/scripts/build.sh
cd crates/strig-node/js
npm ci
npm test              # Node
npm run test:bun      # Bun
```

Defina `STRIG_RUST_SERVER` com a URL do exemplo `server` do `strig-axum` para testar também o cliente JS contra o servidor Rust.

Para rodar o playground localmente, veja [`playground/README.md`](playground/README.md).

Compilar a janela do `strig-inspect` no Linux exige as bibliotecas de desenvolvimento de Wayland e X11, por exemplo `libxkbcommon-dev`, `libwayland-dev`, `libxcb1-dev` e `libvulkan-dev`.

Os comentários do código são em português do Brasil. Issues e pull requests são bem-vindos em inglês ou português; veja o [CONTRIBUTING.md](CONTRIBUTING.md).

## Licença

[MIT](LICENSE). As fontes embutidas no `strig-inspect` estão sob a SIL Open Font License 1.1 (veja `crates/strig-inspect/assets/fonts`).
