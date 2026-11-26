# Security policy

**English** · [Português (Brasil)](#política-de-segurança)

Strig decides who can access what, so a bug that grants access it should not is a security issue.

## Reporting a vulnerability

Report it privately through GitHub Security Advisories: **Security → Report a vulnerability** on this repository
([direct link](https://github.com/The-Hades-Organization/Strig/security/advisories/new)). Please do not open a public
issue, a pull request or a discussion about it.

Include the spec, the grants and the request that reproduce the problem, the decision you got and the one you
expected, and the version (crate or npm package, and the backend: native or wasm).

What to expect:

- **Acknowledgement** within 7 days.
- **Assessment** (accepted, declined with a reason, or more information needed) within 14 days of the acknowledgement.
- **Fix and advisory**: we agree a fix and a release date with you, aim to release within 90 days of the report
  (sooner for an access bypass), and publish a GitHub Security Advisory, with a CVE when it applies, crediting you
  unless you prefer not to be named. Please keep the report private until then.

## Supported versions

Strig is pre-1.0: only the latest minor release (`0.y`) receives security fixes, as a patch release. A fix can come
with a breaking change when keeping the old behaviour would be unsafe; the release notes say so
([versioning.md](docs/versioning.md)). From 1.0, fixes ship in a patch of the latest minor and of the last minor of the
previous major, for 12 months after the new major.

## What is in scope

- A **wrong authorization decision**: an allow where the model says deny (a deny grant, an override, a missing
  prerequisite, an expired validity window, a condition that does not hold, a failed callback), or a deny explained
  wrongly in a way that misleads an operator.
- A **bypass of governance**: a grant or role change that passes the invariants (`NoEscalation`, `NoLockout`,
  `Forbid`, `NonDelegable`, `ManagementOnly`, custom invariants) when it should be refused, or a refused change that
  reaches the stored grants.
- A **break in the audit chain**: a record that can be altered, dropped or reordered without `verify_chain` or
  `verify_chain_anchored` noticing, a hash that does not match [the format](docs/audit-format.md), a redaction that
  leaks a masked attribute into the record, or a change that goes through without a record under `FailMode::Closed`.
- **Leaks across tenants or subjects** in listing and reverse queries (`list`, `who_can_on`, `access_of`), in the SQL
  produced by `strig-postgres`, in the real-time transports (`strig-sync`, `strig-redis`, `strig-axum`,
  `strig-server`) and in the JS integrations (route table, `StrigRouteGuard`, `authorizeRoutes`), including a route
  that the deny-by-default table lets through.
- **Memory-safety or denial-of-service** bugs reachable from untrusted input: a policy file or JSON spec, a request, a
  frame on the wire, a store file.

## What is not in scope

- Policies that are too permissive because of how the grants were written, and a catalog designed with a gap.
- The behaviour of your own callbacks, sinks and stores (`call` conditions, JS overrides, an `AuditSink`), except when
  the engine mishandles what they return or throw.
- Findings that need a malicious host process or access to the machine the engine runs on.
- Vulnerabilities in a dependency with no way to reach them through Strig: report these upstream.
- The `strig-inspect` window and the playground, which are tools with no authority of their own.

## Verifying a release

Every GitHub release carries the native modules (`strig-<version>-<platform>.node`), the wasm archive, a `SHA256SUMS`
file that lists all of them, and CycloneDX SBOMs: `strig-<version>-npm.cdx.json` for the npm package and the
`*.cdx.json` files of the crates. Every npm package is published with provenance by the release workflow.

```sh
# 1. Provenance: registry signatures and build attestations of what is in your node_modules.
npm audit signatures

# 2. A native module or archive from the release against the checksums.
curl -LO https://github.com/The-Hades-Organization/Strig/releases/download/vX.Y.Z/SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS

# 3. The SBOMs: download the *.cdx.json files of the release and give them to your scanner,
#    for example `grype sbom:strig-X.Y.Z-npm.cdx.json`.
```

`npm audit signatures` fails for a package that has no valid signature or provenance. On the npm page of each package,
"Provenance" links to the workflow run that built it. A package that has no provenance, or whose run is not in
`The-Hades-Organization/Strig`, is not ours: do not install it, and tell us.

---

# Política de segurança

A Strig decide quem acessa o quê, então um bug que libera acesso indevido é um problema de segurança.

## Reportando uma vulnerabilidade

Reporte de forma privada pelos GitHub Security Advisories: **Security → Report a vulnerability** neste repositório
([link direto](https://github.com/The-Hades-Organization/Strig/security/advisories/new)). Não abra issue, pull request
nem discussão pública.

Inclua a spec, os grants e o pedido que reproduzem o problema, a decisão que saiu e a esperada, e a versão (crate ou
pacote npm, e o backend: nativo ou wasm).

O que esperar:

- **Confirmação de recebimento** em até 7 dias.
- **Avaliação** (aceito, recusado com motivo ou pedido de mais informação) em até 14 dias após a confirmação.
- **Correção e aviso**: combinamos a correção e a data da release com você, buscamos publicar em até 90 dias do reporte
  (antes, se for um bypass de acesso) e publicamos um GitHub Security Advisory, com CVE quando couber, dando o crédito
  a você, salvo se preferir não ser citado. Mantenha o reporte privado até lá.

## Versões suportadas

Antes da 1.0, só a última minor (`0.y`) recebe correções de segurança, em um patch. Uma correção pode vir com uma
quebra de compatibilidade quando manter o comportamento antigo for inseguro; as notas da release dizem
([versioning.md](docs/versioning.md)). A partir da 1.0, as correções saem em um patch da última minor e da última minor
da major anterior, por 12 meses depois da nova major.

## O que está no escopo

- **Decisão de autorização errada**: um allow onde o modelo manda negar (grant deny, override, pré-requisito ausente,
  janela de validade vencida, condição que não vale, callback que falha), ou um deny explicado errado de modo que
  engana quem opera.
- **Bypass da governança**: mudança de grant ou de papel que passa pelas invariantes (`NoEscalation`, `NoLockout`,
  `Forbid`, `NonDelegable`, `ManagementOnly`, invariantes próprias) quando deveria ser recusada, ou mudança recusada
  que chega aos grants gravados.
- **Quebra da cadeia de auditoria**: registro que pode ser alterado, descartado ou reordenado sem que `verify_chain`
  ou `verify_chain_anchored` percebam, hash que não bate com [o formato](docs/audit-format.md), redação que vaza
  atributo mascarado para o registro, ou mudança que passa sem registro em `FailMode::Closed`.
- **Vazamento entre inquilinos ou sujeitos** nas listagens e consultas reversas (`list`, `who_can_on`, `access_of`), no
  SQL gerado pelo `strig-postgres`, nos transportes em tempo real (`strig-sync`, `strig-redis`, `strig-axum`,
  `strig-server`) e nas integrações JS (tabela de rotas, `StrigRouteGuard`, `authorizeRoutes`), inclusive rota que a
  tabela negada por padrão deixa passar.
- **Falha de memória ou negação de serviço** alcançável por entrada não confiável: arquivo de política ou spec JSON,
  pedido, quadro no protocolo, arquivo do store.

## O que fica fora do escopo

- Política permissiva demais pela forma como os grants foram escritos, e catálogo desenhado com lacuna.
- O comportamento dos seus callbacks, sinks e stores (condições `call`, overrides em JS, um `AuditSink`), salvo quando
  o motor trata mal o que eles devolvem ou lançam.
- Achados que exigem um processo hospedeiro malicioso ou acesso à máquina onde o motor roda.
- Vulnerabilidade em dependência sem caminho de alcance pela Strig: reporte no projeto de origem.
- A janela do `strig-inspect` e o playground, que são ferramentas sem autoridade própria.

## Verificando uma release

Toda release no GitHub traz os módulos nativos (`strig-<versão>-<plataforma>.node`), o arquivo do wasm, um `SHA256SUMS`
que lista todos eles e os SBOMs CycloneDX: `strig-<versão>-npm.cdx.json` do pacote npm e os `*.cdx.json` dos crates.
Todo pacote npm é publicado com provenance pelo workflow de release.

```sh
# 1. Provenance: assinaturas do registro e atestações de build do que está no seu node_modules.
npm audit signatures

# 2. Um módulo nativo ou arquivo da release contra os checksums.
curl -LO https://github.com/The-Hades-Organization/Strig/releases/download/vX.Y.Z/SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS

# 3. Os SBOMs: baixe os arquivos *.cdx.json da release e passe ao seu scanner,
#    por exemplo `grype sbom:strig-X.Y.Z-npm.cdx.json`.
```

O `npm audit signatures` falha para pacote sem assinatura ou provenance válidos. Na página de cada pacote no npm,
"Provenance" leva à execução do workflow que o construiu. Pacote sem provenance, ou cuja execução não está em
`The-Hades-Organization/Strig`, não é nosso: não instale e avise.
