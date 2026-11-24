# The policy language

Themis policies are data: a catalog of permissions, roles, assignments, grants and rules. You can build one in Rust
or load it from JSON, and you can also write it as text. This guide covers the text form, called the policy language
or DSL. It needs the `dsl` feature of `themis-auth`; reading and writing files needs `dsl-fs` as well.

```toml
themis-auth = { version = "0.4", features = ["dsl", "dsl-fs"] }
```

Parsing the text produces a `Policy`, the same value you would build in code.

The smallest policy declares one kind and one permission:

```themis
language blocks

target_kinds = [org]

permission org.read {
  targets = [org]
}
```

## Three syntaxes, one policy

The language has three syntaxes, called types. They describe the same policy. Pick the one that reads best for the
people who maintain the file:

- **blocks** is explicit and regular, with a block per declaration and `key = value` fields. It suits generated files
  and large policies.
- **rules** is one statement per line, written to be read aloud. It suits short policies and review.
- **actors** groups the policy by who acts: a heading names a role, user or principal, and the lines under it say what
  that actor may do. It suits answering "what can an editor do?".

Here is one scenario in all three. A project holds folders and documents; viewers read, editors edit, managers
inherit from editors, and two people have roles in one project.

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

All three parse to equivalent policies. `Policy::equivalent` compares them, and `convert` (below) rewrites one into
another.

## The language declaration

The first non-blank, non-comment line of every source names its type:

```text
language blocks
language rules
language actors
```

Without it the parser stops at line 1 and tells you how to fix it. An unknown name lists the three valid ones:

```text
c.themis:1:1: a source starts by declaring its language
  hint: write on the first line: language blocks
d.themis:1:10: unknown language `prose`
  hint: expected one of: blocks, rules, actors
```

## One file, one type

A file has one `language` line and uses that syntax to the end. A second `language` line is an error, even when it
names the same type, so a file cannot switch syntax half way.

A policy can still span several files and several types. Add each source to a `Project`, then build it:

```rust
use themis::dsl::Project;

let mut project = Project::new();
project.add_source("catalog.themis", "language rules\n\nkinds doc\npermission doc.read on doc\n")?;
project.add_source("people.themis", "language blocks\n\ntarget_kinds = [org]\nrole viewer {\n}\n")?;
let built = project.build()?;
let policy = built.policy;
```

`add_source` returns the type it detected. `build` merges the sources into one policy, and `origins` on the result
says which file each element came from.

The merge refuses a repeated declaration. The error shows both places, so you can remove one:

```text
two.themis:3:1: the kind `doc` is listed in target_kinds twice (also at one.themis:3:1)
  hint: list each kind in one source only
two.themis:4:6: the role `viewer` is declared twice (also at one.themis:4:6)
  hint: declare each role in one source only
```

## Reading and writing files

With `dsl-fs`, `themis::dsl::fs` reads and writes policy files:

```rust
use themis::dsl::{Language, fs};

let policy = fs::read_file("policies/main.themis")?.policy;
let project = fs::read_dir("policies")?;      // every *.themis in the directory
fs::write_file("policies/out.themis", &policy, Language::Rules)?;
```

- `read_file` parses one file.
- `read_dir` builds a `Project` from the `*.themis` files directly inside a directory. It does not descend into
  subdirectories and it refuses a policy file that is a symbolic link. A directory with more than 1024 policy files, or
  more than 64 MiB of them together, is an error.
- `write_file` writes to a file beside the target and renames it over the target, so a reader never sees a half-written
  policy.

These functions are not available on `wasm`.

## Converting between types

`convert` takes source text and returns the same policy written in another type:

```rust
use themis::dsl::{Language, convert};

let actors = convert("language rules\n\nkinds doc\n// hi\nrole viewer\n", Language::Actors)?;
assert_eq!(actors, "language actors\n\n// hi\nrole viewer\n\ncatalog\n  kinds doc\n");
```

`print(&policy, language)` does the same from a `Policy` you already hold. A conversion fails with a `ConvertError`
when the source does not parse, or when the policy cannot be written in the target type.

## Formatting

`format` rewrites a source in the canonical layout of the type its `language` line declares: the spacing, the blank
lines and the order that `print` writes, with the comments kept. Formatting the result again changes nothing.
`is_formatted` says whether a source is already canonical without keeping the new text. `file` only names the source
in error positions.

```rust
use themis::dsl::{format, is_formatted};

let messy = "language rules\n\n\n\nkinds doc   // kinds\n";
assert!(!is_formatted("a.themis", messy)?);
assert_eq!(format("a.themis", messy)?, "language rules\n\nkinds doc  // kinds\n");
```

A source that does not compile is a `FormatError::Parse` with `file:line:column`. From a terminal,
`themis-inspect fmt <file|dir>` rewrites the `.themis` files in place, and `themis-inspect fmt --check <file|dir>`
writes nothing, lists the files that would change and exits with 1 (for CI). In Node, `themis.format(text)` and
`themis.isFormatted(text)` do the same on text.

## Notes and reconstruction

Comments are not thrown away. Every `//` comment becomes a note with its text, the element it is anchored to, and its
place: before the element, after it, on the same line, or inside it. `parse` returns them next to the policy, and
`print` and `convert` write them back beside the same element in the new syntax, as the `// hi` above shows.

Notes belong to the text, not to the policy. They are not part of the JSON, so a policy loaded from JSON prints
without comments.

## The validated JSON is the source of truth

The text is validated when it is parsed, with the same checks as `Policy::validate`. What you store, diff and ship is
the JSON of the validated policy:

```rust
use themis::dsl::parse;

let parsed = parse("main.themis", source)?;
let json = parsed.policy.to_json()?;
let again = themis::dsl::Policy::from_json(&json)?;
assert!(parsed.policy.equivalent(&again));
```

Two files in different types that mean the same thing give the same JSON. Treat the text as the way people edit the
policy and the JSON as the artifact that services load. `Policy::engine_spec` turns the policy into the
specification an engine is built from.

## Macros

The `themis-macros` crate checks a policy while your program compiles, so a policy that does not validate does not
build.

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

- `policy!` takes a text literal. Prefer a raw string for several lines; an error points at the literal, with
  `policy:line:column` counted inside the text.
- `include_policy!` takes a path relative to the `CARGO_MANIFEST_DIR` of the caller and tracks the file, so editing it
  recompiles the caller. The file must be inside the crate, outside `target/` and hidden path components, valid UTF-8
  and at most 4 MiB.
- The expansion embeds the canonical JSON of the validated policy. The text is never parsed at run time, but the JSON
  is read back each time the expansion runs, so keep a frequently used policy in a `LazyLock` static.

There is no `macros` feature on `themis-auth`. The macros run the parser while compiling, so `themis-macros` depends
on `themis-auth`; a re-export behind a feature would make a package cycle, which Cargo refuses. Depend on
`themis-macros` directly, as above. The two crates are pinned to the same version.

## Errors

Every error carries `file:line:column`, a message and, when there is a likely fix, a hint:

```text
a.themis:6:26: unknown permission `doc.write`
  hint: declare it as a permission block
b.themis:3:1: unknown statement `frobnicate`
  hint: expected one of: kinds, broad, strategy, depth, permission, role, subject, tuple, relation, relations, override, always
e.themis:5:3: unknown field `target` in permission
  hint: did you mean `targets`?
```

The parser keeps going after the first error and reports up to 100, then "and N more". An error that involves two
places names the second one with "also at". Messages and hints are in English.

## Limits against hostile input

Parsing is bounded, so untrusted text cannot exhaust memory or the stack:

| Limit | Value |
| --- | --- |
| Size of one source | 4 MiB (`MAX_SOURCE_BYTES`) |
| Sources in a project | 10000 (`MAX_SOURCES`) |
| Total size of a project | 64 MiB (`MAX_PROJECT_BYTES`) |
| Policy files in a directory | 1024 |
| Nesting of conditions and groups | 64 |
| Diagnostics reported | 100 |

A source over the size limit is refused with a position at its start, before any parsing.

## Grammar reference

Common to the three types:

- Comments start with `//` and run to the end of the line.
- Identifiers such as permissions (`doc.read`), roles and kinds are bare words. Strings use double quotes.
- A resource or subject reference is `kind:id`, for example `project:apollo` or `user:ana`.
- Where a field takes a resource (`resource` and `on` in the invariants), it can be a path of steps joined by `>`, such as
  `org:acme > doc`. Each step is `kind` or `kind:id`, and the steps keep the order written, which is the order of
  `Resource::path`: the first is the most specific step.
- Dates are UTC: `2026-01-01` or `2026-01-01T09:00:00Z`, with optional milliseconds.
- Subject matchers: `anyone`, `role <name>`, `user <id>`, `principal <id>`, `relation <name>`.
- Conditions use `==`, `!=`, `<`, `<=`, `>`, `>=`, `in`, `and` (or `&&`), `or` (or `||`), `not` (or `!`),
  `exists <attribute>`, `all(...)`, `any(...)` and `@function(arguments)`. Attributes start with `subject.`,
  `resource.` or `env.`. The text, set and network operators `starts_with`, `ends_with`, `contains`, `any_in`,
  `all_in` and `ip_in` are written between two operands (`a starts_with "x"`), and the time conditions are
  `time_between "HH:MM" "HH:MM"` and `weekday_in [mon, ...]` with the days as strings; see
  [Text, set, network and time conditions](#text-set-network-and-time-conditions).
- Relation rewrites: `this`, a union `a | b`, an intersection `a & b`, a difference `a - b`, a walk `parent->relation`,
  and the function forms `union(...)`, `intersection(...)` and `exclusion(a, b)`. Do not mix `|`, `&` and `-` without
  parentheses.

### Blocks

A source is a list of declarations. Top-level settings are `target_kinds`, `broad_targets`, `strategy` (`most_specific`,
`deny_overrides`, `permit_overrides` or `first_applicable`) and `max_depth`. Fields are `name = value`, and lists are
`[a, b]`.

| Declaration | Fields |
| --- | --- |
| `permission <id> { }` | `label`, `description`, `targets` (required), `implied_by`, `depends_on`, `non_delegable`, `management_only`, `override_only`, `meta { k = "v" }` |
| `role <name> { }` | `inherits` |
| `subject <kind:id> { }` | `principals`, `attrs { }`, `assign <role> { scope, valid_from, valid_until }` |
| `grant <id> { }` | `effect` (`allow` or `deny`), `subject`, `permission`, `target`, `scope`, `when`, `valid_from`, `valid_until` |
| `relation <kind#name> { }` | `rewrite` |
| `relations = []` | declares that the policy uses no relations |
| `tuples { }` | one `object#relation@subject` per line |
| `override resource_owner { }` | `attr`, `except` |
| `override permission_holder { }` | `permission`, `except` |
| `invariant <kind> { }` | depends on the kind, below |

Invariant kinds: `catalog_conformance`, `no_self_management`, `prerequisites`, `require_permission` (`permission`,
`resource`), `no_lockout` (`permissions`, `members`, `resource`, `reserve_role`, `reserve_scope`, `reserve_subjects`,
`reserve_from`, `reserve_until`), `non_delegable` (`manager`), `management_only` (`roles`), `no_escalation` (`bypass`,
`on`) and `forbid` (`subject`, `permissions`).

### Rules

One statement per line. A line indented deeper than the one above continues it.

| Statement | Form |
| --- | --- |
| `kinds` | `kinds a, b, c` |
| `broad` | `broad org` |
| `strategy` | `strategy <name>` |
| `depth` | `depth <n>` |
| `permission` | `permission <id> on <kinds> [implied by <ids>] [needs <ids>] [label "..."] [about "..."] [non-delegable] [management-only] [override-only] [meta k = "v"]` |
| `role` | `role <name> [inherits <names>]` |
| `subject` | `subject team:ops` declares a subject; `user:ana has role <name> [in <scope>] [from <date>] [until <date>]`, `user:ana has principal <id>` and `user:ana has attr <key> = <value>` fill it in |
| `relations` | `relations none` declares that the policy uses no relations |
| `relation` | `relation doc#viewer = this \| owner` |
| `tuple` | `tuple doc:d1#owner@user:bob` |
| grant | `<id>: allow\|deny <matcher> to <permission> on <target> [in <scope>] [when <condition>] [from <date>] [until <date>]` |
| `override` | `override resource-owner <attr> [except <ids>]`, `override permission-holder <id> [except <ids>]` |
| `always` | `always <invariant> [fields]` |

The invariant words are the block names with hyphens: `catalog-conformance`, `no-self-management`, `prerequisites`,
`require-permission`, `no-lockout`, `non-delegable`, `management-only`, `no-escalation` and `forbid`. Fields follow
the word as `name value` pairs, with lists in square brackets.

### Actors

Headings start in the first column and the lines under them are indented.

| Heading | Lines under it |
| --- | --- |
| `role <name> [inherits <names>]` | `in <scope>` and, under it or directly, `allow\|deny <permission> on <target> [when <condition>] [from <date>] [until <date>] as <id>` |
| `user <id>` or `subject <kind:id>` | `role <name> [in <scope>] [from <date>] [until <date>]`, `principal <id>`, `attr <key> = <value>` and the same `allow` and `deny` lines |
| `principal <id>`, `relation <name>`, `anyone` | the `allow` and `deny` lines |
| `catalog` | `kinds`, `broad`, then each permission as in rules, without the `permission` word |
| `relations` | `doc#viewer = this \| owner`, one per line |
| `tuples` | `doc:d1#owner@user:bob`, one per line |
| `engine` | `strategy`, `depth` and `override ...` |
| `governance` | the invariant words, as in rules without `always` |

When a form here is unclear, the corpus in `crates/themis/tests/dsl/corpus` has a working file for each topic in all
three types: roles, governance, validity, conditions, relations, members, overrides.

## Catalog governance in the language

Governance flags and invariants are part of the language, so a catalog can state its own rules. This source, from the
corpus, uses `non_delegable`, `management_only`, `override_only`, the two overrides and every invariant kind:

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

## Validity windows

`valid_from` and `valid_until` limit an assignment or a grant to a window, in UTC:

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

## Conditions and relations

Conditions read subject and resource attributes:

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

### Text, set, network and time conditions

Besides the comparisons, a condition can test text, lists, network addresses and the time of the decision. The three
syntaxes write them the same way, and the JSON `op` is the operator name.

| Condition | Holds when |
| --- | --- |
| `a starts_with b`, `a ends_with b` | the text `a` begins or ends with the text `b` |
| `a contains b` | the text `a` has `b` as a substring, or the list `a` has `b` as an element |
| `a any_in b` | the list `a` has at least one element that is in the list `b` |
| `a all_in b` | every element of the list `a` is in the list `b` (an empty `a` holds) |
| `a ip_in b` | the IPv4 or IPv6 address `a` is inside the CIDR `b`, or inside one CIDR of the list `b` |
| `time_between "09:00" "17:30"` | the UTC time of day is in `[from, until)`; a window with `from` after `until` crosses midnight, and equal bounds make an empty window |
| `weekday_in ["mon", "tue"]` | the UTC weekday is one of the days (`mon`, `tue`, `wed`, `thu`, `fri`, `sat`, `sun`) |

```themis
when = resource.name ends_with ".md" and subject.tags any_in ["docs", "ops"]
when = env.ip ip_in ["10.0.0.0/8", "2001:db8::/32"]
when = time_between "22:00" "06:00" and weekday_in ["mon", "tue", "wed", "thu", "fri"]
```

- An address without a prefix length stands for one host, and an IPv4 address written as IPv4-mapped IPv6
  (`::ffff:10.1.2.3`) is matched against IPv4 CIDRs.
- There is no regular-expression condition.
- The validator rejects a CIDR, a time of day or a weekday that cannot be read, with the position and a hint. The same
  checks run on JSON.
- A wrong operand type or an unreadable operand is an error, like in the comparisons: an `allow` with it does not apply
  and a `deny` with it does.
- The time conditions read the decision instant, `Context::at` (`setNow` in the Node binding), always in UTC. Without
  an instant they cannot be resolved, so a grant that uses them never allows.
- A condition that reads a `resource.` attribute is not translated to SQL: a listing keeps it as a residue to check
  row by row, and `themis-postgres` never turns it into an allow.
- `DSL_SCHEMA` goes from 1 to 2. A policy that uses one of these conditions is refused by a reader of schema 1, and a
  policy without them reads the same as before.

### Relations

Relations rewrite one relation in terms of others, and tuples state the facts:

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
