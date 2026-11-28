# strig-cli

The `strig` command for [Strig](https://github.com/The-Hades-Organization/Strig) policies.

```sh
cargo install strig-cli --locked

strig test policies/                   # every *.strig and *.strig-test.json in the directory
strig test policies/ --junit out.xml   # plus a JUnit report for CI

strig diff before/ after/ --fail-on allow   # decisions that change; exit 1 when access widens
strig lint policies/                         # dead or suspicious policy

strig audit report trail.jsonl --anchor-head <hash> --timestamp head.tsr --root ca.pem   # conformance report
```

`strig test <dir>` reads the `*.strig` files of the directory as one project, runs the cases of every
`*.strig-test.json` beside them and prints one line per case, with the expected and the obtained answer (and the grants
considered) for each that fails. Exit code: `0` all passed, `1` some case failed or could not be judged, `2` the policy,
a test file or the arguments are wrong, or the directory has no test file.

`strig audit report <trail.jsonl>` summarizes an audit trail (period, records per action and outcome, changes per actor,
refusals per invariant, chain breaks, anchors and RFC 3161 stamps verified) in text or, with `--json`, as JSON. Exit code:
`0` the trail conforms, `1` it does not, `2` usage. See [docs/audit-format.md](../../docs/audit-format.md).

`strig diff <before> <after>` (directories or `.strig` files) lists the decisions that change between two versions:
subject, permission, resource, `widened` (deny became allow) or `narrowed`, and the grant or override that decided each
side. `--fixture <file>` gives the subjects, resources, permissions, grants, tuples and environment to ask about; without
it the questions come from the catalogs and the grants of both versions, bounded by `--max-subjects` and
`--max-decisions` and marked partial when a bound cuts them. `--json` prints the diff. Exit `0` no change matches,
`1` a change matches `--fail-on` (`any`, the default, or `allow` to fail only when access widens), `2` usage.

`strig lint <dir>` reports shadowed grants (`L001`), unreachable denies (`L002`), permissions nobody holds (`L003`),
unused roles (`L004`), redundant `implied_by` (`L005`), conditions always false or true (`L006`, `L007`) and fields never
granted (`L008`), each with severity, position and a hint. `--ignore <code|name>` and `strig-lint.json`
(`{"ignore": ["L004"]}`) silence codes; `--fail-on error|warning|info|never` sets the exit threshold (default
`warning`). Exit `1` when a finding reaches it.

The test format is in [docs/dsl.md](../../docs/dsl.md#testing-a-policy). More subcommands arrive in the same binary.
