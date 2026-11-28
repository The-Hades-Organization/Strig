# strig-cli

The `strig` command for [Strig](https://github.com/The-Hades-Organization/Strig) policies.

```sh
cargo install strig-cli --locked

strig test policies/                   # every *.strig and *.strig-test.json in the directory
strig test policies/ --junit out.xml   # plus a JUnit report for CI
```

`strig test <dir>` reads the `*.strig` files of the directory as one project, runs the cases of every
`*.strig-test.json` beside them and prints one line per case, with the expected and the obtained answer (and the grants
considered) for each that fails. Exit code: `0` all passed, `1` some case failed or could not be judged, `2` the policy,
a test file or the arguments are wrong, or the directory has no test file.

The test format is in [docs/dsl.md](../../docs/dsl.md#testing-a-policy). More subcommands arrive in the same binary.
