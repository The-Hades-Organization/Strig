//! `strig test` end to end, on directories written for the case.

use std::fs;
use std::path::{Path, PathBuf};

use strig_cli::{EXIT_FAILED, EXIT_OK, EXIT_USAGE, execute};

const POLICY: &str = "language blocks\n\ntarget_kinds = [doc]\n\npermission doc.read {\n  targets = [doc]\n}\n\n\
role reader {\n}\n\nsubject user:ana {\n  assign reader {\n  }\n}\n\n\
grant g {\n  effect = allow\n  subject = role reader\n  permission = doc.read\n  target = doc\n}\n";

fn case(expect: &str) -> String {
    format!(
        r#"{{"cases": [{{"kind": "check", "name": "ana reads", "subject": "user:ana", "permission": "doc.read",
            "resource": "doc:1", "expect": "{expect}"}}]}}"#
    )
}

fn dir(name: &str, files: &[(&str, &str)]) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    fs::remove_dir_all(&dir).ok();
    fs::create_dir_all(&dir).unwrap();
    for (file, text) in files {
        fs::write(dir.join(file), text).unwrap();
    }
    dir
}

fn strig(args: &[&str]) -> (u8, String, String) {
    let args: Vec<String> = args.iter().map(|a| (*a).to_string()).collect();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = execute(&args, &mut out, &mut err);
    (code, String::from_utf8(out).unwrap(), String::from_utf8(err).unwrap())
}

#[test]
fn passing_tests_exit_zero_and_write_junit() {
    let dir = dir("pass", &[("p.strig", POLICY), ("p.strig-test.json", &case("allow"))]);
    let junit = dir.join("out.xml");
    let (code, out, err) = strig(&["test", dir.to_str().unwrap(), "--junit", junit.to_str().unwrap()]);
    assert_eq!((code, err.as_str()), (EXIT_OK, ""), "{out}");
    assert!(out.contains("PASS ana reads"), "{out}");
    assert!(out.contains("1 passed, 0 failed, 0 errors"), "{out}");
    let xml = fs::read_to_string(junit).unwrap();
    assert!(xml.contains("tests=\"1\" failures=\"0\" errors=\"0\""), "{xml}");
}

#[test]
fn a_failing_case_exits_one_and_shows_the_diff() {
    let dir = dir("fail", &[("p.strig", POLICY), ("p.strig-test.json", &case("deny"))]);
    let junit = dir.join("out.xml");
    let (code, out, _) = strig(&["test", dir.to_str().unwrap(), "--junit", junit.to_str().unwrap()]);
    assert_eq!(code, EXIT_FAILED, "{out}");
    assert!(out.contains("FAIL ana reads"), "{out}");
    assert!(out.contains("expected: deny"), "{out}");
    assert!(
        out.contains("obtained: allow, reason grant, decided by grant `g`"),
        "{out}"
    );
    assert!(out.contains("grant `g` (allow doc.read): candidate"), "{out}");
    assert!(fs::read_to_string(junit).unwrap().contains("<failure"));
}

#[test]
fn an_unjudgeable_case_exits_one() {
    let bad = case("allow").replace("user:ana", "user:ghost");
    let dir = dir("error", &[("p.strig", POLICY), ("p.strig-test.json", &bad)]);
    let (code, out, _) = strig(&["test", dir.to_str().unwrap()]);
    assert_eq!(code, EXIT_FAILED, "{out}");
    assert!(out.contains("ERROR ana reads") && out.contains("user:ghost"), "{out}");
}

#[test]
fn nothing_to_run_or_a_broken_input_exits_two() {
    let no_tests = dir("no-tests", &[("p.strig", POLICY)]);
    let (code, _, err) = strig(&["test", no_tests.to_str().unwrap()]);
    assert_eq!(code, EXIT_USAGE);
    assert!(err.contains("no *.strig-test.json"), "{err}");

    let no_policy = dir("no-policy", &[("p.strig-test.json", &case("allow"))]);
    assert_eq!(strig(&["test", no_policy.to_str().unwrap()]).0, EXIT_USAGE);

    let bad_policy = dir(
        "bad-policy",
        &[
            ("p.strig", "language blocks\n\nnonsense\n"),
            ("p.strig-test.json", &case("allow")),
        ],
    );
    assert_eq!(strig(&["test", bad_policy.to_str().unwrap()]).0, EXIT_USAGE);

    let bad_test = dir("bad-test", &[("p.strig", POLICY), ("p.strig-test.json", "{")]);
    assert_eq!(strig(&["test", bad_test.to_str().unwrap()]).0, EXIT_USAGE);

    assert_eq!(strig(&["test", "/nonexistent/strig/dir"]).0, EXIT_USAGE);
}

#[test]
fn bad_arguments_exit_two() {
    assert_eq!(strig(&[]).0, EXIT_USAGE);
    assert_eq!(strig(&["fly"]).0, EXIT_USAGE);
    assert_eq!(strig(&["test"]).0, EXIT_USAGE);
    assert_eq!(strig(&["test", "a", "b"]).0, EXIT_USAGE);
    assert_eq!(strig(&["test", "a", "--junit"]).0, EXIT_USAGE);
    assert_eq!(strig(&["test", "a", "--bogus"]).0, EXIT_USAGE);
    assert_eq!(strig(&["help"]).0, EXIT_OK);
}

#[test]
fn the_example_project_passes() {
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/policy-tests");
    let (code, out, err) = strig(&["test", example.to_str().unwrap()]);
    assert_eq!((code, err.as_str()), (EXIT_OK, ""), "{out}");
    assert!(out.contains("10 passed, 0 failed, 0 errors"), "{out}");
}
