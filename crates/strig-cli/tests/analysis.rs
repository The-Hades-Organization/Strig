//! `strig diff` and `strig lint` end to end, on directories written for the case.

use std::fs;
use std::path::{Path, PathBuf};

use strig_cli::{EXIT_FAILED, EXIT_OK, EXIT_USAGE, execute};

const BASE: &str = "language blocks\n\ntarget_kinds = [doc]\n\npermission doc.read {\n  targets = [doc]\n}\n\n\
role reader {\n}\n\nrole editor {\n}\n\ngrant g {\n  effect = allow\n  subject = role reader\n  permission = doc.read\n  target = doc\n}\n";

const WIDER: &str = "\ngrant g2 {\n  effect = allow\n  subject = role editor\n  permission = doc.read\n  target = doc\n}\n";

const NARROWER: &str = "\ngrant g-no {\n  effect = deny\n  subject = role reader\n  permission = doc.read\n  target = doc\n}\n";

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

fn path(dir: &Path) -> &str {
    dir.to_str().unwrap()
}

#[test]
fn diff_of_the_same_policy_exits_zero() {
    let a = dir("diff-same-a", &[("p.strig", BASE)]);
    let b = dir("diff-same-b", &[("p.strig", BASE)]);
    let (code, out, err) = strig(&["diff", path(&a), path(&b)]);
    assert_eq!((code, err.as_str()), (EXIT_OK, ""), "{out}");
    assert!(out.contains("0 changed"), "{out}");
}

#[test]
fn diff_reports_a_widening_with_the_responsible_grant_and_exits_one() {
    let a = dir("diff-wide-a", &[("p.strig", BASE)]);
    let b = dir("diff-wide-b", &[("p.strig", &format!("{BASE}{WIDER}"))]);
    let (code, out, _) = strig(&["diff", path(&a), path(&b)]);
    assert_eq!(code, EXIT_FAILED, "{out}");
    assert!(out.contains("WIDENED  role:editor doc.read on doc:(any)"), "{out}");
    assert!(out.contains("before: deny (no_applicable_grant)"), "{out}");
    assert!(out.contains("after:  allow (grant, grant `g2` at "), "{out}");
}

#[test]
fn fail_on_allow_lets_a_narrowing_through_but_not_a_widening() {
    let base = dir("diff-fail-base", &[("p.strig", BASE)]);
    let narrow = dir("diff-fail-narrow", &[("p.strig", &format!("{BASE}{NARROWER}"))]);
    let wide = dir("diff-fail-wide", &[("p.strig", &format!("{BASE}{WIDER}"))]);
    let (code, out, _) = strig(&["diff", path(&base), path(&narrow), "--fail-on", "allow"]);
    assert_eq!(code, EXIT_OK, "{out}");
    assert!(out.contains("NARROWED"), "{out}");
    let (code, _, _) = strig(&["diff", path(&base), path(&wide), "--fail-on", "allow"]);
    assert_eq!(code, EXIT_FAILED);
    let (code, _, _) = strig(&["diff", path(&base), path(&narrow), "--fail-on", "any"]);
    assert_eq!(code, EXIT_FAILED);
}

#[test]
fn diff_takes_single_files_and_writes_json() {
    let a = dir("diff-json-a", &[("p.strig", BASE)]);
    let b = dir("diff-json-b", &[("p.strig", &format!("{BASE}{WIDER}"))]);
    let (before, after) = (a.join("p.strig"), b.join("p.strig"));
    let (code, out, _) = strig(&["diff", path(&before), path(&after), "--json"]);
    assert_eq!(code, EXIT_FAILED);
    let json: serde_json::Value = serde_json::from_str(&out).unwrap();
    let change = &json["changes"][0];
    assert_eq!(change["change"], "widened");
    assert_eq!(change["after"]["grant"], "g2");
    assert_eq!(json["universe"]["partial"], false);
}

#[test]
fn diff_over_an_explicit_fixture_asks_only_what_it_names() {
    let a = dir("diff-fx-a", &[("p.strig", BASE)]);
    let b = dir("diff-fx-b", &[("p.strig", &format!("{BASE}{WIDER}"))]);
    let fixture = dir(
        "diff-fx-f",
        &[(
            "f.json",
            r#"{"subjects": [{"kind": "user", "id": "bia", "roles": [{"role": "editor"}]}],
                "resources": ["doc:1"], "permissions": ["doc.read"]}"#,
        )],
    )
    .join("f.json");
    let (code, out, _) = strig(&["diff", path(&a), path(&b), "--fixture", path(&fixture), "--json"]);
    assert_eq!(code, EXIT_FAILED, "{out}");
    let json: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(json["universe"]["questions"], 1);
    assert_eq!(json["universe"]["derived"], false);
    assert_eq!(json["changes"][0]["subject"], "user:bia");
}

#[test]
fn diff_marks_a_cut_as_partial() {
    let a = dir("diff-cut-a", &[("p.strig", BASE)]);
    let b = dir("diff-cut-b", &[("p.strig", &format!("{BASE}{WIDER}"))]);
    let (_, out, _) = strig(&["diff", path(&a), path(&b), "--max-decisions", "2"]);
    assert!(out.contains("partial:"), "{out}");
}

#[test]
fn diff_usage_errors_exit_two() {
    let a = dir("diff-usage", &[("p.strig", BASE)]);
    assert_eq!(strig(&["diff", path(&a)]).0, EXIT_USAGE);
    assert_eq!(strig(&["diff", path(&a), path(&a), "--fail-on", "sometimes"]).0, EXIT_USAGE);
    assert_eq!(strig(&["diff", path(&a), "/nonexistent/strig"]).0, EXIT_USAGE);
    let empty = dir("diff-usage-empty", &[]);
    assert_eq!(strig(&["diff", path(&a), path(&empty)]).0, EXIT_USAGE);
}

const SHADOWED: &str = "\ngrant g-deny {\n  effect = deny\n  subject = anyone\n  permission = doc.read\n  target = doc\n}\n\n\
grant g-shadowed {\n  effect = allow\n  subject = role reader\n  permission = doc.read\n  target = doc\n}\n";

#[test]
fn lint_reports_findings_with_position_and_exits_one() {
    let d = dir("lint-warn", &[("p.strig", &format!("{BASE}{SHADOWED}"))]);
    let (code, out, _) = strig(&["lint", path(&d)]);
    assert_eq!(code, EXIT_FAILED, "{out}");
    assert!(out.contains("warning L001 [shadowed-grant]"), "{out}");
    assert!(out.contains("p.strig:"), "{out}");
    assert!(out.contains("hint:"), "{out}");
}

#[test]
fn lint_of_a_clean_policy_exits_zero() {
    let d = dir("lint-clean", &[("p.strig", &format!("{BASE}{WIDER}"))]);
    let (code, out, err) = strig(&["lint", path(&d)]);
    assert_eq!((code, err.as_str()), (EXIT_OK, ""), "{out}");
    assert!(out.contains("0 findings"), "{out}");
}

#[test]
fn lint_writes_json() {
    let d = dir("lint-json", &[("p.strig", &format!("{BASE}{SHADOWED}"))]);
    let (_, out, _) = strig(&["lint", path(&d), "--json"]);
    let json: serde_json::Value = serde_json::from_str(&out).unwrap();
    let finding = json
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["element"] == "grant:g-shadowed")
        .unwrap();
    assert_eq!(finding["code"], "L001");
    assert_eq!(finding["name"], "shadowed-grant");
    assert_eq!(finding["severity"], "warning");
    assert_eq!(finding["element"], "grant:g-shadowed");
    assert!(finding["line"].as_u64().unwrap() > 1);
}

#[test]
fn lint_ignores_codes_from_the_flag_and_from_the_config_file() {
    let text = format!("{BASE}{SHADOWED}");
    let d = dir("lint-ignore", &[("p.strig", &text)]);
    let (code, out, _) = strig(&["lint", path(&d), "--ignore", "L001"]);
    assert_eq!(code, EXIT_OK, "{out}");
    let d = dir(
        "lint-config",
        &[("p.strig", &text), ("strig-lint.json", r#"{"ignore": ["shadowed-grant"]}"#)],
    );
    let (code, out, _) = strig(&["lint", path(&d)]);
    assert_eq!(code, EXIT_OK, "{out}");
}

#[test]
fn lint_fail_on_picks_the_severity_that_fails() {
    let unused = format!("{BASE}\nrole lonely {{\n}}\n");
    let d = dir("lint-level", &[("p.strig", &unused)]);
    assert_eq!(strig(&["lint", path(&d)]).0, EXIT_OK);
    assert_eq!(strig(&["lint", path(&d), "--fail-on", "info"]).0, EXIT_FAILED);
    assert_eq!(strig(&["lint", path(&d), "--fail-on", "never"]).0, EXIT_OK);
}

#[test]
fn lint_usage_errors_exit_two() {
    let d = dir("lint-usage", &[("p.strig", BASE)]);
    assert_eq!(strig(&["lint"]).0, EXIT_USAGE);
    assert_eq!(strig(&["lint", path(&d), "--ignore", "L999"]).0, EXIT_USAGE);
    assert_eq!(strig(&["lint", path(&d), "--bogus"]).0, EXIT_USAGE);
    let bad = dir("lint-usage-config", &[("p.strig", BASE), ("strig-lint.json", r#"{"skip": []}"#)]);
    assert_eq!(strig(&["lint", path(&bad)]).0, EXIT_USAGE);
}
