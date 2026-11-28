//! `strig audit report` end to end, on a trail and stamp files written for the case.

use std::fs;
use std::path::{Path, PathBuf};

use strig::audit::{AuditLevel, reference_record};
use strig_cli::{EXIT_FAILED, EXIT_OK, EXIT_USAGE, execute};

const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../strig/tests/fixtures/timestamp/cacert.pem");
const STAMP: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../strig/tests/fixtures/timestamp/resp.tsr");

fn strig(args: &[&str]) -> (u8, String, String) {
    let args: Vec<String> = args.iter().map(|a| (*a).to_string()).collect();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = execute(&args, &mut out, &mut err);
    (code, String::from_utf8(out).unwrap(), String::from_utf8(err).unwrap())
}

fn trail(name: &str, edit: impl Fn(String) -> String) -> (PathBuf, String) {
    let record = reference_record(AuditLevel::Forensic);
    let head = record.hash.clone().unwrap();
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    fs::remove_dir_all(&dir).ok();
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("trail.jsonl");
    fs::write(&path, edit(serde_json::to_string(&record).unwrap() + "\n")).unwrap();
    (path, head)
}

#[test]
fn an_intact_trail_with_its_anchor_conforms() {
    let (path, head) = trail("audit-ok", |t| t);
    let (code, out, err) = strig(&["audit", "report", path.to_str().unwrap(), "--anchor-head", &head]);
    assert_eq!((code, err.as_str()), (EXIT_OK, ""), "{out}");
    assert!(out.contains("chain: intact") && out.contains("anchor head: ok") && out.ends_with("conforming\n"), "{out}");
}

#[test]
fn json_output_is_the_report() {
    let (path, _) = trail("audit-json", |t| t);
    let (code, out, _) = strig(&["audit", "report", path.to_str().unwrap(), "--json"]);
    assert_eq!(code, EXIT_OK);
    let value: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(value["records"], 1);
    assert_eq!(value["chain"]["ok"], true);
}

#[test]
fn an_edited_record_or_a_wrong_anchor_exits_one() {
    let (path, head) = trail("audit-tampered", |t| t.replacen("\"actor\"", "\"actorX\"", 1));
    let (code, out, _) = strig(&["audit", "report", path.to_str().unwrap()]);
    assert_eq!(code, EXIT_FAILED, "{out}");
    assert!(out.contains("NOT conforming"), "{out}");

    let (path, _) = trail("audit-anchor", |t| t);
    let (code, out, _) = strig(&["audit", "report", path.to_str().unwrap(), "--anchor-head", &"0".repeat(head.len())]);
    assert_eq!(code, EXIT_FAILED);
    assert!(out.contains("anchor head: MISMATCH"), "{out}");
}

#[test]
fn a_stamp_of_another_digest_fails_the_report() {
    let (path, _) = trail("audit-stamp", |t| t);
    let (code, out, _) =
        strig(&["audit", "report", path.to_str().unwrap(), "--timestamp", STAMP, "--root", ROOT, "--json"]);
    assert_eq!(code, EXIT_FAILED);
    let value: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(value["timestamps"][0]["ok"], false);
}

#[test]
fn bad_usage_exits_two() {
    let (path, _) = trail("audit-usage", |t| t);
    let p = path.to_str().unwrap();
    assert_eq!(strig(&["audit"]).0, EXIT_USAGE);
    assert_eq!(strig(&["audit", "report"]).0, EXIT_USAGE);
    assert_eq!(strig(&["audit", "report", p, "--timestamp", STAMP]).0, EXIT_USAGE);
    assert_eq!(strig(&["audit", "report", p, "--bogus"]).0, EXIT_USAGE);
    assert_eq!(strig(&["audit", "report", "/no/such/file"]).0, EXIT_USAGE);
}
