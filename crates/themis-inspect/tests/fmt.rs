//! `themis-inspect fmt`: reescreve no lugar, `--check` não escreve e sai com 1, erro traz a posição.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

const MESSY: &str =
    "language blocks\n\n\ntarget_kinds = [org]   // kinds\n\npermission org.read {\n      targets = [org]\n}\n";
const TIDY: &str = "language blocks\n\ntarget_kinds = [org]  // kinds\n\npermission org.read {\n  targets = [org]\n}\n";

fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("fmt").join(name);
    fs::remove_dir_all(&dir).ok();
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn fmt(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_themis-inspect"))
        .arg("fmt")
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn fmt_rewrites_a_file_in_place() {
    let dir = scratch("rewrite");
    let file = dir.join("a.themis");
    fs::write(&file, MESSY).unwrap();
    let out = fmt(&[file.to_str().unwrap()]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(fs::read_to_string(&file).unwrap(), TIDY);
}

#[test]
fn fmt_check_lists_the_file_that_would_change_and_writes_nothing() {
    let dir = scratch("check_diff");
    let file = dir.join("a.themis");
    fs::write(&file, MESSY).unwrap();
    let out = fmt(&["--check", dir.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stdout).contains("a.themis"));
    assert_eq!(fs::read_to_string(&file).unwrap(), MESSY);
}

#[test]
fn fmt_check_passes_when_everything_is_formatted() {
    let dir = scratch("check_ok");
    fs::write(dir.join("a.themis"), TIDY).unwrap();
    let out = fmt(&["--check", dir.to_str().unwrap()]);
    assert!(out.status.success());
    assert!(out.stdout.is_empty());
}

#[test]
fn fmt_on_a_directory_skips_other_extensions_and_formats_the_rest() {
    let dir = scratch("dir");
    fs::write(dir.join("a.themis"), MESSY).unwrap();
    fs::write(dir.join("notes.txt"), "not a policy").unwrap();
    assert!(fmt(&[dir.to_str().unwrap()]).status.success());
    assert_eq!(fs::read_to_string(dir.join("a.themis")).unwrap(), TIDY);
    assert_eq!(fs::read_to_string(dir.join("notes.txt")).unwrap(), "not a policy");
}

#[test]
fn fmt_reports_a_compile_error_as_file_line_column_and_still_formats_the_others() {
    let dir = scratch("broken");
    fs::write(dir.join("a.themis"), MESSY).unwrap();
    let bad = dir.join("b.themis");
    fs::write(&bad, "language blocks\n\npermission {\n").unwrap();
    let out = fmt(&[dir.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains(&format!("{}:", bad.display())), "{stderr}");
    let position = stderr.trim_start_matches(&format!("{}:", bad.display()));
    let mut parts = position.split(':');
    assert!(parts.next().is_some_and(|n| n.parse::<u32>().is_ok()), "{stderr}");
    assert!(parts.next().is_some_and(|n| n.parse::<u32>().is_ok()), "{stderr}");
    assert_eq!(fs::read_to_string(dir.join("a.themis")).unwrap(), TIDY);
}

#[test]
fn fmt_without_a_path_is_a_usage_error() {
    assert_eq!(fmt(&[]).status.code(), Some(2));
}
