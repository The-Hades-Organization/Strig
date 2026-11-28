//! Reading and writing policy files and directories.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use strig::dsl::fs::{FsError, MAX_FILES, read_dir, read_file, read_tests, write_file};
use strig::dsl::{Language, MAX_SOURCE_BYTES};

const KINDS: &str = "language blocks\n\ntarget_kinds = [doc, org]\n";
const READ: &str = "language blocks\n\npermission doc.read {\n  targets = [doc]\n}\n";

/// A directory of its own under the system temporary directory, removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("strig-dsl-{}-{tag}-{id}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn write(&self, name: &str, text: &str) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, text).unwrap();
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).ok();
    }
}

#[test]
fn a_file_is_read_and_its_errors_carry_the_path() {
    let dir = Scratch::new("file");
    let good = dir.write("a.strig", KINDS);
    assert_eq!(read_file(&good).unwrap().language, Language::Blocks);

    let bad = dir.write("b.strig", "target_kinds = [x]\n");
    let Err(FsError::Syntax(errors)) = read_file(&bad) else {
        panic!("a syntax error was expected")
    };
    let at = errors.first().unwrap().location.as_ref().unwrap();
    assert_eq!(&*at.file, bad.display().to_string());
    assert_eq!((at.line, at.column), (1, 1));
}

#[test]
fn a_missing_file_is_an_io_error_with_its_cause() {
    let dir = Scratch::new("missing");
    let error = read_file(dir.path().join("none.strig")).unwrap_err();
    let FsError::Io { source, .. } = &error else {
        panic!("an io error was expected, got {error}")
    };
    assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
}

#[test]
fn a_file_that_is_not_text_is_refused() {
    let dir = Scratch::new("binary");
    let path = dir.0.join("a.strig");
    fs::write(&path, [0xff, 0xfe, 0x00]).unwrap();
    assert!(matches!(read_file(&path), Err(FsError::Io { .. })));
}

#[test]
fn a_file_over_the_limit_is_refused() {
    let dir = Scratch::new("large");
    let path = dir.write("a.strig", &" ".repeat(MAX_SOURCE_BYTES + 1));
    assert!(matches!(read_file(&path), Err(FsError::TooLarge { .. })));
}

#[test]
fn a_directory_becomes_a_project_in_alphabetical_order() {
    let dir = Scratch::new("dir");
    dir.write("b-read.strig", READ);
    dir.write("a-kinds.strig", KINDS);
    dir.write("notes.txt", "not a policy");
    fs::create_dir(dir.path().join("sub.strig")).unwrap();
    let project = read_dir(dir.path()).unwrap();
    assert_eq!(project.len(), 2);
    let built = project.build().unwrap();
    let at = built.origins.get("permission:doc.read").unwrap();
    assert!(at.file.ends_with("b-read.strig"));
    assert_eq!(built.policy.catalog.target_kinds, ["doc", "org"]);
}

#[test]
fn a_clash_between_files_of_a_directory_names_both_files() {
    let dir = Scratch::new("clash");
    dir.write("a.strig", KINDS);
    dir.write("b.strig", READ);
    dir.write("c.strig", READ);
    let errors = read_dir(dir.path()).unwrap().build().unwrap_err();
    let first = errors.first().unwrap();
    assert!(first.location.as_ref().unwrap().file.ends_with("c.strig"));
    assert!(first.related.as_ref().unwrap().file.ends_with("b.strig"));
}

#[test]
fn a_syntax_error_in_a_directory_file_is_reported_with_that_file() {
    let dir = Scratch::new("syntax");
    dir.write("a.strig", "oops\n");
    let Err(FsError::Syntax(errors)) = read_dir(dir.path()) else {
        panic!("a syntax error was expected")
    };
    assert!(
        errors
            .first()
            .unwrap()
            .location
            .as_ref()
            .unwrap()
            .file
            .ends_with("a.strig")
    );
}

#[test]
fn a_missing_directory_is_an_io_error() {
    let dir = Scratch::new("nodir");
    assert!(matches!(read_dir(dir.path().join("none")), Err(FsError::Io { .. })));
}

#[test]
fn a_directory_with_too_many_files_is_refused() {
    let dir = Scratch::new("many");
    for n in 0..=MAX_FILES {
        dir.write(&format!("f{n:05}.strig"), "");
    }
    assert!(matches!(read_dir(dir.path()), Err(FsError::TooManyFiles { .. })));
}

#[cfg(unix)]
#[test]
fn a_link_in_a_directory_is_refused_by_name() {
    let outside = Scratch::new("outside");
    let target = outside.write("secret.strig", KINDS);
    let dir = Scratch::new("link");
    std::os::unix::fs::symlink(&target, dir.path().join("link.strig")).unwrap();
    match read_dir(dir.path()) {
        Err(FsError::Outside { path }) => assert!(path.ends_with("link.strig")),
        other => panic!("expected Outside, got {other:?}"),
    }
}

#[test]
fn a_policy_written_to_a_file_reads_back_the_same() {
    let dir = Scratch::new("write");
    let source = dir.write("in.strig", &format!("// head\n{KINDS}"));
    let parsed = read_file(&source).unwrap();
    let out = dir.path().join("out.strig");
    write_file(&out, &parsed.policy, Language::Blocks).unwrap();
    assert_eq!(fs::read_to_string(&out).unwrap(), format!("// head\n{KINDS}"));
    assert!(read_file(&out).unwrap().policy.equivalent(&parsed.policy));
}

#[test]
fn a_policy_written_in_another_syntax_is_read_back_as_the_same_policy() {
    let dir = Scratch::new("other-syntax");
    let parsed = read_file(dir.write("in.strig", KINDS)).unwrap();
    for language in [Language::Rules, Language::Actors] {
        let out = dir.path().join(format!("out-{language}.strig"));
        write_file(&out, &parsed.policy, language).unwrap();
        let again = read_file(&out).unwrap();
        assert_eq!(again.language, language);
        assert!(parsed.policy.equivalent(&again.policy));
    }
}

#[test]
fn a_policy_the_syntax_cannot_say_fails_before_touching_the_file() {
    let dir = Scratch::new("unrepresentable");
    let mut policy = read_file(dir.write("in.strig", KINDS)).unwrap().policy;
    policy.notes.push(strig::dsl::Note::new(
        "orphan",
        strig::dsl::NoteAnchor::new("permission:gone", strig::dsl::Placement::Before),
        strig::dsl::NoteOrigin::new("x", Language::Blocks, 1, 1),
    ));
    let out = dir.path().join("out.strig");
    let error = write_file(&out, &policy, Language::Rules).unwrap_err();
    assert!(matches!(error, FsError::Print(_)));
    assert!(!out.exists());
}

#[test]
fn read_tests_picks_up_test_files_in_order_and_loads_the_fixture_they_name() {
    let dir = Scratch::new("tests");
    dir.write("b.strig-test.json", r#"{"fixture": "b.fixture.json", "cases": []}"#);
    dir.write("a.strig-test.json", r#"{"cases": []}"#);
    dir.write("b.fixture.json", r#"{"env": {"region": "br"}}"#);
    dir.write("ignored.json", "not a test");
    dir.write("p.strig", READ);
    let files = read_tests(dir.path()).unwrap();
    let names: Vec<_> = files
        .iter()
        .map(|f| f.file.rsplit('/').next().unwrap().to_string())
        .collect();
    assert_eq!(names, ["a.strig-test.json", "b.strig-test.json"]);
    assert_eq!(files[1].fixture_path(), None, "the path was replaced by the content");
}

#[test]
fn read_tests_refuses_a_fixture_that_leaves_the_directory() {
    let dir = Scratch::new("tests-escape");
    let outside = Scratch::new("tests-outside");
    let target = outside.write("f.json", "{}");
    for reference in ["../f.json", target.to_str().unwrap()] {
        dir.write(
            "t.strig-test.json",
            &format!(r#"{{"fixture": {reference:?}, "cases": []}}"#),
        );
        assert!(
            matches!(read_tests(dir.path()), Err(FsError::Outside { .. })),
            "{reference}"
        );
    }
}

#[test]
fn read_tests_reports_a_missing_or_invalid_fixture_and_a_bad_test_file() {
    let dir = Scratch::new("tests-bad");
    dir.write("t.strig-test.json", r#"{"fixture": "gone.json", "cases": []}"#);
    assert!(matches!(read_tests(dir.path()), Err(FsError::Io { .. })));
    dir.write("gone.json", "[1]");
    assert!(matches!(read_tests(dir.path()), Err(FsError::Test(_))));
    dir.write("t.strig-test.json", "{");
    assert!(matches!(read_tests(dir.path()), Err(FsError::Test(_))));
}

#[cfg(unix)]
#[test]
fn read_tests_refuses_a_test_file_that_is_a_link() {
    let dir = Scratch::new("tests-link");
    let real = dir.write("real.json", r#"{"cases": []}"#);
    std::os::unix::fs::symlink(&real, dir.path().join("l.strig-test.json")).unwrap();
    assert!(matches!(read_tests(dir.path()), Err(FsError::Outside { .. })));
}
