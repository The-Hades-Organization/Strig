//! Reading and writing policy files and directories.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use themis::dsl::fs::{read_dir, read_file, write_file, FsError, MAX_FILES};
use themis::dsl::{Language, MAX_SOURCE_BYTES};

const KINDS: &str = "language blocks\n\ntarget_kinds = [org, doc]\n";
const READ: &str = "language blocks\n\npermission doc.read {\n  targets = [doc]\n}\n";

/// A directory of its own under the system temporary directory, removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("themis-dsl-{}-{tag}-{id}", std::process::id()));
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
    let good = dir.write("a.themis", KINDS);
    assert_eq!(read_file(&good).unwrap().language, Language::Blocks);

    let bad = dir.write("b.themis", "target_kinds = [x]\n");
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
    let error = read_file(dir.path().join("none.themis")).unwrap_err();
    let FsError::Io { source, .. } = &error else {
        panic!("an io error was expected, got {error}")
    };
    assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
}

#[test]
fn a_file_that_is_not_text_is_refused() {
    let dir = Scratch::new("binary");
    let path = dir.0.join("a.themis");
    fs::write(&path, [0xff, 0xfe, 0x00]).unwrap();
    assert!(matches!(read_file(&path), Err(FsError::Io { .. })));
}

#[test]
fn a_file_over_the_limit_is_refused() {
    let dir = Scratch::new("large");
    let path = dir.write("a.themis", &" ".repeat(MAX_SOURCE_BYTES + 1));
    assert!(matches!(read_file(&path), Err(FsError::TooLarge { .. })));
}

#[test]
fn a_directory_becomes_a_project_in_alphabetical_order() {
    let dir = Scratch::new("dir");
    dir.write("b-read.themis", READ);
    dir.write("a-kinds.themis", KINDS);
    dir.write("notes.txt", "not a policy");
    fs::create_dir(dir.path().join("sub.themis")).unwrap();
    let project = read_dir(dir.path()).unwrap();
    assert_eq!(project.len(), 2);
    let built = project.build().unwrap();
    let at = built.origins.get("permission:doc.read").unwrap();
    assert!(at.file.ends_with("b-read.themis"));
    assert_eq!(built.policy.catalog.target_kinds, ["org", "doc"]);
}

#[test]
fn a_clash_between_files_of_a_directory_names_both_files() {
    let dir = Scratch::new("clash");
    dir.write("a.themis", KINDS);
    dir.write("b.themis", READ);
    dir.write("c.themis", READ);
    let errors = read_dir(dir.path()).unwrap().build().unwrap_err();
    let first = errors.first().unwrap();
    assert!(first.location.as_ref().unwrap().file.ends_with("c.themis"));
    assert!(first.related.as_ref().unwrap().file.ends_with("b.themis"));
}

#[test]
fn a_syntax_error_in_a_directory_file_is_reported_with_that_file() {
    let dir = Scratch::new("syntax");
    dir.write("a.themis", "oops\n");
    let Err(FsError::Syntax(errors)) = read_dir(dir.path()) else {
        panic!("a syntax error was expected")
    };
    assert!(errors.first().unwrap().location.as_ref().unwrap().file.ends_with("a.themis"));
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
        dir.write(&format!("f{n:05}.themis"), "");
    }
    assert!(matches!(read_dir(dir.path()), Err(FsError::TooManyFiles { .. })));
}

#[cfg(unix)]
#[test]
fn a_link_in_a_directory_is_not_followed() {
    let outside = Scratch::new("outside");
    let target = outside.write("secret.themis", KINDS);
    let dir = Scratch::new("link");
    std::os::unix::fs::symlink(&target, dir.path().join("link.themis")).unwrap();
    assert_eq!(read_dir(dir.path()).unwrap().len(), 0);
}

#[test]
fn a_policy_written_to_a_file_reads_back_the_same() {
    let dir = Scratch::new("write");
    let source = dir.write("in.themis", &format!("// head\n{KINDS}"));
    let parsed = read_file(&source).unwrap();
    let out = dir.path().join("out.themis");
    write_file(&out, &parsed.policy, Language::Blocks).unwrap();
    assert_eq!(fs::read_to_string(&out).unwrap(), format!("// head\n{KINDS}"));
    assert!(read_file(&out).unwrap().policy.equivalent(&parsed.policy));
}

#[test]
fn writing_in_a_syntax_not_yet_available_fails_before_touching_the_file() {
    let dir = Scratch::new("unsupported");
    let parsed = read_file(dir.write("in.themis", KINDS)).unwrap();
    let out = dir.path().join("out.themis");
    let error = write_file(&out, &parsed.policy, Language::Rules).unwrap_err();
    assert!(matches!(error, FsError::Print(_)));
    assert!(!out.exists());
}
