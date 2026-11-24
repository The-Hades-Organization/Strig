//! A project with one file in each syntax, and the files read from a directory.

use std::path::PathBuf;
use strig::dsl::fs::read_dir;
use strig::dsl::{Language, Project};

const KINDS_BLOCKS: &str = "language blocks\n\ntarget_kinds = [org, doc]\n";
const READ_RULES: &str = "language rules\n\npermission doc.read on doc\n";
const VIEWER_ACTORS: &str = "language actors\n\nrole viewer\n";

fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    dir
}

#[test]
fn a_directory_with_the_three_syntaxes_builds_one_policy() {
    let dir = scratch("dsl-mixed-project");
    for (name, text) in [
        ("a.strig", KINDS_BLOCKS),
        ("b.strig", READ_RULES),
        ("c.strig", VIEWER_ACTORS),
    ] {
        std::fs::write(dir.join(name), text).unwrap();
    }
    let built = read_dir(&dir)
        .unwrap()
        .build()
        .unwrap_or_else(|errors| panic!("{errors}"));
    assert_eq!(built.policy.catalog.target_kinds, ["doc", "org"]);
    assert_eq!(built.policy.catalog.permissions.len(), 1);
    assert_eq!(built.policy.roles.len(), 1);
}

#[test]
fn each_source_keeps_its_own_syntax_in_a_project() {
    let mut project = Project::new();
    assert_eq!(project.add_source("a.strig", KINDS_BLOCKS).unwrap(), Language::Blocks);
    assert_eq!(project.add_source("b.strig", READ_RULES).unwrap(), Language::Rules);
    assert_eq!(project.add_source("c.strig", VIEWER_ACTORS).unwrap(), Language::Actors);
}

#[test]
fn the_order_of_mixed_sources_does_not_change_the_policy() {
    let mut forward = Project::new();
    let mut backward = Project::new();
    let all = [("a", KINDS_BLOCKS), ("b", READ_RULES), ("c", VIEWER_ACTORS)];
    for (name, text) in all {
        forward.add_source(name, text).unwrap();
    }
    for (name, text) in all.into_iter().rev() {
        backward.add_source(name, text).unwrap();
    }
    assert!(
        forward
            .build()
            .unwrap()
            .policy
            .equivalent(&backward.build().unwrap().policy)
    );
}
