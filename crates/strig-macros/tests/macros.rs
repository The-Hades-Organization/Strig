//! The macros as a caller sees them.

use strig::dsl::{Language, Policy, parse};
use strig_macros::{include_policy, policy};

const SOURCE: &str = "language blocks\n\ntarget_kinds = [org]\n\npermission org.read {\n  targets = [org]\n}\n";

#[test]
fn policy_macro_gives_the_same_policy_as_parsing_at_runtime() {
    let built: Policy = policy!(
        r#"language blocks

target_kinds = [org]

permission org.read {
  targets = [org]
}
"#
    );
    let parsed = parse("x", SOURCE).unwrap();
    assert_eq!(parsed.language, Language::Blocks);
    assert!(built.equivalent(&parsed.policy));
}

#[test]
fn include_policy_reads_a_fixture_relative_to_the_manifest() {
    let built: Policy = include_policy!("tests/fixtures/ok.strig");
    let parsed = parse("x", SOURCE).unwrap();
    assert!(built.equivalent(&parsed.policy));
}

#[test]
fn both_macros_agree() {
    let a: Policy = policy!("language blocks\n\ntarget_kinds = [org]\n\npermission org.read {\n  targets = [org]\n}\n");
    let b: Policy = include_policy!("tests/fixtures/ok.strig");
    assert!(a.equivalent(&b));
}
