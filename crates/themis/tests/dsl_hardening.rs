//! The language on hostile input, and the printer refusing what it cannot say.

use themis::dsl::{Language, MAX_SOURCE_BYTES, PrintError, Project, parse, print};

const HEADER: &str = "language blocks\n";

const GRANT: &str = "\
language blocks

target_kinds = [project]

permission project.write {
  targets = [project]
}

role editor {
}

grant g1 {
  effect = allow
  subject = role editor
  permission = project.write
  target = project
}
";

fn count(result: Result<themis::dsl::Parsed, themis::dsl::Diagnostics>) -> usize {
    result.err().map_or(0, |errors| errors.len())
}

#[test]
fn an_integer_out_of_range_is_an_error() {
    let text = format!("{HEADER}\nmax_depth = 99999999999999999999999\n");
    assert!(parse("big.themis", &text).is_err());
}

#[test]
fn a_ring_of_a_hundred_thousand_roles_ends_with_a_capped_report() {
    let total = 100_000;
    let mut text = String::from(HEADER);
    for at in 0..total {
        let next = (at + 1) % total;
        text.push_str(&format!("\nrole r{at} {{\n  inherits = [r{next}]\n}}\n"));
    }
    let found = count(parse("ring.themis", &text));
    assert!(found > 0, "a cycle of roles must be reported");
    assert!(found <= 101, "the report must stay capped, got {found}");
}

#[test]
fn a_chain_of_a_hundred_thousand_roles_is_accepted() {
    let total = 100_000;
    let mut text = String::from(HEADER);
    for at in 0..total {
        if at + 1 < total {
            text.push_str(&format!("\nrole r{at} {{\n  inherits = [r{}]\n}}\n", at + 1));
        } else {
            text.push_str(&format!("\nrole r{at} {{\n}}\n"));
        }
    }
    assert_eq!(count(parse("chain.themis", &text)), 0);
}

#[test]
fn half_a_million_comments_are_read() {
    let text = format!("{HEADER}{}", "//\n".repeat(500_000));
    let parsed = parse("comments.themis", &text).unwrap();
    assert_eq!(parsed.policy.notes.len(), 500_000);
}

#[test]
fn a_source_of_nothing_but_garbage_has_a_capped_report() {
    let text = format!("{HEADER}{}", "?".repeat(MAX_SOURCE_BYTES - 1_000));
    let found = count(parse("garbage.themis", &text));
    assert!(found > 0);
    assert!(found <= 101, "the report must stay capped, got {found}");
}

#[test]
fn a_source_over_the_limit_is_refused_with_a_position() {
    let text = format!("{HEADER}{}", " ".repeat(MAX_SOURCE_BYTES));
    let errors = parse("huge.themis", &text).unwrap_err();
    assert!(errors.first().unwrap().message.contains("larger"));
}

#[test]
fn a_second_language_line_points_at_both_lines() {
    let text = "language blocks\n\ntarget_kinds = [x]\n\nlanguage blocks\n";
    let errors = parse("twice.themis", text).unwrap_err();
    let first = errors.first().unwrap();
    assert_eq!(first.location.as_ref().map(|at| at.line), Some(5));
}

#[test]
fn a_date_past_year_9999_cannot_be_printed() {
    let mut policy = parse("g.themis", GRANT).unwrap().policy;
    policy.grants[0].valid_until = Some(u64::MAX);
    let error = print(&policy, Language::Blocks).unwrap_err();
    assert!(matches!(error, PrintError::Unrepresentable { .. }));
}

#[test]
fn text_with_quotes_and_line_breaks_prints_back_as_the_same_policy() {
    let mut policy = parse("g.themis", GRANT).unwrap().policy;
    policy.catalog.permissions[0].label = Some("say \"hi\"\nthen } leave".to_string());
    match print(&policy, Language::Blocks) {
        Ok(text) => {
            let back = parse("back.themis", &text).unwrap().policy;
            assert!(policy.equivalent(&back));
        }
        Err(error) => assert!(matches!(error, PrintError::Unrepresentable { .. })),
    }
}

#[test]
fn a_name_the_lexer_would_split_cannot_be_printed() {
    let mut policy = parse("g.themis", GRANT).unwrap().policy;
    policy.roles[0].role = "two words".to_string();
    let error = print(&policy, Language::Blocks).unwrap_err();
    assert!(matches!(error, PrintError::Unrepresentable { .. }));
}

#[test]
fn a_comment_whose_element_is_gone_cannot_be_printed() {
    let text = format!("// lost\n{GRANT}");
    let mut policy = parse("g.themis", &text).unwrap().policy;
    policy.notes[0].anchor.element = "grant:nowhere".to_string();
    let error = print(&policy, Language::Blocks).unwrap_err();
    assert!(matches!(error, PrintError::Unrepresentable { .. }));
}

#[test]
fn a_comment_holding_a_line_break_cannot_be_printed() {
    let text = format!("// one\n{GRANT}");
    let mut policy = parse("g.themis", &text).unwrap().policy;
    policy.notes[0].text = "one\ntwo".to_string();
    let error = print(&policy, Language::Blocks).unwrap_err();
    assert!(matches!(error, PrintError::Unrepresentable { .. }));
}

#[test]
fn a_comment_on_a_missing_max_depth_cannot_be_printed() {
    let mut policy = parse("g.themis", &format!("// c\n{GRANT}")).unwrap().policy;
    policy.notes[0].anchor.element = "max_depth".to_string();
    let error = print(&policy, Language::Blocks).unwrap_err();
    assert!(matches!(error, PrintError::Unrepresentable { .. }));
}

#[test]
fn an_empty_relation_list_prints_back_in_every_syntax() {
    let mut policy = parse("g.themis", GRANT).unwrap().policy;
    policy.relations = Some(Vec::new());
    for language in [Language::Blocks, Language::Rules, Language::Actors] {
        let text = print(&policy, language).unwrap();
        let back = parse("back.themis", &text).unwrap().policy;
        assert_eq!(back.relations, Some(Vec::new()), "{language:?}");
    }
}

#[test]
fn a_byte_order_mark_at_the_start_is_ignored() {
    let text = format!("\u{feff}{GRANT}");
    assert!(parse("bom.themis", &text).is_ok());
}

#[test]
fn a_date_with_an_offset_is_refused_as_not_utc() {
    let text = format!("{GRANT}\n").replace(
        "  target = project\n",
        "  target = project\n  valid_until = 2026-12-31T23:59:59-03:00\n",
    );
    let errors = parse("offset.themis", &text).unwrap_err();
    assert!(errors.first().unwrap().message.contains("UTC"));
}

#[test]
fn a_project_clash_report_stays_capped() {
    let mut text = String::from(HEADER);
    for at in 0..1_000 {
        text.push_str(&format!("\nrole r{at} {{\n}}\n"));
    }
    let mut project = Project::new();
    project.add_source("a.themis", &text).unwrap();
    project.add_source("b.themis", &text).unwrap();
    let errors = project.build().unwrap_err();
    assert!(errors.len() <= 102);
}
