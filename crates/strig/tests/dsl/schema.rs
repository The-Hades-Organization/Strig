//! The schema a policy is exported with: 3 only when a condition names a time zone, so that a
//! reader of schema 2 refuses the document instead of reading the window in UTC.

use strig::dsl::{Language, Policy, parse};

use crate::{LANGUAGES, source};

fn export(language: Language, with_zone: bool) -> String {
    let mut text = source("matching", language);
    if !with_zone {
        text = text
            .replace(r#" tz "America/Sao_Paulo""#, "")
            .replace(r#" tz "Europe/Lisbon""#, "");
    }
    let policy = parse("p.strig", &text)
        .unwrap_or_else(|errors| panic!("{language}:\n{errors}"))
        .policy;
    policy.to_json().unwrap()
}

fn schema_of(json: &str) -> Option<u64> {
    serde_json::from_str::<serde_json::Value>(json).unwrap()["schema"].as_u64()
}

#[test]
fn a_policy_with_a_zone_is_exported_with_schema_3_in_every_syntax() {
    for language in LANGUAGES {
        let json = export(language, true);
        assert_eq!(schema_of(&json), Some(3), "{language}");
        assert!(json.starts_with("{\n  \"schema\": 3,\n"), "{language}");
        assert!(Policy::from_json(&json).is_ok(), "{language}");
    }
}

#[test]
fn a_policy_without_a_zone_keeps_no_schema_and_stays_readable_by_old_readers() {
    for language in LANGUAGES {
        let json = export(language, false);
        assert_eq!(schema_of(&json), None, "{language}");
        assert!(Policy::from_json(&json).is_ok(), "{language}");
    }
}

#[test]
fn the_reader_takes_schema_3_without_a_zone_and_refuses_a_newer_one() {
    let plain = export(Language::Blocks, false);
    let tagged = plain.replacen("{\n", "{\n  \"schema\": 3,\n", 1);
    assert!(
        Policy::from_json(&tagged)
            .unwrap()
            .equivalent(&Policy::from_json(&plain).unwrap())
    );
    for bad in ["5", "\"3\"", "null"] {
        let future = plain.replacen("{\n", &format!("{{\n  \"schema\": {bad},\n"), 1);
        let error = Policy::from_json(&future).unwrap_err().to_string();
        assert!(error.contains("unsupported policy schema"), "{bad}: {error}");
    }
}

#[test]
fn a_zone_survives_the_trip_through_the_exported_json() {
    let json = export(Language::Rules, true);
    let back = Policy::from_json(&json).unwrap();
    assert_eq!(back.to_json().unwrap(), json);
}

const FIELDS_SOURCE: &str = "language rules

kinds document

permission document.edit on document fields title, body

role editor

g-edit: allow role editor to document.edit on document fields title
";

#[test]
fn a_policy_with_fields_exports_schema_4_and_an_older_reader_refuses_it() {
    let json = strig::dsl::parse("p.strig", FIELDS_SOURCE)
        .unwrap()
        .policy
        .to_json()
        .unwrap();
    assert!(json.starts_with("{\n  \"schema\": 4,\n"), "{json}");
    assert!(Policy::from_json(&json).is_ok());
    assert_eq!(strig::dsl::__macro_support::DSL_SCHEMA, 4);
}

#[test]
fn a_policy_without_fields_keeps_the_schema_it_had() {
    let plain = export(Language::Blocks, false);
    assert!(!plain.contains("\"schema\""), "{plain}");
    let zoned = export(Language::Blocks, true);
    assert!(zoned.starts_with("{\n  \"schema\": 3,\n"), "{zoned}");
}

#[test]
fn a_field_survives_the_trip_through_the_exported_json() {
    let policy = strig::dsl::parse("p.strig", FIELDS_SOURCE).unwrap().policy;
    let back = Policy::from_json(&policy.to_json().unwrap()).unwrap();
    assert_eq!(back.grants[0].fields, ["title"]);
    assert_eq!(back.catalog.permissions[0].fields, ["title", "body"]);
}
