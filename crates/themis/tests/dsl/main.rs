//! The three syntaxes against each other: one corpus of scenarios written in each, ids and
//! comments included.

mod corpus;
mod errors;
mod format;
mod handwritten;
mod hostile;
mod notes;
mod project;

use themis::dsl::Language;

pub const LANGUAGES: [Language; 3] = [Language::Blocks, Language::Rules, Language::Actors];

/// The scenarios. The Rules and Actors files of the first six were written by `convert` from their
/// Blocks file and then checked; the last three were written by hand in all three syntaxes.
pub const SCENARIOS: [&str; 9] = [
    "roles",
    "conditions",
    "validity",
    "relations",
    "governance",
    "members",
    "overrides",
    "late",
    "matching",
];

pub fn source(scenario: &str, language: Language) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/dsl/corpus")
        .join(format!("{scenario}.{language}.themis"));
    std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

/// The canonical JSON without where each note was written: the origin is not part of the policy.
pub fn canonical(policy: &themis::dsl::Policy) -> serde_json::Value {
    let mut json: serde_json::Value = serde_json::from_str(&policy.to_json().unwrap()).unwrap();
    if let Some(notes) = json.get_mut("notes").and_then(|notes| notes.as_array_mut()) {
        for note in notes {
            if let Some(note) = note.as_object_mut() {
                note.remove("origin");
            }
        }
    }
    json
}
