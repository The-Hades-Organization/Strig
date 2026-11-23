//! The three syntaxes against each other: one corpus of scenarios written in each, ids and
//! comments included.

mod corpus;
mod errors;
mod hostile;
mod project;

use themis::dsl::Language;

pub const LANGUAGES: [Language; 3] = [Language::Blocks, Language::Rules, Language::Actors];

pub const SCENARIOS: [&str; 6] = ["roles", "conditions", "validity", "relations", "governance", "members"];

pub fn source(scenario: &str, language: Language) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/dsl/corpus")
        .join(format!("{scenario}.{language}.themis"));
    std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}
