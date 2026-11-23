//! A scratch test that writes the other two syntaxes of each scenario.
use std::path::Path;
use themis::dsl::{Language, convert, parse};

#[test]
fn generate() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/dsl/corpus");
    for name in ["roles", "conditions", "validity", "relations", "governance", "members"] {
        let text = std::fs::read_to_string(dir.join(format!("{name}.blocks.themis"))).unwrap();
        if let Err(e) = parse(name, &text) {
            println!("PARSE {name}: {e}");
            continue;
        }
        for (lang, ext) in [(Language::Rules, "rules"), (Language::Actors, "actors")] {
            match convert(&text, lang) {
                Ok(out) => std::fs::write(dir.join(format!("{name}.{ext}.themis")), out).unwrap(),
                Err(e) => println!("CONVERT {name} {ext}: {e}"),
            }
        }
    }
}
