//! Comments inside an element, and the printer's promise that what it writes reads back as the
//! very same JSON.

use crate::{LANGUAGES, canonical};
use strig::dsl::{Language, Placement, convert, parse, print};

const BLOCKS: &str = "language blocks

target_kinds = [doc]

permission doc.read {  // header
  targets = [doc]  // on the targets
  label = \"Read\"  // on the label
}
";

#[test]
fn a_header_and_two_fields_with_comments_convert_to_the_same_json_everywhere() {
    let original = parse("a", BLOCKS).unwrap();
    let notes: Vec<_> = original
        .policy
        .notes
        .iter()
        .map(|n| (n.text.as_str(), n.anchor.placement))
        .collect();
    assert_eq!(
        notes,
        [
            ("header", Placement::Inline),
            ("on the targets", Placement::Inside),
            ("on the label", Placement::Inside)
        ]
    );
    for to in LANGUAGES {
        let text = convert(BLOCKS, to).unwrap_or_else(|error| panic!("to {to}: {error}"));
        let again = parse("b", &text).unwrap_or_else(|errors| panic!("{errors}\n{text}"));
        assert_eq!(
            canonical(&original.policy),
            canonical(&again.policy),
            "to {to}:\n{text}"
        );
        for back in LANGUAGES {
            let round = convert(&text, back).unwrap_or_else(|error| panic!("{to} to {back}: {error}"));
            let last = parse("c", &round).unwrap();
            assert_eq!(canonical(&original.policy), canonical(&last.policy), "{to} to {back}");
        }
    }
}

#[test]
fn two_comments_on_one_subject_in_rules_read_back() {
    let text = "language rules

kinds doc

user:ana has principal p  // one
user:ana has attr dept = \"it\"  // two
";
    let parsed = parse("a", text).unwrap();
    let placements: Vec<_> = parsed.policy.notes.iter().map(|n| n.anchor.placement).collect();
    assert_eq!(placements, [Placement::Inline, Placement::Inside]);
    let printed = print(&parsed.policy, Language::Rules).unwrap();
    let again = parse("b", &printed).unwrap();
    assert_eq!(canonical(&parsed.policy), canonical(&again.policy));
    for to in [Language::Blocks, Language::Actors] {
        let converted = convert(text, to).unwrap_or_else(|error| panic!("to {to}: {error}"));
        let back = parse("c", &converted).unwrap();
        assert_eq!(canonical(&parsed.policy), canonical(&back.policy), "to {to}");
    }
}

#[test]
fn the_printer_never_hands_out_text_with_other_json() {
    // The comments sit on fields the printer writes in another order than the source has.
    let text = "language blocks

target_kinds = [doc]

permission doc.read {
  // on needs
  depends_on = [doc.view]
  // on label
  label = \"Read\"
  targets = [doc]
}

permission doc.view {
  targets = [doc]
}
";
    let parsed = parse("a", text).unwrap();
    for to in LANGUAGES {
        if let Ok(printed) = print(&parsed.policy, to) {
            let again = parse("b", &printed).unwrap();
            assert_eq!(canonical(&parsed.policy), canonical(&again.policy), "to {to}");
        }
    }
}

#[test]
fn a_policy_out_of_canonical_order_is_refused_not_reordered() {
    let mut policy = parse("a", "language rules\n\nkinds a, b\n").unwrap().policy;
    policy.catalog.target_kinds.reverse();
    for to in LANGUAGES {
        assert!(print(&policy, to).is_err(), "{to}");
        assert!(print(&policy.clone().canonical(), to).is_ok(), "{to}");
    }
}
