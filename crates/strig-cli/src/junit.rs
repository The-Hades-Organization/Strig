//! The JUnit XML report, one suite per test file.

use std::fmt::Write;

use strig::dsl::testing::{Outcome, Report};

/// The report as JUnit XML: a suite per file, a `testcase` per case, `failure` for a case that
/// differs and `error` for one that could not be judged.
pub fn junit_xml(report: &Report) -> String {
    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuites>\n");
    let mut files: Vec<&str> = Vec::new();
    for result in &report.results {
        if !files.contains(&result.file.as_str()) {
            files.push(&result.file);
        }
    }
    for file in files {
        let cases: Vec<_> = report.results.iter().filter(|r| r.file == file).collect();
        let count = |o: Outcome| cases.iter().filter(|r| r.outcome == o).count();
        writeln!(
            xml,
            "  <testsuite name=\"{}\" tests=\"{}\" failures=\"{}\" errors=\"{}\">",
            escape(file),
            cases.len(),
            count(Outcome::Failed),
            count(Outcome::Errored)
        )
        .ok();
        for result in cases {
            let open = format!(
                "    <testcase classname=\"{}\" name=\"{}\"",
                escape(file),
                escape(&result.name)
            );
            match result.outcome {
                Outcome::Passed => writeln!(xml, "{open}/>").ok(),
                Outcome::Errored => writeln!(
                    xml,
                    "{open}>\n      <error message=\"{}\"/>\n    </testcase>",
                    escape(&result.actual)
                )
                .ok(),
                _ => {
                    let message = format!("expected {}, obtained {}", result.expected, result.actual);
                    writeln!(
                        xml,
                        "{open}>\n      <failure message=\"{}\">{}</failure>\n    </testcase>",
                        escape(&message),
                        escape(&result.trace.join("\n"))
                    )
                    .ok()
                }
            };
        }
        xml.push_str("  </testsuite>\n");
    }
    xml.push_str("</testsuites>\n");
    xml
}

/// Escapes text for XML and drops the characters XML 1.0 cannot carry at all.
fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            '\t' | '\n' | '\r' => escaped.push(c),
            c if (c as u32) < 0x20 || c == '\u{fffe}' || c == '\u{ffff}' => {}
            c => escaped.push(c),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;
    use strig::dsl::testing::CaseResult;

    fn result(name: &str, outcome: Outcome) -> CaseResult {
        serde_json::from_value(serde_json::json!({
            "file": "a.strig-test.json", "name": name, "outcome": outcome,
            "expected": "deny", "actual": "allow <x>", "trace": ["grant `g`: candidate"],
        }))
        .unwrap()
    }

    #[test]
    fn escapes_and_counts() {
        let report: Report = serde_json::from_value(serde_json::json!({"results": [
            result("a & b", Outcome::Passed), result("bad", Outcome::Failed), result("oops", Outcome::Errored)
        ]}))
        .unwrap();
        let xml = junit_xml(&report);
        assert!(xml.contains("tests=\"3\" failures=\"1\" errors=\"1\""), "{xml}");
        assert!(xml.contains("name=\"a &amp; b\"/>"), "{xml}");
        assert!(xml.contains("expected deny, obtained allow &lt;x&gt;"), "{xml}");
        assert!(xml.contains("<error message=\"allow &lt;x&gt;\"/>"), "{xml}");
    }

    #[test]
    fn control_characters_are_dropped() {
        assert_eq!(escape("a\u{0}b\u{1b}c"), "abc");
    }
}
