//! The report for people.

use std::fmt::Write;

use strig::dsl::testing::{CaseResult, Outcome, Report};

/// One line per case grouped by file, the diff under each case that did not pass, and a total.
pub fn human(report: &Report) -> String {
    let mut text = String::new();
    let mut file: Option<&str> = None;
    for result in &report.results {
        if file != Some(result.file.as_str()) {
            file = Some(&result.file);
            writeln!(text, "{}", result.file).ok();
        }
        case(&mut text, result);
    }
    writeln!(
        text,
        "\n{} passed, {} failed, {} errors",
        report.count(Outcome::Passed),
        report.count(Outcome::Failed),
        report.count(Outcome::Errored)
    )
    .ok();
    text
}

fn case(text: &mut String, result: &CaseResult) {
    let mark = match result.outcome {
        Outcome::Passed => "PASS",
        Outcome::Failed => "FAIL",
        Outcome::Errored => "ERROR",
        _ => "?",
    };
    writeln!(text, "  {mark} {}", result.name).ok();
    match result.outcome {
        Outcome::Passed => {}
        Outcome::Errored => {
            writeln!(text, "      {}", result.actual).ok();
        }
        _ => {
            writeln!(text, "      expected: {}", result.expected).ok();
            writeln!(text, "      obtained: {}", result.actual).ok();
            for line in &result.trace {
                writeln!(text, "      {line}").ok();
            }
        }
    }
}
