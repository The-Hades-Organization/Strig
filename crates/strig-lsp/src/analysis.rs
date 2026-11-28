//! What the server knows about a directory of sources: diagnostics, and the built policy the
//! other features answer from.

use std::collections::BTreeMap;
use std::path::Path;

use lsp_types::{Diagnostic, DiagnosticRelatedInformation, DiagnosticSeverity, Location as LspLocation, Range};
use strig::dsl::testing::{TestError, TestFile};
use strig::dsl::{self, Built, Project};

use crate::text::{range_of, uri_of};

/// The sources of one project directory: the policy files and the test files, as `(path, text)`.
#[derive(Debug, Clone, Default)]
pub struct Sources {
    pub policies: Vec<(String, String)>,
    pub tests: Vec<(String, String)>,
}

impl Sources {
    pub fn text_of(&self, file: &str) -> Option<&str> {
        self.policies
            .iter()
            .chain(&self.tests)
            .find(|(name, _)| name == file)
            .map(|(_, text)| text.as_str())
    }
}

/// The result of reading a directory.
#[derive(Debug, Default)]
pub struct Analysis {
    /// Diagnostics by file, with an entry (possibly empty) for every file read.
    pub diagnostics: BTreeMap<String, Vec<Diagnostic>>,
    /// The policy the other features answer from. When a source does not parse it is built from
    /// the sources that do, so completion keeps working while a line is half typed; it is `None`
    /// when even that does not validate.
    pub built: Option<Built>,
}

const SOURCE: &str = "strig";

fn error(range: Range, message: String) -> Diagnostic {
    Diagnostic {
        range,
        severity: Some(DiagnosticSeverity::ERROR),
        source: Some(SOURCE.to_string()),
        message,
        ..Diagnostic::default()
    }
}

fn describe(found: &dsl::Diagnostic) -> String {
    match &found.hint {
        Some(hint) => format!("{}\nhint: {hint}", found.message),
        None => found.message.clone(),
    }
}

/// Reads and validates everything in `sources`.
pub fn analyze(sources: &Sources) -> Analysis {
    let mut analysis = Analysis::default();
    for (name, _) in sources.policies.iter().chain(&sources.tests) {
        analysis.diagnostics.insert(name.clone(), Vec::new());
    }

    let mut project = Project::new();
    let mut syntax_broken = false;
    for (name, text) in &sources.policies {
        if let Err(found) = project.add_source(name, text) {
            syntax_broken = true;
            for item in found {
                place(&mut analysis, sources, name, &item);
            }
        }
    }
    if syntax_broken {
        if !project.is_empty() {
            analysis.built = project.build().ok();
        }
    } else if !project.is_empty() {
        match project.build() {
            Ok(built) => analysis.built = Some(built),
            Err(found) => {
                let first = sources
                    .policies
                    .first()
                    .map(|(name, _)| name.as_str())
                    .unwrap_or_default();
                for item in found {
                    place(&mut analysis, sources, first, &item);
                }
            }
        }
    }

    for (name, text) in &sources.tests {
        if let Err(TestError::Invalid { message, .. }) = TestFile::parse(name, text) {
            let (line, column) = json_position(&message).unwrap_or((1, 1));
            let range = range_of(text, line, column, 1);
            if let Some(list) = analysis.diagnostics.get_mut(name) {
                list.push(error(range, message));
            }
        }
    }
    analysis
}

/// Files a diagnostic under the file it points at (or `fallback` when it has no position).
fn place(analysis: &mut Analysis, sources: &Sources, fallback: &str, found: &dsl::Diagnostic) {
    let (file, line, column, len) = match &found.location {
        Some(at) => (at.file.to_string(), at.line, at.column, at.len),
        None => (fallback.to_string(), 1, 1, 1),
    };
    let text = sources.text_of(&file).unwrap_or("");
    let mut diagnostic = error(range_of(text, line, column, len), describe(found));
    if let Some(other) = &found.related
        && let Some(uri) = uri_of(Path::new(other.file.as_ref()))
    {
        let other_text = sources.text_of(&other.file).unwrap_or("");
        diagnostic.related_information = Some(vec![DiagnosticRelatedInformation {
            location: LspLocation {
                uri,
                range: range_of(other_text, other.line, other.column, other.len),
            },
            message: "also declared here".to_string(),
        }]);
    }
    analysis.diagnostics.entry(file).or_default().push(diagnostic);
}

/// `line L column C` out of a `serde_json` message.
fn json_position(message: &str) -> Option<(u32, u32)> {
    let after = message.rsplit_once(" at line ")?.1;
    let (line, rest) = after.split_once(" column ")?;
    let column: String = rest.chars().take_while(char::is_ascii_digit).collect();
    Some((line.trim().parse().ok()?, column.parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KINDS: &str = "language blocks\n\ntarget_kinds = [org]\n";
    const READ: &str = "language blocks\n\npermission org.read {\n  targets = [org]\n}\n";

    fn sources(policies: &[(&str, &str)]) -> Sources {
        Sources {
            policies: policies.iter().map(|(n, t)| (n.to_string(), t.to_string())).collect(),
            tests: Vec::new(),
        }
    }

    #[test]
    fn a_valid_project_builds_with_no_diagnostics() {
        let analysis = analyze(&sources(&[("/p/kinds.strig", KINDS), ("/p/read.strig", READ)]));
        assert!(analysis.built.is_some());
        assert!(analysis.diagnostics.values().all(Vec::is_empty));
    }

    #[test]
    fn a_syntax_error_points_at_its_file_and_hint() {
        let analysis = analyze(&sources(&[("/p/a.strig", "language blocks\n\npermission {\n")]));
        let list = &analysis.diagnostics["/p/a.strig"];
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].range.start.line, 2);
        assert!(analysis.built.is_none());
    }

    #[test]
    fn a_missing_kind_is_reported_across_files() {
        let analysis = analyze(&sources(&[("/p/read.strig", READ)]));
        let list = &analysis.diagnostics["/p/read.strig"];
        assert!(!list.is_empty(), "the permission targets an undeclared kind");
    }

    #[test]
    fn a_clash_between_files_carries_the_other_side() {
        let analysis = analyze(&sources(&[
            ("/p/kinds.strig", KINDS),
            ("/p/a.strig", READ),
            ("/p/b.strig", READ),
        ]));
        let clash = analysis
            .diagnostics
            .values()
            .flatten()
            .find(|d| d.related_information.is_some());
        assert!(clash.is_some());
    }

    #[test]
    fn a_broken_test_file_is_reported_at_its_position() {
        let mut set = sources(&[("/p/kinds.strig", KINDS)]);
        set.tests
            .push(("/p/a.strig-test.json".to_string(), "{\n  \"cases\": [,]\n}".to_string()));
        let analysis = analyze(&set);
        let list = &analysis.diagnostics["/p/a.strig-test.json"];
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].range.start.line, 1);
    }
}
