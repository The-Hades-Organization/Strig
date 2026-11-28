//! The answers of the server, each a pure function of the source text and the built policy.

use std::path::Path;

use lsp_types::{
    CodeAction, CodeActionKind, CompletionItem, CompletionItemKind, Documentation, Hover, HoverContents,
    Location as LspLocation, MarkupContent, MarkupKind, Position, TextEdit, Uri, WorkspaceEdit,
};
use strig::dsl::{self, Built, Language, ids};

use crate::text::{before_cursor, prefix_at, range_of, uri_of, whole, word_at};

/// Operators a condition accepts between two operands, and the words that open or join one.
pub const OPERATORS: [&str; 19] = [
    "==",
    "!=",
    "<",
    ">",
    "<=",
    ">=",
    "in",
    "starts_with",
    "ends_with",
    "contains",
    "any_in",
    "all_in",
    "ip_in",
    "time_between",
    "weekday_in",
    "and",
    "or",
    "not",
    "tz",
];

/// What a line asks for, from the words before the cursor.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Wanted {
    permissions: bool,
    roles: bool,
    kinds: bool,
    operators: bool,
    subjects: bool,
}

impl Wanted {
    fn any(self) -> bool {
        self.permissions || self.roles || self.kinds || self.operators || self.subjects
    }
}

fn wanted(head: &str) -> Wanted {
    let line = head.trim_start();
    let has = |words: &[&str]| words.iter().any(|w| line.contains(w));
    Wanted {
        permissions: has(&[
            "implied_by",
            "implied by",
            "depends_on",
            "permission =",
            "permission\"",
            " to ",
            "requires",
        ]) || line.starts_with("permission ") && line.matches(' ').count() > 1,
        roles: has(&["inherits", "role ", "subject = role"]),
        kinds: has(&[
            "targets", "target =", "target\"", " on ", "kinds", "broad", "scope", " in ",
        ]),
        operators: has(&["when", " and ", " or ", "subject.", "resource.", "env."]),
        subjects: has(&["\"subject\"", "subject ="]),
    }
}

fn item(label: &str, kind: CompletionItemKind, detail: &str, docs: Option<String>) -> CompletionItem {
    CompletionItem {
        label: label.to_string(),
        kind: Some(kind),
        detail: Some(detail.to_string()),
        documentation: docs.map(|value| {
            Documentation::MarkupContent(MarkupContent {
                kind: MarkupKind::Markdown,
                value,
            })
        }),
        ..CompletionItem::default()
    }
}

/// Completion at `at`: permission ids, kinds, roles and condition operators of the project,
/// narrowed by what the line asks for.
pub fn complete(text: &str, at: Position, built: Option<&Built>) -> Vec<CompletionItem> {
    let head = before_cursor(text, at);
    let prefix = prefix_at(text, at);
    let ask = wanted(&head);
    let all = !ask.any();
    let mut items = Vec::new();
    if let Some(built) = built {
        let policy = &built.policy;
        if ask.permissions || all {
            for def in &policy.catalog.permissions {
                items.push(item(
                    &def.key,
                    CompletionItemKind::CONSTANT,
                    "permission",
                    Some(permission_markdown(def)),
                ));
            }
        }
        if ask.kinds || all {
            for kind in policy.catalog.target_kinds.iter().chain(&policy.catalog.broad_targets) {
                items.push(item(kind, CompletionItemKind::CLASS, "kind", None));
            }
        }
        if ask.roles || all {
            for role in &policy.roles {
                items.push(item(&role.role, CompletionItemKind::ENUM_MEMBER, "role", None));
            }
        }
        if ask.subjects {
            for subject in &policy.subjects {
                let Some(id) = &subject.id else { continue };
                let label = format!("{}:{id}", subject.kind);
                items.push(item(&label, CompletionItemKind::VARIABLE, "subject", None));
            }
        }
    }
    if ask.operators || all {
        for op in OPERATORS {
            items.push(item(op, CompletionItemKind::OPERATOR, "condition operator", None));
        }
    }
    items.retain(|i| i.label.starts_with(&prefix));
    items
}

fn permission_markdown(def: &strig::PermissionDef) -> String {
    let list = |items: &[String]| items.iter().map(|i| format!("`{i}`")).collect::<Vec<_>>().join(", ");
    let mut out = format!("**{}**", def.key);
    if let Some(label) = &def.label {
        out.push_str(&format!(" — {label}"));
    }
    if let Some(description) = &def.description {
        out.push_str(&format!("\n\n{description}"));
    }
    out.push_str("\n\n");
    out.push_str(&format!("- targets: {}\n", list(&def.targets)));
    if !def.implied_by.is_empty() {
        out.push_str(&format!("- implied by: {}\n", list(&def.implied_by)));
    }
    if !def.depends_on.is_empty() {
        out.push_str(&format!("- depends on: {}\n", list(&def.depends_on)));
    }
    if !def.fields.is_empty() {
        out.push_str(&format!("- fields: {}\n", list(&def.fields)));
    }
    let flags: Vec<&str> = [
        (def.non_delegable, "non-delegable"),
        (def.management_only, "management only"),
        (def.override_only, "override only"),
    ]
    .into_iter()
    .filter_map(|(on, name)| on.then_some(name))
    .collect();
    if !flags.is_empty() {
        out.push_str(&format!("- flags: {}\n", flags.join(", ")));
    }
    for (locale, label) in &def.labels {
        out.push_str(&format!("- label `{locale}`: {label}\n"));
    }
    for (locale, description) in &def.descriptions {
        out.push_str(&format!("- description `{locale}`: {description}\n"));
    }
    out
}

/// The markdown that explains the name under the cursor, when the project defines it.
pub fn hover(text: &str, at: Position, built: Option<&Built>) -> Option<Hover> {
    let (word, range) = word_at(text, at)?;
    let policy = &built?.policy;
    let value = if let Some(def) = policy.catalog.permissions.iter().find(|d| d.key == word) {
        permission_markdown(def)
    } else if let Some(role) = policy.roles.iter().find(|r| r.role == word) {
        let inherits = if role.inherits.is_empty() {
            "nothing".to_string()
        } else {
            role.inherits
                .iter()
                .map(|r| format!("`{r}`"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        format!("**role {}**\n\ninherits {inherits}", role.role)
    } else if policy.catalog.target_kinds.contains(&word) {
        format!("**kind {word}**")
    } else if policy.catalog.broad_targets.contains(&word) {
        format!("**broad target {word}**")
    } else {
        return None;
    };
    Some(Hover {
        contents: HoverContents::Markup(MarkupContent {
            kind: MarkupKind::Markdown,
            value,
        }),
        range: Some(range),
    })
}

/// Where the name under the cursor is declared.
pub fn definition(
    text: &str,
    at: Position,
    built: Option<&Built>,
    read: impl Fn(&str) -> Option<String>,
) -> Option<LspLocation> {
    let (word, _) = word_at(text, at)?;
    let built = built?;
    let candidates = [
        ids::permission(&word),
        ids::role(&word),
        ids::grant(&word),
        word.split_once(':')
            .map(|(k, i)| ids::subject(k, i))
            .unwrap_or_default(),
    ];
    let origin = candidates
        .iter()
        .filter(|id| !id.is_empty())
        .find_map(|id| built.origins.exact(id))?;
    let uri = uri_of(Path::new(origin.file.as_ref()))?;
    let declared = read(&origin.file).unwrap_or_default();
    Some(LspLocation {
        uri,
        range: range_of(&declared, origin.line, origin.column, origin.len),
    })
}

/// The whole document rewritten in the canonical layout of its syntax; `None` when it does not
/// compile (nothing is touched then).
pub fn format(file: &str, text: &str) -> Option<Vec<TextEdit>> {
    let formatted = dsl::format(file, text).ok()?;
    if formatted == text {
        return Some(Vec::new());
    }
    Some(vec![TextEdit {
        range: whole(text),
        new_text: formatted,
    }])
}

/// One code action per other syntax, each replacing the document with its conversion.
pub fn conversions(uri: &Uri, file: &str, text: &str) -> Vec<CodeAction> {
    let Ok(parsed) = dsl::parse(file, text) else {
        return Vec::new();
    };
    let mut actions = Vec::new();
    for target in [Language::Blocks, Language::Rules, Language::Actors] {
        if target == parsed.language {
            continue;
        }
        let Ok(converted) = dsl::convert(text, target) else {
            continue;
        };
        let edit = TextEdit {
            range: whole(text),
            new_text: converted,
        };
        actions.push(CodeAction {
            title: format!("Convert to {} syntax", target.name()),
            kind: Some(CodeActionKind::new("refactor.rewrite.strig-convert")),
            edit: Some(WorkspaceEdit {
                changes: Some([(uri.clone(), vec![edit])].into_iter().collect()),
                ..WorkspaceEdit::default()
            }),
            ..CodeAction::default()
        });
    }
    actions
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::{Sources, analyze};

    const POLICY: &str = "language blocks\n\ntarget_kinds = [org]\n\npermission org.read {\n  label = \"Read\"\n  targets = [org]\n}\n\npermission org.edit {\n  targets = [org]\n  depends_on = [org.read]\n}\n\nrole editor {\n}\n";

    fn built() -> Built {
        let sources = Sources {
            policies: vec![("/p/a.strig".to_string(), POLICY.to_string())],
            tests: Vec::new(),
        };
        analyze(&sources).built.expect("valid")
    }

    #[test]
    fn completes_permissions_after_depends_on() {
        let text = "  depends_on = [org.";
        let items = complete(text, Position::new(0, 20), Some(&built()));
        let labels: Vec<&str> = items.iter().map(|i| i.label.as_str()).collect();
        assert_eq!(
            labels,
            ["org.read", "org.edit"]
                .iter()
                .copied()
                .filter(|l| l.starts_with("org."))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn completes_roles_after_inherits() {
        let items = complete("role manager inherits ", Position::new(0, 22), Some(&built()));
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].label, "editor");
    }

    #[test]
    fn completes_operators_in_a_condition() {
        let items = complete("when = subject.tags any", Position::new(0, 23), None);
        assert!(items.iter().any(|i| i.label == "any_in"));
    }

    #[test]
    fn hover_describes_the_permission() {
        let found = hover("depends_on = [org.read]", Position::new(0, 18), Some(&built())).expect("hover");
        let HoverContents::Markup(markup) = found.contents else {
            panic!("markup expected");
        };
        assert!(markup.value.contains("**org.read** — Read"));
        assert!(markup.value.contains("targets: `org`"));
    }

    #[test]
    fn definition_jumps_to_the_declaration() {
        let found = definition("depends_on = [org.read]", Position::new(0, 18), Some(&built()), |_| {
            Some(POLICY.to_string())
        })
        .expect("definition");
        assert_eq!(found.uri.as_str(), "file:///p/a.strig");
        assert_eq!(found.range.start.line, 4);
    }

    #[test]
    fn format_returns_one_edit_for_a_source_off_layout() {
        let messy = "language blocks\ntarget_kinds=[org]\n";
        let edits = format("a.strig", messy).expect("formats");
        assert_eq!(edits.len(), 1);
        assert_eq!(edits[0].new_text, "language blocks\n\ntarget_kinds = [org]\n");
        assert!(format("a.strig", &edits[0].new_text).expect("again").is_empty());
    }

    #[test]
    fn format_leaves_a_broken_source_alone() {
        assert!(format("a.strig", "language blocks\npermission {").is_none());
    }

    #[test]
    fn conversions_offer_the_two_other_syntaxes() {
        let uri = uri_of(Path::new("/p/a.strig")).unwrap();
        let actions = conversions(&uri, "/p/a.strig", POLICY);
        let titles: Vec<&str> = actions.iter().map(|a| a.title.as_str()).collect();
        assert_eq!(titles, ["Convert to rules syntax", "Convert to actors syntax"]);
    }
}
