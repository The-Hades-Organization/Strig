//! `strig diff <before> <after>`.

use std::fmt::Write as _;
use std::io::Write;
use std::path::Path;

use strig::QueryLimits;
use strig::dsl::analysis::{self, ChangeKind, DiffFixture, DiffOptions, DiffSide, PolicyDiff, Responsible};

use crate::analysis_support::{load, read_limited};
use crate::{EXIT_FAILED, EXIT_OK, EXIT_USAGE};

#[derive(Clone, Copy, PartialEq, Eq)]
enum FailOn {
    Any,
    Allow,
}

pub(crate) fn run(args: &[String], out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    let mut paths: Vec<&str> = Vec::new();
    let mut fixture_path: Option<&str> = None;
    let mut json = false;
    let mut fail_on = FailOn::Any;
    let mut now: Option<u64> = None;
    let mut limits = QueryLimits::default();
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--json" => json = true,
            "--fixture" => match rest.next() {
                Some(path) => fixture_path = Some(path),
                None => return usage(err, "`--fixture` needs a file"),
            },
            "--fail-on" => match rest.next().map(String::as_str) {
                Some("any") => fail_on = FailOn::Any,
                Some("allow") => fail_on = FailOn::Allow,
                _ => return usage(err, "`--fail-on` is `allow` or `any`"),
            },
            "--now" => match rest.next().and_then(|v| v.parse().ok()) {
                Some(value) => now = Some(value),
                None => return usage(err, "`--now` needs milliseconds since the Unix epoch"),
            },
            "--max-subjects" => match rest.next().and_then(|v| v.parse().ok()) {
                Some(value) => limits = limits.with_max_parties(value),
                None => return usage(err, "`--max-subjects` needs a number"),
            },
            "--max-decisions" => match rest.next().and_then(|v| v.parse().ok()) {
                Some(value) => limits = limits.with_max_decisions(value),
                None => return usage(err, "`--max-decisions` needs a number"),
            },
            flag if flag.starts_with('-') => return usage(err, &format!("unknown option `{flag}`")),
            path => paths.push(path),
        }
    }
    let [before_path, after_path] = paths.as_slice() else {
        return usage(err, "`diff` takes the policy before and the policy after");
    };

    let mut fixture = match fixture_path {
        None => DiffFixture::default(),
        Some(path) => match read_limited(Path::new(path)).and_then(|t| DiffFixture::parse(path, &t).map_err(|e| e.to_string()))
        {
            Ok(fixture) => fixture,
            Err(message) => return usage(err, &message),
        },
    };
    if let Some(now) = now {
        fixture = with_now(fixture, now);
    }
    let (before, after) = match (load(before_path), load(after_path)) {
        (Ok(before), Ok(after)) => (before, after),
        (Err(message), _) | (_, Err(message)) => return usage(err, &message),
    };
    let diff = match analysis::diff(
        DiffSide::new(&before.policy).with_origins(&before.origins),
        DiffSide::new(&after.policy).with_origins(&after.origins),
        &fixture,
        &DiffOptions::default().with_limits(limits),
    ) {
        Ok(diff) => diff,
        Err(error) => return usage(err, &error.to_string()),
    };

    if json {
        match serde_json::to_string_pretty(&diff) {
            Ok(text) => writeln!(out, "{text}").ok(),
            Err(error) => return usage(err, &error.to_string()),
        };
    } else {
        write!(out, "{}", human(&diff)).ok();
    }
    let failing = match fail_on {
        FailOn::Any => !diff.is_empty(),
        FailOn::Allow => diff.count(ChangeKind::Widened) > 0,
    };
    if failing { EXIT_FAILED } else { EXIT_OK }
}

fn with_now(mut fixture: DiffFixture, now: u64) -> DiffFixture {
    fixture.now = Some(now);
    fixture
}

fn human(diff: &PolicyDiff) -> String {
    let mut text = String::new();
    for change in &diff.changes {
        let word = match change.change {
            ChangeKind::Widened => "WIDENED ",
            ChangeKind::Narrowed => "NARROWED",
            _ => "CHANGED ",
        };
        writeln!(text, "{word} {} {} on {}", change.subject, change.permission, change.resource).ok();
        writeln!(text, "  before: {}", side(&change.before)).ok();
        writeln!(text, "  after:  {}", side(&change.after)).ok();
    }
    let universe = &diff.universe;
    writeln!(
        text,
        "{} changed ({} widened, {} narrowed); {} questions over {} subjects, {} permissions, {} resources{}",
        diff.changes.len(),
        diff.count(ChangeKind::Widened),
        diff.count(ChangeKind::Narrowed),
        universe.questions,
        universe.subjects,
        universe.permissions,
        universe.resources,
        if universe.derived { " (derived from the policies)" } else { "" },
    )
    .ok();
    if universe.partial {
        writeln!(
            text,
            "partial: a limit stopped the diff before every question was asked; raise --max-decisions or --max-subjects, or give a --fixture"
        )
        .ok();
    }
    text
}

fn side(side: &Responsible) -> String {
    let effect = match side.effect {
        strig::Effect::Allow => "allow",
        strig::Effect::Deny => "deny",
    };
    let mut text = format!("{effect} ({}", side.reason);
    if let Some(grant) = &side.grant {
        write!(text, ", grant `{grant}`").ok();
    }
    if let Some(name) = &side.override_name {
        write!(text, ", override `{name}`").ok();
    }
    if let Some(at) = &side.at {
        write!(text, " at {at}").ok();
    }
    text.push(')');
    text
}

fn usage(err: &mut dyn Write, message: &str) -> u8 {
    writeln!(err, "strig diff: {message}").ok();
    EXIT_USAGE
}
