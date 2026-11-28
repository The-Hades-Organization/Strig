//! `strig lint <dir>`.

use std::fmt::Write as _;
use std::io::Write;
use std::path::Path;

use strig::dsl::analysis::{self, Finding, LintCode, LintOptions, Severity};

use crate::analysis_support::{load, read_limited};
use crate::{EXIT_FAILED, EXIT_OK, EXIT_USAGE};

/// The file `strig lint` reads from the policy directory when `--config` is not given.
pub(crate) const CONFIG_FILE: &str = "strig-lint.json";

pub(crate) fn run(args: &[String], out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    let mut target: Option<&str> = None;
    let mut config: Option<&str> = None;
    let mut ignore: Vec<String> = Vec::new();
    let mut json = false;
    let mut fail_on: Option<Severity> = Some(Severity::Warning);
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--json" => json = true,
            "--config" => match rest.next() {
                Some(path) => config = Some(path),
                None => return usage(err, "`--config` needs a file"),
            },
            "--ignore" => match rest.next() {
                Some(code) => ignore.extend(code.split(',').map(|c| c.trim().to_string())),
                None => return usage(err, "`--ignore` needs a code or a name"),
            },
            "--fail-on" => match rest.next().map(String::as_str) {
                Some("error") => fail_on = Some(Severity::Error),
                Some("warning") => fail_on = Some(Severity::Warning),
                Some("info") => fail_on = Some(Severity::Info),
                Some("never") => fail_on = None,
                _ => return usage(err, "`--fail-on` is `error`, `warning`, `info` or `never`"),
            },
            flag if flag.starts_with('-') => return usage(err, &format!("unknown option `{flag}`")),
            path if target.is_none() => target = Some(path),
            _ => return usage(err, "`lint` takes one directory"),
        }
    }
    let Some(target) = target else {
        return usage(err, "`lint` needs the directory of the policy");
    };

    let config_path = match config {
        Some(path) => Some(Path::new(path).to_path_buf()),
        None => {
            let beside = Path::new(target).join(CONFIG_FILE);
            Path::new(target).is_dir().then_some(beside).filter(|p| p.is_file())
        }
    };
    if let Some(path) = config_path {
        match read_config(&path) {
            Ok(codes) => ignore.extend(codes),
            Err(message) => return usage(err, &message),
        }
    }
    if let Some(unknown) = ignore.iter().find(|c| LintCode::parse(c).is_none()) {
        return usage(err, &format!("`{unknown}` is not a lint code or name"));
    }

    let built = match load(target) {
        Ok(built) => built,
        Err(message) => return usage(err, &message),
    };
    let options = ignore.into_iter().fold(LintOptions::default(), LintOptions::ignoring);
    let findings = analysis::lint(&built.policy, Some(&built.origins), &options);

    if json {
        match serde_json::to_string_pretty(&findings) {
            Ok(text) => writeln!(out, "{text}").ok(),
            Err(error) => return usage(err, &error.to_string()),
        };
    } else {
        write!(out, "{}", human(&findings)).ok();
    }
    let failing = fail_on.is_some_and(|level| findings.iter().any(|f| f.severity >= level));
    if failing { EXIT_FAILED } else { EXIT_OK }
}

/// `{"ignore": ["L004", "unused-role"]}`.
fn read_config(path: &Path) -> Result<Vec<String>, String> {
    let text = read_limited(path)?;
    let value: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("`{}` is not valid JSON: {e}", path.display()))?;
    let object = value
        .as_object()
        .ok_or_else(|| format!("`{}` must be a JSON object", path.display()))?;
    if let Some(key) = object.keys().find(|k| k.as_str() != "ignore") {
        return Err(format!(
            "`{}` has an unknown key `{key}`; only `ignore` is read",
            path.display()
        ));
    }
    match object.get("ignore") {
        None => Ok(Vec::new()),
        Some(list) => list
            .as_array()
            .and_then(|items| items.iter().map(|i| i.as_str().map(str::to_string)).collect())
            .ok_or_else(|| format!("`ignore` in `{}` must be a list of strings", path.display())),
    }
}

fn human(findings: &[Finding]) -> String {
    let mut text = String::new();
    for finding in findings {
        let place = finding.position().unwrap_or_else(|| finding.element.clone());
        writeln!(
            text,
            "{place}: {} {} [{}] {}",
            finding.severity.name(),
            finding.code,
            finding.name,
            finding.message
        )
        .ok();
        writeln!(text, "  hint: {}", finding.hint).ok();
    }
    let count = |level: Severity| findings.iter().filter(|f| f.severity == level).count();
    writeln!(
        text,
        "{} findings ({} errors, {} warnings, {} info)",
        findings.len(),
        count(Severity::Error),
        count(Severity::Warning),
        count(Severity::Info)
    )
    .ok();
    text
}

fn usage(err: &mut dyn Write, message: &str) -> u8 {
    writeln!(err, "strig lint: {message}").ok();
    EXIT_USAGE
}
