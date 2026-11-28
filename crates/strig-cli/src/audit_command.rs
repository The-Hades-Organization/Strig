//! `strig audit report <trail.jsonl> [options]`.

use std::fmt::Write as _;
use std::io::Write;
use std::path::Path;

use strig::audit_report::{Anchors, ConformanceReport, TimestampCheck};
use strig::timestamp::{VerifyOptions, pem_certificates, verify_response};

use crate::{EXIT_FAILED, EXIT_OK, EXIT_USAGE};

pub(crate) fn run(args: &[String], out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    match args.first().map(String::as_str) {
        Some("report") => report(&args[1..], out, err),
        Some(other) => usage(err, &format!("unknown audit command `{other}`")),
        None => usage(err, "`audit` needs a command (`report`)"),
    }
}

fn report(args: &[String], out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    let mut trail: Option<&str> = None;
    let mut anchors = Anchors::default();
    let mut stamps: Vec<&str> = Vec::new();
    let mut roots: Vec<&str> = Vec::new();
    let mut json = false;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--json" => json = true,
            "--anchor-head" | "--anchor-start" | "--timestamp" | "--root" => {
                let Some(value) = rest.next() else {
                    return usage(err, &format!("`{arg}` needs a value"));
                };
                match arg.as_str() {
                    "--anchor-head" => anchors = anchors.head(value.trim()),
                    "--anchor-start" => anchors = anchors.start(value.trim()),
                    "--timestamp" => stamps.push(value),
                    _ => roots.push(value),
                }
            }
            flag if flag.starts_with('-') => return usage(err, &format!("unknown option `{flag}`")),
            path if trail.is_none() => trail = Some(path),
            _ => return usage(err, "`audit report` takes one trail file"),
        }
    }
    let Some(trail) = trail else {
        return usage(err, "`audit report` needs the trail file (JSON Lines)");
    };
    if !stamps.is_empty() && roots.is_empty() {
        return usage(
            err,
            "`--timestamp` needs at least one `--root` (the CA certificates you trust)",
        );
    }
    let text = match std::fs::read_to_string(trail) {
        Ok(text) => text,
        Err(error) => return usage(err, &format!("cannot read `{trail}`: {error}")),
    };
    let mut trusted: Vec<Vec<u8>> = Vec::new();
    for path in &roots {
        match std::fs::read_to_string(path) {
            Ok(pem) => trusted.extend(pem_certificates(&pem)),
            Err(error) => return usage(err, &format!("cannot read `{path}`: {error}")),
        }
    }

    let report = ConformanceReport::from_json_lines(&text, &anchors);
    let checks = stamps
        .iter()
        .map(|path| check_stamp(path, report.chain.head.as_deref(), &trusted))
        .collect();
    let report = report.with_timestamps(checks);

    if json {
        match serde_json::to_string_pretty(&report) {
            Ok(body) => writeln!(out, "{body}").ok(),
            Err(error) => return usage(err, &error.to_string()),
        };
    } else {
        write!(out, "{}", human(&report)).ok();
    }
    if report.is_conforming() { EXIT_OK } else { EXIT_FAILED }
}

fn check_stamp(path: &str, head: Option<&str>, trusted: &[Vec<u8>]) -> TimestampCheck {
    let label = Path::new(path)
        .file_name()
        .map_or_else(|| path.to_string(), |n| n.to_string_lossy().into_owned());
    let Some(head) = head else {
        return TimestampCheck::failed(label, "HEAD_UNAVAILABLE");
    };
    let response = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => return TimestampCheck::failed(label, format!("UNREADABLE: {error}")),
    };
    let options = match VerifyOptions::for_chain_head(head, trusted.to_vec()) {
        Ok(options) => options,
        Err(_) => return TimestampCheck::failed(label, "HEAD_UNAVAILABLE"),
    };
    match verify_response(&response, &options) {
        Ok(info) => TimestampCheck::verified(label, info.gen_time, info.policy, info.serial),
        Err(error) => TimestampCheck::failed(label, error.code()),
    }
}

/// The report as text for people.
pub fn human(report: &ConformanceReport) -> String {
    let mut text = String::new();
    writeln!(text, "records: {}", report.records).ok();
    match &report.period {
        Some(period) => writeln!(text, "period: {} to {}", period.from, period.to).ok(),
        None => writeln!(text, "period: -").ok(),
    };
    if !report.by_action.is_empty() {
        writeln!(text, "\nby action:").ok();
        for (action, outcomes) in &report.by_action {
            let parts: Vec<String> = outcomes.iter().map(|(o, n)| format!("{o} {n}")).collect();
            writeln!(text, "  {action}: {}", parts.join(", ")).ok();
        }
    }
    if !report.changes_by_actor.is_empty() {
        writeln!(text, "\nchanges by actor:").ok();
        for (actor, count) in &report.changes_by_actor {
            writeln!(text, "  {actor}: {count}").ok();
        }
    }
    if !report.refusals_by_invariant.is_empty() || report.refusals_without_invariant > 0 {
        writeln!(text, "\nrefusals by invariant:").ok();
        for (name, count) in &report.refusals_by_invariant {
            writeln!(text, "  {name}: {count}").ok();
        }
        if report.refusals_without_invariant > 0 {
            writeln!(text, "  (no invariant): {}", report.refusals_without_invariant).ok();
        }
    }
    let chain = &report.chain;
    writeln!(text, "\nchain: {}", if chain.ok { "intact" } else { "BROKEN" }).ok();
    if let Some(head) = &chain.head {
        writeln!(text, "  head: {head}").ok();
    }
    for item in &chain.breaks {
        writeln!(text, "  record {}: {:?}", item.index, item.kind).ok();
    }
    for line in &report.unreadable_lines {
        writeln!(text, "  line {} unreadable: {}", line.line, line.message).ok();
    }
    for anchor in &report.anchors {
        let mark = if anchor.ok { "ok" } else { "MISMATCH" };
        writeln!(text, "anchor {}: {mark} (published {})", anchor.kind, anchor.expected).ok();
    }
    for stamp in &report.timestamps {
        match (&stamp.time, &stamp.error) {
            (Some(time), _) => writeln!(text, "timestamp {}: ok ({time})", stamp.label).ok(),
            (None, error) => writeln!(
                text,
                "timestamp {}: FAILED ({})",
                stamp.label,
                error.as_deref().unwrap_or("unknown")
            )
            .ok(),
        };
    }
    writeln!(
        text,
        "\n{}",
        if report.is_conforming() {
            "conforming"
        } else {
            "NOT conforming"
        }
    )
    .ok();
    text
}

fn usage(err: &mut dyn Write, message: &str) -> u8 {
    writeln!(err, "strig: {message}").ok();
    EXIT_USAGE
}
