//! Conformance report over an audit trail (feature `audit`).
//!
//! [`ConformanceReport::build`] reads the records of a trail, in the order they were written, and
//! summarizes what an auditor asks first: the period covered, how many records of each action and
//! outcome, who changed what, which invariants refused changes, every place where the hash chain
//! breaks, and whether the published anchors and the time stamps hold. It is pure: it reads the
//! records you give it and writes nothing. [`parse_json_lines`] reads the text a `JsonLinesAudit`
//! produced.
//!
//! The report is data (`serde::Serialize`), so JSON output is the type itself; `strig audit report`
//! renders the same data as text.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::audit::{AuditAction, AuditOutcome, AuditRecord, record_hash};

/// A line of a JSON Lines trail that is not an audit record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct LineError {
    /// 1-based line number in the text.
    pub line: usize,
    /// What the parser said.
    pub message: String,
}

/// Parses a JSON Lines trail. Blank lines are skipped; a line that is not a record is reported with
/// its number and does not stop the others, so a damaged log still yields a report.
pub fn parse_json_lines(text: &str) -> (Vec<AuditRecord>, Vec<LineError>) {
    let mut records = Vec::new();
    let mut errors = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<AuditRecord>(line) {
            Ok(record) => records.push(record),
            Err(error) => errors.push(LineError { line: index + 1, message: error.to_string() }),
        }
    }
    (records, errors)
}

/// The span of time the records cover.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Period {
    /// Earliest `at`, milliseconds since the Unix epoch.
    pub from_ms: u64,
    /// Latest `at`, milliseconds since the Unix epoch.
    pub to_ms: u64,
    /// `from_ms` as `YYYY-MM-DDTHH:MM:SS.mmmZ`.
    pub from: String,
    /// `to_ms` as `YYYY-MM-DDTHH:MM:SS.mmmZ`.
    pub to: String,
}

/// How a record fails the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum BreakKind {
    /// The record has no `hash`: it was not written at the `forensic` level.
    Unchained,
    /// `prev_hash` is not the `hash` of the record before it: one was removed, added or reordered.
    Broken,
    /// The `hash` does not match the record's content: it was edited.
    Tampered,
}

/// One place where the chain does not hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ChainBreak {
    /// Position of the record in the trail, from 0.
    pub index: usize,
    /// What is wrong with it.
    pub kind: BreakKind,
}

/// The state of the hash chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ChainStatus {
    /// `true` when every record is chained and nothing breaks.
    pub ok: bool,
    /// `hash` of the last record, the value to anchor.
    pub head: Option<String>,
    /// Every break found. The walk goes on after one, taking the record's own `hash` as the new
    /// link, so a single edit shows as one break and not as the rest of the log.
    pub breaks: Vec<ChainBreak>,
}

/// Anchors known from outside the trail.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Anchors {
    /// The head published for this trail; the last record must carry it.
    pub head: Option<String>,
    /// The hash the first record must continue, when the trail is a segment.
    pub start: Option<String>,
}

impl Anchors {
    /// Sets the published head.
    pub fn head(mut self, head: impl Into<String>) -> Self {
        self.head = Some(head.into());
        self
    }

    /// Sets the hash the first record must continue.
    pub fn start(mut self, start: impl Into<String>) -> Self {
        self.start = Some(start.into());
        self
    }
}

/// Outcome of comparing the trail with an anchor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct AnchorCheck {
    /// `head` or `start`.
    pub kind: &'static str,
    /// The value that was published.
    pub expected: String,
    /// What the trail has in its place, `None` for an empty trail.
    pub found: Option<String>,
    /// Whether they are equal.
    pub ok: bool,
}

/// Result of verifying one time stamp, filled by the caller (see [`crate::timestamp`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct TimestampCheck {
    /// A name for the stamp, usually its file.
    pub label: String,
    /// Whether the stamp verified against the head of the trail.
    pub ok: bool,
    /// Time the TSA states, seconds since the Unix epoch, when it verified.
    pub gen_time: Option<i64>,
    /// `gen_time` as `YYYY-MM-DDTHH:MM:SSZ`.
    pub time: Option<String>,
    /// Policy OID the TSA stated, when it verified.
    pub policy: Option<String>,
    /// Serial number of the stamp, when it verified.
    pub serial: Option<String>,
    /// The error code (`TimestampError::code`) or `HEAD_UNAVAILABLE`, when it did not.
    pub error: Option<String>,
}

impl TimestampCheck {
    /// A stamp that verified.
    pub fn verified(label: impl Into<String>, gen_time: i64, policy: String, serial: String) -> Self {
        Self {
            label: label.into(),
            ok: true,
            gen_time: Some(gen_time),
            time: Some(format_unix_seconds(gen_time)),
            policy: Some(policy),
            serial: Some(serial),
            error: None,
        }
    }

    /// A stamp that did not.
    pub fn failed(label: impl Into<String>, error: impl Into<String>) -> Self {
        Self { label: label.into(), ok: false, gen_time: None, time: None, policy: None, serial: None, error: Some(error.into()) }
    }
}

/// The report. Maps are ordered by key, so the same trail always yields the same JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ConformanceReport {
    /// Number of records read.
    pub records: usize,
    /// Lines that were not records (only from [`parse_json_lines`]).
    pub unreadable_lines: Vec<LineError>,
    /// The period covered, `None` for an empty trail.
    pub period: Option<Period>,
    /// Records per action, then per outcome.
    pub by_action: BTreeMap<String, BTreeMap<String, u64>>,
    /// Applied changes (grant, tuple and role actions) per actor.
    pub changes_by_actor: BTreeMap<String, u64>,
    /// Refused changes per invariant, by the name of the invariant that refused.
    pub refusals_by_invariant: BTreeMap<String, u64>,
    /// Refusals that carry no invariant name (a refused audit sink, for instance).
    pub refusals_without_invariant: u64,
    /// The hash chain.
    pub chain: ChainStatus,
    /// The anchors given, each compared with the trail.
    pub anchors: Vec<AnchorCheck>,
    /// The time stamps given, each verified.
    pub timestamps: Vec<TimestampCheck>,
}

fn name_of<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn is_change(action: AuditAction) -> bool {
    matches!(
        action,
        AuditAction::GrantAdd
            | AuditAction::GrantRemove
            | AuditAction::TupleAdd
            | AuditAction::TupleRemove
            | AuditAction::RoleAssign
            | AuditAction::RoleRevoke
    )
}

fn invariant_of(violation: &str) -> &str {
    if let Some(rest) = violation.strip_prefix('[')
        && let Some((name, _)) = rest.split_once(']')
    {
        return name;
    }
    violation.split_once(": ").map_or(violation, |(name, _)| name)
}

impl ConformanceReport {
    /// Builds the report of `records`, in the order they were written, against `anchors`. Time
    /// stamps are verified by the caller and added with [`ConformanceReport::with_timestamps`].
    pub fn build(records: &[AuditRecord], anchors: &Anchors) -> Self {
        let mut by_action: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
        let mut changes_by_actor: BTreeMap<String, u64> = BTreeMap::new();
        let mut refusals_by_invariant: BTreeMap<String, u64> = BTreeMap::new();
        let mut refusals_without_invariant = 0;
        let mut breaks = Vec::new();
        let mut previous: Option<&str> = None;

        for (index, record) in records.iter().enumerate() {
            *by_action
                .entry(name_of(&record.action))
                .or_default()
                .entry(name_of(&record.outcome))
                .or_default() += 1;
            if is_change(record.action) && record.outcome == AuditOutcome::Applied {
                *changes_by_actor.entry(record.actor.clone()).or_default() += 1;
            }
            if record.outcome == AuditOutcome::Rejected {
                if record.violations.is_empty() {
                    refusals_without_invariant += 1;
                }
                for violation in &record.violations {
                    *refusals_by_invariant.entry(invariant_of(violation).to_owned()).or_default() += 1;
                }
            }
            match record.hash.as_deref() {
                None => breaks.push(ChainBreak { index, kind: BreakKind::Unchained }),
                Some(hash) => {
                    if index > 0 && record.prev_hash.as_deref() != previous {
                        breaks.push(ChainBreak { index, kind: BreakKind::Broken });
                    }
                    if record_hash(record).ok().as_deref() != Some(hash) {
                        breaks.push(ChainBreak { index, kind: BreakKind::Tampered });
                    }
                }
            }
            previous = record.hash.as_deref();
        }

        let head = records.last().and_then(|r| r.hash.clone());
        let mut checks = Vec::new();
        if let Some(expected) = &anchors.head {
            checks.push(AnchorCheck {
                kind: "head",
                expected: expected.clone(),
                found: head.clone(),
                ok: head.as_deref() == Some(expected.as_str()),
            });
        }
        if let Some(expected) = &anchors.start {
            let found = records.first().and_then(|r| r.prev_hash.clone());
            checks.push(AnchorCheck {
                kind: "start",
                expected: expected.clone(),
                ok: found.as_deref() == Some(expected.as_str()),
                found,
            });
        }

        let period = records.iter().map(|r| r.at).min().zip(records.iter().map(|r| r.at).max()).map(|(from, to)| Period {
            from_ms: from,
            to_ms: to,
            from: format_unix_millis(from),
            to: format_unix_millis(to),
        });

        Self {
            records: records.len(),
            unreadable_lines: Vec::new(),
            period,
            by_action,
            changes_by_actor,
            refusals_by_invariant,
            refusals_without_invariant,
            chain: ChainStatus { ok: breaks.is_empty() && !records.is_empty(), head, breaks },
            anchors: checks,
            timestamps: Vec::new(),
        }
    }

    /// Builds the report from the text of a JSON Lines trail.
    pub fn from_json_lines(text: &str, anchors: &Anchors) -> Self {
        let (records, errors) = parse_json_lines(text);
        let mut report = Self::build(&records, anchors);
        report.unreadable_lines = errors;
        report
    }

    /// Adds the results of verifying time stamps.
    pub fn with_timestamps(mut self, timestamps: Vec<TimestampCheck>) -> Self {
        self.timestamps = timestamps;
        self
    }

    /// `true` when nothing in the report is a problem: every line read, the chain intact, every
    /// anchor matched and every time stamp verified.
    pub fn is_conforming(&self) -> bool {
        self.unreadable_lines.is_empty()
            && self.chain.ok
            && self.anchors.iter().all(|a| a.ok)
            && self.timestamps.iter().all(|t| t.ok)
    }
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// `YYYY-MM-DDTHH:MM:SSZ` for seconds since the Unix epoch.
pub fn format_unix_seconds(seconds: i64) -> String {
    let (year, month, day) = civil_from_days(seconds.div_euclid(86_400));
    let rest = seconds.rem_euclid(86_400);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z", rest / 3600, rest % 3600 / 60, rest % 60)
}

/// `YYYY-MM-DDTHH:MM:SS.mmmZ` for milliseconds since the Unix epoch.
pub fn format_unix_millis(millis: u64) -> String {
    let seconds = (millis / 1000) as i64;
    let base = format_unix_seconds(seconds);
    format!("{}.{:03}Z", &base[..base.len() - 1], millis % 1000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_formatting() {
        assert_eq!(format_unix_seconds(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_unix_seconds(1_795_868_280), "2026-11-28T12:18:00Z");
        assert_eq!(format_unix_millis(1_700_000_000_123), "2023-11-14T22:13:20.123Z");
    }

    #[test]
    fn invariant_names() {
        assert_eq!(invariant_of("no_self_management"), "no_self_management");
        assert_eq!(invariant_of("no_self_management: you cannot"), "no_self_management");
        assert_eq!(invariant_of("[no_self_management] you cannot"), "no_self_management");
    }

    #[test]
    fn an_empty_trail_is_not_conforming() {
        let report = ConformanceReport::build(&[], &Anchors::default());
        assert_eq!(report.records, 0);
        assert!(report.period.is_none());
        assert!(!report.is_conforming());
    }
}
