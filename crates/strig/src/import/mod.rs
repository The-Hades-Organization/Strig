//! Importers: the model and the policy of another authorization library, read into a [`Policy`].
//!
//! [`casbin`] reads a Casbin `model.conf` and `policy.csv`; [`openfga`] reads an OpenFGA model (the
//! DSL or the JSON) and its tuples. Both are pure: they take text and return a policy and a
//! [`Report`] of what became what, and no IO happens here (the `strig import` command reads and
//! writes the files).
//!
//! Nothing is approximated towards more access. What has no faithful translation (a matcher this
//! module cannot express, an OpenFGA condition) is an [`ImportError`] that says where and why;
//! what is converted with a narrower reach than the source (a wildcard action expanded over the
//! actions the policy names, a `deny` line Casbin would have ignored) is listed in
//! [`Report::notes`].
//!
//! ```
//! use strig::import::casbin;
//!
//! let model = "[request_definition]\nr = sub, obj, act\n[policy_definition]\np = sub, obj, act\n\
//!              [policy_effect]\ne = some(where (p.eft == allow))\n\
//!              [matchers]\nm = r.sub == p.sub && r.obj == p.obj && r.act == p.act\n";
//! let imported = casbin::import(model, "p, alice, data1, read\n", &casbin::Options::default()).unwrap();
//! let alice = imported.subject("alice");
//! let (permission, resource) = imported.request("data1", "read", None).unwrap();
//! let engine = imported.policy().engine_spec().build().unwrap();
//! let grants = imported.policy().grants.clone();
//! let ctx = strig::Context::new(&grants);
//! assert!(engine.check(&ctx, &strig::Request::new(&alice, &permission, &resource)));
//! ```

use std::collections::BTreeSet;
use std::fmt;

use crate::dsl::{Diagnostic, Location, Policy};

pub mod casbin;
mod csv;
pub mod openfga;

/// What an import did: what was converted, what had no faithful translation and what was
/// converted with a narrower reach.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Report {
    /// One line per kind of element converted, with how many.
    pub converted: Vec<String>,
    /// What could not be translated faithfully, each with its position and the reason. An import
    /// that has any of these fails.
    pub not_converted: Vec<Diagnostic>,
    /// What was converted with a narrower reach than the source, or dropped because the source
    /// would have ignored it.
    pub notes: Vec<Diagnostic>,
}

impl Report {
    pub(crate) fn failed(&self) -> bool {
        !self.not_converted.is_empty()
    }

    pub(crate) fn converted(&mut self, count: usize, what: &str) {
        if count > 0 {
            self.converted.push(format!("{count} {what}"));
        }
    }

    pub(crate) fn refuse(&mut self, at: Option<Location>, message: impl Into<String>, hint: Option<&str>) {
        let mut found = Diagnostic::new(at, message);
        if let Some(hint) = hint {
            found = found.with_hint(hint);
        }
        self.not_converted.push(found);
    }

    pub(crate) fn note(&mut self, at: Option<Location>, message: impl Into<String>) {
        self.notes.push(Diagnostic::new(at, message));
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "converted:")?;
        if self.converted.is_empty() {
            writeln!(f, "  nothing")?;
        }
        for line in &self.converted {
            writeln!(f, "  {line}")?;
        }
        if !self.notes.is_empty() {
            writeln!(f, "converted with a narrower reach or dropped:")?;
            for note in &self.notes {
                writeln!(f, "  {note}")?;
            }
        }
        if !self.not_converted.is_empty() {
            writeln!(f, "not converted:")?;
            for item in &self.not_converted {
                writeln!(f, "  {item}")?;
            }
        }
        Ok(())
    }
}

/// An import that could not be completed: the [`Report`] holds what was converted and what was not.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ImportError {
    /// What was converted and what was not.
    pub report: Report,
}

impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, item) in self.report.not_converted.iter().enumerate() {
            if i > 0 {
                writeln!(f)?;
            }
            write!(f, "{item}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ImportError {}

/// A name usable as one segment of a permission key: lowercase letters, digits and `_`.
pub(crate) fn key_segment(text: &str) -> String {
    let mapped: String = text
        .chars()
        .map(|c| {
            let c = c.to_ascii_lowercase();
            if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if mapped.is_empty() { "_".to_string() } else { mapped }
}

/// An id for a generated element that is unique among `used`.
pub(crate) fn unique_id(base: &str, used: &mut BTreeSet<String>) -> String {
    let clean: String = base
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' })
        .collect();
    let mut id = clean.clone();
    let mut n = 2;
    while !used.insert(id.clone()) {
        id = format!("{clean}_{n}");
        n += 1;
    }
    id
}

pub(crate) fn finish(policy: &Policy, report: &mut Report) {
    if let Err(found) = policy.validate() {
        for item in found {
            report.refuse(
                item.location.clone(),
                format!("the imported policy is not valid: {}", item.message),
                item.hint.as_deref(),
            );
        }
    }
}

/// Whether the language can read `text` back as a bare id.
pub(crate) fn is_name(text: &str) -> bool {
    let mut previous_joiner = true;
    for c in text.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            previous_joiner = false;
        } else if (c == '.' || c == '-') && !previous_joiner {
            previous_joiner = true;
        } else {
            return false;
        }
    }
    !previous_joiner
}
