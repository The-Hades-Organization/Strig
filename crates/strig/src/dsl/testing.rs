//! Tests that live beside a policy: a file of cases, each one a question put to the policy and
//! the answer it must give.
//!
//! A test file is JSON (`*.strig-test.json`) and holds two kinds of case. A `check` case asks the
//! engine whether a subject may use a permission on a resource, at an optional instant and with an
//! optional environment, and says `allow` or `deny`, optionally the reason and the grant that
//! decides. A `mutation` case proposes a grant or role change through the governance of the policy
//! and says whether the invariants `accept` or `refuse` it, optionally naming the invariant.
//!
//! The data a case reads is the policy itself (its grants, tuples, subjects) plus an optional
//! [`Fixture`] of the file, inline or a path the caller resolves with [`TestFile::resolve_fixture`].
//!
//! [`run`] is pure: no IO, no clock. It never panics on a bad case; a case that cannot be judged
//! (unknown subject, permission outside the catalog, invalid fixture grant) is reported as
//! [`Outcome::Errored`], never as a pass.
//!
//! ```
//! use strig::dsl::{parse, testing};
//!
//! let policy = parse(
//!     "policy.strig",
//!     "language blocks\n\ntarget_kinds = [doc]\n\npermission doc.read {\n  targets = [doc]\n}\n",
//! )
//! .unwrap()
//! .policy;
//! let tests = testing::TestFile::parse(
//!     "policy.strig-test.json",
//!     r#"{"cases": [{"kind": "check", "name": "nobody reads", "subject": "user:ana",
//!         "permission": "doc.read", "resource": "doc:1", "expect": "deny"}],
//!         "fixture": {"subjects": [{"kind": "user", "id": "ana"}]}}"#,
//! )
//! .unwrap();
//! assert!(testing::run(&policy, &[tests]).is_success());
//! ```

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::attr::Attributes;
use crate::decision::{Reason, Request};
use crate::dsl::Policy;
use crate::engine::{Context, Engine};
use crate::explain::{Explanation, Verdict};
use crate::governance::{Governance, Mutation, Violation};
use crate::grant::{Effect, Grant};
use crate::rebac::{InMemoryTuples, Tuple};
use crate::resource::Resource;
use crate::subject::Subject;

/// The most cases `run` judges across all files; a bound for input that comes from outside.
pub const MAX_CASES: usize = 100_000;

/// The largest test file [`TestFile::parse`] reads.
pub const MAX_TEST_BYTES: usize = 4 * 1024 * 1024;

/// Why a test file could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TestError {
    /// The text is not a valid test file.
    #[error("{file}: {message}")]
    Invalid {
        /// The name the file was given.
        file: String,
        /// What is wrong, with the line and column when JSON gives them.
        message: String,
    },
}

/// The data a case reads besides the policy: more subjects, grants and tuples, and the base
/// environment of every case of the file.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Fixture {
    /// Subjects a case may name as `"kind:id"`, besides the ones the policy declares.
    #[serde(default)]
    pub subjects: Vec<Subject>,
    /// Grants added to the ones of the policy. An id the policy already uses is an error.
    #[serde(default)]
    pub grants: Vec<Grant>,
    /// Relation tuples added to the ones of the policy.
    #[serde(default)]
    pub tuples: Vec<Tuple>,
    /// Environment attributes every case starts from; a case's own `env` wins per key.
    #[serde(default)]
    pub env: Attributes,
}

/// The fixture of a file: written inline, or the path of a JSON file with the same shape.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
#[non_exhaustive]
pub enum FixtureRef {
    /// The fixture itself.
    Inline(Fixture),
    /// A path, relative to the test file; the caller reads it (see [`TestFile::resolve_fixture`]).
    Path(String),
}

/// A subject named by `"kind:id"` (looked up among the declared ones) or written out.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
#[non_exhaustive]
pub enum SubjectRef {
    /// `kind:id`, or `anonymous`.
    Name(String),
    /// The subject, in full.
    Inline(Subject),
}

/// A resource named by `global` or `kind:id`, or written out with its whole path.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
#[non_exhaustive]
pub enum ResourceRef {
    /// `global` or `kind:id`.
    Name(String),
    /// The resource, in full.
    Inline(Resource),
}

/// What a `check` case expects of the effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ExpectedEffect {
    /// The decision is an allow.
    Allow,
    /// The decision is a deny.
    Deny,
}

/// The reason of a decision, without its payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ExpectedReason {
    /// An override decided.
    Override,
    /// A grant decided.
    Grant,
    /// No grant applied.
    NoApplicableGrant,
    /// The permission is not in the catalog.
    UnknownPermission,
    /// A prerequisite of the permission is missing.
    MissingPrerequisite,
}

impl ExpectedReason {
    fn of(reason: &Reason) -> Self {
        match reason {
            Reason::Override { .. } => Self::Override,
            Reason::Grant { .. } => Self::Grant,
            Reason::NoApplicableGrant => Self::NoApplicableGrant,
            Reason::UnknownPermission => Self::UnknownPermission,
            Reason::MissingPrerequisite { .. } => Self::MissingPrerequisite,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Override => "override",
            Self::Grant => "grant",
            Self::NoApplicableGrant => "no_applicable_grant",
            Self::UnknownPermission => "unknown_permission",
            Self::MissingPrerequisite => "missing_prerequisite",
        }
    }
}

/// What a `mutation` case expects of the governance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ExpectedOutcome {
    /// Every invariant lets the change through.
    Accepted,
    /// At least one invariant refuses it.
    Refused,
}

/// Can `subject` use `permission` on `resource`?
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[non_exhaustive]
pub struct CheckCase {
    /// The name shown in the report; defaults to `case N`.
    #[serde(default)]
    pub name: Option<String>,
    /// Who asks.
    pub subject: SubjectRef,
    /// The permission asked.
    pub permission: String,
    /// What it is asked on.
    pub resource: ResourceRef,
    /// Environment attributes for this case, over the fixture's.
    #[serde(default)]
    pub env: Attributes,
    /// The instant of the decision, milliseconds since the Unix epoch; without it a grant with a
    /// validity window is judged as the engine judges it with no clock.
    #[serde(default)]
    pub now: Option<u64>,
    /// The effect the decision must have.
    pub expect: ExpectedEffect,
    /// The reason the decision must give, when it matters.
    #[serde(default)]
    pub reason: Option<ExpectedReason>,
    /// The id of the grant that must decide, when it matters.
    #[serde(default)]
    pub grant: Option<String>,
}

/// Does the governance accept this change by this actor?
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[non_exhaustive]
pub struct MutationCase {
    /// The name shown in the report; defaults to `case N`.
    #[serde(default)]
    pub name: Option<String>,
    /// Who makes the change.
    pub actor: SubjectRef,
    /// The change: `{"add": grant}`, `{"remove": {"id": ...}}`, `{"assign_role": {...}}` or
    /// `{"revoke_role": {...}}`.
    pub mutation: Mutation,
    /// The instant the governance judges at; without it, windows fail closed as in `Governance::apply`.
    #[serde(default)]
    pub now: Option<u64>,
    /// Whether the change goes through.
    pub expect: ExpectedOutcome,
    /// For a refusal: the invariant that must be among the ones that refuse.
    #[serde(default)]
    pub invariant: Option<String>,
}

/// One case of a test file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Case {
    /// A decision of the engine.
    Check(CheckCase),
    /// A change judged by the governance.
    Mutation(MutationCase),
}

/// A test file: its fixture and its cases.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct TestFile {
    /// The name the file was given, used in the report; not part of the JSON.
    #[serde(skip)]
    pub file: String,
    /// A title for the file, shown in the report.
    #[serde(default)]
    pub name: Option<String>,
    /// The data the cases read besides the policy.
    #[serde(default)]
    pub fixture: Option<FixtureRef>,
    /// The cases, in order.
    pub cases: Vec<Case>,
}

impl TestFile {
    /// Reads a test file. `file` is the name used in the report and in errors; it is never opened.
    ///
    /// # Errors
    /// [`TestError::Invalid`] when the text is too large, is not JSON of the right shape, or names
    /// a field the format does not know.
    pub fn parse(file: &str, text: &str) -> Result<Self, TestError> {
        let invalid = |message: String| TestError::Invalid {
            file: file.to_string(),
            message,
        };
        if text.len() > MAX_TEST_BYTES {
            return Err(invalid(format!("the file is larger than {MAX_TEST_BYTES} bytes")));
        }
        let mut parsed: TestFile = serde_json::from_str(text).map_err(|e| invalid(e.to_string()))?;
        parsed.file = file.to_string();
        Ok(parsed)
    }

    /// The path of the fixture file this one refers to, if its fixture is a path not yet read.
    pub fn fixture_path(&self) -> Option<&str> {
        match &self.fixture {
            Some(FixtureRef::Path(path)) => Some(path),
            _ => None,
        }
    }

    /// Replaces a fixture given as a path by the content of that file, which the caller read.
    ///
    /// # Errors
    /// [`TestError::Invalid`] when `text` is not a fixture.
    pub fn resolve_fixture(&mut self, text: &str) -> Result<(), TestError> {
        let fixture: Fixture = serde_json::from_str(text).map_err(|e| TestError::Invalid {
            file: self.file.clone(),
            message: format!(
                "the fixture `{}` is invalid: {e}",
                self.fixture_path().unwrap_or_default()
            ),
        })?;
        self.fixture = Some(FixtureRef::Inline(fixture));
        Ok(())
    }
}

/// How a case ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Outcome {
    /// The answer is the expected one.
    Passed,
    /// The answer differs from the expected one.
    Failed,
    /// The case could not be judged: the test, not the policy, is wrong.
    Errored,
}

/// The result of one case.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct CaseResult {
    /// The test file of the case.
    pub file: String,
    /// The case name.
    pub name: String,
    /// How it ended.
    pub outcome: Outcome,
    /// What the case expected, in words.
    pub expected: String,
    /// What the policy answered, in words; for an error, what stopped the case.
    pub actual: String,
    /// For a failed `check`: the grants considered and what became of each.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trace: Vec<String>,
    /// For a failed `check`: the full explanation of the decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explanation: Option<Box<Explanation>>,
}

/// The results of a run, in the order of the files and of the cases.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Report {
    /// One entry per case.
    pub results: Vec<CaseResult>,
}

impl Report {
    /// How many cases ended with `outcome`.
    pub fn count(&self, outcome: Outcome) -> usize {
        self.results.iter().filter(|r| r.outcome == outcome).count()
    }

    /// True when every case passed and there is at least one case.
    pub fn is_success(&self) -> bool {
        !self.results.is_empty() && self.results.iter().all(|r| r.outcome == Outcome::Passed)
    }
}

/// Runs the cases of `files` against `policy`.
///
/// The policy is built as it is for serving (`Policy::engine_spec`, its invariants as the
/// governance, its tuples as the tuple store). A policy that does not build, or a file whose
/// fixture is wrong, yields one errored result for that instead of cases; an empty run is not a
/// success.
pub fn run(policy: &Policy, files: &[TestFile]) -> Report {
    let mut report = Report::default();
    let total: usize = files.iter().map(|f| f.cases.len()).sum();
    if total > MAX_CASES {
        report.results.push(errored(
            "(run)",
            "(limit)",
            format!("{total} cases exceed the limit of {MAX_CASES}"),
        ));
        return report;
    }
    let engine = match policy.engine_spec().build() {
        Ok(engine) => engine,
        Err(error) => {
            report.results.push(errored(
                "(policy)",
                "(engine)",
                format!("the policy does not build: {error}"),
            ));
            return report;
        }
    };
    let governance: Governance = policy.invariants.iter().collect();
    for file in files {
        match World::new(policy, &engine, file) {
            Ok(world) => {
                for (at, case) in file.cases.iter().enumerate() {
                    report.results.push(world.judge(&governance, file, at, case));
                }
            }
            Err(message) => report.results.push(errored(&file.file, "(fixture)", message)),
        }
    }
    report
}

fn errored(file: &str, name: &str, message: String) -> CaseResult {
    CaseResult {
        file: file.to_string(),
        name: name.to_string(),
        outcome: Outcome::Errored,
        expected: String::new(),
        actual: message,
        trace: Vec::new(),
        explanation: None,
    }
}

/// The data every case of a file reads.
struct World<'a> {
    engine: &'a Engine,
    subjects: Vec<Subject>,
    grants: Vec<Grant>,
    tuples: InMemoryTuples,
    env: Attributes,
}

impl<'a> World<'a> {
    fn new(policy: &Policy, engine: &'a Engine, file: &TestFile) -> Result<Self, String> {
        let fixture = match &file.fixture {
            None => Fixture::default(),
            Some(FixtureRef::Inline(fixture)) => fixture.clone(),
            Some(FixtureRef::Path(path)) => {
                return Err(format!("the fixture `{path}` was not loaded"));
            }
        };
        let mut seen: HashSet<&str> = policy.grants.iter().map(|g| g.id.as_str()).collect();
        for grant in &fixture.grants {
            engine
                .validate_grant(grant)
                .map_err(|e| format!("fixture grant `{}` is invalid: {e}", grant.id))?;
            if !seen.insert(grant.id.as_str()) {
                return Err(format!(
                    "fixture grant `{}` repeats an id the policy or the fixture uses",
                    grant.id
                ));
            }
        }
        let mut grants = policy.grants.clone();
        grants.extend(fixture.grants);
        let mut subjects = policy.subjects.clone();
        subjects.extend(fixture.subjects);
        let tuples = policy.tuples.iter().cloned().chain(fixture.tuples).collect();
        Ok(Self {
            engine,
            subjects,
            grants,
            tuples,
            env: fixture.env,
        })
    }

    fn subject(&self, reference: &SubjectRef) -> Result<Subject, String> {
        match reference {
            SubjectRef::Inline(subject) => Ok(subject.clone()),
            SubjectRef::Name(name) if name == crate::subject::ANONYMOUS => Ok(Subject::anonymous()),
            SubjectRef::Name(name) => {
                let found: Vec<&Subject> = self.subjects.iter().filter(|s| subject_name(s) == *name).collect();
                match found.as_slice() {
                    [one] => Ok((*one).clone()),
                    [] => Err(format!(
                        "subject `{name}` is neither declared in the policy or the fixture nor written out"
                    )),
                    _ => Err(format!("subject `{name}` is declared more than once")),
                }
            }
        }
    }

    fn judge(&self, governance: &Governance, file: &TestFile, at: usize, case: &Case) -> CaseResult {
        let label = |name: &Option<String>| name.clone().unwrap_or_else(|| format!("case {}", at.saturating_add(1)));
        let (name, outcome) = match case {
            Case::Check(c) => (label(&c.name), self.check(c)),
            Case::Mutation(c) => (label(&c.name), self.mutation(governance, c)),
        };
        let mut result = match outcome {
            Ok(result) => result,
            Err(message) => errored("", "", message),
        };
        result.file = file.file.clone();
        result.name = name;
        result
    }

    fn check(&self, case: &CheckCase) -> Result<CaseResult, String> {
        let subject = self.subject(&case.subject)?;
        let resource = resource_of(&case.resource)?;
        let expected_reason = case.reason;
        if !self.engine.catalog().contains(&case.permission)
            && expected_reason != Some(ExpectedReason::UnknownPermission)
        {
            return Err(format!(
                "permission `{}` is not in the catalog (expect `reason: unknown_permission` to test that on purpose)",
                case.permission
            ));
        }
        let mut env = self.env.clone();
        env.extend(case.env.clone());
        let mut ctx = Context::new(&self.grants).with_tuples(&self.tuples).with_env(&env);
        if let Some(now) = case.now {
            ctx = ctx.at(now);
        }
        let request = Request::new(&subject, &case.permission, &resource);
        let explanation = self.engine.explain(&ctx, &request);
        let decision = &explanation.decision;
        let decisive = match &decision.reason {
            Reason::Grant { grant_id, .. } => Some(grant_id.as_str()),
            _ => None,
        };
        let effect = match case.expect {
            ExpectedEffect::Allow => Effect::Allow,
            ExpectedEffect::Deny => Effect::Deny,
        };
        let actual_reason = ExpectedReason::of(&decision.reason);
        let passed = decision.effect == effect
            && expected_reason.is_none_or(|r| r == actual_reason)
            && case.grant.as_deref().is_none_or(|g| decisive == Some(g));
        let mut expected = effect_name(effect).to_string();
        if let Some(reason) = expected_reason {
            expected.push_str(&format!(", reason {}", reason.name()));
        }
        if let Some(grant) = &case.grant {
            expected.push_str(&format!(", decided by grant `{grant}`"));
        }
        let mut actual = format!("{}, reason {}", effect_name(decision.effect), actual_reason.name());
        if let Some(grant) = decisive {
            actual.push_str(&format!(", decided by grant `{grant}`"));
        }
        let mut result = CaseResult {
            file: String::new(),
            name: String::new(),
            outcome: if passed { Outcome::Passed } else { Outcome::Failed },
            expected,
            actual,
            trace: Vec::new(),
            explanation: None,
        };
        if !passed {
            result.trace = explanation.grants.iter().map(trace_line).collect();
            result.explanation = Some(Box::new(explanation));
        }
        Ok(result)
    }

    fn mutation(&self, governance: &Governance, case: &MutationCase) -> Result<CaseResult, String> {
        let actor = self.subject(&case.actor)?;
        let judged = match case.now {
            Some(now) => {
                governance
                    .at(now)
                    .apply(self.engine, &actor, &self.grants, &case.mutation, Some(&self.tuples))
            }
            None => governance.apply(self.engine, &actor, &self.grants, &case.mutation, Some(&self.tuples)),
        };
        let (got, refused_by) = match &judged {
            Ok(_) => (ExpectedOutcome::Accepted, Vec::new()),
            Err(violations) => (ExpectedOutcome::Refused, violations.iter().collect::<Vec<&Violation>>()),
        };
        let invariant_ok = case
            .invariant
            .as_deref()
            .is_none_or(|name| refused_by.iter().any(|v| v.invariant == name));
        let passed = got == case.expect && (case.expect == ExpectedOutcome::Accepted || invariant_ok);
        let mut expected = outcome_name(case.expect).to_string();
        if let Some(name) = &case.invariant {
            expected.push_str(&format!(" by `{name}`"));
        }
        let actual = if refused_by.is_empty() {
            outcome_name(got).to_string()
        } else {
            let list: Vec<String> = refused_by.iter().map(|v| v.to_string()).collect();
            format!("refused: {}", list.join("; "))
        };
        Ok(CaseResult {
            file: String::new(),
            name: String::new(),
            outcome: if passed { Outcome::Passed } else { Outcome::Failed },
            expected,
            actual,
            trace: Vec::new(),
            explanation: None,
        })
    }
}

fn subject_name(subject: &Subject) -> String {
    match &subject.id {
        Some(id) => format!("{}:{id}", subject.kind),
        None => subject.kind.clone(),
    }
}

fn resource_of(reference: &ResourceRef) -> Result<Resource, String> {
    match reference {
        ResourceRef::Inline(resource) => Ok(resource.clone()),
        ResourceRef::Name(name) if name == crate::resource::GLOBAL => Ok(Resource::global()),
        ResourceRef::Name(name) => match name.split_once(':') {
            Some((kind, id)) if !kind.is_empty() && !id.is_empty() => Ok(Resource::new(kind, id)),
            _ => Err(format!(
                "resource `{name}` is not `global` or `kind:id`; write the resource out to give it a path"
            )),
        },
    }
}

fn effect_name(effect: Effect) -> &'static str {
    match effect {
        Effect::Allow => "allow",
        Effect::Deny => "deny",
    }
}

fn outcome_name(outcome: ExpectedOutcome) -> &'static str {
    match outcome {
        ExpectedOutcome::Accepted => "accepted",
        ExpectedOutcome::Refused => "refused",
    }
}

fn trace_line(trace: &crate::explain::GrantTrace) -> String {
    let verdict = serde_json::to_value(&trace.verdict)
        .ok()
        .and_then(|v| v.get("kind").and_then(|k| k.as_str().map(str::to_string)))
        .unwrap_or_else(|| format!("{:?}", trace.verdict));
    let detail = match &trace.verdict {
        Verdict::CandidateFailSafe { problem }
        | Verdict::SubjectUnresolved { problem }
        | Verdict::ConditionUnresolved { problem } => format!(" ({problem})"),
        _ => String::new(),
    };
    format!(
        "grant `{}` ({} {}): {verdict}{detail}",
        trace.grant.id,
        effect_name(trace.grant.effect),
        trace.grant.permission
    )
}

/// A string names the value, anything else is the value itself, and a mistake inside it is
/// reported by serde at its own field instead of as "no variant matched".
macro_rules! string_or_value {
    ($name:ident, $text:ident, $inline:ident, $value:ty) => {
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                use serde::de::Error as _;
                match serde_json::Value::deserialize(deserializer)? {
                    serde_json::Value::String(text) => Ok(Self::$text(text)),
                    other => <$value>::deserialize(other)
                        .map(Self::$inline)
                        .map_err(D::Error::custom),
                }
            }
        }
    };
}

string_or_value!(FixtureRef, Path, Inline, Fixture);
string_or_value!(SubjectRef, Name, Inline, Subject);
string_or_value!(ResourceRef, Name, Inline, Resource);
