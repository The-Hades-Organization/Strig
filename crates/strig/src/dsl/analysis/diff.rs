//! `diff`: the decisions that change between two versions of a policy.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::attr::Attributes;
use crate::decision::{Decision, Reason, Request};
use crate::dsl::policy::{Origins, Policy, ids};
use crate::dsl::testing::{ResourceRef, resource_of, subject_name};
use crate::engine::{Context, Engine};
use crate::grant::{Effect, Grant, SubjectMatcher};
use crate::query::QueryLimits;
use crate::rebac::{InMemoryTuples, Tuple, TupleSubject};
use crate::resource::{Anchor, Resource};
use crate::subject::{ANONYMOUS, Subject};

/// The largest fixture [`DiffFixture::parse`] reads.
pub const MAX_FIXTURE_BYTES: usize = 4 * 1024 * 1024;

/// The data a diff asks its questions about, besides the two policies. Every list is optional: what
/// is left out is derived from the catalogs and the grants of both versions.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct DiffFixture {
    /// Subjects to ask about, written out. A subject a policy declares under the same
    /// `kind:id` is taken from that policy, on its side.
    #[serde(default)]
    pub subjects: Vec<Subject>,
    /// Resources to ask about: `global`, `kind:id`, or written out with the whole path.
    #[serde(default)]
    pub resources: Vec<ResourceRef>,
    /// Permissions to ask about; by default every one of the two catalogs.
    #[serde(default)]
    pub permissions: Vec<String>,
    /// Grants added to both versions. An id a version already uses is an error.
    #[serde(default)]
    pub grants: Vec<Grant>,
    /// Relation tuples added to both versions.
    #[serde(default)]
    pub tuples: Vec<Tuple>,
    /// The environment of every question.
    #[serde(default)]
    pub env: Attributes,
    /// The instant of every question, milliseconds since the Unix epoch; without it a grant with
    /// a validity window is judged as the engine judges it with no clock.
    #[serde(default)]
    pub now: Option<u64>,
}

impl DiffFixture {
    /// Reads a fixture. `file` names it in errors and is never opened.
    ///
    /// # Errors
    /// [`DiffError::Fixture`] when the text is too large or is not a fixture.
    pub fn parse(file: &str, text: &str) -> Result<Self, DiffError> {
        let invalid = |message: String| DiffError::Fixture {
            file: file.to_string(),
            message,
        };
        if text.len() > MAX_FIXTURE_BYTES {
            return Err(invalid(format!("the file is larger than {MAX_FIXTURE_BYTES} bytes")));
        }
        serde_json::from_str(text).map_err(|e| invalid(e.to_string()))
    }
}

/// Why a diff could not be made.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DiffError {
    /// One version does not build an engine.
    #[error("the {side} policy does not build: {message}")]
    Policy {
        /// `before` or `after`.
        side: &'static str,
        /// What the engine said.
        message: String,
    },
    /// The fixture is not valid.
    #[error("{file}: {message}")]
    Fixture {
        /// The name the fixture was given.
        file: String,
        /// What is wrong.
        message: String,
    },
}

/// What bounds the work of a diff.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct DiffOptions {
    /// `max_parties` caps the subjects, `max_decisions` the decisions (two per question). Past a
    /// cap the diff stops and says [`Universe::partial`].
    pub limits: QueryLimits,
}

impl DiffOptions {
    /// Options with these limits.
    #[must_use]
    pub fn with_limits(mut self, limits: QueryLimits) -> Self {
        self.limits = limits;
        self
    }
}

/// One version of a policy and, when it came from sources, where its elements are written.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct DiffSide<'a> {
    /// The policy.
    pub policy: &'a Policy,
    /// Where its elements were declared.
    pub origins: Option<&'a Origins>,
}

impl<'a> DiffSide<'a> {
    /// A version without positions.
    pub fn new(policy: &'a Policy) -> Self {
        Self { policy, origins: None }
    }

    /// A version with the positions of its elements.
    #[must_use]
    pub fn with_origins(mut self, origins: &'a Origins) -> Self {
        self.origins = Some(origins);
        self
    }
}

/// Which way a decision moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ChangeKind {
    /// Deny became allow: access grew.
    Widened,
    /// Allow became deny: access shrank.
    Narrowed,
}

/// What decided on one side.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Responsible {
    /// `allow` or `deny`.
    pub effect: Effect,
    /// `grant`, `override`, `no_applicable_grant`, `unknown_permission` or `missing_prerequisite`.
    pub reason: String,
    /// The grant that decided, for a `grant` reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<String>,
    /// The override that decided, for an `override` reason.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "override")]
    pub override_name: Option<String>,
    /// Where the grant is written (`file:line:column`), when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
}

/// A question whose answer differs between the two versions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct DecisionChange {
    /// Who asks, as `kind:id` (or `anonymous`).
    pub subject: String,
    /// The permission asked.
    pub permission: String,
    /// What it is asked on: `global`, `kind:id`, or `kind:id in kind:id` for a path.
    pub resource: String,
    /// Which way it moved.
    pub change: ChangeKind,
    /// The decision of the first version.
    pub before: Responsible,
    /// The decision of the second version.
    pub after: Responsible,
}

/// The questions a diff asked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Universe {
    /// Subjects asked about.
    pub subjects: usize,
    /// Permissions asked about.
    pub permissions: usize,
    /// Resources asked about.
    pub resources: usize,
    /// Questions answered on both sides.
    pub questions: usize,
    /// True when the subjects or the resources were derived from the policies, not given.
    pub derived: bool,
    /// True when a limit stopped the diff before every question was asked: no change found is not
    /// proof there is none.
    pub partial: bool,
}

/// The decisions that differ between two versions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct PolicyDiff {
    /// The questions whose answer changed, ordered by subject, permission and resource.
    pub changes: Vec<DecisionChange>,
    /// What was asked.
    pub universe: Universe,
}

impl PolicyDiff {
    /// True when no question changed its answer.
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    /// How many changes went this way.
    pub fn count(&self, kind: ChangeKind) -> usize {
        self.changes.iter().filter(|c| c.change == kind).count()
    }
}

const PLACEHOLDER_ID: &str = "(any)";

/// Lists the decisions that change from `before` to `after`.
///
/// Both versions are built as for serving; the same questions go to each engine, with the grants
/// and tuples of the fixture added to both. A subject a version declares is taken from that
/// version, so a role assigned or taken away shows up as a change.
///
/// # Errors
/// [`DiffError::Policy`] when a version does not build; [`DiffError::Fixture`] when a fixture
/// grant repeats an id a version uses.
pub fn diff(
    before: DiffSide<'_>,
    after: DiffSide<'_>,
    fixture: &DiffFixture,
    options: &DiffOptions,
) -> Result<PolicyDiff, DiffError> {
    let engines = [engine(before, "before")?, engine(after, "after")?];
    let sides = [before, after];
    let grants = [
        merged_grants(before.policy, fixture)?,
        merged_grants(after.policy, fixture)?,
    ];
    let tuples = sides.map(|s| -> InMemoryTuples { s.policy.tuples.iter().chain(&fixture.tuples).cloned().collect() });

    let derived_subjects = fixture.subjects.is_empty();
    let derived_resources = fixture.resources.is_empty();
    let names = subject_names(&sides, fixture, &grants);
    let resources = resource_list(fixture, &grants)?;
    let permissions = permission_list(&engines, fixture);

    let mut universe = Universe {
        subjects: 0,
        permissions: permissions.len(),
        resources: resources.len(),
        questions: 0,
        derived: derived_subjects || derived_resources,
        partial: false,
    };
    let mut names = names;
    if names.len() > options.limits.max_parties {
        names.truncate(options.limits.max_parties);
        universe.partial = true;
    }
    universe.subjects = names.len();

    let mut changes = Vec::new();
    let max_questions = options.limits.max_decisions / 2;
    'asking: for (name, base) in &names {
        let subjects = [
            subject_on(sides[0].policy, name, base),
            subject_on(sides[1].policy, name, base),
        ];
        for permission in &permissions {
            for resource in &resources {
                if universe.questions >= max_questions {
                    universe.partial = true;
                    break 'asking;
                }
                universe.questions += 1;
                let decide = |side: usize| -> Decision {
                    let mut ctx = Context::new(&grants[side])
                        .with_tuples(&tuples[side])
                        .with_env(&fixture.env);
                    if let Some(now) = fixture.now {
                        ctx = ctx.at(now);
                    }
                    engines[side].decide(&ctx, &Request::new(&subjects[side], permission, resource))
                };
                let (was, now) = (decide(0), decide(1));
                if was.effect == now.effect {
                    continue;
                }
                changes.push(DecisionChange {
                    subject: name.clone(),
                    permission: permission.clone(),
                    resource: display_resource(resource),
                    change: if now.effect == Effect::Allow {
                        ChangeKind::Widened
                    } else {
                        ChangeKind::Narrowed
                    },
                    before: responsible(&was, sides[0]),
                    after: responsible(&now, sides[1]),
                });
            }
        }
    }
    Ok(PolicyDiff { changes, universe })
}

fn engine(side: DiffSide<'_>, label: &'static str) -> Result<Engine, DiffError> {
    side.policy.engine_spec().build().map_err(|e| DiffError::Policy {
        side: label,
        message: e.to_string(),
    })
}

fn merged_grants(policy: &Policy, fixture: &DiffFixture) -> Result<Vec<Grant>, DiffError> {
    let used: BTreeSet<&str> = policy.grants.iter().map(|g| g.id.as_str()).collect();
    let mut seen = used.clone();
    for grant in &fixture.grants {
        if !seen.insert(grant.id.as_str()) {
            return Err(DiffError::Fixture {
                file: "(fixture)".to_string(),
                message: format!("fixture grant `{}` repeats an id a policy or the fixture uses", grant.id),
            });
        }
    }
    Ok(policy.grants.iter().chain(&fixture.grants).cloned().collect())
}

fn permission_list(engines: &[Engine; 2], fixture: &DiffFixture) -> Vec<String> {
    if !fixture.permissions.is_empty() {
        let set: BTreeSet<&String> = fixture.permissions.iter().collect();
        return set.into_iter().cloned().collect();
    }
    let all: BTreeSet<&str> = engines
        .iter()
        .flat_map(|e| e.catalog().all().iter().map(|d| d.key.as_str()))
        .collect();
    all.into_iter().map(str::to_string).collect()
}

/// The subjects to ask about by name, with the definition they have when no version declares them.
fn subject_names(
    sides: &[DiffSide<'_>; 2],
    fixture: &DiffFixture,
    grants: &[Vec<Grant>; 2],
) -> Vec<(String, Subject)> {
    let mut found: BTreeMap<String, Subject> = BTreeMap::new();
    for subject in sides.iter().flat_map(|s| &s.policy.subjects) {
        found.entry(subject_name(subject)).or_insert_with(|| subject.clone());
    }
    for subject in &fixture.subjects {
        found.insert(subject_name(subject), subject.clone());
    }
    if fixture.subjects.is_empty() {
        for subject in derived_subjects(sides, grants) {
            found.entry(subject_name(&subject)).or_insert(subject);
        }
    }
    found.into_iter().collect()
}

fn derived_subjects(sides: &[DiffSide<'_>; 2], grants: &[Vec<Grant>; 2]) -> Vec<Subject> {
    let mut out = vec![Subject::anonymous(), Subject::user("(other)")];
    for grant in grants.iter().flatten() {
        match &grant.subject {
            SubjectMatcher::User { id } => out.push(Subject::user(id.clone())),
            SubjectMatcher::Role { id } => out.push(Subject::of_kind("role", id.clone()).with_role(id.clone())),
            SubjectMatcher::Principal { name } if name == ANONYMOUS => {}
            SubjectMatcher::Principal { name } => {
                out.push(Subject::of_kind("principal", name.clone()).with_principal(name.clone()));
            }
            SubjectMatcher::Relation { .. } | SubjectMatcher::Any => {}
        }
    }
    for tuple in sides.iter().flat_map(|s| &s.policy.tuples) {
        if let TupleSubject::Object(object) = &tuple.subject
            && object.id != "*"
        {
            out.push(if object.kind == "user" {
                Subject::user(object.id.clone())
            } else {
                Subject::of_kind(object.kind.clone(), object.id.clone())
            });
        }
    }
    out
}

/// The subject as one version sees it: its own declaration when it has one.
fn subject_on(policy: &Policy, name: &str, base: &Subject) -> Subject {
    policy
        .subjects
        .iter()
        .find(|s| subject_name(s) == name)
        .cloned()
        .unwrap_or_else(|| base.clone())
}

fn resource_list(fixture: &DiffFixture, grants: &[Vec<Grant>; 2]) -> Result<Vec<Resource>, DiffError> {
    if !fixture.resources.is_empty() {
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for reference in &fixture.resources {
            let resource = resource_of(reference).map_err(|message| DiffError::Fixture {
                file: "(fixture)".to_string(),
                message,
            })?;
            if seen.insert(display_resource(&resource)) {
                out.push(resource);
            }
        }
        return Ok(out);
    }
    let mut singles: BTreeMap<String, Resource> = BTreeMap::new();
    for grant in grants.iter().flatten() {
        let mut path = Vec::new();
        if !(grant.target.kind == crate::resource::GLOBAL && grant.target.id.is_none()) {
            path.push(anchor_of(&grant.target.kind, grant.target.id.as_deref()));
        }
        if let Some(scope) = &grant.scope
            && !scope.is_global()
            && !path.contains(&filled(scope))
        {
            path.push(filled(scope));
        }
        let resource = Resource {
            path,
            attrs: Attributes::new(),
        };
        singles.entry(display_resource(&resource)).or_insert(resource);
    }
    singles.entry("global".to_string()).or_insert_with(Resource::global);
    let mut pairs: BTreeMap<String, Resource> = BTreeMap::new();
    let bases: Vec<&Resource> = singles.values().filter(|r| r.path.len() == 1).collect();
    for inner in &bases {
        for outer in &bases {
            if inner.path[0].kind == outer.path[0].kind {
                continue;
            }
            let resource = Resource {
                path: vec![inner.path[0].clone(), outer.path[0].clone()],
                attrs: Attributes::new(),
            };
            pairs.entry(display_resource(&resource)).or_insert(resource);
        }
    }
    let mut out: Vec<Resource> = singles.into_values().collect();
    out.sort_by_key(display_resource);
    let single_names: BTreeSet<String> = out.iter().map(display_resource).collect();
    out.extend(pairs.into_iter().filter(|(k, _)| !single_names.contains(k)).map(|(_, r)| r));
    Ok(out)
}

fn anchor_of(kind: &str, id: Option<&str>) -> Anchor {
    Anchor::new(kind, id.unwrap_or(PLACEHOLDER_ID))
}

fn filled(anchor: &Anchor) -> Anchor {
    anchor_of(&anchor.kind, anchor.id.as_deref())
}

fn display_resource(resource: &Resource) -> String {
    let steps: Vec<String> = resource.path.iter().map(Anchor::to_string).collect();
    if steps.is_empty() {
        "global".to_string()
    } else {
        steps.join(" in ")
    }
}

fn responsible(decision: &Decision, side: DiffSide<'_>) -> Responsible {
    let (reason, grant, override_name) = match &decision.reason {
        Reason::Grant { grant_id, .. } => ("grant", Some(grant_id.clone()), None),
        Reason::Override { name } => ("override", None, Some(name.clone())),
        Reason::NoApplicableGrant => ("no_applicable_grant", None, None),
        Reason::UnknownPermission => ("unknown_permission", None, None),
        Reason::MissingPrerequisite { .. } => ("missing_prerequisite", None, None),
    };
    let at = grant
        .as_deref()
        .and_then(|id| side.origins?.get(&ids::grant(id)))
        .map(|l| format!("{}:{}:{}", l.file, l.line, l.column));
    Responsible {
        effect: decision.effect,
        reason: reason.to_string(),
        grant,
        override_name,
        at,
    }
}
