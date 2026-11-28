//! "Why not?": for a denial, the smallest changes that would turn it into an `allow`.
//!
//! [`crate::Engine::why_not`] reads the trace of the denial ([`crate::Engine::explain`]), builds
//! candidate changes from it and **verifies each one**: the change is applied to a copy of the
//! subject or of the grants and the request is decided again. Only a candidate that comes out as
//! `allow` is returned, so a suggestion is never a guess. Nothing is written anywhere.
//!
//! Candidates, from the trace:
//!
//! - [`Change::AddGrant`]: an `allow` for the subject on the most specific step of the path
//!   (the exact target, then the kind), checked with [`crate::Engine::validate_grant`] so it
//!   respects the catalog's `targets` and `fields`.
//! - [`Change::AssignRole`]: a role that has an applicable `allow`, scoped to the narrowest step.
//! - [`Change::RemoveDeny`] / [`Change::NarrowDeny`]: the deny that decided, whole or without the
//!   asked field.
//! - [`Change::SatisfyCondition`]: the condition of an otherwise applicable `allow` that failed or
//!   could not be evaluated. The attribute value is never invented: the change names what failed and
//!   the verification replaces the condition by a true one only to prove it is the sole obstacle.
//!
//! Limits: the changes are single (no combination of two), and the governance flags known to the
//! catalog (`override_only`, `management_only`, `non_delegable`) mark a remedy as a [`Caveat`]; the
//! invariants of a [`crate::Governance`] are not consulted.

use std::borrow::Cow;

use serde::{Deserialize, Serialize};

use crate::decision::{Reason, Request};
use crate::engine::{Context, Engine};
use crate::explain::{ConditionTrace, Explanation, GrantTrace, TraceResult, Verdict};
use crate::grant::{Effect, Grant, GrantSource, SubjectMatcher, TargetSelector};
use crate::query::QueryLimits;
use crate::resource::{Anchor, Resource};
use crate::subject::{RoleAssignment, Subject};

/// Bounds of a [`crate::Engine::why_not`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct WhyNotOptions {
    /// `max_decisions` caps the verifications (one decision each); past it the answer is marked
    /// [`Remedies::partial`]. The engine does no IO and has no clock, so the work is bounded by
    /// count, as in the reverse queries.
    pub limits: QueryLimits,
    /// Most remedies returned. More than this are cut and the answer is marked partial.
    pub max_remedies: usize,
}

impl WhyNotOptions {
    /// Default of [`WhyNotOptions::max_remedies`].
    pub const DEFAULT_MAX_REMEDIES: usize = 16;

    #[must_use]
    pub fn with_limits(mut self, limits: QueryLimits) -> Self {
        self.limits = limits;
        self
    }

    #[must_use]
    pub fn with_max_remedies(mut self, max_remedies: usize) -> Self {
        self.max_remedies = max_remedies;
        self
    }
}

impl Default for WhyNotOptions {
    fn default() -> Self {
        Self {
            limits: QueryLimits::default(),
            max_remedies: Self::DEFAULT_MAX_REMEDIES,
        }
    }
}

/// What denied the request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Cause {
    /// An override ruled before the grants. No change of grants or roles can undo it, so there are
    /// no remedies.
    Override { name: String },
    /// A `deny` grant decided.
    Deny {
        grant_id: String,
        permission: String,
        target: TargetSelector,
    },
    /// No grant applied (default deny).
    NoApplicableGrant,
    /// The permission is not in the catalog.
    UnknownPermission,
    /// The requested permission is `override_only`: grants are ignored for it, so only an override
    /// can allow it.
    OverrideOnlyPermission,
    /// A prerequisite (`depends_on`) is not allowed; `cause` is what denied that prerequisite.
    MissingPrerequisite { prerequisite: String, cause: Box<Cause> },
}

/// A known governance rule the remedy runs into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Caveat {
    /// A permission involved is `override_only`.
    OverrideOnly,
    /// A permission involved is `management_only`: only management roles may receive it.
    ManagementOnly,
    /// A permission involved is `non_delegable`: only the management permission holder may grant it.
    NonDelegable,
    /// The change edits a grant that is not the subject's own (a role's or everyone's), so it
    /// reaches other subjects too.
    AffectsOthers,
}

/// One change that, applied alone, makes the decision `allow`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Change {
    /// Assign `role` to the subject, restricted to `scope` (the narrowest step of the path).
    AssignRole {
        role: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scope: Option<Anchor>,
    },
    /// Add this `allow` (its id is a placeholder).
    AddGrant { grant: Box<Grant> },
    /// Remove the `deny` that decided.
    RemoveDeny {
        grant_id: String,
        permission: String,
        target: TargetSelector,
    },
    /// Take `field` out of the `fields` of the `deny` that decided.
    NarrowDeny { grant_id: String, field: String },
    /// Make the condition of this `allow` hold. `failed` are the leaves that were false and
    /// `unresolved` the ones that could not be evaluated (a missing attribute, for example), with the
    /// values the engine saw.
    SatisfyCondition {
        grant_id: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        failed: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        unresolved: Vec<String>,
    },
}

impl Change {
    /// Order of the answer, smallest reach first: a condition (no policy change), a grant on the
    /// exact target, a narrowed deny, a grant on the kind, a role, and last the removal of a deny.
    fn weight(&self) -> u8 {
        match self {
            Change::SatisfyCondition { .. } => 0,
            Change::AddGrant { grant } if grant.target.id.is_some() => 1,
            Change::NarrowDeny { .. } => 2,
            Change::AddGrant { .. } => 3,
            Change::AssignRole { .. } => 4,
            Change::RemoveDeny { .. } => 5,
        }
    }
}

/// A verified remedy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Remedy {
    #[serde(flatten)]
    pub change: Change,
    /// Position of the path step the change acts on (0 = most specific), when it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rank: Option<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caveats: Vec<Caveat>,
}

/// The answer of [`crate::Engine::why_not`]: what denied and what would allow.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Remedies {
    pub cause: Cause,
    /// Verified changes, smallest and most specific first. Empty when nothing alone would allow.
    pub remedies: Vec<Remedy>,
    /// The verification budget or `max_remedies` cut the list: there may be more.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub partial: bool,
}

enum Edit {
    Remove(String),
    Replace(String, Grant),
    Add(Grant),
    Role(RoleAssignment),
}

struct Overlay<'a> {
    inner: &'a dyn GrantSource,
    edit: &'a Edit,
}

impl GrantSource for Overlay<'_> {
    fn visit(&self, subject: &Subject, resource: &Resource, visitor: &mut dyn FnMut(&Grant)) {
        self.inner.visit(subject, resource, &mut |grant| match self.edit {
            Edit::Remove(id) if &grant.id == id => {}
            Edit::Replace(id, replacement) if &grant.id == id => visitor(replacement),
            _ => visitor(grant),
        });
        if let Edit::Add(grant) = self.edit {
            visitor(grant);
        }
    }
}

struct Candidate {
    change: Change,
    edit: Edit,
    rank: Option<usize>,
    permissions: Vec<String>,
    shared: bool,
}

impl Engine {
    /// For a denial, the smallest changes that would make `request` an `allow`, each verified by
    /// deciding again on a copy. `None` when the request is already allowed.
    ///
    /// The answer names the cause ([`Cause`]); when an override decided it says so and offers no
    /// remedy. Grants of other subjects are never listed: only the `deny` that decided is named, and
    /// only a role's `allow` is used to suggest that role.
    pub fn why_not(&self, ctx: &Context<'_>, request: &Request<'_>, options: &WhyNotOptions) -> Option<Remedies> {
        let explanation = self.explain(ctx, request);
        if explanation.decision.is_allowed() {
            return None;
        }
        let (cause, source) = self.cause_and_source(ctx, request, &explanation);
        let mut out = Remedies {
            cause,
            remedies: Vec::new(),
            partial: false,
        };
        let Some(source) = source else {
            return Some(out);
        };
        let gen_request = source.request(request);
        let mut candidates = self.candidates(&gen_request, &source.explanation);
        candidates.sort_by_key(|c| (c.change.weight(), c.rank));

        let mut budget = options.limits.max_decisions;
        for candidate in candidates {
            if budget == 0 {
                out.partial = true;
                break;
            }
            budget -= 1;
            if !self.verify(ctx, request, &candidate.edit) {
                continue;
            }
            if out.remedies.len() >= options.max_remedies {
                out.partial = true;
                break;
            }
            out.remedies.push(self.remedy(candidate));
        }
        Some(out)
    }

    /// The cause of the denial and the explanation candidates are drawn from (the prerequisite's,
    /// when that is what is missing). `None` when no change of grants or roles can help.
    fn cause_and_source(
        &self,
        ctx: &Context<'_>,
        request: &Request<'_>,
        explanation: &Explanation,
    ) -> (Cause, Option<Source>) {
        let cause = self.cause_of(explanation);
        match &explanation.decision.reason {
            Reason::MissingPrerequisite { prerequisite, .. } => {
                let sub = self.prerequisite_request(request, prerequisite);
                let sub_explanation = self.explain(ctx, &sub);
                let sub_cause = self.cause_of(&sub_explanation);
                let usable = sub_cause.is_actionable();
                let cause = Cause::MissingPrerequisite {
                    prerequisite: prerequisite.clone(),
                    cause: Box::new(sub_cause),
                };
                let source = usable.then(|| Source {
                    permission: prerequisite.clone(),
                    field: sub.field.map(str::to_string),
                    explanation: sub_explanation,
                });
                (cause, source)
            }
            _ => {
                let source = cause.is_actionable().then(|| Source {
                    permission: request.permission.to_string(),
                    field: request.field.map(str::to_string),
                    explanation: explanation.clone(),
                });
                (cause, source)
            }
        }
    }

    fn cause_of(&self, explanation: &Explanation) -> Cause {
        match &explanation.decision.reason {
            Reason::Override { name } => Cause::Override { name: name.clone() },
            Reason::UnknownPermission => Cause::UnknownPermission,
            Reason::MissingPrerequisite { prerequisite, .. } => Cause::MissingPrerequisite {
                prerequisite: prerequisite.clone(),
                cause: Box::new(Cause::NoApplicableGrant),
            },
            Reason::Grant { .. } => match explanation.decisive() {
                Some(trace) => Cause::Deny {
                    grant_id: trace.grant.id.clone(),
                    permission: trace.grant.permission.clone(),
                    target: trace.grant.target.clone(),
                },
                None => Cause::NoApplicableGrant,
            },
            Reason::NoApplicableGrant if self.catalog.is_override_only(&explanation.permission) => {
                Cause::OverrideOnlyPermission
            }
            Reason::NoApplicableGrant => Cause::NoApplicableGrant,
        }
    }

    fn candidates(&self, request: &Request<'_>, explanation: &Explanation) -> Vec<Candidate> {
        let mut out = Vec::new();
        self.deny_candidates(request, explanation, &mut out);
        self.add_grant_candidates(request, &mut out);
        let mut roles_seen = Vec::new();
        for trace in &explanation.grants {
            self.role_candidate(request, trace, &mut roles_seen, &mut out);
            self.condition_candidate(trace, &mut out);
        }
        out
    }

    fn deny_candidates(&self, request: &Request<'_>, explanation: &Explanation, out: &mut Vec<Candidate>) {
        let Some(trace) = explanation.decisive().filter(|t| t.grant.effect == Effect::Deny) else {
            return;
        };
        let deny = &trace.grant;
        let shared = deny.subject != own_matcher(request.subject);
        let permissions = vec![deny.permission.clone()];
        out.push(Candidate {
            change: Change::RemoveDeny {
                grant_id: deny.id.clone(),
                permission: deny.permission.clone(),
                target: deny.target.clone(),
            },
            edit: Edit::Remove(deny.id.clone()),
            rank: trace.rank,
            permissions: permissions.clone(),
            shared,
        });
        let Some(field) = request.field else { return };
        if !deny.fields.iter().any(|f| f == field) || deny.fields.len() < 2 {
            return;
        }
        let mut narrowed = deny.clone();
        narrowed.fields.retain(|f| f != field);
        out.push(Candidate {
            change: Change::NarrowDeny {
                grant_id: deny.id.clone(),
                field: field.to_string(),
            },
            edit: Edit::Replace(deny.id.clone(), narrowed),
            rank: trace.rank,
            permissions,
            shared,
        });
    }

    fn add_grant_candidates(&self, request: &Request<'_>, out: &mut Vec<Candidate>) {
        let Some(matcher) = request_matcher(request.subject) else {
            return;
        };
        let Some((rank, anchor)) = request.resource.anchors().next() else {
            return;
        };
        let mut targets = vec![TargetSelector::from(anchor)];
        if anchor.id.is_some() {
            targets.push(TargetSelector::kind(anchor.kind.clone()));
        }
        for target in targets {
            let mut grant = Grant::allow(
                format!("suggested:{}:{}", request.permission, target_label(&target)),
                matcher.clone(),
                request.permission,
                target,
            );
            if let Some(field) = request.field {
                grant.fields = vec![field.to_string()];
            }
            if self.validate_grant(&grant).is_err() {
                continue;
            }
            out.push(Candidate {
                change: Change::AddGrant {
                    grant: Box::new(grant.clone()),
                },
                edit: Edit::Add(grant),
                rank: Some(rank),
                permissions: vec![request.permission.to_string()],
                shared: false,
            });
        }
    }

    fn role_candidate(
        &self,
        request: &Request<'_>,
        trace: &GrantTrace,
        seen: &mut Vec<String>,
        out: &mut Vec<Candidate>,
    ) {
        let SubjectMatcher::Role { id } = &trace.grant.subject else {
            return;
        };
        if trace.grant.effect != Effect::Allow || trace.verdict != Verdict::SubjectMismatch || seen.contains(id) {
            return;
        }
        seen.push(id.clone());
        let scope = request
            .resource
            .path
            .first()
            .filter(|a| !a.is_global() && a.id.is_some())
            .cloned();
        let assignment = match &scope {
            Some(anchor) => RoleAssignment::in_scope(id.clone(), anchor.clone()),
            None => RoleAssignment::new(id.clone()),
        };
        out.push(Candidate {
            change: Change::AssignRole {
                role: id.clone(),
                scope,
            },
            edit: Edit::Role(assignment),
            rank: trace.rank,
            permissions: vec![trace.grant.permission.clone()],
            shared: false,
        });
    }

    fn condition_candidate(&self, trace: &GrantTrace, out: &mut Vec<Candidate>) {
        let grant = &trace.grant;
        if grant.effect != Effect::Allow
            || !matches!(
                trace.verdict,
                Verdict::ConditionFalse | Verdict::ConditionUnresolved { .. }
            )
        {
            return;
        }
        let Some(condition) = &trace.condition else {
            return;
        };
        let (mut failed, mut unresolved) = (Vec::new(), Vec::new());
        failing_leaves(condition, &mut failed, &mut unresolved);
        let mut relaxed = grant.clone();
        relaxed.condition = None;
        out.push(Candidate {
            change: Change::SatisfyCondition {
                grant_id: grant.id.clone(),
                failed,
                unresolved,
            },
            edit: Edit::Replace(grant.id.clone(), relaxed),
            rank: trace.rank,
            permissions: vec![grant.permission.clone()],
            shared: false,
        });
    }

    /// Decides `request` again with the candidate's edit applied to a copy.
    fn verify(&self, ctx: &Context<'_>, request: &Request<'_>, edit: &Edit) -> bool {
        let subject: Cow<'_, Subject> = match edit {
            Edit::Role(assignment) => {
                let mut copy = request.subject.clone();
                copy.roles.push(assignment.clone());
                Cow::Owned(copy)
            }
            _ => Cow::Borrowed(request.subject),
        };
        let overlay = Overlay {
            inner: ctx.grants,
            edit,
        };
        let edited = Context {
            grants: &overlay,
            ..*ctx
        };
        let mut asked = Request::new(&subject, request.permission, request.resource);
        asked.field = request.field;
        self.decide_unobserved(&edited, &asked).is_allowed()
    }

    fn remedy(&self, candidate: Candidate) -> Remedy {
        let mut caveats = Vec::new();
        for permission in &candidate.permissions {
            let Some(def) = self.catalog.get(permission) else {
                continue;
            };
            for (flag, caveat) in [
                (def.override_only, Caveat::OverrideOnly),
                (def.management_only, Caveat::ManagementOnly),
                (def.non_delegable, Caveat::NonDelegable),
            ] {
                if flag && !caveats.contains(&caveat) {
                    caveats.push(caveat);
                }
            }
        }
        if candidate.shared {
            caveats.push(Caveat::AffectsOthers);
        }
        Remedy {
            change: candidate.change,
            rank: candidate.rank,
            caveats,
        }
    }
}

struct Source {
    permission: String,
    field: Option<String>,
    explanation: Explanation,
}

impl Source {
    fn request<'a>(&'a self, original: &Request<'a>) -> Request<'a> {
        let mut request = *original;
        request.permission = &self.permission;
        request.field = self.field.as_deref();
        request
    }
}

impl Cause {
    /// Can a change of grants or roles alter this cause?
    fn is_actionable(&self) -> bool {
        matches!(self, Cause::Deny { .. } | Cause::NoApplicableGrant)
    }
}

fn own_matcher(subject: &Subject) -> SubjectMatcher {
    subject
        .id
        .as_ref()
        .map_or(SubjectMatcher::Any, |id| SubjectMatcher::user(id.clone()))
}

/// Who a suggested grant is for: the subject by id, or its first principal when it has no id.
fn request_matcher(subject: &Subject) -> Option<SubjectMatcher> {
    match (&subject.id, subject.principals.first()) {
        (Some(id), _) => Some(SubjectMatcher::user(id.clone())),
        (None, Some(principal)) => Some(SubjectMatcher::principal(principal.clone())),
        (None, None) => None,
    }
}

fn target_label(target: &TargetSelector) -> String {
    match &target.id {
        Some(id) => format!("{}:{id}", target.kind),
        None => target.kind.clone(),
    }
}

/// The false and the unresolved leaves of a condition tree: what would have to change.
fn failing_leaves(node: &ConditionTrace, failed: &mut Vec<String>, unresolved: &mut Vec<String>) {
    match &node.result {
        TraceResult::True | TraceResult::Skipped => {}
        result if node.children.is_empty() => match result {
            TraceResult::Error(problem) => unresolved.push(format!("{}: {problem}", node.label)),
            _ => failed.push(node.label.clone()),
        },
        _ => {
            let negated = node.label == "não";
            if negated {
                let inner: Vec<&str> = node.children.iter().map(|c| c.label.as_str()).collect();
                failed.push(format!("não ({})", inner.join(", ")));
                return;
            }
            for child in &node.children {
                failing_leaves(child, failed, unresolved);
            }
        }
    }
}
