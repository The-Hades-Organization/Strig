//! Listing and reverse queries: which resources a subject reaches, and who reaches a resource.
//!
//! [`Engine::check`] answers one question about one resource. This module answers the questions
//! asked from the other side without enumerating a table:
//!
//! - [`Engine::list`] turns a subject, a permission and a resource kind into an [`AccessFilter`]:
//!   a description of the reach (the whole kind, a set of ids, everything inside some scopes,
//!   nothing) that a database turns into a `WHERE` clause and that [`AccessFilter::resolve`]
//!   evaluates over in-memory resources. What cannot be decided without the resource (an ABAC
//!   condition over a resource attribute, an override that is a closure) stays as an explicit
//!   residue to check row by row; it is never read as an allow.
//! - [`Engine::who_can`], [`Engine::who_can_on`] and [`Engine::access_of`] ask who holds a
//!   permission, and [`Engine::check_for`] asks one subject by reference, with the path that
//!   decided.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

use crate::attr::{Attributes, Value};
use crate::condition::{Condition, ConditionRegistry, EvalContext, Operand};
use crate::decision::{Decision, Reason, Request};
use crate::engine::{Context, Engine};
use crate::explain::Explanation;
use crate::grant::{Effect, Grant, GrantIndex, SubjectMatcher, TargetSelector};
use crate::overrides::{OverrideGate, OverrideReach, ReachRequest, SubjectsRequest};
use crate::rebac::{RebacError, TupleIndex, TupleStore, TupleSubject};
use crate::resource::{Anchor, GLOBAL, ObjectRef, Resource};
use crate::strategy::{Candidate, NativeStrategy, Strategy};
use crate::subject::{AUTHENTICATED, RoleAssignment, Subject};

static EMPTY_ENV: Attributes = Attributes::new();

/// Ceilings on the work a reverse query does, so a large table cannot turn one call into an
/// unbounded loop. Past a ceiling the query fails with [`QueryError::LimitExceeded`], never with a
/// partial answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct QueryLimits {
    /// Most parties (users, roles, principals, usersets) one query decides for.
    pub max_parties: usize,
    /// Most [`Engine::check`]-equivalent decisions one query makes: parties times permissions for
    /// [`Engine::access_of`], parties plus party-and-deny pairs for [`Engine::who_can_on`].
    pub max_decisions: usize,
}

impl QueryLimits {
    /// Default of [`QueryLimits::max_parties`].
    pub const DEFAULT_MAX_PARTIES: usize = 10_000;
    /// Default of [`QueryLimits::max_decisions`]: a few seconds of work.
    pub const DEFAULT_MAX_DECISIONS: usize = 500_000;

    #[must_use]
    pub fn with_max_parties(mut self, max_parties: usize) -> Self {
        self.max_parties = max_parties;
        self
    }

    #[must_use]
    pub fn with_max_decisions(mut self, max_decisions: usize) -> Self {
        self.max_decisions = max_decisions;
        self
    }

    fn check(what: &'static str, used: usize, limit: usize) -> Result<(), QueryError> {
        if used > limit {
            return Err(QueryError::LimitExceeded { what, limit });
        }
        Ok(())
    }
}

impl Default for QueryLimits {
    fn default() -> Self {
        Self {
            max_parties: Self::DEFAULT_MAX_PARTIES,
            max_decisions: Self::DEFAULT_MAX_DECISIONS,
        }
    }
}

/// Data for a listing or a reverse query: indexed grants, indexed ReBAC tuples and the
/// environment attributes. The counterpart of [`Context`] for the queries that start without a
/// resource.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub struct QueryContext<'a> {
    pub grants: &'a dyn GrantIndex,
    pub tuples: Option<&'a dyn TupleIndex>,
    pub env: &'a Attributes,
    pub limits: QueryLimits,
    /// The instant the queries are answered at, in milliseconds since the Unix epoch. Without it a
    /// grant or a role assignment with a validity window grants nothing, and a `deny` with a window
    /// still holds, exactly as in [`Engine::check`] with no instant.
    pub now: Option<u64>,
}

impl<'a> QueryContext<'a> {
    pub fn new(grants: &'a dyn GrantIndex) -> Self {
        Self {
            grants,
            tuples: None,
            env: &EMPTY_ENV,
            now: None,
            limits: QueryLimits {
                max_parties: QueryLimits::DEFAULT_MAX_PARTIES,
                max_decisions: QueryLimits::DEFAULT_MAX_DECISIONS,
            },
        }
    }

    #[must_use]
    pub fn with_limits(mut self, limits: QueryLimits) -> Self {
        self.limits = limits;
        self
    }

    pub fn with_tuples(mut self, tuples: &'a dyn TupleIndex) -> Self {
        self.tuples = Some(tuples);
        self
    }

    /// Answers the queries at `now`, like [`Context::at`]: grants and role assignments outside
    /// their validity window stop counting.
    #[must_use]
    pub fn at(mut self, now: u64) -> Self {
        self.now = Some(now);
        self
    }

    pub fn with_env(mut self, env: &'a Attributes) -> Self {
        self.env = env;
        self
    }

    /// The same data as a [`Context`], to run [`Engine::check`] over the same sources.
    pub fn context(&self) -> Context<'a> {
        let mut ctx = Context::new(self.grants).with_env(self.env);
        if let Some(now) = self.now {
            ctx = ctx.at(now);
        }
        if let Some(tuples) = self.tuples {
            ctx = ctx.with_tuples(tuples);
        }
        ctx
    }
}

/// Error of a query that names its subject by reference.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum QueryError {
    /// The [`SubjectResolver`] does not know the subject, and it is not a kind that can be
    /// represented without loading.
    #[error("subject not found: {0}")]
    UnknownSubject(SubjectRef),
    /// The query would go past one of the [`QueryLimits`].
    #[error("query limit exceeded: more than {limit} {what}")]
    LimitExceeded { what: &'static str, limit: usize },
    /// A deny grant through a relation could not be settled because the relation chain is deeper
    /// than the engine allows. The query fails instead of leaving the denied party in the answer.
    #[error("relation depth exceeded while reading the deny grant {grant_id}")]
    RelationDepthExceeded { grant_id: String },
}

/// A party named by a grant or a tuple, in the terms the queries use: it keeps the kind of the
/// subject (a user, a role, a principal, a userset), so a grant to a role is reported as the role,
/// not as each of its members.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum SubjectRef {
    /// A subject by id (`SubjectMatcher::User`).
    User { id: String },
    /// A direct object of a ReBAC tuple (`group:9`, `service:billing`).
    Object { kind: String, id: String },
    /// Whoever has the role, directly or inherited.
    Role { id: String },
    /// Whoever carries the principal.
    Principal { name: String },
    /// Everyone who has `relation` on `object` (`group:9#member`).
    Userset { object: ObjectRef, relation: String },
    /// Every subject of a kind (`user:*`).
    Wildcard { kind: String },
    /// Any subject.
    Anyone,
}

impl fmt::Display for SubjectRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SubjectRef::User { id } => write!(f, "user:{id}"),
            SubjectRef::Object { kind, id } => write!(f, "{kind}:{id}"),
            SubjectRef::Role { id } => write!(f, "role:{id}"),
            SubjectRef::Principal { name } => write!(f, "principal:{name}"),
            SubjectRef::Userset { object, relation } => write!(f, "{object}#{relation}"),
            SubjectRef::Wildcard { kind } => write!(f, "{kind}:*"),
            SubjectRef::Anyone => f.write_str("anyone"),
        }
    }
}

/// Loads the [`Subject`] (roles, principals, attributes) behind a [`SubjectRef`].
pub trait SubjectResolver {
    fn resolve(&self, subject: &SubjectRef) -> Option<Subject>;
}

impl<F> SubjectResolver for F
where
    F: Fn(&SubjectRef) -> Option<Subject>,
{
    fn resolve(&self, subject: &SubjectRef) -> Option<Subject> {
        self(subject)
    }
}

/// Subjects kept in memory, by reference.
#[derive(Debug, Clone, Default)]
pub struct InMemorySubjects {
    subjects: BTreeMap<SubjectRef, Subject>,
}

impl InMemorySubjects {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, reference: SubjectRef, subject: Subject) {
        self.subjects.insert(reference, subject);
    }

    /// Registers an identified subject under the reference that names it.
    pub fn with(mut self, subject: Subject) -> Self {
        if let Some(id) = subject.id.clone() {
            let reference = if subject.kind == "user" {
                SubjectRef::User { id }
            } else {
                SubjectRef::Object {
                    kind: subject.kind.clone(),
                    id,
                }
            };
            self.subjects.insert(reference, subject);
        }
        self
    }
}

impl SubjectResolver for InMemorySubjects {
    fn resolve(&self, subject: &SubjectRef) -> Option<Subject> {
        self.subjects.get(subject).cloned()
    }
}

// ---------------------------------------------------------------------------------------------
// Expr
// ---------------------------------------------------------------------------------------------

/// A condition over a resource, built from what the listing could settle about the subject.
///
/// The atoms that talk about the path assume that a kind appears at most once in a resource's
/// path (a document has one project), which is how the path is built.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Expr {
    True,
    False,
    /// The resource path goes through this step (the implicit `global` always does).
    Within(Anchor),
    /// Some step of the path matches the selector.
    OnPath(TargetSelector),
    /// The step of this kind has one of these ids.
    AnchorIn {
        kind: String,
        ids: BTreeSet<String>,
    },
    /// The resource attribute holds this string.
    AttrEq {
        attr: String,
        value: String,
    },
    /// A part that only the resource can settle, by index into [`AccessFilter::residual`].
    Residual(usize),
    Not(Box<Expr>),
    And(Vec<Expr>),
    Or(Vec<Expr>),
}

impl Expr {
    #[allow(clippy::should_implement_trait)]
    pub fn not(expr: Expr) -> Expr {
        Expr::Not(Box::new(expr))
    }

    fn id_of<'a>(resource: &'a Resource, kind: &str) -> Option<&'a str> {
        resource
            .anchors()
            .find(|(_, anchor)| anchor.kind == kind)
            .and_then(|(_, anchor)| anchor.id.as_deref())
    }

    /// Evaluates over a resource. `residual` settles the residual parts; `None` is unknown, and
    /// the logic is three-valued (an unknown part does not hide what the rest decides).
    pub fn holds(&self, resource: &Resource, residual: &dyn Fn(usize) -> Option<bool>) -> Option<bool> {
        match self {
            Expr::True => Some(true),
            Expr::False => Some(false),
            Expr::Within(anchor) => Some(resource.contains(anchor)),
            Expr::OnPath(selector) => Some(resource.locate(selector).is_some()),
            Expr::AnchorIn { kind, ids } => Some(Self::id_of(resource, kind).is_some_and(|id| ids.contains(id))),
            Expr::AttrEq { attr, value } => Some(matches!(
                resource.attrs.get(attr),
                Some(Value::Str(held)) if held == value
            )),
            Expr::Residual(index) => residual(*index),
            Expr::Not(inner) => inner.holds(resource, residual).map(|v| !v),
            Expr::And(items) => {
                let mut unknown = false;
                for item in items {
                    match item.holds(resource, residual) {
                        Some(false) => return Some(false),
                        Some(true) => {}
                        None => unknown = true,
                    }
                }
                (!unknown).then_some(true)
            }
            Expr::Or(items) => {
                let mut unknown = false;
                for item in items {
                    match item.holds(resource, residual) {
                        Some(true) => return Some(true),
                        Some(false) => {}
                        None => unknown = true,
                    }
                }
                (!unknown).then_some(false)
            }
        }
    }

    /// The same expression with every residual index replaced by `f(index)`.
    #[must_use]
    pub fn map_residuals(&self, f: &dyn Fn(usize) -> usize) -> Expr {
        match self {
            Expr::Residual(index) => Expr::Residual(f(*index)),
            Expr::Not(inner) => Expr::Not(Box::new(inner.map_residuals(f))),
            Expr::And(items) => Expr::And(items.iter().map(|e| e.map_residuals(f)).collect()),
            Expr::Or(items) => Expr::Or(items.iter().map(|e| e.map_residuals(f)).collect()),
            other => other.clone(),
        }
    }

    /// Whether any residual part is left.
    pub fn has_residual(&self) -> bool {
        match self {
            Expr::Residual(_) => true,
            Expr::Not(inner) => inner.has_residual(),
            Expr::And(items) | Expr::Or(items) => items.iter().any(Expr::has_residual),
            _ => false,
        }
    }

    /// The equivalent expression with constants folded, nesting flattened and the exact steps
    /// (`project:42`) written as id sets, which merge.
    #[must_use]
    pub fn simplify(&self) -> Expr {
        match self {
            Expr::Within(anchor) if anchor.is_global() => Expr::True,
            Expr::Within(Anchor { kind, id: Some(id) }) => Expr::AnchorIn {
                kind: kind.clone(),
                ids: BTreeSet::from([id.clone()]),
            },
            Expr::OnPath(selector) if selector.kind == GLOBAL => Expr::True,
            Expr::OnPath(TargetSelector { kind, id: Some(id) }) => Expr::AnchorIn {
                kind: kind.clone(),
                ids: BTreeSet::from([id.clone()]),
            },
            Expr::AnchorIn { ids, .. } if ids.is_empty() => Expr::False,
            Expr::Not(inner) => match inner.simplify() {
                Expr::True => Expr::False,
                Expr::False => Expr::True,
                Expr::Not(twice) => *twice,
                other => Expr::Not(Box::new(other)),
            },
            Expr::And(items) => Self::simplify_and(items),
            Expr::Or(items) => Self::simplify_or(items),
            other => other.clone(),
        }
    }

    fn simplify_and(items: &[Expr]) -> Expr {
        let mut flat: Vec<Expr> = Vec::new();
        for item in items {
            match item.simplify() {
                Expr::True => {}
                Expr::False => return Expr::False,
                Expr::And(inner) => flat.extend(inner),
                other => flat.push(other),
            }
        }
        let merged = Self::merge_terms(flat, |held, ids| held.retain(|id| ids.contains(id)));
        if merged
            .iter()
            .any(|e| matches!(e, Expr::AnchorIn { ids, .. } if ids.is_empty()))
        {
            return Expr::False;
        }
        Self::collapse(merged, Expr::True, Expr::And)
    }

    fn simplify_or(items: &[Expr]) -> Expr {
        let mut flat: Vec<Expr> = Vec::new();
        for item in items {
            match item.simplify() {
                Expr::False => {}
                Expr::True => return Expr::True,
                Expr::Or(inner) => flat.extend(inner),
                other => flat.push(other),
            }
        }
        let merged = Self::merge_terms(flat, |held, ids| held.extend(ids.iter().cloned()));
        Self::collapse(merged, Expr::False, Expr::Or)
    }

    /// Drops repeated terms and merges the id sets of the terms on the same kind with `combine`,
    /// in one pass (a hash set and a map by kind, not a scan per term).
    fn merge_terms(terms: Vec<Expr>, combine: impl Fn(&mut BTreeSet<String>, &BTreeSet<String>)) -> Vec<Expr> {
        let mut merged: Vec<Expr> = Vec::with_capacity(terms.len());
        let mut seen: HashSet<Expr> = HashSet::new();
        let mut slot_of_kind: HashMap<String, usize> = HashMap::new();
        for item in terms {
            if let Expr::AnchorIn { kind, ids } = &item {
                match slot_of_kind.get(kind) {
                    Some(&slot) => {
                        if let Some(Expr::AnchorIn { ids: held, .. }) = merged.get_mut(slot) {
                            combine(held, ids);
                        }
                    }
                    None => {
                        slot_of_kind.insert(kind.clone(), merged.len());
                        merged.push(item);
                    }
                }
            } else if seen.insert(item.clone()) {
                merged.push(item);
            }
        }
        merged
    }

    fn collapse(mut terms: Vec<Expr>, empty: Expr, join: fn(Vec<Expr>) -> Expr) -> Expr {
        match terms.len() {
            0 => empty,
            1 => terms.remove(0),
            _ => join(terms),
        }
    }

    /// Bounds when every residual part is unknown: `lower` holds only where the expression
    /// certainly holds, `upper` wherever it may hold. Without residue both are the expression.
    pub fn bounds(&self) -> (Expr, Expr) {
        match self {
            Expr::Residual(_) => (Expr::False, Expr::True),
            Expr::Not(inner) => {
                let (lower, upper) = inner.bounds();
                (Expr::not(upper), Expr::not(lower))
            }
            Expr::And(items) => {
                let (lower, upper): (Vec<_>, Vec<_>) = items.iter().map(Expr::bounds).unzip();
                (Expr::And(lower).simplify(), Expr::And(upper).simplify())
            }
            Expr::Or(items) => {
                let (lower, upper): (Vec<_>, Vec<_>) = items.iter().map(Expr::bounds).unzip();
                (Expr::Or(lower).simplify(), Expr::Or(upper).simplify())
            }
            other => (other.simplify(), other.simplify()),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Layout and shape
// ---------------------------------------------------------------------------------------------

/// Order of the kinds in a resource path, most specific first: `PathLayout::new("document")
/// .within("doc_type").within("project").within("org")`. The strategy reads specificity from the
/// path position, so turning the filter into a structural [`Expr`] needs the order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathLayout {
    kinds: Vec<String>,
}

impl PathLayout {
    pub fn new(kind: impl Into<String>) -> Self {
        Self {
            kinds: vec![kind.into()],
        }
    }

    /// Adds a broader step at the end.
    #[must_use]
    pub fn within(mut self, kind: impl Into<String>) -> Self {
        self.kinds.push(kind.into());
        self
    }

    pub fn kinds(&self) -> &[String] {
        &self.kinds
    }

    fn rank(&self, kind: &str) -> Option<usize> {
        if kind == GLOBAL {
            return Some(self.kinds.len());
        }
        self.kinds.iter().position(|k| k == kind)
    }
}

/// The reach of a listing, in the simplest terms that describe it.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum FilterShape {
    /// No resource.
    Nothing,
    /// Every resource of the kind except the listed ids (empty: the whole kind).
    Kind { except: BTreeSet<String> },
    /// Exactly these ids.
    Ids(BTreeSet<String>),
    /// Everything inside any of these steps of the path.
    Within(Vec<Anchor>),
    /// Anything else, as a structural expression.
    Compound(Expr),
}

/// What an [`AccessFilter`] knows about one resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterOutcome {
    Allowed,
    Denied,
    /// Depends on something the filter cannot inspect (an override that is a closure).
    Undecided,
}

/// Result of [`AccessFilter::resolve`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FilterResolution {
    /// Ids of the resources the filter allows.
    pub allowed: Vec<String>,
    /// Ids of the resources the filter cannot decide: check them with [`Engine::check`] or
    /// [`AccessFilter::resolve_with`].
    pub undecided: Vec<String>,
}

/// How a listing sees a grant. A listing answers for the whole resource, so a field-restricted
/// `allow` is left out (it never opens the resource) and a field-restricted `deny` counts as a
/// plain one (it keeps the resource out, failing closed). See [`crate::field`].
pub(crate) fn whole_resource_form(grant: &Grant) -> Option<Grant> {
    match (grant.is_field_restricted(), grant.effect) {
        (false, _) => Some(grant.clone()),
        (true, Effect::Allow) => None,
        (true, Effect::Deny) => {
            let mut whole = grant.clone();
            whole.fields.clear();
            Some(whole)
        }
    }
}

/// A part of the decision that only the resource can settle.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum FilterResidual {
    /// A condition over resource attributes, to evaluate row by row.
    Condition { grant_id: String, condition: Condition },
    /// An override that cannot describe where it decides.
    Override { name: String },
    /// A strategy the filter does not reproduce structurally.
    Strategy { name: String },
    /// Grants whose target kind is not a step of the [`PathLayout`] the structural form was asked
    /// for: where they apply depends on the resource's real path, so the structural form cannot
    /// say. Only [`AccessFilter::residual_for`] lists it.
    OutsideLayout { grant_ids: Vec<String> },
}

// ---------------------------------------------------------------------------------------------
// AccessFilter
// ---------------------------------------------------------------------------------------------

#[derive(Clone)]
struct Entry {
    grant: Grant,
    /// Scope and subject side, settled for this subject.
    gate: Expr,
    residual: Option<usize>,
}

#[derive(Clone)]
struct OverridePlan {
    reach: OverrideReach,
    residual: Option<usize>,
    /// Where the residuals of a nested listing (`OverrideGate::Holds`) start in the outer list.
    nested_offset: usize,
}

impl OverridePlan {
    /// The nested listing of an override that decides where another permission is held.
    fn nested(&self) -> Option<&AccessFilter> {
        match &self.reach {
            OverrideReach::Allows(OverrideGate::Holds(nested)) | OverrideReach::Denies(OverrideGate::Holds(nested))
                if nested.known =>
            {
                Some(nested)
            }
            _ => None,
        }
    }
}

/// The reach of one subject with one permission over the resources of one kind.
///
/// Built by [`Engine::list`]. It holds the grants that can apply to the subject, with the subject
/// side already settled, so it never enumerates the resources.
#[derive(Clone)]
pub struct AccessFilter {
    kind: String,
    permission: String,
    known: bool,
    subject: Subject,
    env: Attributes,
    /// The decision instant the listing was built for, which the time conditions read.
    now: Option<u64>,
    conditions: ConditionRegistry,
    strategy: Arc<dyn Strategy>,
    /// The strategy as a crate strategy, when it really is one (not decided by its name).
    native: Option<NativeStrategy>,
    entries: Vec<Entry>,
    overrides: Vec<OverridePlan>,
    residuals: Vec<FilterResidual>,
    strategy_residual: Option<usize>,
    warnings: Vec<String>,
    /// The listings of the permission's `depends_on` closure: an allow only stands where all of
    /// them allow too, as in `check`.
    prerequisites: Vec<PrerequisitePlan>,
}

/// The listing of one prerequisite, with where its residuals were copied into the outer filter.
#[derive(Clone)]
struct PrerequisitePlan {
    filter: AccessFilter,
    offset: usize,
}

impl fmt::Debug for AccessFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccessFilter")
            .field("kind", &self.kind)
            .field("permission", &self.permission)
            .field("grants", &self.entries.iter().map(|e| &e.grant.id).collect::<Vec<_>>())
            .field("residuals", &self.residuals)
            .field("strategy", &self.strategy.name())
            .finish_non_exhaustive()
    }
}

impl AccessFilter {
    /// The resource kind the filter lists.
    pub fn kind(&self) -> &str {
        &self.kind
    }

    pub fn permission(&self) -> &str {
        &self.permission
    }

    /// The parts that only the resource can settle.
    pub fn residual(&self) -> &[FilterResidual] {
        &self.residuals
    }

    /// The parts that only the resource can settle, including the ones that depend on `layout`
    /// (the indexes `Expr::Residual` of [`AccessFilter::expr`] point into this list).
    pub fn residual_for(&self, layout: &PathLayout) -> Vec<FilterResidual> {
        let mut out = self.residuals.clone();
        let grant_ids = self.outside_layout(layout);
        if !grant_ids.is_empty() {
            out.push(FilterResidual::OutsideLayout { grant_ids });
        }
        out
    }

    /// Ids of the grants (this filter's and its nested listings') whose target kind is not in
    /// `layout`.
    fn outside_layout(&self, layout: &PathLayout) -> Vec<String> {
        let mut ids: BTreeSet<String> = self
            .entries
            .iter()
            .filter(|e| layout.rank(&e.grant.target.kind).is_none())
            .map(|e| e.grant.id.clone())
            .collect();
        for plan in &self.overrides {
            if let Some(nested) = plan.nested() {
                ids.extend(nested.outside_layout(layout));
            }
        }
        for plan in &self.prerequisites {
            ids.extend(plan.filter.outside_layout(layout));
        }
        ids.into_iter().collect()
    }

    /// Problems found while planning (a relation grant with no tuple store, a condition that
    /// failed for every resource). An allow with a problem is left out, a deny with a problem
    /// applies, as in [`Engine::check`].
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Whether the structural form over `layout` has no residue: the database alone settles it.
    pub fn is_exact(&self, layout: &PathLayout) -> bool {
        !self.expr(layout).has_residual()
    }

    /// Decides one resource from the filter alone (no engine, no sources). Resources of another
    /// kind are denied.
    pub fn allows(&self, resource: &Resource) -> FilterOutcome {
        if resource.primary().is_none_or(|anchor| anchor.kind != self.kind) {
            return FilterOutcome::Denied;
        }
        self.decide_row(resource, true)
    }

    /// Ids of the resources of the kind that the filter allows, evaluating it over `resources`
    /// (for in-memory sources). The undecided ones are reported apart.
    pub fn resolve<'r>(&self, resources: impl IntoIterator<Item = &'r Resource>) -> FilterResolution {
        let mut out = FilterResolution::default();
        for resource in resources {
            let Some(id) = resource.primary().and_then(|a| a.id.clone()) else {
                continue;
            };
            match self.allows(resource) {
                FilterOutcome::Allowed => out.allowed.push(id),
                FilterOutcome::Undecided => out.undecided.push(id),
                FilterOutcome::Denied => {}
            }
        }
        out
    }

    /// Like [`AccessFilter::resolve`], settling the undecided resources with [`Engine::check`].
    pub fn resolve_with<'r>(
        &self,
        engine: &Engine,
        ctx: &Context<'_>,
        resources: impl IntoIterator<Item = &'r Resource>,
    ) -> Vec<String> {
        let mut by_id: BTreeMap<String, &Resource> = BTreeMap::new();
        let resolution = self.resolve(resources.into_iter().inspect(|r| {
            if let Some(id) = r.primary().and_then(|a| a.id.clone()) {
                by_id.insert(id, r);
            }
        }));
        let mut allowed = resolution.allowed;
        for id in resolution.undecided {
            if let Some(resource) = by_id.get(&id)
                && engine.check(ctx, &Request::new(&self.subject, &self.permission, resource))
            {
                allowed.push(id);
            }
        }
        allowed
    }

    /// The structural form of the filter over `layout`, for a database. The expression assumes
    /// the resource paths follow the layout.
    pub fn expr(&self, layout: &PathLayout) -> Expr {
        if !self.known {
            return Expr::False;
        }
        self.full_expr(layout).simplify()
    }

    /// The reach in its simplest description.
    pub fn shape(&self, layout: &PathLayout) -> FilterShape {
        let expr = self.expr(layout);
        let own = layout.kinds().first().map(String::as_str).unwrap_or_default();
        match &expr {
            Expr::False => FilterShape::Nothing,
            Expr::True => FilterShape::Kind {
                except: BTreeSet::new(),
            },
            Expr::AnchorIn { kind, ids } if kind == own => FilterShape::Ids(ids.clone()),
            Expr::Not(inner) => match inner.as_ref() {
                Expr::AnchorIn { kind, ids } if kind == own => FilterShape::Kind { except: ids.clone() },
                _ => FilterShape::Compound(expr),
            },
            Expr::AnchorIn { .. } => FilterShape::Within(Self::anchors_of(&expr)),
            Expr::Or(items)
                if items
                    .iter()
                    .all(|e| matches!(e, Expr::AnchorIn { kind, .. } if kind != own)) =>
            {
                FilterShape::Within(items.iter().flat_map(Self::anchors_of).collect())
            }
            _ => FilterShape::Compound(expr),
        }
    }

    fn anchors_of(expr: &Expr) -> Vec<Anchor> {
        match expr {
            Expr::AnchorIn { kind, ids } => ids.iter().map(|id| Anchor::new(kind.clone(), id.clone())).collect(),
            _ => Vec::new(),
        }
    }

    // --- structural form -------------------------------------------------------------------

    fn full_expr(&self, layout: &PathLayout) -> Expr {
        let outside = self.residuals.len();
        let mut acc = self.grants_expr(layout);
        for plan in self.overrides.iter().rev() {
            match &plan.reach {
                OverrideReach::Never => {}
                OverrideReach::Opaque => {
                    let unknown = plan.residual.map_or(Expr::False, Expr::Residual);
                    acc = Expr::Or(vec![unknown.clone(), Expr::And(vec![Expr::not(unknown), acc])]);
                }
                OverrideReach::Allows(gate) => acc = Expr::Or(vec![Self::gate_expr(plan, gate, layout, outside), acc]),
                OverrideReach::Denies(gate) => {
                    acc = Expr::And(vec![Expr::not(Self::gate_expr(plan, gate, layout, outside)), acc]);
                }
            }
        }
        if self.prerequisites.is_empty() {
            return acc;
        }
        let mut parts = vec![acc];
        for plan in &self.prerequisites {
            let own = plan.filter.residuals.len();
            parts.push(if plan.filter.known {
                plan.filter
                    .full_expr(layout)
                    .map_residuals(&|i| if i < own { i + plan.offset } else { outside })
            } else {
                Expr::False
            });
        }
        Expr::And(parts)
    }

    /// The gate of an override as an expression over the outer filter's residuals: the residuals
    /// of a nested listing were copied at `plan.nested_offset`, and the ones of its grants outside
    /// the layout fold into the outer `outside` slot.
    fn gate_expr(plan: &OverridePlan, gate: &OverrideGate, layout: &PathLayout, outside: usize) -> Expr {
        match gate {
            OverrideGate::Expr(expr) => expr.clone(),
            OverrideGate::Holds(filter) if filter.known => {
                let own = filter.residuals.len();
                filter.grants_expr(layout).map_residuals(&|i| {
                    if i < own { i + plan.nested_offset } else { outside }
                })
            }
            OverrideGate::Holds(_) => Expr::False,
        }
    }

    fn applies_expr(&self, index: usize) -> Expr {
        let entry = &self.entries[index];
        let mut parts = vec![Expr::OnPath(entry.grant.target.clone()), entry.gate.clone()];
        parts.extend(entry.residual.map(Expr::Residual));
        Expr::And(parts)
    }

    /// Combination of the grants by the strategy, without overrides. Its `Residual` indexes are
    /// relative to this filter, with the grants outside the layout at `self.residuals.len()`.
    fn grants_expr(&self, layout: &PathLayout) -> Expr {
        // (rank, effect, applies) in source order; a target outside the layout has no rank.
        let all: Vec<(Option<usize>, Effect, Expr)> = (0..self.entries.len())
            .map(|i| {
                let entry = &self.entries[i];
                (
                    layout.rank(&entry.grant.target.kind),
                    entry.grant.effect,
                    self.applies_expr(i),
                )
            })
            .collect();
        if all.iter().any(|(rank, _, _)| rank.is_none()) {
            // The strategy reads specificity from the path position, and a grant outside the layout
            // has none the filter can see: keep the upper bound (some allow applies) and leave the
            // rest to the row.
            let allows = all
                .iter()
                .filter(|(_, effect, _)| *effect == Effect::Allow)
                .map(|(_, _, applies)| applies.clone())
                .collect();
            return Expr::And(vec![Expr::Residual(self.residuals.len()), Expr::Or(allows)]);
        }
        let ranked: Vec<(usize, Effect, Expr)> = all
            .into_iter()
            .filter_map(|(rank, effect, applies)| Some((rank?, effect, applies)))
            .collect();
        let any = |effect: Effect, only_rank: Option<usize>| {
            Expr::Or(
                ranked
                    .iter()
                    .filter(|(r, e, _)| *e == effect && only_rank.is_none_or(|x| x == *r))
                    .map(|(_, _, applies)| applies.clone())
                    .collect(),
            )
        };
        let allow_any = any(Effect::Allow, None);
        match self.native {
            Some(NativeStrategy::MostSpecific) => {
                let ranks: BTreeSet<usize> = ranked.iter().map(|(r, _, _)| *r).collect();
                let mut none_before: Vec<Expr> = Vec::new();
                let mut terms = Vec::new();
                for rank in ranks {
                    let allow = any(Effect::Allow, Some(rank));
                    let deny = any(Effect::Deny, Some(rank));
                    let mut term = none_before.clone();
                    term.push(allow.clone());
                    term.push(Expr::not(deny.clone()));
                    terms.push(Expr::And(term));
                    none_before.push(Expr::not(allow));
                    none_before.push(Expr::not(deny));
                }
                Expr::Or(terms)
            }
            Some(NativeStrategy::DenyOverrides) => {
                Expr::And(vec![allow_any.clone(), Expr::not(any(Effect::Deny, None))])
            }
            Some(NativeStrategy::PermitOverrides) => allow_any.clone(),
            Some(NativeStrategy::FirstApplicable) => {
                // The first applicable grant decides, so a run of grants with the same effect
                // decides together: it holds if any of them applies, and otherwise the rest decides.
                // Built from the end, the expression grows with the grants, not with their square.
                let mut runs: Vec<(Effect, Vec<Expr>)> = Vec::new();
                for (_, effect, applies) in &ranked {
                    match runs.last_mut() {
                        Some((last, applied)) if last == effect => applied.push(applies.clone()),
                        _ => runs.push((*effect, vec![applies.clone()])),
                    }
                }
                runs.into_iter()
                    .rev()
                    .fold(Expr::False, |rest, (effect, applied)| match effect {
                        Effect::Allow => Expr::Or(vec![Expr::Or(applied), rest]),
                        Effect::Deny => Expr::And(vec![Expr::not(Expr::Or(applied)), rest]),
                    })
            }
            _ => Expr::And(vec![
                self.strategy_residual.map_or(Expr::False, Expr::Residual),
                allow_any,
            ]),
        }
    }

    // --- row evaluation --------------------------------------------------------------------

    fn residual_holds(&self, index: usize, resource: &Resource) -> Option<bool> {
        match self.residuals.get(index)? {
            FilterResidual::Condition { condition, .. } => {
                let ctx = EvalContext {
                    subject: &self.subject,
                    resource,
                    env: &self.env,
                };
                condition.evaluate_at(&ctx, &self.conditions, self.now).ok()
            }
            FilterResidual::Override { .. }
            | FilterResidual::Strategy { .. }
            | FilterResidual::OutsideLayout { .. } => None,
        }
    }

    fn gate_holds(&self, gate: &OverrideGate, resource: &Resource) -> Option<bool> {
        match gate {
            OverrideGate::Expr(expr) => expr.holds(resource, &|i| self.residual_holds(i, resource)),
            OverrideGate::Holds(filter) => match filter.decide_row(resource, false) {
                FilterOutcome::Allowed => Some(true),
                FilterOutcome::Denied => Some(false),
                FilterOutcome::Undecided => None,
            },
        }
    }

    fn decide_row(&self, resource: &Resource, with_overrides: bool) -> FilterOutcome {
        let own = self.decide_row_core(resource, with_overrides);
        if own == FilterOutcome::Denied || self.prerequisites.is_empty() {
            return own;
        }
        let mut outcome = own;
        for plan in &self.prerequisites {
            match plan.filter.decide_row_core(resource, with_overrides) {
                FilterOutcome::Denied => return FilterOutcome::Denied,
                FilterOutcome::Undecided => outcome = FilterOutcome::Undecided,
                FilterOutcome::Allowed => {}
            }
        }
        outcome
    }

    fn decide_row_core(&self, resource: &Resource, with_overrides: bool) -> FilterOutcome {
        if !self.known {
            return FilterOutcome::Denied;
        }
        if with_overrides {
            for plan in &self.overrides {
                let (gate, effect) = match &plan.reach {
                    OverrideReach::Never => continue,
                    OverrideReach::Opaque => return FilterOutcome::Undecided,
                    OverrideReach::Allows(gate) => (gate, FilterOutcome::Allowed),
                    OverrideReach::Denies(gate) => (gate, FilterOutcome::Denied),
                };
                match self.gate_holds(gate, resource) {
                    Some(true) => return effect,
                    Some(false) => {}
                    None => return FilterOutcome::Undecided,
                }
            }
        }
        let mut candidates: Vec<(usize, Effect, usize)> = Vec::new();
        for (index, entry) in self.entries.iter().enumerate() {
            let Some((rank, _)) = resource.locate(&entry.grant.target) else {
                continue;
            };
            if !entry.gate.holds(resource, &|_| None).unwrap_or(false) {
                continue;
            }
            if let Some(residual) = entry.residual {
                match self.residual_holds(residual, resource) {
                    Some(true) => {}
                    Some(false) => continue,
                    // The condition failed: an error never opens access.
                    None if entry.grant.effect == Effect::Allow => continue,
                    None => {}
                }
            }
            candidates.push((rank, entry.grant.effect, index));
        }
        match self.combine(&candidates) {
            Some(Effect::Allow) => FilterOutcome::Allowed,
            _ => FilterOutcome::Denied,
        }
    }

    fn combine(&self, candidates: &[(usize, Effect, usize)]) -> Option<Effect> {
        let has = |effect: Effect, rank: Option<usize>| {
            candidates
                .iter()
                .any(|(r, e, _)| *e == effect && rank.is_none_or(|x| x == *r))
        };
        match self.native {
            Some(NativeStrategy::MostSpecific) => {
                let best = candidates.iter().map(|(r, _, _)| *r).min()?;
                if has(Effect::Deny, Some(best)) {
                    Some(Effect::Deny)
                } else {
                    Some(Effect::Allow)
                }
            }
            Some(NativeStrategy::DenyOverrides) if has(Effect::Deny, None) => Some(Effect::Deny),
            Some(NativeStrategy::PermitOverrides) if has(Effect::Allow, None) => Some(Effect::Allow),
            Some(NativeStrategy::DenyOverrides | NativeStrategy::PermitOverrides | NativeStrategy::FirstApplicable) => {
                candidates.first().map(|(_, effect, _)| *effect)
            }
            _ => {
                let list: Vec<Candidate> = candidates
                    .iter()
                    .map(|(rank, _, index)| Candidate {
                        grant: self.entries[*index].grant.clone(),
                        rank: *rank,
                    })
                    .collect();
                self.strategy.combine(&list).map(|i| list[i].grant.effect)
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Planning
// ---------------------------------------------------------------------------------------------

/// Whether the condition reads anything of the resource besides its kind.
fn reads_resource(condition: &Condition) -> bool {
    let operand = |o: &Operand| matches!(o, Operand::Attr { attr } if resource_attr(attr));
    match condition {
        Condition::Eq { left, right }
        | Condition::Ne { left, right }
        | Condition::Lt { left, right }
        | Condition::Le { left, right }
        | Condition::Gt { left, right }
        | Condition::Ge { left, right } => operand(left) || operand(right),
        Condition::In { item, set } => operand(item) || operand(set),
        Condition::StartsWith { left, right }
        | Condition::EndsWith { left, right }
        | Condition::Contains { left, right }
        | Condition::AnyIn { left, right }
        | Condition::AllIn { left, right } => operand(left) || operand(right),
        Condition::IpIn { item, set } => operand(item) || operand(set),
        Condition::TimeBetween { .. } | Condition::WeekdayIn { .. } => false,
        Condition::Exists { attr } => resource_attr(attr),
        Condition::All { of } | Condition::Any { of } => of.iter().any(reads_resource),
        Condition::Not { cond } => reads_resource(cond),
        Condition::Call { args, .. } => args.iter().any(operand),
    }
}

fn resource_attr(path: &str) -> bool {
    path.split_once('.')
        .is_some_and(|(root, name)| root == "resource" && name != "kind")
}

/// Most alternations of allow and deny runs (under `FirstApplicable`) that a listing writes as an
/// expression; past it the strategy is left to the row.
const MAX_FIRST_APPLICABLE_RUNS: usize = 256;

fn effect_runs(entries: &[Entry]) -> usize {
    let mut runs = 0;
    let mut last = None;
    for entry in entries {
        if last != Some(entry.grant.effect) {
            runs += 1;
            last = Some(entry.grant.effect);
        }
    }
    runs
}

/// The roles a subject holds with everything they inherit, expanded once per listing.
struct HeldRoles {
    /// Each role held at `now`: its scope and the roles it stands for (itself and what it inherits).
    held: Vec<(Option<Anchor>, BTreeSet<String>)>,
    /// Like `held`, but counting the assignments whose window could not be checked (no `now`): a
    /// `deny` keyed on a role uses this set, as in `check`.
    held_for_denial: Vec<(Option<Anchor>, BTreeSet<String>)>,
    all: BTreeSet<String>,
}

impl HeldRoles {
    fn new(engine: &Engine, subject: &Subject, now: Option<u64>) -> Self {
        let expand = |holds_without_now: bool| -> Vec<(Option<Anchor>, BTreeSet<String>)> {
            subject
                .roles
                .iter()
                .filter(|r| r.validity().in_force(now, holds_without_now))
                .map(|r| (r.scope.clone(), engine.roles.expand([r.role.as_str()])))
                .collect()
        };
        let held_for_denial = expand(true);
        let all = held_for_denial
            .iter()
            .flat_map(|(_, expanded)| expanded.iter().cloned())
            .collect();
        Self {
            held: expand(false),
            held_for_denial,
            all,
        }
    }

    fn for_effect(&self, effect: Effect) -> &[(Option<Anchor>, BTreeSet<String>)] {
        match effect {
            Effect::Allow => &self.held,
            Effect::Deny => &self.held_for_denial,
        }
    }

    /// Cheap test, before a grant is copied: could the grant's subject side hold for this subject?
    /// A relation is settled later, with the tuples.
    fn may_match(&self, subject: &Subject, matcher: &SubjectMatcher) -> bool {
        match matcher {
            SubjectMatcher::User { id } => subject.id.as_deref() == Some(id.as_str()),
            SubjectMatcher::Principal { name } => subject.has_principal(name),
            SubjectMatcher::Role { id } => self.all.contains(id),
            SubjectMatcher::Any | SubjectMatcher::Relation { .. } => true,
        }
    }
}

/// What planning one listing carries besides the filter.
struct SubjectPlan<'a> {
    subject: &'a Subject,
    roles: HeldRoles,
    probe: Resource,
}

impl Engine {
    /// The reach of `subject` with `permission` over the resources of `kind`.
    ///
    /// The filter is exact against [`Engine::check`]: deny, overrides, `implied_by`, role
    /// inheritance, scoped roles, ReBAC and the configured strategy are all accounted for. A
    /// permission outside the catalog lists nothing. What the resource alone can settle is left
    /// in [`AccessFilter::residual`].
    pub fn list(&self, ctx: &QueryContext<'_>, subject: &Subject, permission: &str, kind: &str) -> AccessFilter {
        crate::obs::query("list", permission, Some(kind), || {
            self.plan(ctx, subject, permission, kind, true)
        })
    }

    pub(crate) fn plan(
        &self,
        ctx: &QueryContext<'_>,
        subject: &Subject,
        permission: &str,
        kind: &str,
        with_overrides: bool,
    ) -> AccessFilter {
        let mut filter = self.plan_core(ctx, subject, permission, kind, with_overrides);
        if !filter.known || !self.catalog.has_prerequisites(permission) {
            return filter;
        }
        for prerequisite in self.catalog.prerequisites(permission) {
            let nested = self.plan_core(ctx, subject, prerequisite, kind, with_overrides);
            let offset = filter.residuals.len();
            filter.residuals.extend(nested.residuals.iter().cloned());
            filter.warnings.extend(nested.warnings.iter().cloned());
            filter.prerequisites.push(PrerequisitePlan { filter: nested, offset });
        }
        filter
    }

    /// The listing of one permission, without its prerequisites.
    fn plan_core(
        &self,
        ctx: &QueryContext<'_>,
        subject: &Subject,
        permission: &str,
        kind: &str,
        with_overrides: bool,
    ) -> AccessFilter {
        let native = self.strategy.native();
        let mut filter = AccessFilter {
            kind: kind.to_string(),
            permission: permission.to_string(),
            known: true,
            subject: subject.clone(),
            env: ctx.env.clone(),
            now: ctx.now,
            conditions: self.conditions.clone(),
            strategy: Arc::clone(&self.strategy),
            native,
            entries: Vec::new(),
            overrides: Vec::new(),
            residuals: Vec::new(),
            strategy_residual: None,
            warnings: Vec::new(),
            prerequisites: Vec::new(),
        };
        let Some(effective) = self.catalog.effective(permission) else {
            filter.known = false;
            return filter;
        };
        if native.is_none() {
            filter.residuals.push(FilterResidual::Strategy {
                name: self.strategy.name().to_string(),
            });
            filter.strategy_residual = Some(filter.residuals.len() - 1);
        }
        let keys: Vec<&str> = effective.iter().map(String::as_str).collect();
        let who = SubjectPlan {
            subject,
            roles: HeldRoles::new(self, subject, ctx.now),
            probe: Resource::new(kind, ""),
        };
        let mut grants = Vec::new();
        ctx.grants.visit_by_permission(&keys, &mut |g| {
            if effective.contains(&g.permission) && who.roles.may_match(subject, &g.subject) {
                grants.extend(whole_resource_form(g));
            }
        });
        for grant in grants {
            self.plan_grant(&mut filter, ctx, &who, grant);
        }
        if native == Some(NativeStrategy::FirstApplicable) && effect_runs(&filter.entries) > MAX_FIRST_APPLICABLE_RUNS {
            // Too many alternations to write as an expression of reasonable size: fail closed, the
            // row decides.
            filter.native = None;
            filter.residuals.push(FilterResidual::Strategy {
                name: self.strategy.name().to_string(),
            });
            filter.strategy_residual = Some(filter.residuals.len() - 1);
        }
        if with_overrides {
            for entry in &self.overrides {
                if entry.except.iter().any(|key| effective.contains(key)) {
                    continue;
                }
                let name = entry.inner.name().to_string();
                let reach = entry.inner.reach(&ReachRequest {
                    engine: self,
                    ctx,
                    subject,
                    permission,
                    kind,
                });
                let residual = matches!(reach, OverrideReach::Opaque).then(|| {
                    filter.residuals.push(FilterResidual::Override { name: name.clone() });
                    filter.residuals.len() - 1
                });
                let nested_offset = filter.residuals.len();
                if let OverrideReach::Allows(OverrideGate::Holds(nested))
                | OverrideReach::Denies(OverrideGate::Holds(nested)) = &reach
                {
                    filter.residuals.extend(nested.residuals.iter().cloned());
                }
                filter.overrides.push(OverridePlan {
                    reach,
                    residual,
                    nested_offset,
                });
            }
        }
        filter
    }

    /// Settles the subject side of one grant, and the condition when it does not read the resource.
    fn plan_grant(&self, filter: &mut AccessFilter, ctx: &QueryContext<'_>, who: &SubjectPlan<'_>, grant: Grant) {
        let (subject, probe) = (who.subject, &who.probe);
        // Outside its window an allow grants nothing and a deny that is provably expired stops
        // denying; with no instant a windowed deny still holds.
        if !grant.in_force(ctx.now) {
            return;
        }
        let fail_safe = grant.effect == Effect::Deny;
        let mut parts = Vec::new();
        if let Some(scope) = &grant.scope {
            parts.push(Expr::Within(scope.clone()));
        }
        match self.subject_gate(filter, ctx, who, &grant) {
            Some(gate) => parts.push(gate),
            None => return,
        }
        let mut residual = None;
        if let Some(condition) = &grant.condition {
            if reads_resource(condition) {
                filter.residuals.push(FilterResidual::Condition {
                    grant_id: grant.id.clone(),
                    condition: condition.clone(),
                });
                residual = Some(filter.residuals.len() - 1);
            } else {
                let eval = EvalContext {
                    subject,
                    resource: probe,
                    env: ctx.env,
                };
                match condition.evaluate_at(&eval, &self.conditions, ctx.now) {
                    Ok(true) => {}
                    Ok(false) => return,
                    Err(error) => {
                        filter.warnings.push(format!("grant {}: {error}", grant.id));
                        if !fail_safe {
                            return;
                        }
                    }
                }
            }
        }
        filter.entries.push(Entry {
            gate: Expr::And(parts).simplify(),
            grant,
            residual,
        });
    }

    /// The part of the grant's subject match that depends on the resource. `None`: the grant
    /// never applies to this subject.
    fn subject_gate(
        &self,
        filter: &mut AccessFilter,
        ctx: &QueryContext<'_>,
        who: &SubjectPlan<'_>,
        grant: &Grant,
    ) -> Option<Expr> {
        let subject = who.subject;
        match &grant.subject {
            SubjectMatcher::User { id } => (subject.id.as_deref() == Some(id.as_str())).then_some(Expr::True),
            SubjectMatcher::Principal { name } => subject.has_principal(name).then_some(Expr::True),
            SubjectMatcher::Any => Some(Expr::True),
            SubjectMatcher::Role { id } => {
                let alternatives: Vec<Expr> = who
                    .roles
                    .for_effect(grant.effect)
                    .iter()
                    .filter(|(_, expanded)| expanded.contains(id))
                    .map(|(scope, _)| scope.clone().map_or(Expr::True, Expr::Within))
                    .collect();
                (!alternatives.is_empty()).then_some(Expr::Or(alternatives))
            }
            SubjectMatcher::Relation { relation } => self.relation_gate(filter, ctx, subject, grant, relation),
        }
    }

    fn relation_gate(
        &self,
        filter: &mut AccessFilter,
        ctx: &QueryContext<'_>,
        subject: &Subject,
        grant: &Grant,
        relation: &str,
    ) -> Option<Expr> {
        let fail_safe = grant.effect == Effect::Deny;
        let problem = |filter: &mut AccessFilter, error: &str| {
            filter.warnings.push(format!("grant {}: {error}", grant.id));
            fail_safe.then_some(Expr::True)
        };
        let Some(schema) = self.relations.as_ref() else {
            return problem(filter, "ReBAC disabled in the engine");
        };
        let Some(tuples) = ctx.tuples else {
            return problem(filter, "context without a tuple index");
        };
        let who = subject.object_ref()?;
        let target = &grant.target;
        if target.kind == GLOBAL {
            return None;
        }
        if let Some(id) = &target.id {
            let object = ObjectRef::new(target.kind.clone(), id.clone());
            return match schema.check(tuples, &object, relation, &who, self.max_relation_depth) {
                Ok(true) => Some(Expr::True),
                Ok(false) => None,
                Err(error) => problem(filter, &error.to_string()),
            };
        }
        let (holds, failed) = schema.objects_with(tuples, &target.kind, relation, &who, self.max_relation_depth);
        let mut ids: BTreeSet<String> = holds.into_iter().map(|o| o.id).collect();
        if !failed.is_empty() {
            filter.warnings.push(format!(
                "grant {}: relation depth exceeded on {} object(s)",
                grant.id,
                failed.len()
            ));
            if fail_safe {
                ids.extend(failed.into_iter().map(|o| o.id));
            }
        }
        (!ids.is_empty()).then(|| Expr::AnchorIn {
            kind: target.kind.clone(),
            ids,
        })
    }
}

// ---------------------------------------------------------------------------------------------
// Reverse queries
// ---------------------------------------------------------------------------------------------

/// How a decision was reached, in the terms of the question "why does this subject have access".
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AccessVia {
    /// An override decided before the grants.
    Override { name: String },
    /// A grant to the subject itself, to a principal it carries or to everyone.
    Grant { grant_id: String },
    /// A grant to a role the subject holds directly.
    Role { grant_id: String, role: String },
    /// A grant to a role the subject holds through the inheritance of another role.
    InheritedRole {
        grant_id: String,
        role: String,
        from: String,
    },
    /// A grant to the subject through a relation on the matched object.
    Relation {
        grant_id: String,
        relation: String,
        object: ObjectRef,
    },
    /// Nothing applied: default-deny.
    Nothing,
}

/// Decision of [`Engine::check_for`], with the path that led to it.
#[derive(Debug, Clone, PartialEq)]
pub struct CheckAnswer {
    pub subject: SubjectRef,
    pub decision: Decision,
    pub via: AccessVia,
    pub explanation: Explanation,
}

impl CheckAnswer {
    pub fn is_allowed(&self) -> bool {
        self.decision.is_allowed()
    }
}

/// A party that holds the permission, and how.
#[derive(Debug, Clone, PartialEq)]
pub struct WhoCanEntry {
    pub subject: SubjectRef,
    pub via: AccessVia,
}

/// Two parties that each hold the permission but are denied when one subject is both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhoCanExcept {
    pub allowed: SubjectRef,
    pub with: SubjectRef,
}

/// Parties that hold a permission, from [`Engine::who_can_on`].
///
/// An entry says that a subject that is exactly that party (and nothing else) is allowed. A subject
/// that is several parties at once can be denied by a rule that targets one of them; the pairs that
/// the grants make conflict are in [`WhoCan::except`], and [`WhoCan::admits`] applies them. Pairs
/// are the approximation: [`Engine::check_for`] is the authority for one subject.
///
/// The parties are decided as bare archetypes: a role, a principal or a user id with no attributes.
/// A deny conditioned on `subject.<attr>` is therefore not seen, and [`WhoCan::except`] only covers
/// pairs of parties named by deny grants, not the decisions of an override.
#[derive(Debug, Clone, PartialEq)]
pub struct WhoCan {
    pub permission: String,
    pub resource: Option<Resource>,
    pub entries: Vec<WhoCanEntry>,
    pub except: Vec<WhoCanExcept>,
}

impl WhoCan {
    pub fn subjects(&self) -> impl Iterator<Item = &SubjectRef> {
        self.entries.iter().map(|e| &e.subject)
    }

    /// Whether the subject is one of the parties (and not in an excepted pair).
    pub fn admits(&self, engine: &Engine, tuples: Option<&dyn TupleStore>, subject: &Subject) -> bool {
        let is = |party: &SubjectRef| self.is_party(engine, tuples, subject, party);
        self.entries.iter().any(|entry| is(&entry.subject))
            && !self.except.iter().any(|pair| is(&pair.allowed) && is(&pair.with))
    }

    fn is_party(
        &self,
        engine: &Engine,
        tuples: Option<&dyn TupleStore>,
        subject: &Subject,
        party: &SubjectRef,
    ) -> bool {
        match party {
            SubjectRef::User { id } => subject.id.as_deref() == Some(id.as_str()),
            SubjectRef::Object { kind, id } => subject.kind == *kind && subject.id.as_deref() == Some(id.as_str()),
            SubjectRef::Role { id } => {
                let empty = Resource::global();
                let resource = self.resource.as_ref().unwrap_or(&empty);
                engine.roles.expand(subject.roles_for(resource)).contains(id)
            }
            SubjectRef::Principal { name } => subject.has_principal(name),
            SubjectRef::Anyone => true,
            SubjectRef::Wildcard { kind } => subject.kind == *kind && subject.id.is_some(),
            SubjectRef::Userset { object, relation } => {
                let (Some(schema), Some(store), Some(who)) = (engine.relations.as_ref(), tuples, subject.object_ref())
                else {
                    return false;
                };
                schema
                    .check(store, object, relation, &who, engine.max_relation_depth)
                    .unwrap_or(false)
            }
        }
    }
}

/// What a subject can do on a resource, from [`Engine::access_of`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyAccess {
    pub subject: SubjectRef,
    pub permissions: BTreeSet<String>,
}

/// A tuple store with one extra, made-up tuple set, to ask "would a member of this userset be
/// allowed" without writing anything.
struct Overlay<'a> {
    inner: Option<&'a dyn TupleIndex>,
    extra: Vec<(ObjectRef, String, TupleSubject)>,
}

impl TupleStore for Overlay<'_> {
    fn visit(&self, object: &ObjectRef, relation: &str, visitor: &mut dyn FnMut(&TupleSubject)) {
        if let Some(inner) = self.inner {
            inner.visit(object, relation, visitor);
        }
        for (o, r, s) in &self.extra {
            if o == object && r == relation {
                visitor(s);
            }
        }
    }
}

impl TupleIndex for Overlay<'_> {
    fn visit_objects(&self, kind: &str, visitor: &mut dyn FnMut(&ObjectRef)) {
        if let Some(inner) = self.inner {
            inner.visit_objects(kind, visitor);
        }
        for (o, _, _) in self.extra.iter().filter(|(o, _, _)| o.kind == kind) {
            visitor(o);
        }
    }

    fn visit_subjects(&self, object: &ObjectRef, visitor: &mut dyn FnMut(&str, &TupleSubject)) {
        if let Some(inner) = self.inner {
            inner.visit_subjects(object, visitor);
        }
        for (o, r, s) in &self.extra {
            if o == object {
                visitor(r, s);
            }
        }
    }
}

/// The subject a set of parties would be, all at once.
fn archetype(parties: &[&SubjectRef]) -> (Subject, Vec<(ObjectRef, String)>) {
    let mut subject = Subject {
        kind: "party".to_string(),
        id: None,
        roles: Vec::new(),
        principals: Vec::new(),
        attrs: Attributes::new(),
    };
    let mut usersets = Vec::new();
    for party in parties {
        match party {
            SubjectRef::User { id } => {
                subject.kind = "user".to_string();
                subject.id = Some(id.clone());
                subject.principals.push(AUTHENTICATED.to_string());
            }
            SubjectRef::Object { kind, id } => {
                subject.kind = kind.clone();
                subject.id = Some(id.clone());
                if kind == "user" {
                    subject.principals.push(AUTHENTICATED.to_string());
                }
            }
            SubjectRef::Wildcard { kind } => {
                subject.kind = kind.clone();
                subject.id = Some(crate::rebac::WILDCARD.to_string());
            }
            SubjectRef::Role { id } => subject.roles.push(RoleAssignment::new(id.clone())),
            SubjectRef::Principal { name } => subject.principals.push(name.clone()),
            SubjectRef::Userset { object, relation } => usersets.push((object.clone(), relation.clone())),
            SubjectRef::Anyone => {}
        }
    }
    if !usersets.is_empty() && subject.id.is_none() {
        subject.kind = "probe".to_string();
        subject.id = Some("1".to_string());
    }
    (subject, usersets)
}

impl Engine {
    /// Explanation of the decision for a set of parties acting as one subject.
    fn decide_parties(
        &self,
        ctx: &QueryContext<'_>,
        parties: &[&SubjectRef],
        permission: &str,
        resource: &Resource,
        with_overrides: bool,
    ) -> Explanation {
        let (subject, usersets) = archetype(parties);
        let overlay = Overlay {
            inner: ctx.tuples,
            extra: match subject.object_ref() {
                Some(who) => usersets
                    .into_iter()
                    .map(|(object, relation)| (object, relation, TupleSubject::Object(who.clone())))
                    .collect(),
                None => Vec::new(),
            },
        };
        let mut data = ctx.context();
        if ctx.tuples.is_some() || !overlay.extra.is_empty() {
            data = data.with_tuples(&overlay);
        }
        self.explain_with(&data, &Request::new(&subject, permission, resource), with_overrides)
    }

    /// Parties named by the grants that can reach the resource, with the effects they have.
    fn parties_on(
        &self,
        ctx: &QueryContext<'_>,
        grants: &[Grant],
        resource: &Resource,
    ) -> Result<(BTreeSet<SubjectRef>, BTreeSet<SubjectRef>), QueryError> {
        let mut all = BTreeSet::new();
        let mut denied = BTreeSet::new();
        for grant in grants {
            if !grant.in_force(ctx.now) || grant.scope.as_ref().is_some_and(|scope| !resource.contains(scope)) {
                continue;
            }
            let Some((_, anchor)) = resource.locate(&grant.target) else {
                continue;
            };
            let parties = match &grant.subject {
                SubjectMatcher::User { id } => vec![SubjectRef::User { id: id.clone() }],
                SubjectMatcher::Role { id } => vec![SubjectRef::Role { id: id.clone() }],
                SubjectMatcher::Principal { name } => vec![SubjectRef::Principal { name: name.clone() }],
                SubjectMatcher::Any => vec![SubjectRef::Anyone],
                SubjectMatcher::Relation { relation } => {
                    match self.relation_parties(ctx, anchor.object_ref(), relation) {
                        Ok(parties) => parties,
                        // A deny that cannot be read must not drop its parties from the answer.
                        Err(RebacError::DepthExceeded(_)) if grant.effect == Effect::Deny => {
                            return Err(QueryError::RelationDepthExceeded {
                                grant_id: grant.id.clone(),
                            });
                        }
                        // An allow that cannot be read grants nothing, as in `check`.
                        Err(RebacError::DepthExceeded(_)) => continue,
                    }
                }
            };
            if grant.effect == Effect::Deny {
                denied.extend(parties.iter().cloned());
            }
            all.extend(parties);
        }
        Ok((all, denied))
    }

    /// Parties that may hold `relation` on `object`: the direct subjects of the relation and of the
    /// relations it derives from, usersets kept as usersets.
    ///
    /// # Errors
    ///
    /// [`RebacError::DepthExceeded`] when the relation chain is deeper than the engine allows.
    fn relation_parties(
        &self,
        ctx: &QueryContext<'_>,
        object: Option<ObjectRef>,
        relation: &str,
    ) -> Result<Vec<SubjectRef>, RebacError> {
        let (Some(schema), Some(tuples), Some(object)) = (self.relations.as_ref(), ctx.tuples, object) else {
            return Ok(Vec::new());
        };
        let subjects = schema.subjects_of(tuples, &object, relation, self.max_relation_depth)?;
        Ok(subjects
            .into_iter()
            .map(|subject| match subject {
                TupleSubject::Object(o) if o.id == crate::rebac::WILDCARD => SubjectRef::Wildcard { kind: o.kind },
                TupleSubject::Object(o) if o.kind == "user" => SubjectRef::User { id: o.id },
                TupleSubject::Object(o) => SubjectRef::Object { kind: o.kind, id: o.id },
                TupleSubject::Userset(object, relation) => SubjectRef::Userset { object, relation },
            })
            .collect())
    }

    /// Grants of the permission (and the ones that imply it) that sit on the resource's path.
    fn grants_on_path(&self, ctx: &QueryContext<'_>, permissions: Option<&[&str]>, resource: &Resource) -> Vec<Grant> {
        let mut out: Vec<Grant> = Vec::new();
        let mut seen = BTreeSet::new();
        for (_, anchor) in resource.anchors() {
            ctx.grants.visit_by_target_kind(&anchor.kind, &mut |g| {
                let on_step = g.target.id.as_ref().is_none_or(|id| anchor.id.as_ref() == Some(id));
                if on_step
                    && permissions.is_none_or(|keys| keys.contains(&g.permission.as_str()))
                    && seen.insert(g.id.clone())
                {
                    out.push(g.clone());
                }
            });
        }
        out
    }

    fn who_can_inner(
        &self,
        ctx: &QueryContext<'_>,
        permission: &str,
        resource: &Resource,
        with_overrides: bool,
    ) -> Result<WhoCan, QueryError> {
        let mut result = WhoCan {
            permission: permission.to_string(),
            resource: Some(resource.clone()),
            entries: Vec::new(),
            except: Vec::new(),
        };
        let Some(effective) = self.catalog.effective(permission) else {
            return Ok(result);
        };
        let keys: Vec<&str> = effective.iter().map(String::as_str).collect();
        let grants = self.grants_on_path(ctx, Some(&keys), resource);
        let (mut candidates, denied) = self.parties_on(ctx, &grants, resource)?;
        if with_overrides {
            let request = SubjectsRequest {
                engine: self,
                ctx,
                permission,
                resource,
            };
            for entry in &self.overrides {
                if !entry.except.iter().any(|key| effective.contains(key)) {
                    candidates.extend(entry.inner.subjects(&request)?);
                }
            }
        }
        QueryLimits::check("parties", candidates.len(), ctx.limits.max_parties)?;
        QueryLimits::check(
            "decisions",
            candidates
                .len()
                .saturating_add(candidates.len().saturating_mul(denied.len())),
            ctx.limits.max_decisions,
        )?;
        for party in &candidates {
            let explanation = self.decide_parties(ctx, &[party], permission, resource, with_overrides);
            if explanation.decision.is_allowed() {
                result.entries.push(WhoCanEntry {
                    subject: party.clone(),
                    via: self.via(&explanation),
                });
            }
        }
        let allowed: Vec<SubjectRef> = result.entries.iter().map(|e| e.subject.clone()).collect();
        for party in &allowed {
            for other in denied.iter().filter(|d| *d != party) {
                let merged = self.decide_parties(ctx, &[party, other], permission, resource, with_overrides);
                if !merged.decision.is_allowed() {
                    result.except.push(WhoCanExcept {
                        allowed: party.clone(),
                        with: other.clone(),
                    });
                }
            }
        }
        Ok(result)
    }

    pub(crate) fn who_can_on_by_grants(
        &self,
        ctx: &QueryContext<'_>,
        permission: &str,
        resource: &Resource,
    ) -> Result<WhoCan, QueryError> {
        self.who_can_inner(ctx, permission, resource, false)
    }

    /// Parties that hold `permission` (or something that implies it) on `resource`, grants and
    /// overrides included. See [`WhoCan`] for what an entry promises.
    ///
    /// # Errors
    ///
    /// [`QueryError::LimitExceeded`] past the [`QueryLimits`] of `ctx`;
    /// [`QueryError::RelationDepthExceeded`] when a deny grant through a relation cannot be read.
    pub fn who_can_on(
        &self,
        ctx: &QueryContext<'_>,
        permission: &str,
        resource: &Resource,
    ) -> Result<WhoCan, QueryError> {
        crate::obs::query("who_can_on", permission, None, || {
            self.who_can_inner(ctx, permission, resource, true)
        })
    }

    /// Parties named by an allow grant of `permission` (or of something that implies it),
    /// anywhere. Without a resource nothing is evaluated: a deny, an override or a condition can
    /// still keep a party out of a given resource, which [`Engine::who_can_on`] settles.
    pub fn who_can(&self, ctx: &QueryContext<'_>, permission: &str) -> Vec<SubjectRef> {
        crate::obs::query("who_can", permission, None, || self.who_can_parties(ctx, permission))
    }

    fn who_can_parties(&self, ctx: &QueryContext<'_>, permission: &str) -> Vec<SubjectRef> {
        let Some(effective) = self.catalog.effective(permission) else {
            return Vec::new();
        };
        let keys: Vec<&str> = effective.iter().map(String::as_str).collect();
        let mut out = BTreeSet::new();
        ctx.grants.visit_by_permission(&keys, &mut |grant| {
            if grant.effect != Effect::Allow
                || grant.is_field_restricted()
                || !effective.contains(&grant.permission)
                || !grant.in_force(ctx.now)
            {
                return;
            }
            match &grant.subject {
                SubjectMatcher::User { id } => {
                    out.insert(SubjectRef::User { id: id.clone() });
                }
                SubjectMatcher::Role { id } => {
                    out.insert(SubjectRef::Role { id: id.clone() });
                }
                SubjectMatcher::Principal { name } => {
                    out.insert(SubjectRef::Principal { name: name.clone() });
                }
                SubjectMatcher::Any => {
                    out.insert(SubjectRef::Anyone);
                }
                SubjectMatcher::Relation { relation } => {
                    let Some(tuples) = ctx.tuples else { return };
                    let mut objects = Vec::new();
                    match &grant.target.id {
                        Some(id) => objects.push(ObjectRef::new(grant.target.kind.clone(), id.clone())),
                        None => tuples.visit_objects(&grant.target.kind, &mut |o| objects.push(o.clone())),
                    }
                    for object in objects {
                        // An allow that cannot be read names nobody, as in `check`.
                        if let Ok(parties) = self.relation_parties(ctx, Some(object), relation) {
                            out.extend(parties);
                        }
                    }
                }
            }
        });
        out.into_iter().collect()
    }

    /// Who has access to the resource, with the permissions of each party. A party is listed with
    /// what it holds alone; [`Engine::check_for`] is the authority for a subject that is several.
    ///
    /// # Errors
    ///
    /// [`QueryError::LimitExceeded`] past the [`QueryLimits`] of `ctx`;
    /// [`QueryError::RelationDepthExceeded`] when a deny grant through a relation cannot be read.
    pub fn access_of(&self, ctx: &QueryContext<'_>, resource: &Resource) -> Result<Vec<PartyAccess>, QueryError> {
        let grants = self.grants_on_path(ctx, None, resource);
        let (mut parties, _) = self.parties_on(ctx, &grants, resource)?;
        for def in self.catalog.all() {
            let request = SubjectsRequest {
                engine: self,
                ctx,
                permission: &def.key,
                resource,
            };
            for entry in &self.overrides {
                parties.extend(entry.inner.subjects(&request)?);
            }
        }
        QueryLimits::check("parties", parties.len(), ctx.limits.max_parties)?;
        QueryLimits::check(
            "decisions",
            parties.len().saturating_mul(self.catalog.all().len()),
            ctx.limits.max_decisions,
        )?;
        let mut out = Vec::new();
        for party in parties {
            let permissions: BTreeSet<String> = self
                .catalog
                .all()
                .iter()
                .filter(|def| {
                    self.decide_parties(ctx, &[&party], &def.key, resource, true)
                        .decision
                        .is_allowed()
                })
                .map(|def| def.key.clone())
                .collect();
            if !permissions.is_empty() {
                out.push(PartyAccess {
                    subject: party,
                    permissions,
                });
            }
        }
        Ok(out)
    }

    /// Does `subject` have `permission` on `resource`? The subject is loaded by `resolver` and the
    /// answer carries the path: grant, inherited role, relation or override.
    ///
    /// Whatever the resolver cannot load is an error, whatever the kind of the reference: a role, a
    /// principal or `Anyone` is not answered "as the party alone", because a failed load (a database
    /// error mapped to `None`) would then read as a permission. To ask about a party alone, have the
    /// resolver return the [`Subject`] that stands for it, or use [`Engine::who_can_on`].
    ///
    /// # Errors
    ///
    /// [`QueryError::UnknownSubject`] when the resolver returns `None` for the reference.
    pub fn check_for(
        &self,
        ctx: &QueryContext<'_>,
        resolver: &dyn SubjectResolver,
        subject: &SubjectRef,
        permission: &str,
        resource: &Resource,
    ) -> Result<CheckAnswer, QueryError> {
        let loaded = resolver.resolve(subject);
        let (decision, explanation) = match loaded {
            Some(loaded) => {
                let data = ctx.context();
                let request = Request::new(&loaded, permission, resource);
                let explanation = self.explain(&data, &request);
                (explanation.decision.clone(), explanation)
            }
            // A resolver that cannot load the subject says nothing about what the subject holds, and
            // it cannot tell "unknown" from "failed to load": deny, never answer as a made-up party.
            None => return Err(QueryError::UnknownSubject(subject.clone())),
        };
        let via = self.via(&explanation);
        Ok(CheckAnswer {
            subject: subject.clone(),
            decision,
            via,
            explanation,
        })
    }

    /// The path of a decision, from its explanation.
    fn via(&self, explanation: &Explanation) -> AccessVia {
        match &explanation.decision.reason {
            Reason::Override { name } => AccessVia::Override { name: name.clone() },
            Reason::Grant { grant_id, .. } => {
                let Some(trace) = explanation.decisive() else {
                    return AccessVia::Nothing;
                };
                let grant_id = grant_id.clone();
                match &trace.grant.subject {
                    SubjectMatcher::Role { id } => {
                        let held = explanation.subject.roles_for(&explanation.resource).any(|r| r == id);
                        if held {
                            return AccessVia::Role {
                                grant_id,
                                role: id.clone(),
                            };
                        }
                        let from = explanation
                            .subject
                            .roles_for(&explanation.resource)
                            .find(|direct| self.roles.expand([*direct]).contains(id))
                            .unwrap_or(id)
                            .to_string();
                        AccessVia::InheritedRole {
                            grant_id,
                            role: id.clone(),
                            from,
                        }
                    }
                    SubjectMatcher::Relation { relation } => match trace.anchor.as_ref().and_then(Anchor::object_ref) {
                        Some(object) => AccessVia::Relation {
                            grant_id,
                            relation: relation.clone(),
                            object,
                        },
                        None => AccessVia::Grant { grant_id },
                    },
                    _ => AccessVia::Grant { grant_id },
                }
            }
            Reason::NoApplicableGrant | Reason::UnknownPermission | Reason::MissingPrerequisite { .. } => {
                AccessVia::Nothing
            }
        }
    }
}

#[cfg(test)]
mod expr_tests {
    use super::*;

    fn leaf() -> Expr {
        Expr::Within(Anchor::new("org", "o1"))
    }

    /// `simplify` rewrites a step with an id as a one-element id set.
    fn simplified_leaf() -> Expr {
        leaf().simplify()
    }

    #[test]
    fn empty_and_is_true_and_empty_or_is_false() {
        assert_eq!(Expr::And(vec![]).simplify(), Expr::True);
        assert_eq!(Expr::Or(vec![]).simplify(), Expr::False);
    }

    #[test]
    fn constants_absorb_in_and_or() {
        assert_eq!(Expr::And(vec![leaf(), Expr::False]).simplify(), Expr::False);
        assert_eq!(Expr::Or(vec![leaf(), Expr::True]).simplify(), Expr::True);
        assert_eq!(Expr::And(vec![leaf(), Expr::True]).simplify(), simplified_leaf());
    }

    #[test]
    fn double_negation_cancels() {
        assert_eq!(Expr::not(Expr::not(leaf())).simplify(), simplified_leaf());
    }

    #[test]
    fn bounds_of_a_residue_are_false_below_and_true_above() {
        assert_eq!(Expr::Residual(0).bounds(), (Expr::False, Expr::True));
    }

    #[test]
    fn a_residue_under_a_deny_never_widens_the_lower_bound() {
        let (lower, upper) = Expr::And(vec![leaf(), Expr::not(Expr::Residual(0))]).bounds();
        assert_eq!(lower, Expr::False);
        assert_eq!(upper, simplified_leaf());
    }
}
