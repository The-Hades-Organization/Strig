//! What a change does to access, before it is applied.
//!
//! [`Governance::impact`](crate::Governance::impact) compares the decisions before and after a
//! [`Mutation`] for a set of questions (who, which permission, on which resource, optionally which
//! field) and answers who gains access, who loses it and what could not be settled.
//!
//! # Where "who and where" comes from
//!
//! - [`ImpactSource::Sample`]: the caller lists subjects, resources and permissions. The
//!   subjects are whole [`Subject`]s, so conditions that read their attributes are decided for real.
//!   Empty resources and permissions default to the ones the change touches.
//! - [`ImpactSource::Derived`]: the parties come from the reverse queries ([`Engine::who_can_on`]) over
//!   the permissions the change touches, before and after, plus the party the changed grant names. A
//!   party is a user, a role, a principal or a userset as in the queries, not each member of a role. A
//!   role change asks about the subject whose roles change.
//!
//! The permissions touched are the one in the grant, everything it implies (`implied_by`) and everything
//! that depends on those (`depends_on`). A grant that names fields is also asked per field.
//!
//! # What it promises
//!
//! - Only a decision that is certain on both sides counts as a gain or a loss. A `deny` that came with a
//!   warning (a condition that could not be evaluated, a relation without a store) is
//!   [`Access::Indeterminate`]: the change is reported under [`Impact::indeterminate`], never as a gain.
//! - The work is bounded by [`QueryLimits`]. When a ceiling is reached the answer is cut and
//!   [`Impact::partial`] is set, with the reason in [`Impact::notes`]; what is listed is still correct.
//! - Nothing is written and nothing is audited by computing an impact.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::attr::Attributes;
use crate::decision::{Decision, Request};
use crate::engine::{Context, Engine};
use crate::governance::{Mutation, matcher_subject, same_subject, with_role_change};
use crate::grant::{Effect, Grant, SubjectMatcher};
use crate::query::{QueryContext, QueryLimits, SubjectRef};
use crate::rebac::{TupleIndex, TupleStore};
use crate::resource::{Anchor, GLOBAL, Resource};
use crate::separation::{Clash, clashes_of};
use crate::subject::Subject;

static EMPTY_ENV: Attributes = Attributes::new();

/// Most examples an audit record keeps.
pub const AUDIT_EXAMPLES: usize = 10;

/// Subjects, resources and permissions to ask about, chosen by the caller.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
#[non_exhaustive]
pub struct SampleSpec {
    pub subjects: Vec<Subject>,
    /// Empty: the resources the change reaches.
    pub resources: Vec<Resource>,
    /// Empty: the permissions the change touches.
    pub permissions: Vec<String>,
    /// Fields to ask about besides the whole resource. A grant that names fields adds its own.
    pub fields: Vec<String>,
}

impl SampleSpec {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn subject(mut self, subject: Subject) -> Self {
        self.subjects.push(subject);
        self
    }

    #[must_use]
    pub fn resource(mut self, resource: Resource) -> Self {
        self.resources.push(resource);
        self
    }

    #[must_use]
    pub fn permission(mut self, permission: impl Into<String>) -> Self {
        self.permissions.push(permission.into());
        self
    }

    #[must_use]
    pub fn field(mut self, field: impl Into<String>) -> Self {
        self.fields.push(field.into());
        self
    }
}

/// How the subjects and the resources of an impact are found.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", rename_all_fields = "camelCase")]
#[non_exhaustive]
pub enum ImpactSource {
    /// The caller's own list.
    Sample(SampleSpec),
    /// From the reverse queries. `resources` empty: the resources the change reaches.
    Derived {
        #[serde(default)]
        resources: Vec<Resource>,
    },
}

impl ImpactSource {
    pub fn derived() -> Self {
        ImpactSource::Derived { resources: Vec::new() }
    }

    pub fn sample(spec: SampleSpec) -> Self {
        ImpactSource::Sample(spec)
    }
}

/// What the impact of a change is computed over.
#[derive(Clone)]
#[non_exhaustive]
pub struct ImpactOptions<'a> {
    pub source: ImpactSource,
    /// The tuples the questions run against; also lists the objects of a relation grant.
    pub tuples: Option<&'a dyn TupleIndex>,
    pub env: &'a Attributes,
    pub limits: QueryLimits,
    /// The instant the questions are answered at, as in [`Context::at`].
    pub now: Option<u64>,
}

impl<'a> ImpactOptions<'a> {
    pub fn new(source: ImpactSource) -> Self {
        Self {
            source,
            tuples: None,
            env: &EMPTY_ENV,
            limits: QueryLimits::default(),
            now: None,
        }
    }

    #[must_use]
    pub fn with_tuples(mut self, tuples: &'a dyn TupleIndex) -> Self {
        self.tuples = Some(tuples);
        self
    }

    #[must_use]
    pub fn with_env(mut self, env: &'a Attributes) -> Self {
        self.env = env;
        self
    }

    #[must_use]
    pub fn with_limits(mut self, limits: QueryLimits) -> Self {
        self.limits = limits;
        self
    }

    #[must_use]
    pub fn at(mut self, now: u64) -> Self {
        self.now = Some(now);
        self
    }
}

/// What one side of a question came out as.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Access {
    Allowed,
    Denied,
    /// Denied with a warning: something that could have allowed could not be evaluated.
    Indeterminate,
}

/// One question whose answer the change moves.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct AccessChange {
    /// `user:alice`, `role:editor`, `principal:authenticated`, `anyone`.
    pub subject: String,
    pub permission: String,
    pub resource: Resource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    pub before: Access,
    pub after: Access,
}

impl AccessChange {
    fn label(&self) -> String {
        let field = self.field.as_deref().map(|f| format!(".{f}")).unwrap_or_default();
        format!(
            "{} {}{field} {}",
            self.subject,
            self.permission,
            resource_label(&self.resource)
        )
    }
}

/// Who gains and who loses access with a change.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Impact {
    pub gained: Vec<AccessChange>,
    pub lost: Vec<AccessChange>,
    /// Questions the change moves toward or away from a decision that could not be settled.
    pub indeterminate: Vec<AccessChange>,
    /// The permissions the change touches, the ones asked about unless the sample named others.
    pub permissions: Vec<String>,
    /// How many decisions were made.
    pub checked: usize,
    /// A limit cut the answer: more may gain or lose than is listed.
    #[serde(default)]
    pub partial: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    /// Separation of duties the change would break: pairs of members of a `mutually_exclusive` set
    /// that the subject the change touches would hold together and does not hold now. Listed
    /// whether or not the [`SeparationOfDuties`](crate::SeparationOfDuties) invariant is on, so a
    /// dry run shows the violation a governance without it would let through.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub separation: Vec<PotentialClash>,
}

/// A separation clash the change would create, and who would hold it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct PotentialClash {
    /// `user:alice`, `role:editor`, `principal:authenticated`, `anyone`.
    pub subject: String,
    pub clash: Clash,
}

impl Impact {
    /// Nothing gains, nothing loses, nothing is undecided (and nothing was cut).
    pub fn is_empty(&self) -> bool {
        self.gained.is_empty()
            && self.lost.is_empty()
            && self.indeterminate.is_empty()
            && self.separation.is_empty()
            && !self.partial
    }

    /// Counts and a few examples, for the audit record.
    pub fn summary(&self) -> ImpactSummary {
        let examples = self
            .gained
            .iter()
            .map(|c| ("gained", c))
            .chain(self.lost.iter().map(|c| ("lost", c)))
            .chain(self.indeterminate.iter().map(|c| ("indeterminate", c)))
            .take(AUDIT_EXAMPLES)
            .map(|(kind, change)| format!("{kind} {}", change.label()))
            .collect();
        ImpactSummary {
            gained: self.gained.len(),
            lost: self.lost.len(),
            indeterminate: self.indeterminate.len(),
            partial: self.partial,
            examples,
        }
    }
}

/// The impact of a change as the audit trail keeps it: counts and a bounded list of examples.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ImpactSummary {
    pub gained: usize,
    pub lost: usize,
    pub indeterminate: usize,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub partial: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub examples: Vec<String>,
}

fn resource_label(resource: &Resource) -> String {
    if resource.path.is_empty() {
        return GLOBAL.to_string();
    }
    resource
        .path
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" > ")
}

fn subject_label(subject: &Subject) -> String {
    match &subject.id {
        Some(id) => format!("{}:{id}", subject.kind),
        None => format!("{}:<anonymous>", subject.kind),
    }
}

fn access_of(decision: &Decision) -> Access {
    if decision.is_allowed() {
        Access::Allowed
    } else if decision.warnings.is_empty() {
        Access::Denied
    } else {
        Access::Indeterminate
    }
}

enum Who {
    Party(SubjectRef),
    Subject { before: Subject, after: Subject },
}

struct Probe {
    who: Who,
    permission: String,
    resource: Resource,
    field: Option<String>,
}

/// The grants the change adds, removes or hands over through a role, and the scope of a role change.
struct Reach<'a> {
    grants: Vec<&'a Grant>,
    role_scope: Option<&'a Anchor>,
}

fn reach<'a>(engine: &Engine, current: &'a [Grant], mutation: &'a Mutation) -> Reach<'a> {
    match mutation {
        Mutation::Add(grant) => Reach {
            grants: vec![grant],
            role_scope: None,
        },
        Mutation::Remove { id } => Reach {
            grants: current.iter().filter(|g| &g.id == id).collect(),
            role_scope: None,
        },
        Mutation::AssignRole { role, .. } | Mutation::RevokeRole { role, .. } => {
            let held = engine.roles.expand([role.role.as_str()]);
            Reach {
                grants: current
                    .iter()
                    .filter(|g| matches!(&g.subject, SubjectMatcher::Role { id } if held.contains(id)))
                    .collect(),
                role_scope: role.scope.as_ref(),
            }
        }
    }
}

/// `permission`, everything it implies and everything that depends on those.
fn touched_permissions(engine: &Engine, grants: &[&Grant]) -> BTreeSet<String> {
    let catalog = &engine.catalog;
    let mut set = BTreeSet::new();
    for grant in grants {
        set.insert(grant.permission.clone());
        set.extend(catalog.descendants(&grant.permission));
    }
    loop {
        let before = set.len();
        for def in catalog.all() {
            if catalog.prerequisites(&def.key).any(|p| set.contains(p)) {
                set.insert(def.key.clone());
            }
        }
        if set.len() == before {
            return set;
        }
    }
}

fn resource_of(grant: &Grant, role_scope: Option<&Anchor>) -> Resource {
    let mut path = Vec::new();
    if grant.target.kind != GLOBAL {
        path.push(Anchor {
            kind: grant.target.kind.clone(),
            id: grant.target.id.clone(),
        });
    }
    for scope in grant.scope.iter().chain(role_scope) {
        if !path.contains(scope) {
            path.push(scope.clone());
        }
    }
    Resource {
        path,
        attrs: Attributes::new(),
    }
}

fn resources_reached(reach: &Reach<'_>) -> Vec<Resource> {
    let mut out: Vec<Resource> = Vec::new();
    for grant in &reach.grants {
        let resource = resource_of(grant, reach.role_scope);
        if !out.contains(&resource) {
            out.push(resource);
        }
    }
    out
}

fn party_of(matcher: &SubjectMatcher) -> Option<SubjectRef> {
    match matcher {
        SubjectMatcher::User { id } => Some(SubjectRef::User { id: id.clone() }),
        SubjectMatcher::Role { id } => Some(SubjectRef::Role { id: id.clone() }),
        SubjectMatcher::Principal { name } => Some(SubjectRef::Principal { name: name.clone() }),
        SubjectMatcher::Any => Some(SubjectRef::Anyone),
        SubjectMatcher::Relation { .. } => None,
    }
}

struct Side<'a> {
    data: Context<'a>,
    query: QueryContext<'a>,
}

impl<'a> Side<'a> {
    fn new(grants: &'a &'a [Grant], options: &ImpactOptions<'a>) -> Self {
        let mut data = Context::new(grants).with_env(options.env);
        let mut query = QueryContext::new(grants)
            .with_env(options.env)
            .with_limits(options.limits);
        if let Some(index) = options.tuples {
            let store: &dyn TupleStore = index;
            data = data.with_tuples(store);
            query = query.with_tuples(index);
        }
        if let Some(now) = options.now {
            data = data.at(now);
            query = query.at(now);
        }
        Self { data, query }
    }

    fn decide(&self, engine: &Engine, probe: &Probe, after: bool) -> Decision {
        match &probe.who {
            Who::Party(party) => engine.decide_party(
                &self.query,
                party,
                &probe.permission,
                &probe.resource,
                probe.field.as_deref(),
            ),
            Who::Subject { before: b, after: a } => {
                let subject = if after { a } else { b };
                let request = Request::new(subject, &probe.permission, &probe.resource);
                let request = match probe.field.as_deref() {
                    Some(field) => request.field(field),
                    None => request,
                };
                engine.decide(&self.data, &request)
            }
        }
    }
}

/// The impact of `mutation`, which turns `current` into `after`.
pub(crate) fn compute(
    engine: &Engine,
    current: &[Grant],
    after: &[Grant],
    mutation: &Mutation,
    options: &ImpactOptions<'_>,
) -> Impact {
    let mut impact = Impact::default();
    let reach = reach(engine, current, mutation);
    let touched = touched_permissions(engine, &reach.grants);
    impact.permissions = touched.iter().cloned().collect();
    let mut grant_fields: Vec<String> = reach.grants.iter().flat_map(|g| g.fields.clone()).collect();
    grant_fields.sort();
    grant_fields.dedup();
    let reached = resources_reached(&reach);

    let (before_grants, after_grants) = (current, after);
    let (before_side, after_side) = (Side::new(&before_grants, options), Side::new(&after_grants, options));

    let probes = match &options.source {
        ImpactSource::Sample(spec) => sample_probes(mutation, spec, &touched, &reached, &grant_fields, &mut impact),
        ImpactSource::Derived { resources } => {
            let resources = if resources.is_empty() { &reached } else { resources };
            derived_probes(
                engine,
                mutation,
                &reach,
                (&before_side, &after_side),
                &touched,
                resources,
                &grant_fields,
                options.limits,
                &mut impact,
            )
        }
    };

    let ceiling = options.limits.max_decisions;
    for probe in &probes {
        if impact.checked.saturating_add(2) > ceiling {
            cut(&mut impact, format!("decisions: stopped at {ceiling}"));
            break;
        }
        let before = before_side.decide(engine, probe, false);
        let now = after_side.decide(engine, probe, true);
        impact.checked += 2;
        classify(&mut impact, probe, &before, &now);
    }
    sort(&mut impact);
    impact.separation = new_clashes(engine, current, after, mutation, options);
    impact
}

/// The clashes of the sets of the catalog that `after` has and `current` did not, for the subject
/// the mutation names, or for what its grant's matcher selects.
fn new_clashes(
    engine: &Engine,
    current: &[Grant],
    after: &[Grant],
    mutation: &Mutation,
    options: &ImpactOptions<'_>,
) -> Vec<PotentialClash> {
    if engine.catalog().mutual_exclusions().is_empty() {
        return Vec::new();
    }
    let (label, before_subject, after_subject) = match mutation {
        Mutation::AssignRole { subject, .. } => match mutation.subject_after() {
            Some(changed) => (subject_label(subject), subject.clone(), changed),
            None => return Vec::new(),
        },
        Mutation::Add(grant) if grant.effect == Effect::Allow => {
            let Some(probe) = matcher_subject(&grant.subject) else {
                return Vec::new();
            };
            (matcher_label(&grant.subject), probe.clone(), probe)
        }
        _ => return Vec::new(),
    };
    let was = clashes_of(engine, &before_subject, current, options.now);
    clashes_of(engine, &after_subject, after, options.now)
        .into_iter()
        .filter(|c| !was.iter().any(|w| w == c))
        .map(|clash| PotentialClash {
            subject: label.clone(),
            clash,
        })
        .collect()
}

fn matcher_label(matcher: &SubjectMatcher) -> String {
    match matcher {
        SubjectMatcher::User { id } => format!("user:{id}"),
        SubjectMatcher::Role { id } => format!("role:{id}"),
        SubjectMatcher::Principal { name } => format!("principal:{name}"),
        _ => "anyone".to_string(),
    }
}

fn cut(impact: &mut Impact, note: String) {
    impact.partial = true;
    if !impact.notes.contains(&note) {
        impact.notes.push(note);
    }
}

fn classify(impact: &mut Impact, probe: &Probe, before: &Decision, after: &Decision) {
    let (b, a) = (access_of(before), access_of(after));
    let bucket = match (b, a) {
        (Access::Denied, Access::Denied) | (Access::Allowed, Access::Allowed) => return,
        (Access::Denied, Access::Allowed) => &mut impact.gained,
        (Access::Allowed, Access::Denied) => &mut impact.lost,
        (Access::Indeterminate, Access::Indeterminate) if before.warnings == after.warnings => return,
        _ => &mut impact.indeterminate,
    };
    let subject = match &probe.who {
        Who::Party(party) => party.to_string(),
        Who::Subject { before, .. } => subject_label(before),
    };
    bucket.push(AccessChange {
        subject,
        permission: probe.permission.clone(),
        resource: probe.resource.clone(),
        field: probe.field.clone(),
        before: b,
        after: a,
    });
}

fn sort(impact: &mut Impact) {
    for list in [&mut impact.gained, &mut impact.lost, &mut impact.indeterminate] {
        list.sort_by_cached_key(|c| {
            (
                c.subject.clone(),
                c.permission.clone(),
                resource_label(&c.resource),
                c.field.clone(),
            )
        });
    }
}

fn fields_to_ask(extra: &[String], grant_fields: &[String]) -> Vec<Option<String>> {
    let mut fields: Vec<Option<String>> = vec![None];
    for field in extra.iter().chain(grant_fields) {
        let field = Some(field.clone());
        if !fields.contains(&field) {
            fields.push(field);
        }
    }
    fields
}

fn sample_probes(
    mutation: &Mutation,
    spec: &SampleSpec,
    touched: &BTreeSet<String>,
    reached: &[Resource],
    grant_fields: &[String],
    impact: &mut Impact,
) -> Vec<Probe> {
    if spec.subjects.is_empty() {
        cut(impact, "sample: no subjects".to_string());
    }
    let permissions: Vec<String> = if spec.permissions.is_empty() {
        touched.iter().cloned().collect()
    } else {
        spec.permissions.clone()
    };
    impact.permissions.clone_from(&permissions);
    let resources: &[Resource] = if spec.resources.is_empty() {
        reached
    } else {
        &spec.resources
    };
    let fields = fields_to_ask(&spec.fields, grant_fields);
    let mut probes = Vec::new();
    for subject in &spec.subjects {
        let after = match mutation.role_change() {
            Some((target, role, assigned)) if same_subject(target, subject) => {
                with_role_change(subject, role, assigned)
            }
            _ => subject.clone(),
        };
        for resource in resources {
            for permission in &permissions {
                for field in &fields {
                    probes.push(Probe {
                        who: Who::Subject {
                            before: subject.clone(),
                            after: after.clone(),
                        },
                        permission: permission.clone(),
                        resource: resource.clone(),
                        field: field.clone(),
                    });
                }
            }
        }
    }
    probes
}

#[allow(clippy::too_many_arguments)]
fn derived_probes(
    engine: &Engine,
    mutation: &Mutation,
    reach: &Reach<'_>,
    sides: (&Side<'_>, &Side<'_>),
    touched: &BTreeSet<String>,
    resources: &[Resource],
    grant_fields: &[String],
    limits: QueryLimits,
    impact: &mut Impact,
) -> Vec<Probe> {
    let mut probes = Vec::new();
    if let Some((subject, role, assigned)) = mutation.role_change() {
        let after = with_role_change(subject, role, assigned);
        for resource in resources {
            for permission in touched {
                probes.push(Probe {
                    who: Who::Subject {
                        before: subject.clone(),
                        after: after.clone(),
                    },
                    permission: permission.clone(),
                    resource: resource.clone(),
                    field: None,
                });
            }
        }
        return probes;
    }
    let fields = fields_to_ask(&[], grant_fields);
    let own: Vec<SubjectRef> = reach.grants.iter().filter_map(|g| party_of(&g.subject)).collect();
    for resource in resources {
        for permission in touched {
            let mut parties: BTreeSet<SubjectRef> = own.iter().cloned().collect();
            for side in [sides.0, sides.1] {
                match engine.who_can_on(&side.query, permission, resource) {
                    Ok(who) => parties.extend(who.entries.into_iter().map(|e| e.subject)),
                    Err(error) => cut(impact, format!("who_can_on {permission}: {error}")),
                }
            }
            if parties.len() > limits.max_parties {
                cut(impact, format!("parties: more than {}", limits.max_parties));
            }
            for party in parties.into_iter().take(limits.max_parties) {
                for field in &fields {
                    probes.push(Probe {
                        who: Who::Party(party.clone()),
                        permission: permission.clone(),
                        resource: resource.clone(),
                        field: field.clone(),
                    });
                }
            }
        }
    }
    probes
}
