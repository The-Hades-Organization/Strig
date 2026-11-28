use std::collections::BTreeSet;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::attr::Attributes;
use crate::catalog::Catalog;
use crate::condition::{ConditionRegistry, EvalContext};
use crate::decision::{Decision, Reason, Request};
use crate::explain::{
    ConditionTrace, Explanation, GrantTrace, OverrideOutcome, OverrideStep, PrerequisiteStep, Verdict,
    trace_condition_at,
};
use crate::field::{FieldExplanation, FieldSet, FieldVerdict};
use crate::grant::{Effect, Grant, GrantIndex, GrantSource, SubjectMatcher};
use crate::overrides::Override;
use crate::rbac::RoleGraph;
use crate::rebac::{RelationSchema, TupleStore};
use crate::resource::{Anchor, Resource};
use crate::separation::SeparationRule;
use crate::strategy::{Candidate, MostSpecific, Strategy};
use crate::subject::Subject;
use crate::validity::ValidityError;

static EMPTY_ENV: Attributes = Attributes::new();

#[derive(Default)]
struct Recorder {
    overrides: Vec<OverrideStep>,
    grants: Vec<GrantTrace>,
    prerequisites: Vec<PrerequisiteStep>,
}

struct Judged {
    verdict: Verdict,
    rank: Option<usize>,
    anchor: Option<Anchor>,
    condition: Option<ConditionTrace>,
}

const DEFAULT_MAX_RELATION_DEPTH: usize = 32;

/// Stands for "any field no grant names". Not a valid field name, so no grant can list it.
const OTHER_FIELD: &str = "\0other";

/// Data of a decision: grants, ReBAC tuples, environment attributes and the current instant. The
/// [`Engine`] only holds configuration; the data arrives with each call.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub struct Context<'a> {
    pub grants: &'a dyn GrantSource,
    pub tuples: Option<&'a dyn TupleStore>,
    pub env: &'a Attributes,
    /// Instant of the decision, in milliseconds since the Unix epoch. It decides which validity
    /// windows are open (see [`crate::validity`]). `None` fails closed.
    pub now: Option<u64>,
}

impl<'a> Context<'a> {
    pub fn new(grants: &'a dyn GrantSource) -> Self {
        Self {
            grants,
            tuples: None,
            env: &EMPTY_ENV,
            now: None,
        }
    }

    pub fn with_tuples(mut self, tuples: &'a dyn TupleStore) -> Self {
        self.tuples = Some(tuples);
        self
    }

    pub fn with_env(mut self, env: &'a Attributes) -> Self {
        self.env = env;
        self
    }

    /// Sets the instant of the decision (milliseconds since the Unix epoch). A grant or a role
    /// assignment outside its validity window does not exist for the decision, the explanation
    /// and the capabilities. Without it, an `allow` with a window is ignored and a `deny` with a
    /// window still holds.
    ///
    /// The ABAC `env.now` is not derived from this value: it is whatever `env` carries. Feed both
    /// from the same instant.
    pub fn at(mut self, now: u64) -> Self {
        self.now = Some(now);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EngineError {
    #[error("exceção de override cita permissão fora do catálogo: {0}")]
    UnknownPermission(String),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum GrantError {
    #[error("grant sem id")]
    EmptyId,
    #[error("permissão desconhecida: {0}")]
    UnknownPermission(String),
    #[error("tipo de alvo não registrado: {0}")]
    UnknownTargetKind(String),
    #[error("a permissão {permission} não aceita alvo {target}")]
    TargetNotAllowed { permission: String, target: String },
    #[error("a permissão {0} vale só por override e não pode ser citada em grant")]
    OverrideOnly(String),
    #[error("grant por relação exige RelationSchema no motor")]
    RelationsDisabled,
    #[error("condição chama função não registrada: {0}")]
    UnknownFunction(String),
    #[error("janela de validade inválida: {0}")]
    InvalidWindow(#[from] ValidityError),
    #[error("campo inválido '{0}': use segmentos [A-Za-z_][A-Za-z0-9_]* separados por ponto")]
    InvalidField(String),
    #[error("a permissão {permission} não declara o campo {field}")]
    UnknownField { permission: String, field: String },
}

pub(crate) struct OverrideEntry {
    pub(crate) inner: Box<dyn Override>,
    pub(crate) except: Vec<String>,
}

/// Decision engine. Immutable and shareable between threads once built.
pub struct Engine {
    pub(crate) catalog: Arc<Catalog>,
    pub(crate) roles: RoleGraph,
    pub(crate) relations: Option<RelationSchema>,
    pub(crate) conditions: ConditionRegistry,
    pub(crate) strategy: Arc<dyn Strategy>,
    pub(crate) overrides: Vec<OverrideEntry>,
    pub(crate) max_relation_depth: usize,
}

pub struct EngineBuilder {
    engine: Engine,
}

impl EngineBuilder {
    pub fn roles(mut self, roles: RoleGraph) -> Self {
        self.engine.roles = roles;
        self
    }

    pub fn relations(mut self, schema: RelationSchema) -> Self {
        self.engine.relations = Some(schema);
        self
    }

    pub fn conditions(mut self, registry: ConditionRegistry) -> Self {
        self.engine.conditions = registry;
        self
    }

    pub fn strategy(mut self, strategy: impl Strategy + 'static) -> Self {
        self.engine.strategy = Arc::new(strategy);
        self
    }

    pub fn override_with(self, rule: impl Override + 'static) -> Self {
        self.override_except(rule, std::iter::empty::<String>())
    }

    /// Override that does not apply to the listed permissions or to the ones they grant
    /// (for example, the organization administrator does not delete another owner's project).
    pub fn override_except<I, S>(mut self, rule: impl Override + 'static, except: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.engine.overrides.push(OverrideEntry {
            inner: Box::new(rule),
            except: except.into_iter().map(Into::into).collect(),
        });
        self
    }

    pub fn max_relation_depth(mut self, depth: usize) -> Self {
        self.engine.max_relation_depth = depth;
        self
    }

    pub fn build(self) -> Result<Engine, EngineError> {
        let engine = self.engine;
        for key in engine.overrides.iter().flat_map(|o| &o.except) {
            if !engine.catalog.contains(key) {
                return Err(EngineError::UnknownPermission(key.clone()));
            }
        }
        Ok(engine)
    }
}

impl Engine {
    pub fn builder(catalog: impl Into<Arc<Catalog>>) -> EngineBuilder {
        let catalog = catalog.into();
        let separation = catalog
            .action_conflicts()
            .iter()
            .map(|rule| OverrideEntry {
                inner: Box::new(SeparationRule::new(rule.clone())),
                except: Vec::new(),
            })
            .collect();
        EngineBuilder {
            engine: Engine {
                catalog,
                roles: RoleGraph::default(),
                relations: None,
                conditions: ConditionRegistry::default(),
                strategy: Arc::new(MostSpecific),
                overrides: separation,
                max_relation_depth: DEFAULT_MAX_RELATION_DEPTH,
            },
        }
    }

    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }

    pub fn roles(&self) -> &RoleGraph {
        &self.roles
    }

    pub fn check(&self, ctx: &Context<'_>, request: &Request<'_>) -> bool {
        self.decide(ctx, request).is_allowed()
    }

    pub fn decide(&self, ctx: &Context<'_>, request: &Request<'_>) -> Decision {
        crate::obs::decision(
            "decide",
            request,
            || self.decide_inner(ctx, request, true, None),
            |decision| decision,
        )
    }

    /// Decision by the grants only, without overrides. Used by overrides that depend on a permission.
    pub fn decide_without_overrides(&self, ctx: &Context<'_>, request: &Request<'_>) -> Decision {
        self.decide_inner(ctx, request, false, None)
    }

    /// Decision of the request alone, overrides included but without the prerequisite check. Lets
    /// governance tell a plain `allow` from one that only stands because its prerequisites hold. Not
    /// public: an `allow` from here ignores `depends_on`, so it must never authorize anything.
    pub(crate) fn decide_ignoring_prerequisites(&self, ctx: &Context<'_>, request: &Request<'_>) -> Decision {
        self.decide_core(ctx, request, true, None)
    }

    /// [`Engine::decide`] without the span and the metrics: for the engine's own what-if
    /// verifications, which are not decisions the application asked for.
    pub(crate) fn decide_unobserved(&self, ctx: &Context<'_>, request: &Request<'_>) -> Decision {
        self.decide_inner(ctx, request, true, None)
    }

    /// The same decision as [`Engine::decide`], with the trace of each override and of each grant
    /// delivered by the source. More expensive: it evaluates the condition tree and clones the grants.
    pub fn explain(&self, ctx: &Context<'_>, request: &Request<'_>) -> Explanation {
        self.explain_with(ctx, request, true)
    }

    pub(crate) fn explain_with(&self, ctx: &Context<'_>, request: &Request<'_>, with_overrides: bool) -> Explanation {
        crate::obs::decision(
            "explain",
            request,
            || self.explain_traced(ctx, request, with_overrides),
            |explanation| &explanation.decision,
        )
    }

    fn explain_traced(&self, ctx: &Context<'_>, request: &Request<'_>, with_overrides: bool) -> Explanation {
        let mut recorder = Recorder::default();
        let decision = self.decide_inner(ctx, request, with_overrides, Some(&mut recorder));
        if matches!(decision.reason, Reason::Override { .. }) {
            ctx.grants.visit(request.subject, request.resource, &mut |grant| {
                recorder.grants.push(GrantTrace {
                    grant: grant.clone(),
                    verdict: Verdict::NotReached,
                    rank: None,
                    anchor: None,
                    condition: None,
                });
            });
        }
        Explanation {
            subject: request.subject.clone(),
            permission: request.permission.to_string(),
            field: request.field.map(str::to_string),
            resource: request.resource.clone(),
            effective: self
                .catalog
                .effective(request.permission)
                .map(|set| set.iter().cloned().collect())
                .unwrap_or_default(),
            path: request.resource.anchors().map(|(_, a)| a.clone()).collect(),
            roles: self
                .roles
                .expand(request.subject.roles_at(request.resource, ctx.now))
                .into_iter()
                .collect(),
            overrides: recorder.overrides,
            grants: recorder.grants,
            prerequisites: recorder.prerequisites,
            strategy: self.strategy.name().to_string(),
            decision,
        }
    }

    /// Decision of the request followed by the prerequisite check: an `allow` only stands if
    /// every transitive prerequisite is also allowed on the same resource.
    fn decide_inner(
        &self,
        ctx: &Context<'_>,
        request: &Request<'_>,
        with_overrides: bool,
        mut recorder: Option<&mut Recorder>,
    ) -> Decision {
        let mut decision = self.decide_core(ctx, request, with_overrides, recorder.as_deref_mut());
        if !decision.is_allowed() || !self.catalog.has_prerequisites(request.permission) {
            return decision;
        }
        // A flat pass over the transitive closure: each prerequisite is judged on its own grants,
        // so the cost is bounded by the closure size and never recurses.
        let mut missing = None;
        for prerequisite in self.catalog.prerequisites(request.permission) {
            let sub = self.prerequisite_request(request, prerequisite);
            let allowed = self.decide_core(ctx, &sub, with_overrides, None).is_allowed();
            if let Some(r) = recorder.as_deref_mut() {
                r.prerequisites.push(PrerequisiteStep {
                    permission: prerequisite.to_string(),
                    allowed,
                });
            }
            if !allowed && missing.is_none() {
                missing = Some(prerequisite.to_string());
                if recorder.is_none() {
                    break;
                }
            }
        }
        if let Some(prerequisite) = missing {
            decision.effect = Effect::Deny;
            decision.reason = Reason::MissingPrerequisite {
                permission: request.permission.to_string(),
                prerequisite,
            };
        }
        decision
    }

    fn decide_core(
        &self,
        ctx: &Context<'_>,
        request: &Request<'_>,
        with_overrides: bool,
        mut recorder: Option<&mut Recorder>,
    ) -> Decision {
        let Some(effective) = self.catalog.effective(request.permission) else {
            return Decision::deny(Reason::UnknownPermission);
        };
        if let Some(field) = request.field {
            let declared = self.catalog.fields(request.permission);
            if !declared.is_empty() && !declared.iter().any(|f| f == field) {
                return Decision::deny(Reason::NoApplicableGrant);
            }
        }

        if with_overrides {
            for entry in &self.overrides {
                let name = entry.inner.name().to_string();
                if entry.except.iter().any(|key| effective.contains(key)) {
                    if let Some(r) = recorder.as_deref_mut() {
                        r.overrides.push(OverrideStep {
                            name,
                            outcome: OverrideOutcome::Excepted,
                        });
                    }
                    continue;
                }
                let outcome = entry.inner.evaluate(self, ctx, request);
                if let Some(r) = recorder.as_deref_mut() {
                    r.overrides.push(OverrideStep {
                        name: name.clone(),
                        outcome: outcome.into(),
                    });
                }
                if let Some(effect) = outcome {
                    return Decision {
                        effect,
                        reason: Reason::Override { name },
                        matched: Vec::new(),
                        warnings: Vec::new(),
                    };
                }
            }
        }

        let mut warnings = Vec::new();
        let candidates = self.collect(ctx, request, effective, &mut warnings, recorder);
        let matched = candidates.iter().map(|c| c.grant.id.clone()).collect();
        match self.pick(&candidates, request.field.is_some()) {
            Some(i) => {
                let decisive = &candidates[i];
                Decision {
                    effect: decisive.grant.effect,
                    reason: Reason::Grant {
                        grant_id: decisive.grant.id.clone(),
                        permission: decisive.grant.permission.clone(),
                        rank: decisive.rank,
                        strategy: self.strategy.name().to_string(),
                    },
                    matched,
                    warnings,
                }
            }
            None => Decision {
                effect: Effect::Deny,
                reason: Reason::NoApplicableGrant,
                matched,
                warnings,
            },
        }
    }

    /// The strategy's pick among candidates already filtered to the requested field (or, without a
    /// field, among all of them). Policies without field-restricted grants go straight to the
    /// strategy.
    fn pick(&self, candidates: &[Candidate], field_filtered: bool) -> Option<usize> {
        if field_filtered || !candidates.iter().any(|c| c.grant.is_field_restricted()) {
            return self.strategy.combine(candidates);
        }
        let whole: Vec<usize> = (0..candidates.len())
            .filter(|&i| !candidates[i].grant.is_field_restricted())
            .collect();
        let whole_candidates: Vec<Candidate> = whole.iter().map(|&i| candidates[i].clone()).collect();
        let decided = whole[self.strategy.combine(&whole_candidates)?];
        if candidates[decided].grant.effect == Effect::Deny {
            return Some(decided);
        }
        let fields: BTreeSet<&str> = candidates
            .iter()
            .flat_map(|c| c.grant.fields.iter().map(String::as_str))
            .collect();
        for field in fields {
            let covering: Vec<usize> = (0..candidates.len())
                .filter(|&i| candidates[i].grant.covers_field(field))
                .collect();
            let covering_candidates: Vec<Candidate> = covering.iter().map(|&i| candidates[i].clone()).collect();
            if let Some(i) = self.strategy.combine(&covering_candidates).map(|i| covering[i])
                && candidates[i].grant.effect == Effect::Deny
            {
                return Some(i);
            }
        }
        Some(decided)
    }

    /// The request for a prerequisite: on the same field when the prerequisite can be restricted to
    /// it, and on the whole resource when the prerequisite declares fields that do not include it.
    pub(crate) fn prerequisite_request<'a>(&self, request: &Request<'a>, prerequisite: &'a str) -> Request<'a> {
        let mut sub = *request;
        sub.permission = prerequisite;
        if let Some(field) = request.field {
            let declared = self.catalog.fields(prerequisite);
            if !declared.is_empty() && !declared.iter().any(|f| f == field) {
                sub.field = None;
            }
        }
        sub
    }

    /// The first override that rules on the request, if any.
    fn override_effect(
        &self,
        ctx: &Context<'_>,
        request: &Request<'_>,
        effective: &BTreeSet<String>,
    ) -> Option<(String, Effect)> {
        self.overrides
            .iter()
            .filter(|entry| !entry.except.iter().any(|key| effective.contains(key)))
            .find_map(|entry| {
                entry
                    .inner
                    .evaluate(self, ctx, request)
                    .map(|effect| (entry.inner.name().to_string(), effect))
            })
    }

    /// The fields to ask about: what the catalog declares for the permission or, when it declares
    /// nothing, what the grants that could apply name (the permission's and its prerequisites').
    fn field_plan(&self, ctx: &Context<'_>, request: &Request<'_>) -> (BTreeSet<String>, bool) {
        let declared = self.catalog.fields(request.permission);
        if !declared.is_empty() {
            return (declared.iter().cloned().collect(), true);
        }
        let mut named = BTreeSet::new();
        let permissions = std::iter::once(request.permission).chain(self.catalog.prerequisites(request.permission));
        for permission in permissions {
            let Some(effective) = self.catalog.effective(permission) else {
                continue;
            };
            let mut probe = *request;
            probe.permission = permission;
            probe.field = None;
            let candidates = self.collect(ctx, &probe, effective, &mut Vec::new(), None);
            named.extend(candidates.into_iter().flat_map(|c| c.grant.fields));
        }
        (named, false)
    }

    fn assemble_fields(declared: bool, fields: &BTreeSet<String>, allowed: BTreeSet<String>, rest: bool) -> FieldSet {
        if declared {
            return if allowed.len() == fields.len() {
                FieldSet::All
            } else {
                FieldSet::only(allowed)
            };
        }
        if rest {
            FieldSet::all_except(fields.difference(&allowed).cloned().collect())
        } else {
            FieldSet::only(allowed)
        }
    }

    /// The fields of `resource` the subject may use for `permission`: every field, none, or a
    /// list. It is the per-field version of [`Engine::decide`]; see [`crate::field`] for how the
    /// grants combine. A condition that cannot be evaluated never opens a field.
    pub fn allowed_fields(
        &self,
        ctx: &Context<'_>,
        subject: &Subject,
        permission: &str,
        resource: &Resource,
    ) -> FieldSet {
        self.explain_fields(ctx, subject, permission, resource).allowed
    }

    /// The same answer as [`Engine::allowed_fields`], with, for each field, the grants that gave it
    /// and the ones that took it away.
    pub fn explain_fields(
        &self,
        ctx: &Context<'_>,
        subject: &Subject,
        permission: &str,
        resource: &Resource,
    ) -> FieldExplanation {
        let request = Request::new(subject, permission, resource);
        let mut out = FieldExplanation {
            permission: permission.to_string(),
            allowed: FieldSet::None,
            overridden_by: None,
            fields: Vec::new(),
        };
        let Some(effective) = self.catalog.effective(permission) else {
            return out;
        };
        if let Some((name, effect)) = self.override_effect(ctx, &request, effective) {
            out.allowed = if effect == Effect::Allow {
                FieldSet::All
            } else {
                FieldSet::None
            };
            out.overridden_by = Some(name);
            return out;
        }
        let (fields, declared) = self.field_plan(ctx, &request);
        let mut allowed = BTreeSet::new();
        let mut asked: Vec<Option<&str>> = fields.iter().map(|f| Some(f.as_str())).collect();
        if !declared {
            asked.push(Some(OTHER_FIELD));
        }
        let mut rest = false;
        for field in asked {
            let sub = request.field(field.unwrap_or_default());
            let explanation = self.explain_with(ctx, &sub, true);
            let is_rest = field == Some(OTHER_FIELD);
            let is_allowed = explanation.decision.is_allowed();
            if is_rest {
                rest = is_allowed;
            } else if is_allowed {
                allowed.insert(field.unwrap_or_default().to_string());
            }
            let of_effect = |effect| {
                explanation
                    .candidates()
                    .filter(|g| g.grant.effect == effect)
                    .map(|g| g.grant.id.clone())
                    .collect::<Vec<_>>()
            };
            out.fields.push(FieldVerdict {
                field: (!is_rest).then(|| field.unwrap_or_default().to_string()),
                allowed: is_allowed,
                reason: explanation.decision.reason.clone(),
                granted_by: of_effect(Effect::Allow),
                denied_by: of_effect(Effect::Deny),
            });
        }
        out.allowed = Self::assemble_fields(declared, &fields, allowed, rest);
        out
    }

    /// Grants that apply to the request. When in doubt (a condition or relation that could not be
    /// evaluated), a `deny` applies and an `allow` does not: an error never opens access.
    fn collect(
        &self,
        ctx: &Context<'_>,
        request: &Request<'_>,
        effective: &BTreeSet<String>,
        warnings: &mut Vec<String>,
        mut recorder: Option<&mut Recorder>,
    ) -> Vec<Candidate> {
        let roles = self.roles.expand(request.subject.roles_at(request.resource, ctx.now));
        let denial_roles = self
            .roles
            .expand(request.subject.roles_for_denial(request.resource, ctx.now));
        let eval_ctx = EvalContext {
            subject: request.subject,
            resource: request.resource,
            env: ctx.env,
        };
        let tracing = recorder.is_some();
        let mut out = Vec::new();
        ctx.grants.visit(request.subject, request.resource, &mut |grant| {
            let roles = if grant.effect == Effect::Deny {
                &denial_roles
            } else {
                &roles
            };
            let judged = self.judge(ctx, request, effective, roles, &eval_ctx, grant, warnings, tracing);
            if let (true, Some(rank)) = (judged.verdict.is_candidate(), judged.rank) {
                out.push(Candidate {
                    grant: grant.clone(),
                    rank,
                });
            }
            if let Some(r) = recorder.as_deref_mut() {
                r.grants.push(GrantTrace {
                    grant: grant.clone(),
                    verdict: judged.verdict,
                    rank: judged.rank,
                    anchor: judged.anchor,
                    condition: judged.condition,
                });
            }
        });
        out
    }

    /// Checks a grant in order: permission, scope, target, subject, condition.
    #[allow(clippy::too_many_arguments)]
    fn judge(
        &self,
        ctx: &Context<'_>,
        request: &Request<'_>,
        effective: &BTreeSet<String>,
        roles: &BTreeSet<String>,
        eval_ctx: &EvalContext<'_>,
        grant: &Grant,
        warnings: &mut Vec<String>,
        tracing: bool,
    ) -> Judged {
        let out = |verdict| Judged {
            verdict,
            rank: None,
            anchor: None,
            condition: None,
        };
        if !effective.contains(&grant.permission) {
            return out(Verdict::PermissionUnrelated);
        }
        if !grant.in_force(ctx.now) {
            return out(Verdict::OutsideWindow);
        }
        if request.field.is_some_and(|field| !grant.covers_field(field)) {
            return out(Verdict::FieldNotCovered);
        }
        if self.catalog.is_override_only(request.permission) || self.catalog.is_override_only(&grant.permission) {
            return out(Verdict::OverrideOnly);
        }
        if grant
            .scope
            .as_ref()
            .is_some_and(|scope| !request.resource.contains(scope))
        {
            return out(Verdict::OutOfScope);
        }
        let Some((rank, anchor)) = request.resource.locate(&grant.target) else {
            return out(Verdict::TargetNotOnPath);
        };
        let mut judged = Judged {
            verdict: Verdict::Candidate,
            rank: Some(rank),
            anchor: Some(anchor.clone()),
            condition: None,
        };
        let fail_safe = grant.effect == Effect::Deny;
        let mut problem = None;
        match self.subject_matches(ctx, request.subject, roles, &grant.subject, anchor) {
            Ok(true) => {}
            Ok(false) => {
                judged.verdict = Verdict::SubjectMismatch;
                return judged;
            }
            Err(error) => {
                warnings.push(format!("grant {}: {error}", grant.id));
                if !fail_safe {
                    judged.verdict = Verdict::SubjectUnresolved { problem: error };
                    return judged;
                }
                problem = Some(error);
            }
        }
        if let Some(condition) = &grant.condition {
            if tracing {
                judged.condition = Some(trace_condition_at(condition, eval_ctx, &self.conditions, ctx.now));
            }
            match condition.evaluate_at(eval_ctx, &self.conditions, ctx.now) {
                Ok(true) => {}
                Ok(false) => {
                    judged.verdict = Verdict::ConditionFalse;
                    return judged;
                }
                Err(error) => {
                    warnings.push(format!("grant {}: {error}", grant.id));
                    if !fail_safe {
                        judged.verdict = Verdict::ConditionUnresolved {
                            problem: error.to_string(),
                        };
                        return judged;
                    }
                    problem.get_or_insert(error.to_string());
                }
            }
        }
        if let Some(problem) = problem {
            judged.verdict = Verdict::CandidateFailSafe { problem };
        }
        judged
    }

    fn subject_matches(
        &self,
        ctx: &Context<'_>,
        subject: &Subject,
        roles: &BTreeSet<String>,
        matcher: &SubjectMatcher,
        anchor: &Anchor,
    ) -> Result<bool, String> {
        match matcher {
            SubjectMatcher::User { id } => Ok(subject.id.as_deref() == Some(id.as_str())),
            SubjectMatcher::Role { id } => Ok(roles.contains(id)),
            SubjectMatcher::Principal { name } => Ok(subject.has_principal(name)),
            SubjectMatcher::Any => Ok(true),
            SubjectMatcher::Relation { relation } => {
                let schema = self.relations.as_ref().ok_or("ReBAC desligado no motor")?;
                let store = ctx.tuples.ok_or("contexto sem TupleStore")?;
                let (Some(object), Some(who)) = (anchor.object_ref(), subject.object_ref()) else {
                    return Ok(false);
                };
                schema
                    .check(store, &object, relation, &who, self.max_relation_depth)
                    .map_err(|e| e.to_string())
            }
        }
    }

    /// Checks a grant against the catalog and the engine configuration before writing it.
    pub fn validate_grant(&self, grant: &Grant) -> Result<(), GrantError> {
        if grant.id.trim().is_empty() {
            return Err(GrantError::EmptyId);
        }
        grant.validity().check()?;
        if !self.catalog.contains(&grant.permission) {
            return Err(GrantError::UnknownPermission(grant.permission.clone()));
        }
        if self.catalog.is_override_only(&grant.permission) {
            return Err(GrantError::OverrideOnly(grant.permission.clone()));
        }
        if !self.catalog.is_target_kind(&grant.target.kind) {
            return Err(GrantError::UnknownTargetKind(grant.target.kind.clone()));
        }
        if !self.catalog.allows_target(&grant.permission, &grant.target.kind) {
            return Err(GrantError::TargetNotAllowed {
                permission: grant.permission.clone(),
                target: grant.target.kind.clone(),
            });
        }
        let declared = self.catalog.fields(&grant.permission);
        for field in &grant.fields {
            if !crate::catalog::valid_field(field) {
                return Err(GrantError::InvalidField(field.clone()));
            }
            if !declared.is_empty() && !declared.contains(field) {
                return Err(GrantError::UnknownField {
                    permission: grant.permission.clone(),
                    field: field.clone(),
                });
            }
        }
        if matches!(grant.subject, SubjectMatcher::Relation { .. }) && self.relations.is_none() {
            return Err(GrantError::RelationsDisabled);
        }
        if let Some(condition) = &grant.condition
            && let Some(missing) = condition.functions().into_iter().find(|f| !self.conditions.contains(f))
        {
            return Err(GrantError::UnknownFunction(missing.to_string()));
        }
        Ok(())
    }

    /// Preloads, in one trip to the source, the grants that may hold for `subject` within
    /// `scope`. The result is itself a [`GrantSource`] for repeated decisions (a WebSocket
    /// connection, a page with many buttons) and serializes for the frontend.
    pub fn capabilities(&self, ctx: &Context<'_>, subject: &Subject, scope: &Resource) -> CapabilitySet {
        let roles = self.roles.expand(subject.roles_at(scope, ctx.now));
        let denial_roles = self.roles.expand(subject.roles_for_denial(scope, ctx.now));
        let mut grants = Vec::new();
        ctx.grants.visit(subject, scope, &mut |grant| {
            if !grant.in_force(ctx.now) {
                return;
            }
            let concerns = match &grant.subject {
                SubjectMatcher::User { id } => subject.id.as_deref() == Some(id.as_str()),
                SubjectMatcher::Role { id } if grant.effect == Effect::Deny => denial_roles.contains(id),
                SubjectMatcher::Role { id } => roles.contains(id),
                SubjectMatcher::Principal { name } => subject.has_principal(name),
                SubjectMatcher::Relation { .. } | SubjectMatcher::Any => true,
            };
            if concerns {
                grants.push(grant.clone());
            }
        });
        CapabilitySet {
            subject: subject.clone(),
            grants,
        }
    }
}

/// Preloaded grants of a subject.
///
/// On the wire (`serde`), a set whose grants include field-restricted ones is written twice: the
/// `grants` key holds a form every reader decides safely (see [`crate::query`]: a field-restricted
/// `allow` is left out and a field-restricted `deny` counts as a plain one), and `withFields` holds
/// the real grants. A reader that knows fields takes `withFields`; an older one never sees it and so
/// never reads a restricted grant as one over the whole resource. A set without field-restricted
/// grants is written as it always was.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(from = "CapabilityWire", into = "CapabilityWire")]
pub struct CapabilitySet {
    pub subject: Subject,
    pub grants: Vec<Grant>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CapabilityWire {
    subject: Subject,
    grants: Vec<Grant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    with_fields: Option<Vec<Grant>>,
}

impl From<CapabilitySet> for CapabilityWire {
    fn from(set: CapabilitySet) -> Self {
        if !set.grants.iter().any(Grant::is_field_restricted) {
            return Self {
                subject: set.subject,
                grants: set.grants,
                with_fields: None,
            };
        }
        let safe = set
            .grants
            .iter()
            .filter_map(crate::query::whole_resource_form)
            .collect();
        Self {
            subject: set.subject,
            grants: safe,
            with_fields: Some(set.grants),
        }
    }
}

impl From<CapabilityWire> for CapabilitySet {
    fn from(wire: CapabilityWire) -> Self {
        Self {
            subject: wire.subject,
            grants: wire.with_fields.unwrap_or(wire.grants),
        }
    }
}

impl CapabilitySet {
    /// The next instant after `now` at which a grant or a role assignment of the subject starts or
    /// stops being in force. The set was computed for `now` and is stale from this instant on.
    pub fn next_boundary(&self, now: u64) -> Option<u64> {
        crate::validity::next_boundary(now, &self.grants, &self.subject.roles)
    }
}

impl GrantSource for CapabilitySet {
    fn visit(&self, _: &Subject, _: &Resource, visitor: &mut dyn FnMut(&Grant)) {
        for grant in &self.grants {
            visitor(grant);
        }
    }
}

impl GrantIndex for CapabilitySet {
    fn visit_by_permission(&self, permissions: &[&str], visitor: &mut dyn FnMut(&Grant)) {
        self.grants.visit_by_permission(permissions, visitor);
    }

    fn visit_by_target_kind(&self, kind: &str, visitor: &mut dyn FnMut(&Grant)) {
        self.grants.visit_by_target_kind(kind, visitor);
    }

    fn visit_by_subject(&self, subject: &SubjectMatcher, visitor: &mut dyn FnMut(&Grant)) {
        self.grants.visit_by_subject(subject, visitor);
    }
}
