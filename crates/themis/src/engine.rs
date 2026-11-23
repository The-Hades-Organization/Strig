use std::collections::BTreeSet;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::attr::Attributes;
use crate::catalog::Catalog;
use crate::condition::{ConditionRegistry, EvalContext};
use crate::decision::{Decision, Reason, Request};
use crate::explain::{
    ConditionTrace, Explanation, GrantTrace, OverrideOutcome, OverrideStep, Verdict, trace_condition,
};
use crate::grant::{Effect, Grant, GrantIndex, GrantSource, SubjectMatcher};
use crate::overrides::Override;
use crate::rbac::RoleGraph;
use crate::rebac::{RelationSchema, TupleStore};
use crate::resource::{Anchor, Resource};
use crate::strategy::{Candidate, MostSpecific, Strategy};
use crate::subject::Subject;

static EMPTY_ENV: Attributes = Attributes::new();

#[derive(Default)]
struct Recorder {
    overrides: Vec<OverrideStep>,
    grants: Vec<GrantTrace>,
}

struct Judged {
    verdict: Verdict,
    rank: Option<usize>,
    anchor: Option<Anchor>,
    condition: Option<ConditionTrace>,
}

const DEFAULT_MAX_RELATION_DEPTH: usize = 32;

/// Data of a decision: grants, ReBAC tuples and environment attributes. The [`Engine`] only holds
/// configuration; the data arrives with each call.
#[derive(Clone, Copy)]
pub struct Context<'a> {
    pub grants: &'a dyn GrantSource,
    pub tuples: Option<&'a dyn TupleStore>,
    pub env: &'a Attributes,
}

impl<'a> Context<'a> {
    pub fn new(grants: &'a dyn GrantSource) -> Self {
        Self {
            grants,
            tuples: None,
            env: &EMPTY_ENV,
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
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EngineError {
    #[error("exceção de override cita permissão fora do catálogo: {0}")]
    UnknownPermission(String),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GrantError {
    #[error("grant sem id")]
    EmptyId,
    #[error("permissão desconhecida: {0}")]
    UnknownPermission(String),
    #[error("tipo de alvo não registrado: {0}")]
    UnknownTargetKind(String),
    #[error("a permissão {permission} não aceita alvo {target}")]
    TargetNotAllowed { permission: String, target: String },
    #[error("grant por relação exige RelationSchema no motor")]
    RelationsDisabled,
    #[error("condição chama função não registrada: {0}")]
    UnknownFunction(String),
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
        EngineBuilder {
            engine: Engine {
                catalog: catalog.into(),
                roles: RoleGraph::default(),
                relations: None,
                conditions: ConditionRegistry::default(),
                strategy: Arc::new(MostSpecific),
                overrides: Vec::new(),
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
        self.decide_inner(ctx, request, true, None)
    }

    /// Decision by the grants only, without overrides. Used by overrides that depend on a permission.
    pub fn decide_without_overrides(&self, ctx: &Context<'_>, request: &Request<'_>) -> Decision {
        self.decide_inner(ctx, request, false, None)
    }

    /// The same decision as [`Engine::decide`], with the trace of each override and of each grant
    /// delivered by the source. More expensive: it evaluates the condition tree and clones the grants.
    pub fn explain(&self, ctx: &Context<'_>, request: &Request<'_>) -> Explanation {
        self.explain_with(ctx, request, true)
    }

    pub(crate) fn explain_with(&self, ctx: &Context<'_>, request: &Request<'_>, with_overrides: bool) -> Explanation {
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
            resource: request.resource.clone(),
            effective: self
                .catalog
                .effective(request.permission)
                .map(|set| set.iter().cloned().collect())
                .unwrap_or_default(),
            path: request.resource.anchors().map(|(_, a)| a.clone()).collect(),
            roles: self
                .roles
                .expand(request.subject.roles_for(request.resource))
                .into_iter()
                .collect(),
            overrides: recorder.overrides,
            grants: recorder.grants,
            strategy: self.strategy.name().to_string(),
            decision,
        }
    }

    fn decide_inner(
        &self,
        ctx: &Context<'_>,
        request: &Request<'_>,
        with_overrides: bool,
        mut recorder: Option<&mut Recorder>,
    ) -> Decision {
        let Some(effective) = self.catalog.effective(request.permission) else {
            return Decision::deny(Reason::UnknownPermission);
        };

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
        match self.strategy.combine(&candidates) {
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
        let roles = self.roles.expand(request.subject.roles_for(request.resource));
        let eval_ctx = EvalContext {
            subject: request.subject,
            resource: request.resource,
            env: ctx.env,
        };
        let tracing = recorder.is_some();
        let mut out = Vec::new();
        ctx.grants.visit(request.subject, request.resource, &mut |grant| {
            let judged = self.judge(ctx, request, effective, &roles, &eval_ctx, grant, warnings, tracing);
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
                judged.condition = Some(trace_condition(condition, eval_ctx, &self.conditions));
            }
            match condition.evaluate(eval_ctx, &self.conditions) {
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
        if !self.catalog.contains(&grant.permission) {
            return Err(GrantError::UnknownPermission(grant.permission.clone()));
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
        let roles = self.roles.expand(subject.roles_for(scope));
        let mut grants = Vec::new();
        ctx.grants.visit(subject, scope, &mut |grant| {
            let concerns = match &grant.subject {
                SubjectMatcher::User { id } => subject.id.as_deref() == Some(id.as_str()),
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilitySet {
    pub subject: Subject,
    pub grants: Vec<Grant>,
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
