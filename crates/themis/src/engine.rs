use std::collections::BTreeSet;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::attr::Attributes;
use crate::catalog::Catalog;
use crate::condition::{ConditionRegistry, EvalContext};
use crate::decision::{Decision, Reason, Request};
use crate::grant::{Effect, Grant, GrantSource, SubjectMatcher};
use crate::overrides::Override;
use crate::rbac::RoleGraph;
use crate::rebac::{RelationSchema, TupleStore};
use crate::resource::{Anchor, Resource};
use crate::strategy::{Candidate, MostSpecific, Strategy};
use crate::subject::Subject;

static EMPTY_ENV: Attributes = Attributes::new();

const DEFAULT_MAX_RELATION_DEPTH: usize = 32;

/// Dados de uma decisão: grants, tuplas ReBAC e atributos de ambiente. O [`Engine`] guarda só
/// configuração; os dados chegam por chamada.
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

struct OverrideEntry {
    inner: Box<dyn Override>,
    except: Vec<String>,
}

/// Motor de decisão. Imutável e compartilhável entre threads depois de construído.
pub struct Engine {
    catalog: Arc<Catalog>,
    roles: RoleGraph,
    relations: Option<RelationSchema>,
    conditions: ConditionRegistry,
    strategy: Box<dyn Strategy>,
    overrides: Vec<OverrideEntry>,
    max_relation_depth: usize,
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
        self.engine.strategy = Box::new(strategy);
        self
    }

    pub fn override_with(self, rule: impl Override + 'static) -> Self {
        self.override_except(rule, std::iter::empty::<String>())
    }

    /// Override que não vale para as permissões listadas nem para as que elas concedem
    /// (o administrador da organização não apaga projeto de outro dono, por exemplo).
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
                strategy: Box::new(MostSpecific),
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
        self.decide_inner(ctx, request, true)
    }

    /// Decisão só pelos grants, sem overrides. Usada por overrides que dependem de permissão.
    pub fn decide_without_overrides(&self, ctx: &Context<'_>, request: &Request<'_>) -> Decision {
        self.decide_inner(ctx, request, false)
    }

    fn decide_inner(&self, ctx: &Context<'_>, request: &Request<'_>, with_overrides: bool) -> Decision {
        let Some(effective) = self.catalog.effective(request.permission) else {
            return Decision::deny(Reason::UnknownPermission);
        };

        if with_overrides {
            for entry in &self.overrides {
                if entry.except.iter().any(|key| effective.contains(key)) {
                    continue;
                }
                if let Some(effect) = entry.inner.evaluate(self, ctx, request) {
                    return Decision {
                        effect,
                        reason: Reason::Override {
                            name: entry.inner.name().to_string(),
                        },
                        matched: Vec::new(),
                        warnings: Vec::new(),
                    };
                }
            }
        }

        let mut warnings = Vec::new();
        let candidates = self.collect(ctx, request, effective, &mut warnings);
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

    /// Grants que se aplicam ao pedido. Na dúvida (condição ou relação que não pôde ser
    /// avaliada), um `deny` se aplica e um `allow` não: o erro nunca abre acesso.
    fn collect(
        &self,
        ctx: &Context<'_>,
        request: &Request<'_>,
        effective: &BTreeSet<String>,
        warnings: &mut Vec<String>,
    ) -> Vec<Candidate> {
        let roles = self.roles.expand(request.subject.roles_for(request.resource));
        let eval_ctx = EvalContext {
            subject: request.subject,
            resource: request.resource,
            env: ctx.env,
        };
        let mut out = Vec::new();
        ctx.grants.visit(request.subject, request.resource, &mut |grant| {
            if !effective.contains(&grant.permission) {
                return;
            }
            if grant
                .scope
                .as_ref()
                .is_some_and(|scope| !request.resource.contains(scope))
            {
                return;
            }
            let Some((rank, anchor)) = request.resource.locate(&grant.target) else {
                return;
            };
            let fail_safe = grant.effect == Effect::Deny;
            match self.subject_matches(ctx, request.subject, &roles, &grant.subject, anchor) {
                Ok(true) => {}
                Ok(false) => return,
                Err(error) => {
                    warnings.push(format!("grant {}: {error}", grant.id));
                    if !fail_safe {
                        return;
                    }
                }
            }
            if let Some(condition) = &grant.condition {
                match condition.evaluate(&eval_ctx, &self.conditions) {
                    Ok(true) => {}
                    Ok(false) => return,
                    Err(error) => {
                        warnings.push(format!("grant {}: {error}", grant.id));
                        if !fail_safe {
                            return;
                        }
                    }
                }
            }
            out.push(Candidate {
                grant: grant.clone(),
                rank,
            });
        });
        out
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

    /// Confere um grant contra o catálogo e a configuração do motor antes de gravá-lo.
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

    /// Pré-carrega, numa ida à fonte, os grants que podem valer para `subject` dentro de
    /// `scope`. O resultado é ele mesmo uma [`GrantSource`] para decisões repetidas (uma
    /// conexão WebSocket, uma página com muitos botões) e serializa para o frontend.
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

/// Grants pré-carregados de um sujeito.
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
