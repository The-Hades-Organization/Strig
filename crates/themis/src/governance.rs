use std::fmt;
#[cfg(feature = "audit")]
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::attr::Attributes;
#[cfg(feature = "audit")]
use crate::audit::Auditor;
use crate::decision::Request;
use crate::engine::{Context, Engine};
use crate::grant::{Effect, Grant, SubjectMatcher};
use crate::rebac::TupleStore;
use crate::resource::Resource;
use crate::subject::Subject;

/// Mudança proposta no conjunto de grants.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum Mutation {
    Add(Grant),
    Remove { id: String },
}

/// O que um invariante enxerga: quem muda, o quê, e o conjunto antes e depois.
pub struct Proposal<'a> {
    pub actor: &'a Subject,
    pub mutation: &'a Mutation,
    pub before: &'a [Grant],
    pub after: &'a [Grant],
    pub tuples: Option<&'a dyn TupleStore>,
}

impl<'a> Proposal<'a> {
    /// O grant adicionado, ou o removido.
    pub fn grant(&self) -> Option<&'a Grant> {
        match self.mutation {
            Mutation::Add(grant) => Some(grant),
            Mutation::Remove { id } => self.before.iter().find(|g| &g.id == id),
        }
    }

    pub fn before_context(&self) -> Context<'_> {
        self.context(&self.before)
    }

    pub fn after_context(&self) -> Context<'_> {
        self.context(&self.after)
    }

    fn context<'s>(&'s self, grants: &'s &'a [Grant]) -> Context<'s> {
        let ctx = Context::new(grants);
        match self.tuples {
            Some(tuples) => ctx.with_tuples(tuples),
            None => ctx,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Violation {
    pub invariant: String,
    pub message: String,
}

impl Violation {
    pub fn new(invariant: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            invariant: invariant.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.invariant, self.message)
    }
}

/// Regra que toda mudança de grant precisa respeitar.
pub trait Invariant: Send + Sync {
    fn name(&self) -> &str;
    fn check(&self, engine: &Engine, proposal: &Proposal<'_>) -> Result<(), Violation>;
}

/// Aplica mudanças de grant só depois de passar por todos os invariantes e, com a feature
/// `audit`, de registrar a decisão.
#[derive(Default)]
pub struct Governance {
    invariants: Vec<Box<dyn Invariant>>,
    #[cfg(feature = "audit")]
    auditor: Option<Arc<Auditor>>,
}

impl Governance {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(mut self, invariant: impl Invariant + 'static) -> Self {
        self.invariants.push(Box::new(invariant));
        self
    }

    /// Registra toda mudança, aplicada ou recusada. Se o registro falhar, a mudança é recusada
    /// com a violação `audit`.
    #[cfg(feature = "audit")]
    pub fn audited(mut self, auditor: Arc<Auditor>) -> Self {
        self.auditor = Some(auditor);
        self
    }

    pub fn len(&self) -> usize {
        self.invariants.len()
    }

    pub fn is_empty(&self) -> bool {
        self.invariants.is_empty()
    }

    /// Devolve o conjunto de grants depois da mudança, ou todas as violações. A persistência
    /// fica com a aplicação, que grava só no `Ok`.
    pub fn apply(
        &self,
        engine: &Engine,
        actor: &Subject,
        current: &[Grant],
        mutation: &Mutation,
        tuples: Option<&dyn TupleStore>,
    ) -> Result<Vec<Grant>, Vec<Violation>> {
        self.apply_with(engine, actor, current, mutation, tuples, &Attributes::new())
    }

    /// Como [`Governance::apply`], com metadados da requisição (ip, request id, motivo) que vão
    /// para a auditoria a partir do nível `detailed`.
    pub fn apply_with(
        &self,
        engine: &Engine,
        actor: &Subject,
        current: &[Grant],
        mutation: &Mutation,
        tuples: Option<&dyn TupleStore>,
        meta: &Attributes,
    ) -> Result<Vec<Grant>, Vec<Violation>> {
        let result = self.evaluate(engine, actor, current, mutation, tuples);
        #[cfg(feature = "audit")]
        if let Some(auditor) = &self.auditor
            && let Err(error) = auditor.grant_mutation(actor, mutation, current, &result, meta)
        {
            return Err(vec![Violation::new("audit", error.to_string())]);
        }
        #[cfg(not(feature = "audit"))]
        let _ = meta;
        result
    }

    fn evaluate(
        &self,
        engine: &Engine,
        actor: &Subject,
        current: &[Grant],
        mutation: &Mutation,
        tuples: Option<&dyn TupleStore>,
    ) -> Result<Vec<Grant>, Vec<Violation>> {
        let after = match mutation {
            Mutation::Add(grant) => {
                if current.iter().any(|g| g.id == grant.id) {
                    return Err(vec![Violation::new(
                        "mutation",
                        format!("grant {} já existe", grant.id),
                    )]);
                }
                let mut next = current.to_vec();
                next.push(grant.clone());
                next
            }
            Mutation::Remove { id } => {
                if !current.iter().any(|g| &g.id == id) {
                    return Err(vec![Violation::new("mutation", format!("grant {id} não existe"))]);
                }
                current.iter().filter(|g| &g.id != id).cloned().collect()
            }
        };
        let proposal = Proposal {
            actor,
            mutation,
            before: current,
            after: &after,
            tuples,
        };
        let violations: Vec<Violation> = self
            .invariants
            .iter()
            .filter_map(|inv| inv.check(engine, &proposal).err())
            .collect();
        if violations.is_empty() {
            Ok(after)
        } else {
            Err(violations)
        }
    }
}

/// O grant adicionado existe no catálogo e mira um alvo aceito pela permissão.
pub struct CatalogConformance;

impl Invariant for CatalogConformance {
    fn name(&self) -> &str {
        "catalog_conformance"
    }

    fn check(&self, engine: &Engine, proposal: &Proposal<'_>) -> Result<(), Violation> {
        match proposal.mutation {
            Mutation::Add(grant) => engine
                .validate_grant(grant)
                .map_err(|e| Violation::new(self.name(), e.to_string())),
            Mutation::Remove { .. } => Ok(()),
        }
    }
}

/// Ninguém mexe em grant que vale para si: nem o próprio usuário, nem um papel que tem
/// (direto ou herdado). Grants por principal e por relação ficam de fora.
pub struct NoSelfManagement;

impl Invariant for NoSelfManagement {
    fn name(&self) -> &str {
        "no_self_management"
    }

    fn check(&self, engine: &Engine, proposal: &Proposal<'_>) -> Result<(), Violation> {
        let Some(grant) = proposal.grant() else {
            return Ok(());
        };
        let actor = proposal.actor;
        let affects_actor = match &grant.subject {
            SubjectMatcher::User { id } => actor.id.as_deref() == Some(id.as_str()),
            SubjectMatcher::Role { id } => engine
                .roles()
                .expand(actor.roles.iter().map(|r| r.role.as_str()))
                .contains(id),
            _ => false,
        };
        if affects_actor {
            Err(Violation::new(
                self.name(),
                "não é permitido gerenciar as próprias permissões",
            ))
        } else {
            Ok(())
        }
    }
}

/// O ator precisa ter `key` sobre `resource` antes da mudança.
pub struct RequirePermission {
    key: String,
    resource: Resource,
}

impl RequirePermission {
    pub fn new(key: impl Into<String>, resource: Resource) -> Self {
        Self {
            key: key.into(),
            resource,
        }
    }
}

impl Invariant for RequirePermission {
    fn name(&self) -> &str {
        "require_permission"
    }

    fn check(&self, engine: &Engine, proposal: &Proposal<'_>) -> Result<(), Violation> {
        let request = Request::new(proposal.actor, &self.key, &self.resource);
        if engine.check(&proposal.before_context(), &request) {
            Ok(())
        } else {
            Err(Violation::new(self.name(), format!("falta a permissão {}", self.key)))
        }
    }
}

/// Depois da mudança, cada permissão crítica continua com pelo menos um membro capaz de
/// exercê-la sobre `resource`. Impede trancar um escopo para fora da própria gestão.
pub struct NoLockout {
    critical: Vec<String>,
    members: Vec<Subject>,
    resource: Resource,
}

impl NoLockout {
    pub fn new<I, S>(critical: I, members: Vec<Subject>, resource: Resource) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            critical: critical.into_iter().map(Into::into).collect(),
            members,
            resource,
        }
    }
}

impl Invariant for NoLockout {
    fn name(&self) -> &str {
        "no_lockout"
    }

    fn check(&self, engine: &Engine, proposal: &Proposal<'_>) -> Result<(), Violation> {
        let ctx = proposal.after_context();
        for key in &self.critical {
            let covered = self
                .members
                .iter()
                .any(|m| engine.check(&ctx, &Request::new(m, key, &self.resource)));
            if !covered {
                return Err(Violation::new(
                    self.name(),
                    format!("a mudança deixaria ninguém com a permissão {key}"),
                ));
            }
        }
        Ok(())
    }
}

/// `subject` nunca recebe `allow` em `permissions` nem em permissão que as conceda.
pub struct Forbid {
    subject: SubjectMatcher,
    permissions: Vec<String>,
}

impl Forbid {
    pub fn new<I, S>(subject: SubjectMatcher, permissions: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            subject,
            permissions: permissions.into_iter().map(Into::into).collect(),
        }
    }
}

impl Invariant for Forbid {
    fn name(&self) -> &str {
        "forbid"
    }

    fn check(&self, engine: &Engine, proposal: &Proposal<'_>) -> Result<(), Violation> {
        let Mutation::Add(grant) = proposal.mutation else {
            return Ok(());
        };
        if grant.effect != Effect::Allow || grant.subject != self.subject {
            return Ok(());
        }
        match self
            .permissions
            .iter()
            .find(|p| engine.catalog().implies(&grant.permission, p))
        {
            Some(forbidden) => Err(Violation::new(
                self.name(),
                format!(
                    "{} concederia {forbidden}, proibido para este sujeito",
                    grant.permission
                ),
            )),
            None => Ok(()),
        }
    }
}
