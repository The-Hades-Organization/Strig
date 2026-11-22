use std::borrow::Cow;
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
use crate::subject::{RoleAssignment, Subject};

/// Mudança proposta no conjunto de grants ou nos papéis de um sujeito.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum Mutation {
    Add(Grant),
    Remove {
        id: String,
    },
    /// Dá `role` a `subject`. O conjunto de grants não muda; quem guarda os papéis do sujeito
    /// grava [`Mutation::subject_after`].
    AssignRole {
        subject: Subject,
        role: RoleAssignment,
    },
    /// Tira `role` de `subject`, comparando papel e escopo.
    RevokeRole {
        subject: Subject,
        role: RoleAssignment,
    },
}

impl Mutation {
    /// Sujeito, atribuição e `true` para atribuir (`false` para revogar), se a mudança é de
    /// papel.
    pub fn role_change(&self) -> Option<(&Subject, &RoleAssignment, bool)> {
        match self {
            Mutation::AssignRole { subject, role } => Some((subject, role, true)),
            Mutation::RevokeRole { subject, role } => Some((subject, role, false)),
            Mutation::Add(_) | Mutation::Remove { .. } => None,
        }
    }

    /// O sujeito da mudança de papel com o papel acrescentado ou removido. `None` para mudança
    /// de grant.
    pub fn subject_after(&self) -> Option<Subject> {
        let (subject, role, assigned) = self.role_change()?;
        Some(with_role_change(subject, role, assigned))
    }
}

fn with_role_change(subject: &Subject, role: &RoleAssignment, assigned: bool) -> Subject {
    let mut next = subject.clone();
    if !assigned {
        next.roles.retain(|r| r != role);
    } else if !next.roles.contains(role) {
        next.roles.push(role.clone());
    }
    next
}

/// Mesmo sujeito: sujeitos são identificados pelo id, sem olhar o tipo, e só quando o id existe.
/// O mesmo id com outro tipo conta como o mesmo sujeito, o lado seguro para autogestão e lockout.
fn same_subject(a: &Subject, b: &Subject) -> bool {
    a.id.is_some() && a.id == b.id
}

fn role_label(role: &RoleAssignment) -> String {
    match &role.scope {
        Some(scope) => format!("{} em {scope}", role.role),
        None => role.role.clone(),
    }
}

/// O que um invariante enxerga: quem muda, o quê, e o conjunto antes e depois. Numa mudança de
/// papel, `before` e `after` são o mesmo conjunto; o efeito aparece em
/// [`Proposal::subject_after`].
pub struct Proposal<'a> {
    pub actor: &'a Subject,
    pub mutation: &'a Mutation,
    pub before: &'a [Grant],
    pub after: &'a [Grant],
    pub tuples: Option<&'a dyn TupleStore>,
}

impl<'a> Proposal<'a> {
    /// O grant adicionado, ou o removido. `None` para mudança de papel.
    pub fn grant(&self) -> Option<&'a Grant> {
        match self.mutation {
            Mutation::Add(grant) => Some(grant),
            Mutation::Remove { id } => self.before.iter().find(|g| &g.id == id),
            Mutation::AssignRole { .. } | Mutation::RevokeRole { .. } => None,
        }
    }

    /// `subject` como ficaria depois da mudança: com o papel aplicado, se for o sujeito da
    /// mudança de papel (mesmo id); sem alteração nos outros casos.
    pub fn subject_after<'s>(&self, subject: &'s Subject) -> Cow<'s, Subject> {
        match self.mutation.role_change() {
            Some((target, role, assigned)) if same_subject(target, subject) => {
                Cow::Owned(with_role_change(subject, role, assigned))
            }
            _ => Cow::Borrowed(subject),
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

/// Regra que toda mudança de grant ou de papel precisa respeitar.
pub trait Invariant: Send + Sync {
    fn name(&self) -> &str;
    fn check(&self, engine: &Engine, proposal: &Proposal<'_>) -> Result<(), Violation>;
}

/// Aplica mudanças de grant e de papel só depois de passar por todos os invariantes e, com a
/// feature `audit`, de registrar a decisão.
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
    /// fica com a aplicação, que grava só no `Ok`. Numa mudança de papel o conjunto volta igual
    /// e o sujeito a gravar sai de [`Mutation::subject_after`].
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
        let after: Cow<'_, [Grant]> = match mutation {
            Mutation::Add(grant) => {
                if current.iter().any(|g| g.id == grant.id) {
                    return Err(vec![Violation::new(
                        "mutation",
                        format!("grant {} já existe", grant.id),
                    )]);
                }
                let mut next = current.to_vec();
                next.push(grant.clone());
                Cow::Owned(next)
            }
            Mutation::Remove { id } => {
                if !current.iter().any(|g| &g.id == id) {
                    return Err(vec![Violation::new("mutation", format!("grant {id} não existe"))]);
                }
                Cow::Owned(current.iter().filter(|g| &g.id != id).cloned().collect())
            }
            Mutation::AssignRole { subject, role } => {
                check_role_mutation(subject, role, true)?;
                Cow::Borrowed(current)
            }
            Mutation::RevokeRole { subject, role } => {
                check_role_mutation(subject, role, false)?;
                Cow::Borrowed(current)
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
            Ok(after.into_owned())
        } else {
            Err(violations)
        }
    }
}

fn check_role_mutation(subject: &Subject, role: &RoleAssignment, assigned: bool) -> Result<(), Vec<Violation>> {
    let Some(id) = subject.id.as_deref() else {
        return Err(vec![Violation::new(
            "mutation",
            "papel só se atribui a sujeito identificado",
        )]);
    };
    let has = subject.roles.contains(role);
    let message = match (assigned, has) {
        (true, true) => format!("{id} já tem o papel {}", role_label(role)),
        (false, false) => format!("{id} não tem o papel {}", role_label(role)),
        _ => return Ok(()),
    };
    Err(vec![Violation::new("mutation", message)])
}

/// O grant adicionado existe no catálogo e mira um alvo aceito pela permissão. O papel atribuído
/// é conhecido (está no [`RoleGraph`](crate::RoleGraph) do motor ou em algum grant atual) e o
/// escopo dele, se houver, usa um tipo do catálogo. Revogar passa sempre: tirar papel
/// desconhecido é limpeza.
pub struct CatalogConformance;

impl CatalogConformance {
    fn check_role(&self, engine: &Engine, current: &[Grant], role: &RoleAssignment) -> Result<(), Violation> {
        let known = engine.roles().contains(&role.role)
            || current
                .iter()
                .any(|g| matches!(&g.subject, SubjectMatcher::Role { id } if *id == role.role));
        if !known {
            return Err(Violation::new(
                self.name(),
                format!("papel desconhecido: {}", role.role),
            ));
        }
        match &role.scope {
            Some(scope) if !engine.catalog().is_target_kind(&scope.kind) => Err(Violation::new(
                self.name(),
                format!("escopo {scope} usa tipo fora do catálogo"),
            )),
            _ => Ok(()),
        }
    }
}

impl Invariant for CatalogConformance {
    fn name(&self) -> &str {
        "catalog_conformance"
    }

    fn check(&self, engine: &Engine, proposal: &Proposal<'_>) -> Result<(), Violation> {
        match proposal.mutation {
            Mutation::Add(grant) => engine
                .validate_grant(grant)
                .map_err(|e| Violation::new(self.name(), e.to_string())),
            Mutation::AssignRole { role, .. } => self.check_role(engine, proposal.before, role),
            Mutation::Remove { .. } | Mutation::RevokeRole { .. } => Ok(()),
        }
    }
}

/// Ninguém mexe em grant que vale para si: nem o próprio usuário, nem um papel que tem
/// (direto ou herdado). Grants por principal e por relação ficam de fora. Também ninguém atribui
/// nem revoga papel de si mesmo.
pub struct NoSelfManagement;

impl Invariant for NoSelfManagement {
    fn name(&self) -> &str {
        "no_self_management"
    }

    fn check(&self, engine: &Engine, proposal: &Proposal<'_>) -> Result<(), Violation> {
        let actor = proposal.actor;
        if let Some((subject, _, _)) = proposal.mutation.role_change() {
            return if same_subject(subject, actor) {
                Err(Violation::new(
                    self.name(),
                    "não é permitido gerenciar os próprios papéis",
                ))
            } else {
                Ok(())
            };
        }
        let Some(grant) = proposal.grant() else {
            return Ok(());
        };
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
/// exercê-la sobre `resource`. Impede trancar um escopo para fora da própria gestão. Cada membro
/// é avaliado como ficaria depois da mudança ([`Proposal::subject_after`]), então revogar o
/// papel do último que exerce a permissão também é recusado.
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
            let covered = self.members.iter().any(|m| {
                let member = proposal.subject_after(m);
                engine.check(&ctx, &Request::new(&member, key, &self.resource))
            });
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
///
/// Em atribuição de papel, só vale quando `subject` é [`SubjectMatcher::User`] com o id do
/// sujeito: recusa o papel se algum grant `allow` atual para ele, ou para um papel que ele herda,
/// concede uma permissão proibida, sem olhar escopo. Os outros matchers (principal, `any`,
/// papel, relação) não se aplicam a atribuição de papel.
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
        match proposal.mutation {
            Mutation::Add(grant) => self.check_grant(engine, grant),
            Mutation::AssignRole { subject, role } => self.check_role(engine, proposal.before, subject, role),
            Mutation::Remove { .. } | Mutation::RevokeRole { .. } => Ok(()),
        }
    }
}

impl Forbid {
    fn forbidden_by<'s>(&'s self, engine: &Engine, permission: &str) -> Option<&'s String> {
        self.permissions
            .iter()
            .find(|p| engine.catalog().implies(permission, p))
    }

    fn check_grant(&self, engine: &Engine, grant: &Grant) -> Result<(), Violation> {
        if grant.effect != Effect::Allow || grant.subject != self.subject {
            return Ok(());
        }
        match self.forbidden_by(engine, &grant.permission) {
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

    fn check_role(
        &self,
        engine: &Engine,
        current: &[Grant],
        subject: &Subject,
        role: &RoleAssignment,
    ) -> Result<(), Violation> {
        let SubjectMatcher::User { id } = &self.subject else {
            return Ok(());
        };
        if subject.id.as_deref() != Some(id.as_str()) {
            return Ok(());
        }
        let roles = engine.roles().expand([role.role.as_str()]);
        for grant in current.iter().filter(|g| g.effect == Effect::Allow) {
            let SubjectMatcher::Role { id: granted } = &grant.subject else {
                continue;
            };
            if !roles.contains(granted) {
                continue;
            }
            if let Some(forbidden) = self.forbidden_by(engine, &grant.permission) {
                return Err(Violation::new(
                    self.name(),
                    format!(
                        "o papel {} concederia {forbidden} pelo grant {} ({}), proibido para este sujeito",
                        role.role, grant.id, grant.permission
                    ),
                ));
            }
        }
        Ok(())
    }
}
