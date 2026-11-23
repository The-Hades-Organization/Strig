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
use crate::resource::{Anchor, Resource};
use crate::subject::{RoleAssignment, Subject};

/// Proposed change to the grant set or to a subject's roles.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum Mutation {
    Add(Grant),
    Remove {
        id: String,
    },
    /// Gives `role` to `subject`. The grant set does not change; whoever stores the subject's roles
    /// writes [`Mutation::subject_after`].
    AssignRole {
        subject: Subject,
        role: RoleAssignment,
    },
    /// Takes `role` from `subject`, comparing role and scope.
    RevokeRole {
        subject: Subject,
        role: RoleAssignment,
    },
}

impl Mutation {
    /// Subject, assignment and `true` to assign (`false` to revoke), if the change is a
    /// role change.
    pub fn role_change(&self) -> Option<(&Subject, &RoleAssignment, bool)> {
        match self {
            Mutation::AssignRole { subject, role } => Some((subject, role, true)),
            Mutation::RevokeRole { subject, role } => Some((subject, role, false)),
            Mutation::Add(_) | Mutation::Remove { .. } => None,
        }
    }

    /// The subject of the role change with the role added or removed. `None` for a grant
    /// change.
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

/// Same subject: subjects are identified by id, ignoring the kind, and only when the id exists.
/// The same id with another kind counts as the same subject, the safe side for self-management and lockout.
fn same_subject(a: &Subject, b: &Subject) -> bool {
    a.id.is_some() && a.id == b.id
}

fn role_label(role: &RoleAssignment) -> String {
    match &role.scope {
        Some(scope) => format!("{} em {scope}", role.role),
        None => role.role.clone(),
    }
}

/// What an invariant sees: who changes, what, and the set before and after. In a role
/// change, `before` and `after` are the same set; the effect shows up in
/// [`Proposal::subject_after`].
pub struct Proposal<'a> {
    pub actor: &'a Subject,
    pub mutation: &'a Mutation,
    pub before: &'a [Grant],
    pub after: &'a [Grant],
    pub tuples: Option<&'a dyn TupleStore>,
}

impl<'a> Proposal<'a> {
    /// The grant added, or the one removed. `None` for a role change.
    pub fn grant(&self) -> Option<&'a Grant> {
        match self.mutation {
            Mutation::Add(grant) => Some(grant),
            Mutation::Remove { id } => self.before.iter().find(|g| &g.id == id),
            Mutation::AssignRole { .. } | Mutation::RevokeRole { .. } => None,
        }
    }

    /// `subject` as it would be after the change: with the role applied, if it is the subject of
    /// the role change (same id); unchanged in the other cases.
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Violation {
    pub invariant: String,
    pub message: String,
    /// Compensating change the invariant proposes. Nothing is applied: the caller sends it as an
    /// ordinary mutation (which goes through the invariants too) and then sends the refused one
    /// again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<Box<Mutation>>,
}

impl Violation {
    pub fn new(invariant: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            invariant: invariant.into(),
            message: message.into(),
            suggestion: None,
        }
    }

    /// Attaches the compensating change.
    #[must_use]
    pub fn with_suggestion(mut self, mutation: Mutation) -> Self {
        self.suggestion = Some(Box::new(mutation));
        self
    }
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.invariant, self.message)
    }
}

/// Rule that every grant or role change must respect.
pub trait Invariant: Send + Sync {
    fn name(&self) -> &str;
    fn check(&self, engine: &Engine, proposal: &Proposal<'_>) -> Result<(), Violation>;
}

/// Applies grant and role changes only after they pass every invariant and, with the
/// `audit` feature, after recording the decision.
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

    /// Records every change, applied or refused. If the record fails, the change is refused
    /// with the `audit` violation.
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

    /// Returns the grant set after the change, or all the violations. Persistence
    /// is up to the application, which writes only on `Ok`. For a role change the set comes back unchanged
    /// and the subject to write comes from [`Mutation::subject_after`].
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

    /// Like [`Governance::apply`], with request metadata (ip, request id, reason) that goes
    /// to the audit from the `detailed` level upward.
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

/// The added grant exists in the catalog and targets a kind the permission accepts. The assigned
/// role is known (it is in the engine's [`RoleGraph`](crate::RoleGraph) or in some current grant) and
/// its scope, if any, uses a kind from the catalog. Revoking always passes: removing an
/// unknown role is cleanup.
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

/// Nobody changes a grant that applies to themselves: neither the user directly, nor a role they
/// hold (direct or inherited). Grants by principal and by relation are left out. Nobody assigns
/// or revokes a role of their own, either.
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

/// The actor must hold `key` on `resource` before the change.
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

/// After the change, each critical permission still has at least one member able to
/// exercise it on `resource`. Prevents locking a scope out of its own management. Each member
/// is evaluated as they would be after the change ([`Proposal::subject_after`]), so revoking the
/// role of the last one who exercises the permission is also refused.
///
/// With [`NoLockout::with_reserve`], the [`Violation`] also carries the compensating change:
/// assigning the administrator role to the first reserve subject who would cover every
/// permission left uncovered.
pub struct NoLockout {
    critical: Vec<String>,
    members: Vec<Subject>,
    resource: Resource,
    reserve: Option<Reserve>,
}

struct Reserve {
    admin_role: RoleAssignment,
    subjects: Vec<Subject>,
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
            reserve: None,
        }
    }

    /// Subjects held in reserve and the administrator role that the suggestion assigns to one of
    /// them. A reserve subject that already has the role, or has no id, is never suggested.
    #[must_use]
    pub fn with_reserve<I>(mut self, admin_role: RoleAssignment, subjects: I) -> Self
    where
        I: IntoIterator<Item = Subject>,
    {
        self.reserve = Some(Reserve {
            admin_role,
            subjects: subjects.into_iter().collect(),
        });
        self
    }

    fn suggestion(&self, engine: &Engine, ctx: &Context<'_>, uncovered: &[&String]) -> Option<Mutation> {
        let reserve = self.reserve.as_ref()?;
        reserve
            .subjects
            .iter()
            .filter(|s| s.id.is_some() && !s.roles.contains(&reserve.admin_role))
            .find(|s| {
                let promoted = with_role_change(s, &reserve.admin_role, true);
                uncovered
                    .iter()
                    .all(|key| engine.check(ctx, &Request::new(&promoted, key, &self.resource)))
            })
            .map(|subject| Mutation::AssignRole {
                subject: subject.clone(),
                role: reserve.admin_role.clone(),
            })
    }
}

impl Invariant for NoLockout {
    fn name(&self) -> &str {
        "no_lockout"
    }

    fn check(&self, engine: &Engine, proposal: &Proposal<'_>) -> Result<(), Violation> {
        let ctx = proposal.after_context();
        let uncovered: Vec<&String> = self
            .critical
            .iter()
            .filter(|key| {
                !self.members.iter().any(|m| {
                    let member = proposal.subject_after(m);
                    engine.check(&ctx, &Request::new(&member, key, &self.resource))
                })
            })
            .collect();
        let Some(first) = uncovered.first() else {
            return Ok(());
        };
        let violation = Violation::new(
            self.name(),
            format!("a mudança deixaria ninguém com a permissão {first}"),
        );
        Err(match self.suggestion(engine, &ctx, &uncovered) {
            Some(fix) => violation.with_suggestion(fix),
            None => violation,
        })
    }
}

/// `subject` never receives `allow` on `permissions` or on any permission that grants them.
///
/// On a role assignment, it only applies when `subject` is [`SubjectMatcher::User`] with the
/// subject's id: it refuses the role if any current `allow` grant for them, or for a role they inherit,
/// grants a forbidden permission, regardless of scope. The other matchers (principal, `any`,
/// role, relation) do not apply to role assignment.
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
