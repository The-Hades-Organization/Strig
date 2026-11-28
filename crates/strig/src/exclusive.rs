//! Exclusive ownership of a resource, with priority, preemption and a time limit.
//!
//! At most one holder owns a resource ([`ObjectRef`]) at a time. A holder with a strictly higher
//! priority can take it over, and only when the engine allows it: [`ExclusiveRegistry::acquire_checked`]
//! requires the ownership permission on the resource and, to preempt, the preemption permission too.
//! The result of a preemption carries the previous lease so the application can notify its holder.
//!
//! Nothing here reads a clock: `now` is milliseconds since the Unix epoch, passed by the caller, as
//! in the rest of the crate. A lease is active while `now < expires_at`. State lives behind
//! [`ExclusiveStore`]; [`MemoryExclusiveStore`] keeps it in memory and adapters can persist it.
//!
//! Trust: the priority and the lifetime in [`Terms`], the holder passed to `release`/`renew` and
//! the path of the [`Resource`] given to the checked acquisition must come from the application
//! (the authenticated subject, its policy, the resource's canonical path), never straight from a
//! request. The permission is checked on the whole path, but the lease is keyed by its first step.
//!
//! The registry takes `&mut self`, so one registry is one writer. A store shared between processes
//! must make each decision atomic by itself: [`ExclusiveStore::acquire_lease`],
//! [`ExclusiveStore::renew_lease`], [`ExclusiveStore::release_lease`] and
//! [`ExclusiveStore::remove_expired`] are the units it has to keep indivisible, and
//! [`Acquisition::decide`] is the rule they all apply. The defaults compose `get`/`put`/`remove`,
//! which is atomic only for a store that has a single writer, like [`MemoryExclusiveStore`].

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::attr::Value;
use crate::decision::Request;
use crate::engine::{Context, Engine};
use crate::resource::{ObjectRef, Resource};
use crate::subject::Subject;

#[cfg(feature = "audit")]
use crate::attr::Attributes;
#[cfg(feature = "audit")]
use crate::audit::{AuditAction, AuditError, AuditOutcome, Auditor};
#[cfg(feature = "audit")]
use std::sync::Arc;

/// Permission that allows holding a resource exclusively, unless configured otherwise.
pub const DEFAULT_HOLD_PERMISSION: &str = "exclusive.hold";
/// Permission that allows taking a resource from a lower-priority holder, unless configured otherwise.
pub const DEFAULT_PREEMPT_PERMISSION: &str = "exclusive.preempt";

/// Active or expired ownership of a resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lease {
    pub resource: ObjectRef,
    pub holder: ObjectRef,
    pub priority: i64,
    /// Milliseconds since the Unix epoch.
    pub acquired_at: u64,
    /// Milliseconds since the Unix epoch. The lease is over at this instant.
    pub expires_at: u64,
}

impl Lease {
    pub fn is_active(&self, now: u64) -> bool {
        now < self.expires_at
    }

    /// The lease `claim` creates when granted at `now`.
    #[must_use]
    pub fn granted(claim: &Claim, now: u64) -> Self {
        Self {
            resource: claim.resource.clone(),
            holder: claim.holder.clone(),
            priority: claim.terms.priority,
            acquired_at: now,
            expires_at: now.saturating_add(claim.terms.ttl_ms),
        }
    }

    /// This lease extended to `now + ttl_ms`, keeping holder, priority and acquisition instant.
    #[must_use]
    pub fn renewed(&self, now: u64, ttl_ms: u64) -> Self {
        Self {
            expires_at: now.saturating_add(ttl_ms),
            ..self.clone()
        }
    }
}

/// Priority and duration of a claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Terms {
    /// Higher wins. Compared only against the current holder's priority.
    pub priority: i64,
    /// Lifetime of the lease, in milliseconds. Must be greater than zero.
    pub ttl_ms: u64,
}

impl Terms {
    #[must_use]
    pub fn new(priority: i64, ttl_ms: u64) -> Self {
        Self { priority, ttl_ms }
    }
}

/// Request to own `resource` on behalf of `holder`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    pub resource: ObjectRef,
    pub holder: ObjectRef,
    pub terms: Terms,
}

impl Claim {
    #[must_use]
    pub fn new(resource: ObjectRef, holder: ObjectRef, terms: Terms) -> Self {
        Self {
            resource,
            holder,
            terms,
        }
    }
}

/// Whether [`ExclusiveRegistry::acquire`] may take a resource from a lower-priority holder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preemption {
    Forbidden,
    Allowed,
}

/// Outcome of an acquisition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Acquisition {
    /// The claimant holds the resource now: it was free, its lease had run out, or the claimant
    /// already held it (the lease is replaced).
    Granted,
    /// The claimant took the resource from `previous`, whose holder the application should tell.
    Preempted { previous: Lease },
    /// Someone else holds it and the claimant cannot take it.
    Busy { holder: Lease },
}

impl Acquisition {
    /// The decision for `claim` at `now` against the lease on the resource, if there is one. A lease
    /// that ran out does not count. This is the one rule every store applies, so a store that
    /// decides inside its own transaction agrees with [`MemoryExclusiveStore`].
    #[must_use]
    pub fn decide(current: Option<Lease>, claim: &Claim, now: u64, preemption: Preemption) -> Self {
        match current.filter(|lease| lease.is_active(now)) {
            None => Self::Granted,
            Some(lease) if lease.holder == claim.holder => Self::Granted,
            Some(lease) if preemption == Preemption::Allowed && claim.terms.priority > lease.priority => {
                Self::Preempted { previous: lease }
            }
            Some(lease) => Self::Busy { holder: lease },
        }
    }
}

/// Outcome of a change only the holder can make: [`ExclusiveStore::renew_lease`] and
/// [`ExclusiveStore::release_lease`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum OwnedChange {
    /// Applied. Carries the lease as it is now (renewed) or as it was (released).
    Applied(Lease),
    /// There is no active lease on the resource.
    NotHeld,
    /// Another holder has it.
    NotHolder { holder: ObjectRef },
}

impl OwnedChange {
    /// The decision for `holder` against the lease on the resource, if there is one.
    #[must_use]
    pub fn decide(current: Option<Lease>, holder: &ObjectRef, now: u64) -> Self {
        match current.filter(|lease| lease.is_active(now)) {
            None => Self::NotHeld,
            Some(lease) if &lease.holder != holder => Self::NotHolder { holder: lease.holder },
            Some(lease) => Self::Applied(lease),
        }
    }
}

/// Failure to read or write the lease store.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("falha no armazenamento de posse exclusiva: {0}")]
pub struct StoreError(pub String);

#[derive(Debug, thiserror::Error)]
pub enum ExclusiveError {
    #[error("o prazo da posse precisa ser maior que zero")]
    ZeroTtl,
    #[error("o recurso {0} não está sob posse exclusiva")]
    NotHeld(ObjectRef),
    #[error("o recurso {resource} pertence a {holder}")]
    NotHolder { resource: ObjectRef, holder: ObjectRef },
    #[error("o sujeito não tem id e não pode manter posse")]
    AnonymousSubject,
    #[error("o recurso não tem um passo identificado (kind:id) para ser exclusivo")]
    UnidentifiedResource,
    #[error("o prazo da posse passa do máximo de {0} ms")]
    TtlTooLong(u64),
    #[error("permissão negada: {0}")]
    Denied(String),
    #[error("permissão fora do catálogo: {0}")]
    UnknownPermission(String),
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The change was applied but its audit record could not be written.
    #[cfg(feature = "audit")]
    #[error("a posse foi alterada, mas a auditoria falhou: {0}")]
    Audit(#[from] AuditError),
}

/// Persistence of the leases, one per resource.
pub trait ExclusiveStore {
    fn get(&self, resource: &ObjectRef) -> Result<Option<Lease>, StoreError>;
    /// Writes the lease, replacing the one on the same resource.
    fn put(&mut self, lease: Lease) -> Result<(), StoreError>;
    fn remove(&mut self, resource: &ObjectRef) -> Result<Option<Lease>, StoreError>;
    /// Every stored lease, expired or not, ordered by resource.
    fn leases(&self) -> Result<Vec<Lease>, StoreError>;

    /// Decides and writes a claim as one step ([`Acquisition::decide`]). A store shared between
    /// processes overrides it with one atomic operation; the default reads, decides and writes.
    fn acquire_lease(&mut self, claim: &Claim, now: u64, preemption: Preemption) -> Result<Acquisition, StoreError> {
        let outcome = Acquisition::decide(self.get(&claim.resource)?, claim, now, preemption);
        if !matches!(outcome, Acquisition::Busy { .. }) {
            self.put(Lease::granted(claim, now))?;
        }
        Ok(outcome)
    }

    /// Extends the lease of `holder` to `now + ttl_ms` as one step ([`OwnedChange::decide`]).
    fn renew_lease(
        &mut self,
        resource: &ObjectRef,
        holder: &ObjectRef,
        now: u64,
        ttl_ms: u64,
    ) -> Result<OwnedChange, StoreError> {
        let change = OwnedChange::decide(self.get(resource)?, holder, now);
        if let OwnedChange::Applied(lease) = &change {
            let renewed = lease.renewed(now, ttl_ms);
            self.put(renewed.clone())?;
            return Ok(OwnedChange::Applied(renewed));
        }
        Ok(change)
    }

    /// Removes the lease of `holder` as one step ([`OwnedChange::decide`]).
    fn release_lease(&mut self, resource: &ObjectRef, holder: &ObjectRef, now: u64) -> Result<OwnedChange, StoreError> {
        let change = OwnedChange::decide(self.get(resource)?, holder, now);
        if matches!(change, OwnedChange::Applied(_)) {
            self.remove(resource)?;
        }
        Ok(change)
    }

    /// Removes and returns the leases that ran out at `now`, ordered by resource, so a lease
    /// renewed or taken meanwhile by another process is never removed.
    fn remove_expired(&mut self, now: u64) -> Result<Vec<Lease>, StoreError> {
        let mut expired = Vec::new();
        for lease in self.leases()? {
            if !lease.is_active(now) {
                self.remove(&lease.resource)?;
                expired.push(lease);
            }
        }
        Ok(expired)
    }
}

/// Leases in memory.
#[derive(Debug, Clone, Default)]
pub struct MemoryExclusiveStore {
    leases: BTreeMap<ObjectRef, Lease>,
}

impl MemoryExclusiveStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl ExclusiveStore for MemoryExclusiveStore {
    fn get(&self, resource: &ObjectRef) -> Result<Option<Lease>, StoreError> {
        Ok(self.leases.get(resource).cloned())
    }

    fn put(&mut self, lease: Lease) -> Result<(), StoreError> {
        self.leases.insert(lease.resource.clone(), lease);
        Ok(())
    }

    fn remove(&mut self, resource: &ObjectRef) -> Result<Option<Lease>, StoreError> {
        Ok(self.leases.remove(resource))
    }

    fn leases(&self) -> Result<Vec<Lease>, StoreError> {
        Ok(self.leases.values().cloned().collect())
    }
}

/// Names of the permissions the checked acquisition asks the engine for. The catalog must declare
/// both; [`ExclusiveRegistry::validate`] checks it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExclusivePermissions {
    pub hold: String,
    pub preempt: String,
}

impl Default for ExclusivePermissions {
    fn default() -> Self {
        Self {
            hold: DEFAULT_HOLD_PERMISSION.to_string(),
            preempt: DEFAULT_PREEMPT_PERMISSION.to_string(),
        }
    }
}

/// Reads a priority from the attribute `key` of the subject. Only an integer counts: a missing
/// attribute or any other type gives `None`, so the caller decides the fallback explicitly.
#[must_use]
pub fn priority_from_attr(subject: &Subject, key: &str) -> Option<i64> {
    match subject.attrs.get(key) {
        Some(Value::Int(priority)) => Some(*priority),
        _ => None,
    }
}

/// Exclusive ownership of resources over a store.
pub struct ExclusiveRegistry<S = MemoryExclusiveStore> {
    store: S,
    permissions: ExclusivePermissions,
    max_ttl_ms: Option<u64>,
    #[cfg(feature = "audit")]
    auditor: Option<Arc<Auditor>>,
}

impl Default for ExclusiveRegistry<MemoryExclusiveStore> {
    fn default() -> Self {
        Self::new(MemoryExclusiveStore::new())
    }
}

impl<S: ExclusiveStore> ExclusiveRegistry<S> {
    #[must_use]
    pub fn new(store: S) -> Self {
        Self {
            store,
            permissions: ExclusivePermissions::default(),
            max_ttl_ms: None,
            #[cfg(feature = "audit")]
            auditor: None,
        }
    }

    /// Replaces the permission names used by [`ExclusiveRegistry::acquire_checked`].
    #[must_use]
    pub fn with_permissions(mut self, permissions: ExclusivePermissions) -> Self {
        self.permissions = permissions;
        self
    }

    /// Caps the lifetime of any lease, on acquisition and on renewal. Without it a holder can ask
    /// for a lease that practically never runs out.
    #[must_use]
    pub fn with_max_ttl(mut self, max_ttl_ms: u64) -> Self {
        self.max_ttl_ms = Some(max_ttl_ms);
        self
    }

    fn check_ttl(&self, ttl_ms: u64) -> Result<(), ExclusiveError> {
        if ttl_ms == 0 {
            return Err(ExclusiveError::ZeroTtl);
        }
        match self.max_ttl_ms {
            Some(max) if ttl_ms > max => Err(ExclusiveError::TtlTooLong(max)),
            _ => Ok(()),
        }
    }

    /// Records acquisitions, preemptions, releases and expirations. A record that cannot be
    /// written makes the operation return [`ExclusiveError::Audit`] after the change is applied.
    #[cfg(feature = "audit")]
    #[must_use]
    pub fn with_audit(mut self, auditor: Arc<Auditor>) -> Self {
        self.auditor = Some(auditor);
        self
    }

    pub fn permissions(&self) -> &ExclusivePermissions {
        &self.permissions
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    /// Checks that the catalog of `engine` declares both permissions.
    ///
    /// # Errors
    /// [`ExclusiveError::UnknownPermission`] with the first one that is missing.
    pub fn validate(&self, engine: &Engine) -> Result<(), ExclusiveError> {
        for permission in [&self.permissions.hold, &self.permissions.preempt] {
            if !engine.catalog().contains(permission) {
                return Err(ExclusiveError::UnknownPermission(permission.clone()));
            }
        }
        Ok(())
    }

    /// Active lease of the resource, if any. An expired lease does not count.
    ///
    /// # Errors
    /// [`ExclusiveError::Store`] when the store cannot be read.
    pub fn holder(&self, resource: &ObjectRef, now: u64) -> Result<Option<Lease>, ExclusiveError> {
        Ok(self.store.get(resource)?.filter(|lease| lease.is_active(now)))
    }

    /// Acquires the resource without consulting the engine. Preemption happens only when
    /// `preemption` is [`Preemption::Allowed`] and the claim's priority is strictly higher than the
    /// holder's; an equal priority never preempts. Use [`ExclusiveRegistry::acquire_checked`] when
    /// the claimant is a subject whose permissions matter.
    ///
    /// # Errors
    /// [`ExclusiveError::ZeroTtl`], or [`ExclusiveError::Store`] / [`ExclusiveError::Audit`].
    pub fn acquire(&mut self, claim: &Claim, now: u64, preemption: Preemption) -> Result<Acquisition, ExclusiveError> {
        self.check_ttl(claim.terms.ttl_ms)?;
        let outcome = self.store.acquire_lease(claim, now, preemption)?;
        self.record_acquisition(claim, now, &outcome)?;
        Ok(outcome)
    }

    /// Acquires `resource` for `subject` after asking the engine.
    ///
    /// The ownership permission is required on the resource. If the claim would take the resource
    /// from a holder with a strictly lower priority, or if the current holder asks for a higher
    /// priority than it has, the preemption permission is required as well.
    /// Without it the call fails with [`ExclusiveError::Denied`] and the holder keeps the resource;
    /// a claim that cannot preempt anyway (equal or lower priority) gets [`Acquisition::Busy`].
    ///
    /// # Errors
    /// [`ExclusiveError::AnonymousSubject`], [`ExclusiveError::UnidentifiedResource`],
    /// [`ExclusiveError::Denied`], plus the errors of [`ExclusiveRegistry::acquire`].
    pub fn acquire_checked(
        &mut self,
        engine: &Engine,
        ctx: &Context<'_>,
        subject: &Subject,
        resource: &Resource,
        terms: Terms,
        now: u64,
    ) -> Result<Acquisition, ExclusiveError> {
        let holder = subject.object_ref().ok_or(ExclusiveError::AnonymousSubject)?;
        let target = resource
            .primary()
            .and_then(|anchor| anchor.object_ref())
            .ok_or(ExclusiveError::UnidentifiedResource)?;
        let claim = Claim::new(target, holder, terms);

        if let Err(denied) = self.require(engine, ctx, subject, resource, &self.permissions.hold) {
            self.record_refusal(&claim, now)?;
            return Err(denied);
        }
        let preempting = self
            .holder(&claim.resource, now)?
            .is_some_and(|lease| terms.priority > lease.priority);
        if preempting && let Err(denied) = self.require(engine, ctx, subject, resource, &self.permissions.preempt) {
            self.record_refusal(&claim, now)?;
            return Err(denied);
        }
        let preemption = if preempting {
            Preemption::Allowed
        } else {
            Preemption::Forbidden
        };
        self.acquire(&claim, now, preemption)
    }

    /// Releases the resource, which only its holder can do. The caller vouches for `holder`.
    ///
    /// # Errors
    /// [`ExclusiveError::NotHeld`] when there is no active lease, [`ExclusiveError::NotHolder`]
    /// when another holder has it.
    pub fn release(&mut self, resource: &ObjectRef, holder: &ObjectRef, now: u64) -> Result<Lease, ExclusiveError> {
        let lease = Self::applied(resource, self.store.release_lease(resource, holder, now)?)?;
        self.record(AuditKind::Release, &lease.holder, resource, now, &lease)?;
        Ok(lease)
    }

    /// Extends the holder's lease to `now + ttl_ms`, keeping its priority. It checks no permission
    /// and writes no audit record: the caller vouches for `holder` and decides whether it may still
    /// hold the resource. Use [`ExclusiveRegistry::renew_checked`] to have the engine decide.
    ///
    /// # Errors
    /// [`ExclusiveError::ZeroTtl`], [`ExclusiveError::TtlTooLong`], [`ExclusiveError::NotHeld`] (including when the lease already
    /// ran out), [`ExclusiveError::NotHolder`].
    pub fn renew(
        &mut self,
        resource: &ObjectRef,
        holder: &ObjectRef,
        now: u64,
        ttl_ms: u64,
    ) -> Result<Lease, ExclusiveError> {
        self.check_ttl(ttl_ms)?;
        Self::applied(resource, self.store.renew_lease(resource, holder, now, ttl_ms)?)
    }

    /// Renews the lease of `subject` on `resource` after asking the engine: the ownership
    /// permission must still hold at `now` (the instant of `ctx` is replaced by it), so a holder who
    /// lost it cannot keep the resource by renewing. Preemption is not involved: the lease keeps
    /// its priority. Like [`ExclusiveRegistry::renew`] it writes no audit record, and a refusal
    /// leaves the lease as it was.
    ///
    /// # Errors
    /// [`ExclusiveError::AnonymousSubject`], [`ExclusiveError::UnidentifiedResource`],
    /// [`ExclusiveError::Denied`], plus the errors of [`ExclusiveRegistry::renew`].
    pub fn renew_checked(
        &mut self,
        engine: &Engine,
        ctx: &Context<'_>,
        subject: &Subject,
        resource: &Resource,
        now: u64,
        ttl_ms: u64,
    ) -> Result<Lease, ExclusiveError> {
        let holder = subject.object_ref().ok_or(ExclusiveError::AnonymousSubject)?;
        let target = resource
            .primary()
            .and_then(|anchor| anchor.object_ref())
            .ok_or(ExclusiveError::UnidentifiedResource)?;
        self.require(engine, &ctx.at(now), subject, resource, &self.permissions.hold)?;
        self.renew(&target, &holder, now, ttl_ms)
    }

    /// Removes the leases that ran out and returns them, ordered by resource.
    ///
    /// # Errors
    /// [`ExclusiveError::Store`] or [`ExclusiveError::Audit`]. On an audit failure the leases
    /// already removed stay removed.
    pub fn expire(&mut self, now: u64) -> Result<Vec<Lease>, ExclusiveError> {
        let expired = self.store.remove_expired(now)?;
        for lease in &expired {
            self.record(AuditKind::Expire, &lease.holder, &lease.resource, now, lease)?;
        }
        Ok(expired)
    }

    fn applied(resource: &ObjectRef, change: OwnedChange) -> Result<Lease, ExclusiveError> {
        match change {
            OwnedChange::Applied(lease) => Ok(lease),
            OwnedChange::NotHolder { holder } => Err(ExclusiveError::NotHolder {
                resource: resource.clone(),
                holder,
            }),
            OwnedChange::NotHeld => Err(ExclusiveError::NotHeld(resource.clone())),
        }
    }

    fn require(
        &self,
        engine: &Engine,
        ctx: &Context<'_>,
        subject: &Subject,
        resource: &Resource,
        permission: &str,
    ) -> Result<(), ExclusiveError> {
        if engine.check(ctx, &Request::new(subject, permission, resource)) {
            Ok(())
        } else {
            Err(ExclusiveError::Denied(permission.to_string()))
        }
    }
}

/// What an audit record says happened.
// Without the `audit` feature nothing is recorded and most variants are never built.
#[cfg_attr(not(feature = "audit"), allow(dead_code))]
enum AuditKind {
    Acquire,
    Preempt,
    Refused,
    Release,
    Expire,
}

#[cfg(feature = "audit")]
impl<S: ExclusiveStore> ExclusiveRegistry<S> {
    fn record_acquisition(&self, claim: &Claim, now: u64, outcome: &Acquisition) -> Result<(), ExclusiveError> {
        match outcome {
            Acquisition::Granted => self.write(
                AuditKind::Acquire,
                &claim.holder,
                &claim.resource,
                now,
                Some(claim),
                None,
            ),
            Acquisition::Preempted { previous } => self.write(
                AuditKind::Preempt,
                &claim.holder,
                &claim.resource,
                now,
                Some(claim),
                Some(previous),
            ),
            Acquisition::Busy { holder } => self.write(
                AuditKind::Refused,
                &claim.holder,
                &claim.resource,
                now,
                Some(claim),
                Some(holder),
            ),
        }
    }

    fn record_refusal(&self, claim: &Claim, now: u64) -> Result<(), ExclusiveError> {
        self.write(
            AuditKind::Refused,
            &claim.holder,
            &claim.resource,
            now,
            Some(claim),
            None,
        )
    }

    fn record(
        &self,
        kind: AuditKind,
        holder: &ObjectRef,
        resource: &ObjectRef,
        now: u64,
        lease: &Lease,
    ) -> Result<(), ExclusiveError> {
        self.write(kind, holder, resource, now, None, Some(lease))
    }

    fn write(
        &self,
        kind: AuditKind,
        holder: &ObjectRef,
        resource: &ObjectRef,
        now: u64,
        claim: Option<&Claim>,
        other: Option<&Lease>,
    ) -> Result<(), ExclusiveError> {
        let Some(auditor) = &self.auditor else {
            return Ok(());
        };
        let (action, outcome) = match kind {
            AuditKind::Acquire => (AuditAction::ExclusiveAcquire, AuditOutcome::Applied),
            AuditKind::Preempt => (AuditAction::ExclusivePreempt, AuditOutcome::Applied),
            AuditKind::Refused => (AuditAction::ExclusiveAcquire, AuditOutcome::Rejected),
            AuditKind::Release => (AuditAction::ExclusiveRelease, AuditOutcome::Applied),
            AuditKind::Expire => (AuditAction::ExclusiveExpire, AuditOutcome::Applied),
        };
        let mut meta = Attributes::new();
        if let Some(claim) = claim {
            meta.insert("priority".to_string(), Value::Int(claim.terms.priority));
        }
        if let Some(lease) = other {
            meta.insert("other_holder".to_string(), Value::Str(lease.holder.to_string()));
            meta.insert("other_priority".to_string(), Value::Int(lease.priority));
        }
        let actor = Subject::of_kind(holder.kind.clone(), holder.id.clone());
        auditor.exclusive(&actor, action, resource, outcome, now, &meta)?;
        Ok(())
    }
}

#[cfg(not(feature = "audit"))]
impl<S: ExclusiveStore> ExclusiveRegistry<S> {
    fn record_acquisition(&self, _claim: &Claim, _now: u64, _outcome: &Acquisition) -> Result<(), ExclusiveError> {
        Ok(())
    }

    fn record_refusal(&self, _claim: &Claim, _now: u64) -> Result<(), ExclusiveError> {
        Ok(())
    }

    fn record(
        &self,
        _kind: AuditKind,
        _holder: &ObjectRef,
        _resource: &ObjectRef,
        _now: u64,
        _lease: &Lease,
    ) -> Result<(), ExclusiveError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(id: &str) -> ObjectRef {
        ObjectRef::new("document", id)
    }

    fn user(id: &str) -> ObjectRef {
        ObjectRef::new("user", id)
    }

    fn claim(holder: &str, priority: i64) -> Claim {
        Claim::new(doc("d1"), user(holder), Terms::new(priority, 1_000))
    }

    #[test]
    fn higher_priority_takes_over_only_when_allowed() {
        let mut registry = ExclusiveRegistry::default();
        registry.acquire(&claim("a", 1), 0, Preemption::Forbidden).unwrap();
        let busy = registry.acquire(&claim("b", 5), 10, Preemption::Forbidden).unwrap();
        assert!(matches!(busy, Acquisition::Busy { holder } if holder.holder == user("a")));
        let taken = registry.acquire(&claim("b", 5), 10, Preemption::Allowed).unwrap();
        assert!(matches!(taken, Acquisition::Preempted { previous } if previous.holder == user("a")));
    }

    #[test]
    fn zero_ttl_is_refused() {
        let mut registry = ExclusiveRegistry::default();
        let zero = Claim::new(doc("d1"), user("a"), Terms::new(1, 0));
        assert!(matches!(
            registry.acquire(&zero, 0, Preemption::Forbidden),
            Err(ExclusiveError::ZeroTtl)
        ));
    }

    #[test]
    fn priority_helper_reads_integers_only() {
        let subject = Subject::user("u").with_attr("priority", 7).with_attr("level", "high");
        assert_eq!(priority_from_attr(&subject, "priority"), Some(7));
        assert_eq!(priority_from_attr(&subject, "level"), None);
        assert_eq!(priority_from_attr(&subject, "missing"), None);
    }
}
