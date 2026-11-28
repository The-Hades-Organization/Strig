//! Approval flow for a [`Mutation`]: a change the [`ApprovalPolicy`] marks as needing approval does not
//! apply on the spot. It becomes a [`PendingRequest`] that another actor approves or refuses.
//!
//! - **Where the policy lives.** Per kind of change ([`MutationKind`]): a rule names the permission an
//!   approver must hold, and the resource they must hold it on. A kind with no rule applies at once, as
//!   [`Governance::apply`] always did.
//! - **Propose.** The invariants judge the change first, so a request that could never apply is refused
//!   up front; a change that passes is stored as pending, with an optional expiry.
//! - **Approve or refuse.** The approver needs the rule's permission and is never the author. An approval
//!   runs the invariants again over the grants as they are *now*, with the author as the actor, and only
//!   then applies; if they refuse, the request stays pending and the violations come back. A refusal
//!   carries a reason.
//! - **Impact.** With [`Approvals::with_impact`], a proposal stores what the change does to access
//!   ([`Impact`]) in the request, so the approver sees it. Approving recomputes it over the grants as
//!   they are now (they may have changed since the proposal); [`Approvals::review_impact`] shows both
//!   before deciding, and an approved request keeps the recomputed one.
//! - **Expiry.** A request is expired from the instant `expires_at` on. [`Approvals::expire_due`] closes
//!   the ones due; approving or refusing one that is due closes it too.
//! - **Audit.** With the `audit` feature and an auditor on the [`Governance`], every step is a record:
//!   `mutation_propose`, `mutation_approve`, `mutation_reject` and `mutation_expire`, under the fail mode
//!   of the call. The approval record is written before the change is applied, so a failed write never
//!   leaves an applied change the trail does not know about.
//!
//! The crate reads no clock: every step takes the instant. Requests live in a [`PendingStore`];
//! [`MemoryPendingStore`] is the in-memory one. The caller persists the grants an approval returns, as
//! with [`Governance::apply`]. Two approvers of the same request must not run at once: the store's
//! [`PendingStore::update`] refuses a request that is no longer pending, and a host with several
//! processes serialises approvals per request (a lock, a transaction) before applying the grants.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

use serde::{Deserialize, Serialize};

use crate::attr::{Attributes, Value};
#[cfg(feature = "audit")]
use crate::audit::{AuditAction, AuditOutcome, FailMode, PendingRef};
use crate::decision::Request;
use crate::engine::{Context, Engine};
use crate::governance::{Governance, Mutation, MutationKind, Violation, same_subject};
use crate::grant::Grant;
use crate::impact::{Impact, ImpactOptions};
use crate::rebac::TupleStore;
use crate::resource::Resource;
use crate::subject::Subject;

/// Who may approve a kind of change: whoever holds `permission` on `resource`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalRule {
    pub kind: MutationKind,
    pub permission: String,
    pub resource: Resource,
}

/// The kinds of change that wait for approval.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ApprovalPolicy {
    rules: Vec<ApprovalRule>,
}

impl ApprovalPolicy {
    /// No kind needs approval.
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_rules(rules: impl IntoIterator<Item = ApprovalRule>) -> Self {
        Self {
            rules: rules.into_iter().collect(),
        }
    }

    /// `kind` waits for an approver holding `permission` on `resource`. A later rule for the same kind
    /// replaces the earlier one.
    #[must_use]
    pub fn require(mut self, kind: MutationKind, permission: impl Into<String>, resource: Resource) -> Self {
        self.rules.retain(|r| r.kind != kind);
        self.rules.push(ApprovalRule {
            kind,
            permission: permission.into(),
            resource,
        });
        self
    }

    /// Every kind of change waits for an approver holding `permission` on `resource`.
    #[must_use]
    pub fn require_all(self, permission: impl Into<String>, resource: Resource) -> Self {
        let permission = permission.into();
        MutationKind::ALL.into_iter().fold(self, |policy, kind| {
            policy.require(kind, permission.clone(), resource.clone())
        })
    }

    pub fn rule_for(&self, mutation: &Mutation) -> Option<&ApprovalRule> {
        let kind = mutation.kind();
        self.rules.iter().find(|r| r.kind == kind)
    }

    pub fn rules(&self) -> &[ApprovalRule] {
        &self.rules
    }
}

/// Where a request stands. Only `Pending` can still change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", rename_all_fields = "camelCase")]
pub enum PendingStatus {
    Pending,
    Approved { by: String, at: u64 },
    Rejected { by: String, at: u64, reason: String },
    Expired { at: u64 },
}

/// A change waiting for another actor.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct PendingRequest {
    pub id: String,
    /// Whoever proposed the change. The invariants judge the change as this actor, at proposal and at approval.
    pub actor: Subject,
    pub mutation: Mutation,
    /// Milliseconds since the Unix epoch.
    pub requested_at: u64,
    /// From this instant on nobody can decide the request any more.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    pub status: PendingStatus,
    /// What the change does to access: computed when it was proposed, and again when it was approved.
    /// Absent when the flow ran without [`Approvals::with_impact`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impact: Option<Impact>,
}

impl PendingRequest {
    /// A pending request with no expiry and no impact.
    pub fn new(id: impl Into<String>, actor: Subject, mutation: Mutation, requested_at: u64) -> Self {
        Self {
            id: id.into(),
            actor,
            mutation,
            requested_at,
            expires_at: None,
            status: PendingStatus::Pending,
            impact: None,
        }
    }

    #[must_use]
    pub fn expiring_at(mut self, expires_at: Option<u64>) -> Self {
        self.expires_at = expires_at;
        self
    }

    #[must_use]
    pub fn with_status(mut self, status: PendingStatus) -> Self {
        self.status = status;
        self
    }

    #[must_use]
    pub fn with_impact(mut self, impact: Impact) -> Self {
        self.impact = Some(impact);
        self
    }

    pub fn is_pending(&self) -> bool {
        self.status == PendingStatus::Pending
    }

    pub fn is_due(&self, now: u64) -> bool {
        self.expires_at.is_some_and(|at| now >= at)
    }

    /// Grant id, or `role@subject` (`role#scope@subject` with a scope) for a role change.
    pub fn target(&self) -> String {
        match &self.mutation {
            Mutation::Add(grant) => grant.id.clone(),
            Mutation::Remove { id } => id.clone(),
            Mutation::AssignRole { subject, role } | Mutation::RevokeRole { subject, role } => {
                let who = subject
                    .id
                    .clone()
                    .unwrap_or_else(|| format!("{}:<anonymous>", subject.kind));
                match &role.scope {
                    Some(scope) => format!("{}#{scope}@{who}", role.role),
                    None => format!("{}@{who}", role.role),
                }
            }
        }
    }

    #[cfg(feature = "audit")]
    fn author(&self) -> String {
        self.actor.id.clone().unwrap_or_else(|| self.actor.kind.clone())
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PendingError {
    #[error("o pedido {0} já existe")]
    Duplicate(String),
    #[error("o pedido {0} não existe")]
    Unknown(String),
    #[error("o pedido {0} não está mais pendente")]
    NotPending(String),
    #[error("falha no armazenamento de pedidos: {0}")]
    Store(String),
}

/// Where the requests are kept. Implementations are shared between threads.
pub trait PendingStore: Send + Sync {
    /// Stores a new request; [`PendingError::Duplicate`] if the id is taken.
    fn insert(&self, request: PendingRequest) -> Result<(), PendingError>;
    fn get(&self, id: &str) -> Result<Option<PendingRequest>, PendingError>;
    /// Replaces the request with the same id. It must fail with [`PendingError::NotPending`] when the stored
    /// request is no longer pending, so a decided request is never decided again.
    fn update(&self, request: PendingRequest) -> Result<(), PendingError>;
    /// Every request, whatever its status, oldest first.
    fn list(&self) -> Result<Vec<PendingRequest>, PendingError>;
}

/// [`PendingStore`] in memory.
#[derive(Debug, Default)]
pub struct MemoryPendingStore {
    requests: Mutex<BTreeMap<String, PendingRequest>>,
}

impl MemoryPendingStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, BTreeMap<String, PendingRequest>> {
        self.requests.lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl PendingStore for MemoryPendingStore {
    fn insert(&self, request: PendingRequest) -> Result<(), PendingError> {
        let mut requests = self.lock();
        if requests.contains_key(&request.id) {
            return Err(PendingError::Duplicate(request.id));
        }
        requests.insert(request.id.clone(), request);
        Ok(())
    }

    fn get(&self, id: &str) -> Result<Option<PendingRequest>, PendingError> {
        Ok(self.lock().get(id).cloned())
    }

    fn update(&self, request: PendingRequest) -> Result<(), PendingError> {
        let mut requests = self.lock();
        match requests.get_mut(&request.id) {
            None => Err(PendingError::Unknown(request.id)),
            Some(stored) if !stored.is_pending() => Err(PendingError::NotPending(request.id)),
            Some(stored) => {
                *stored = request;
                Ok(())
            }
        }
    }

    fn list(&self) -> Result<Vec<PendingRequest>, PendingError> {
        let mut all: Vec<PendingRequest> = self.lock().values().cloned().collect();
        all.sort_by(|a, b| a.requested_at.cmp(&b.requested_at).then_with(|| a.id.cmp(&b.id)));
        Ok(all)
    }
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ApprovalError {
    /// The invariants, the approval rule or the audit refused. The request, if any, stays as it was.
    #[error("recusado: {}", .0.iter().map(ToString::to_string).collect::<Vec<_>>().join("; "))]
    Refused(Vec<Violation>),
    /// The request ran out of time; it is now `expired`.
    #[error("o pedido {0} expirou")]
    Expired(String),
    #[error(transparent)]
    Store(#[from] PendingError),
}

impl ApprovalError {
    fn refused(invariant: &str, message: impl Into<String>) -> Self {
        Self::Refused(vec![Violation::new(invariant, message)])
    }
}

/// What a change is judged against: the grants as they are now, the tuples, the instant and the
/// metadata of the call (ip, request id, reason) that the audit keeps from the `detailed` level.
pub struct Review<'a> {
    pub engine: &'a Engine,
    pub current: &'a [Grant],
    pub tuples: Option<&'a dyn TupleStore>,
    pub now: u64,
    pub meta: &'a Attributes,
}

/// The outcome of [`Approvals::propose`].
#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum Proposed {
    /// The policy asks no approval for this kind of change: it went through the governance and these are
    /// the grants after it.
    Applied(Vec<Grant>),
    /// The change waits for an approver.
    Pending(PendingRequest),
}

/// A request approved and applied: the grants to persist (unchanged for a role change; the subject to
/// write comes from [`Mutation::subject_after`] of the request) and the request as it now stands.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Approved {
    pub grants: Vec<Grant>,
    /// The request as it now stands; its `impact` is the one recomputed at the approval.
    pub request: PendingRequest,
    /// The impact the request had when it was proposed, to compare with `request.impact`.
    pub proposed_impact: Option<Impact>,
}

/// The impact of a pending request as proposed and as it would be now, from [`Approvals::review_impact`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ImpactReview {
    pub proposed: Option<Impact>,
    pub current: Option<Impact>,
    /// The grants moved the answer since the proposal.
    pub changed: bool,
}

/// The approval flow over a [`Governance`], an [`ApprovalPolicy`] and a [`PendingStore`].
pub struct Approvals<'a> {
    governance: &'a Governance,
    policy: &'a ApprovalPolicy,
    store: &'a dyn PendingStore,
    impact: Option<&'a ImpactOptions<'a>>,
    #[cfg(feature = "audit")]
    call_mode: Option<FailMode>,
}

const SELF_APPROVAL: &str = "no_self_approval";
const APPROVAL_PERMISSION: &str = "require_approval_permission";
const SYSTEM_KIND: &str = "system";
const SYSTEM_ID: &str = "strig-expiry";

impl<'a> Approvals<'a> {
    pub fn new(governance: &'a Governance, policy: &'a ApprovalPolicy, store: &'a dyn PendingStore) -> Self {
        Self {
            governance,
            policy,
            store,
            impact: None,
            #[cfg(feature = "audit")]
            call_mode: None,
        }
    }

    /// Computes the [`Impact`] of every change proposed or approved through this flow, over `options`.
    /// The instant is the one of the [`Review`], and `options.tuples` should be the store the review
    /// reads. An impact that cannot be computed (the change is refused) is simply absent.
    #[must_use]
    pub fn with_impact(mut self, options: &'a ImpactOptions<'a>) -> Self {
        self.impact = Some(options);
        self
    }

    fn impact_now(&self, review: &Review<'_>, actor: &Subject, mutation: &Mutation) -> Option<Impact> {
        let options = ImpactOptions {
            now: Some(review.now),
            ..self.impact?.clone()
        };
        self.governance
            .impact(review.engine, actor, review.current, mutation, &options)
            .ok()
    }

    /// The impact of pending request `id` as proposed and as it would be over the grants now, for the
    /// approver to see before deciding. Neither is recorded.
    pub fn review_impact(&self, review: &Review<'_>, id: &str) -> Result<ImpactReview, ApprovalError> {
        let request = self
            .store
            .get(id)?
            .ok_or_else(|| PendingError::Unknown(id.to_string()))?;
        let current = self.impact_now(review, &request.actor, &request.mutation);
        let changed = request.impact != current;
        Ok(ImpactReview {
            proposed: request.impact,
            current,
            changed,
        })
    }

    /// The [`FailMode`] of every audit record of this flow, over the mode of the permission and the
    /// auditor's default.
    #[cfg(feature = "audit")]
    #[must_use]
    pub fn fail_mode(mut self, mode: FailMode) -> Self {
        self.call_mode = Some(mode);
        self
    }

    /// The requests still waiting at `now`: pending and not due.
    pub fn pending(&self, now: u64) -> Result<Vec<PendingRequest>, PendingError> {
        Ok(self
            .store
            .list()?
            .into_iter()
            .filter(|r| r.is_pending() && !r.is_due(now))
            .collect())
    }

    /// `actor` asks for `mutation`. Without a rule for its kind the change goes through the governance
    /// right away. With one, the invariants judge it first and, if they accept, it is stored as a pending
    /// request `id` that expires at `expires_at` (if given). Either way the audit records what happened,
    /// refusals included.
    pub fn propose(
        &self,
        review: &Review<'_>,
        actor: &Subject,
        mutation: &Mutation,
        id: impl Into<String>,
        expires_at: Option<u64>,
    ) -> Result<Proposed, ApprovalError> {
        crate::obs::approval("propose", || {
            self.propose_inner(review, actor, mutation, id.into(), expires_at)
        })
    }

    fn propose_inner(
        &self,
        review: &Review<'_>,
        actor: &Subject,
        mutation: &Mutation,
        id: String,
        expires_at: Option<u64>,
    ) -> Result<Proposed, ApprovalError> {
        let Some(rule) = self.policy.rule_for(mutation) else {
            return self.apply_directly(review, actor, mutation).map(Proposed::Applied);
        };
        let request = PendingRequest {
            id,
            actor: actor.clone(),
            mutation: mutation.clone(),
            requested_at: review.now,
            expires_at,
            status: PendingStatus::Pending,
            impact: None,
        };
        let refuse = |violations: Vec<Violation>| -> ApprovalError {
            match self.record(
                review,
                actor,
                Step::Propose,
                &request,
                Some(violations.as_slice()),
                None,
                rule,
            ) {
                Ok(()) => ApprovalError::Refused(violations),
                Err(audit) => audit,
            }
        };
        if request.id.is_empty() {
            return Err(refuse(vec![Violation::new("mutation", "o pedido precisa de um id")]));
        }
        if expires_at.is_some_and(|at| at <= review.now) {
            return Err(refuse(vec![Violation::new(
                "mutation",
                "a expiração do pedido precisa ser depois do instante do pedido",
            )]));
        }
        if self.store.get(&request.id)?.is_some() {
            return Err(PendingError::Duplicate(request.id.clone()).into());
        }
        if let Err(violations) = self.judge(review, actor, mutation) {
            return Err(refuse(violations));
        }
        self.record(review, actor, Step::Propose, &request, None, None, rule)?;
        let mut request = request;
        request.impact = self.impact_now(review, actor, mutation);
        self.store.insert(request.clone())?;
        Ok(Proposed::Pending(request))
    }

    /// `approver` approves request `id`. Refused, with the request left pending, when the approver is the
    /// author, lacks the rule's permission, or the invariants now refuse the change; the refusal is
    /// audited. On success the change has been applied through the governance and the request is
    /// `approved`.
    pub fn approve(&self, review: &Review<'_>, approver: &Subject, id: &str) -> Result<Approved, ApprovalError> {
        crate::obs::approval("approve", || self.approve_inner(review, approver, id))
    }

    fn approve_inner(&self, review: &Review<'_>, approver: &Subject, id: &str) -> Result<Approved, ApprovalError> {
        let (request, rule) = self.open_for_decision(review, id)?;
        let refuse = |violations: Vec<Violation>| -> ApprovalError {
            match self.record(
                review,
                approver,
                Step::Approve,
                &request,
                Some(violations.as_slice()),
                None,
                &rule,
            ) {
                Ok(()) => ApprovalError::Refused(violations),
                Err(audit) => audit,
            }
        };
        let violations = self.approver_violations(review, approver, &request, &rule);
        if !violations.is_empty() {
            return Err(refuse(violations));
        }
        if let Err(violations) = self.judge(review, &request.actor, &request.mutation) {
            return Err(refuse(violations));
        }
        self.record(review, approver, Step::Approve, &request, None, None, &rule)?;
        let current_impact = self.impact_now(review, &request.actor, &request.mutation);
        let mut meta = review.meta.clone();
        meta.insert("request_id".into(), Value::Str(request.id.clone()));
        meta.insert("approved_by".into(), Value::Str(subject_label(approver)));
        let grants = self.apply_directly(&Review { meta: &meta, ..*review }, &request.actor, &request.mutation)?;
        let mut request = request;
        let proposed_impact = request.impact.take();
        request.impact = current_impact;
        request.status = PendingStatus::Approved {
            by: subject_label(approver),
            at: review.now,
        };
        self.store.update(request.clone())?;
        Ok(Approved {
            grants,
            request,
            proposed_impact,
        })
    }

    /// `approver` refuses request `id`, with a non-empty `reason`. Same checks on the approver as in
    /// [`Approvals::approve`]; nothing is applied.
    pub fn reject(
        &self,
        review: &Review<'_>,
        approver: &Subject,
        id: &str,
        reason: &str,
    ) -> Result<PendingRequest, ApprovalError> {
        crate::obs::approval("reject", || self.reject_inner(review, approver, id, reason))
    }

    fn reject_inner(
        &self,
        review: &Review<'_>,
        approver: &Subject,
        id: &str,
        reason: &str,
    ) -> Result<PendingRequest, ApprovalError> {
        let (request, rule) = self.open_for_decision(review, id)?;
        let mut violations = self.approver_violations(review, approver, &request, &rule);
        if reason.trim().is_empty() {
            violations.push(Violation::new("mutation", "a recusa precisa de um motivo"));
        }
        if !violations.is_empty() {
            return Err(
                match self.record(
                    review,
                    approver,
                    Step::Reject,
                    &request,
                    Some(violations.as_slice()),
                    Some(reason),
                    &rule,
                ) {
                    Ok(()) => ApprovalError::Refused(violations),
                    Err(audit) => audit,
                },
            );
        }
        self.record(review, approver, Step::Reject, &request, None, Some(reason), &rule)?;
        let mut request = request;
        request.status = PendingStatus::Rejected {
            by: subject_label(approver),
            at: review.now,
            reason: reason.to_string(),
        };
        self.store.update(request.clone())?;
        Ok(request)
    }

    /// Closes every pending request due at `now` and returns them, each with its `mutation_expire` record.
    pub fn expire_due(&self, now: u64, meta: &Attributes) -> Result<Vec<PendingRequest>, ApprovalError> {
        crate::obs::approval("expire", || self.expire_due_inner(now, meta))
    }

    fn expire_due_inner(&self, now: u64, meta: &Attributes) -> Result<Vec<PendingRequest>, ApprovalError> {
        let mut expired = Vec::new();
        for request in self.store.list()? {
            if request.is_pending() && request.is_due(now) {
                expired.push(self.expire(request, now, meta)?);
            }
        }
        Ok(expired)
    }

    fn expire(
        &self,
        mut request: PendingRequest,
        now: u64,
        meta: &Attributes,
    ) -> Result<PendingRequest, ApprovalError> {
        let rule = self.policy.rule_for(&request.mutation);
        #[cfg(feature = "audit")]
        if let Some(auditor) = self.governance.auditor() {
            let system = Subject::of_kind(SYSTEM_KIND, SYSTEM_ID);
            auditor
                .pending_event(
                    &system,
                    AuditAction::MutationExpire,
                    pending_ref(&request, None),
                    AuditOutcome::Applied,
                    &[],
                    meta,
                    rule.map(|r| r.permission.as_str()),
                    self.call_mode,
                    now,
                )
                .map_err(|e| ApprovalError::refused("audit", e.to_string()))?;
        }
        #[cfg(not(feature = "audit"))]
        let _ = (meta, rule, SYSTEM_KIND, SYSTEM_ID);
        request.status = PendingStatus::Expired { at: now };
        self.store.update(request.clone())?;
        Ok(request)
    }

    /// The pending request `id` and the rule that governs it. A request that is due is closed first.
    fn open_for_decision(
        &self,
        review: &Review<'_>,
        id: &str,
    ) -> Result<(PendingRequest, ApprovalRule), ApprovalError> {
        let request = self
            .store
            .get(id)?
            .ok_or_else(|| PendingError::Unknown(id.to_string()))?;
        if !request.is_pending() {
            return Err(PendingError::NotPending(id.to_string()).into());
        }
        if request.is_due(review.now) {
            self.expire(request, review.now, review.meta)?;
            return Err(ApprovalError::Expired(id.to_string()));
        }
        let rule = self.policy.rule_for(&request.mutation).cloned().ok_or_else(|| {
            ApprovalError::refused(
                "approval_policy",
                "a política não pede mais aprovação para esta mudança",
            )
        })?;
        Ok((request, rule))
    }

    fn approver_violations(
        &self,
        review: &Review<'_>,
        approver: &Subject,
        request: &PendingRequest,
        rule: &ApprovalRule,
    ) -> Vec<Violation> {
        let mut violations = Vec::new();
        if approver.id.is_none() {
            violations.push(Violation::new(
                APPROVAL_PERMISSION,
                "quem decide o pedido precisa ser identificado",
            ));
        } else if same_subject(approver, &request.actor) {
            violations.push(Violation::new(
                SELF_APPROVAL,
                "quem propôs a mudança não decide o próprio pedido",
            ));
        }
        let ctx = Context::new(&review.current).at(review.now);
        let ctx = match review.tuples {
            Some(tuples) => ctx.with_tuples(tuples),
            None => ctx,
        };
        if !review
            .engine
            .check(&ctx, &Request::new(approver, &rule.permission, &rule.resource))
        {
            violations.push(Violation::new(
                APPROVAL_PERMISSION,
                format!("falta a permissão {}", rule.permission),
            ));
        }
        violations
    }

    /// The invariants over the grants now, with no record and no side effect.
    fn judge(&self, review: &Review<'_>, actor: &Subject, mutation: &Mutation) -> Result<Vec<Grant>, Vec<Violation>> {
        self.governance.evaluate_at(
            review.engine,
            actor,
            review.current,
            mutation,
            review.tuples,
            review.now,
        )
    }

    fn apply_directly(
        &self,
        review: &Review<'_>,
        actor: &Subject,
        mutation: &Mutation,
    ) -> Result<Vec<Grant>, ApprovalError> {
        let at = self.governance.at(review.now);
        #[cfg(feature = "audit")]
        let at = match self.call_mode {
            Some(mode) => at.fail_mode(mode),
            None => at,
        };
        if let Some(options) = self.impact {
            return at
                .apply_with_impact(
                    review.engine,
                    actor,
                    review.current,
                    mutation,
                    review.tuples,
                    review.meta,
                    options,
                )
                .map(|applied| applied.grants)
                .map_err(ApprovalError::Refused);
        }
        at.apply_with(
            review.engine,
            actor,
            review.current,
            mutation,
            review.tuples,
            review.meta,
        )
        .map_err(ApprovalError::Refused)
    }

    /// Writes the record of one step (`violations` present means the step was refused). Does nothing
    /// without an auditor; with one, a record that cannot be written refuses the step.
    #[allow(clippy::too_many_arguments)]
    fn record(
        &self,
        review: &Review<'_>,
        actor: &Subject,
        step: Step,
        request: &PendingRequest,
        violations: Option<&[Violation]>,
        reason: Option<&str>,
        rule: &ApprovalRule,
    ) -> Result<(), ApprovalError> {
        #[cfg(feature = "audit")]
        if let Some(auditor) = self.governance.auditor() {
            let (action, ok) = match step {
                Step::Propose => (AuditAction::MutationPropose, AuditOutcome::Pending),
                Step::Approve => (AuditAction::MutationApprove, AuditOutcome::Applied),
                Step::Reject => (AuditAction::MutationReject, AuditOutcome::Applied),
            };
            let outcome = if violations.is_some() {
                AuditOutcome::Rejected
            } else {
                ok
            };
            auditor
                .pending_event(
                    actor,
                    action,
                    pending_ref(request, reason),
                    outcome,
                    violations.unwrap_or(&[]),
                    review.meta,
                    Some(&rule.permission),
                    self.call_mode,
                    review.now,
                )
                .map_err(|e| ApprovalError::refused("audit", e.to_string()))?;
        }
        #[cfg(not(feature = "audit"))]
        let _ = (review, actor, step, request, violations, reason, rule);
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Step {
    Propose,
    Approve,
    Reject,
}

fn subject_label(subject: &Subject) -> String {
    subject.id.clone().unwrap_or_else(|| subject.kind.clone())
}

#[cfg(feature = "audit")]
fn pending_ref(request: &PendingRequest, reason: Option<&str>) -> PendingRef {
    PendingRef {
        id: request.id.clone(),
        author: request.author(),
        kind: request.mutation.kind(),
        target: request.target(),
        expires_at: request.expires_at,
        reason: reason.map(str::to_string),
    }
}
