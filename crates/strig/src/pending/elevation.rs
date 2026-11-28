//! Time-boxed elevation: an actor asks for a role or a permission for a limited time, an approver
//! grants it, and it expires on its own. Break-glass lets the actor grant it to themselves in an
//! emergency, where the policy allows, under a mandatory forensic audit and a review afterwards.
//!
//! It is the approval flow of [`crate::pending`] with a policy per role or permission and a
//! validity window. Nothing here is a new kind of change: an elevation is a [`Mutation::Add`] of an
//! allow grant or a [`Mutation::AssignRole`], both with a window.
//!
//! - **Policy.** [`ElevationPolicy`] holds one [`ElevationRule`] per role or permission: the longest
//!   time it can be held, the permission an approver must hold, whether a justification is
//!   required, and whether (and for how long) break-glass is allowed. What the policy does not list
//!   cannot be elevated.
//! - **Request.** [`Elevations::request`] refuses a duration over the maximum, a missing
//!   justification and an unidentified actor. The invariants judge the change as the actor, as in
//!   [`Approvals::propose`]. A request that passes waits as a [`PendingRequest`] carrying an
//!   [`ElevationInfo`].
//! - **Approval.** [`Elevations::approve`] is [`Approvals::approve`] (the author never approves their
//!   own request, the invariants run again over the grants as they are now, the impact is recomputed)
//!   with one difference: the window opens at the approval, `valid_until` being the approval instant
//!   plus the requested duration, never past the policy's maximum. The grant or role then stops
//!   applying by itself at that instant; nothing has to remove it.
//! - **Break-glass.** With a rule that allows it, [`ElevationRequest::break_glass`] skips the approver:
//!   the actor is the approver of their own request, and the elevation is applied at once, for at most
//!   the rule's break-glass duration. It requires a justification and an [`Auditor`](crate::audit::Auditor)
//!   at the `forensic` level on the governance, and every record of it is written under
//!   [`FailMode::Closed`], whatever the general mode: a sink that fails denies the elevation. It leaves
//!   the request with a review `pending`, listed by [`Elevations::pending_reviews`], that another actor
//!   closes with [`Elevations::close_review`].
//! - **Revocation.** [`Elevations::revoke`], by the actor or by anyone who holds the approver permission,
//!   removes the grant or the role before its time. Renewing is a new request.
//! - **Audit.** The steps are the `mutation_*` records of the approval flow, with `elevation` (and
//!   `break_glass`, `justification`) in the metadata, plus `elevation_review` when a review is closed.
//!
//! The crate reads no clock and persists nothing: the caller passes the instant and stores the grants
//! and the subject that an approval returns, as with [`Approvals`]. The requests live in a
//! [`PendingStore`]; revocation and review are kept on the request with [`PendingStore::annotate`].

use serde::{Deserialize, Serialize};

use super::{
    ApprovalError, ApprovalPolicy, ApprovalRule, Approvals, Approved, PendingError, PendingRequest, PendingStatus,
    PendingStore, Review, Step, subject_label,
};
use crate::attr::{Attributes, Value};
#[cfg(feature = "audit")]
use crate::audit::{AuditLevel, FailMode};
use crate::decision::Request;
use crate::engine::Context;
use crate::governance::{Governance, Mutation, Violation, same_subject};
use crate::grant::{Grant, SubjectMatcher, TargetSelector};
use crate::impact::ImpactOptions;
use crate::resource::{Anchor, Resource};
use crate::subject::{RoleAssignment, Subject};

const ELEVATION: &str = "elevation_policy";
const NOT_IN_POLICY: &str = "not_in_policy";
const ELEVATION_ACTOR: &str = "elevation_actor";
const ELEVATION_DURATION: &str = "elevation_duration";
const ELEVATION_JUSTIFICATION: &str = "elevation_justification";
const ELEVATION_STATE: &str = "elevation_state";
const BREAK_GLASS: &str = "break_glass";
const BREAK_GLASS_AUDIT: &str = "break_glass_audit";
const REVIEW: &str = "elevation_review";

/// What an elevation gives: a role, or a permission on a target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ElevationTarget {
    /// `role`, optionally restricted to the resources under `scope`.
    Role {
        role: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scope: Option<Anchor>,
    },
    /// `permission` on the resources `target` matches, optionally restricted to those under `scope`.
    Permission {
        permission: String,
        target: TargetSelector,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scope: Option<Anchor>,
    },
}

impl ElevationTarget {
    /// An unscoped role.
    pub fn role(role: impl Into<String>) -> Self {
        Self::Role {
            role: role.into(),
            scope: None,
        }
    }

    /// A permission on `target`, with no scope.
    pub fn permission(permission: impl Into<String>, target: TargetSelector) -> Self {
        Self::Permission {
            permission: permission.into(),
            target,
            scope: None,
        }
    }

    /// Restricts the elevation to the resources under `scope`.
    #[must_use]
    pub fn scoped(mut self, new_scope: Anchor) -> Self {
        match &mut self {
            Self::Role { scope, .. } | Self::Permission { scope, .. } => *scope = Some(new_scope),
        }
        self
    }

    /// The role or permission the policy keys on.
    pub fn key(&self) -> ElevationKey {
        match self {
            Self::Role { role, .. } => ElevationKey::Role(role.clone()),
            Self::Permission { permission, .. } => ElevationKey::Permission(permission.clone()),
        }
    }
}

/// A role or a permission, as the policy names it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ElevationKey {
    Role(String),
    Permission(String),
}

/// How a role or permission may be elevated.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ElevationRule {
    pub key: ElevationKey,
    /// The longest an approved elevation lasts, in milliseconds.
    pub max_duration_ms: u64,
    /// What an approver (or the reviewer of a break-glass, or whoever revokes) must hold...
    pub approver_permission: String,
    /// ...and on which resource.
    pub approver_resource: Resource,
    /// A request without a justification is refused.
    #[serde(default)]
    pub require_justification: bool,
    /// Present when the actor may elevate themselves in an emergency.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub break_glass: Option<BreakGlassRule>,
}

/// The limit of a break-glass elevation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct BreakGlassRule {
    /// The longest a break-glass elevation lasts, in milliseconds. It is also capped by the rule's own
    /// `max_duration_ms`.
    pub max_duration_ms: u64,
}

impl ElevationRule {
    /// `key` can be held for up to `max_duration_ms`, approved by whoever holds `approver_permission`
    /// on `approver_resource`. No justification is required and break-glass is not allowed.
    pub fn new(
        key: ElevationKey,
        max_duration_ms: u64,
        approver_permission: impl Into<String>,
        approver_resource: Resource,
    ) -> Self {
        Self {
            key,
            max_duration_ms,
            approver_permission: approver_permission.into(),
            approver_resource,
            require_justification: false,
            break_glass: None,
        }
    }

    #[must_use]
    pub fn requiring_justification(mut self) -> Self {
        self.require_justification = true;
        self
    }

    /// Allows break-glass for up to `max_duration_ms`.
    #[must_use]
    pub fn allowing_break_glass(mut self, max_duration_ms: u64) -> Self {
        self.break_glass = Some(BreakGlassRule { max_duration_ms });
        self
    }
}

/// The roles and permissions that can be elevated, and how.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ElevationPolicy {
    rules: Vec<ElevationRule>,
}

impl ElevationPolicy {
    /// Nothing can be elevated.
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_rules(rules: impl IntoIterator<Item = ElevationRule>) -> Self {
        rules.into_iter().fold(Self::new(), Self::with)
    }

    /// Adds `rule`; a later rule for the same role or permission replaces the earlier one.
    #[must_use]
    pub fn with(mut self, rule: ElevationRule) -> Self {
        self.rules.retain(|r| r.key != rule.key);
        self.rules.push(rule);
        self
    }

    pub fn rule_for(&self, target: &ElevationTarget) -> Option<&ElevationRule> {
        let key = target.key();
        self.rules.iter().find(|r| r.key == key)
    }

    pub fn rules(&self) -> &[ElevationRule] {
        &self.rules
    }
}

/// A request for an elevation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ElevationRequest {
    pub id: String,
    /// Who gets the elevation. Must be identified.
    pub actor: Subject,
    pub target: ElevationTarget,
    /// How long it should last once approved, in milliseconds.
    pub duration_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub justification: Option<String>,
    /// The actor approves it themselves, as an emergency.
    #[serde(default)]
    pub break_glass: bool,
}

impl ElevationRequest {
    pub fn new(id: impl Into<String>, actor: Subject, target: ElevationTarget, duration_ms: u64) -> Self {
        Self {
            id: id.into(),
            actor,
            target,
            duration_ms,
            justification: None,
            break_glass: false,
        }
    }

    #[must_use]
    pub fn justified(mut self, justification: impl Into<String>) -> Self {
        self.justification = Some(justification.into());
        self
    }

    /// The actor approves it themselves; see the [module](self).
    #[must_use]
    pub fn break_glass(mut self) -> Self {
        self.break_glass = true;
        self
    }
}

/// What a [`PendingRequest`] says about the elevation it carries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ElevationInfo {
    pub target: ElevationTarget,
    /// The duration asked for, in milliseconds. The window opens at the approval.
    pub duration_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub justification: Option<String>,
    #[serde(default)]
    pub break_glass: bool,
    /// The instant the elevation stops applying, once it is approved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<u64>,
    /// The review of a break-glass elevation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review: Option<ReviewState>,
    /// Set when the elevation was revoked before its time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<Revocation>,
}

impl ElevationInfo {
    /// An elevation of `target` for `duration_ms`, not yet approved.
    pub fn new(target: ElevationTarget, duration_ms: u64) -> Self {
        Self {
            target,
            duration_ms,
            justification: None,
            break_glass: false,
            valid_until: None,
            review: None,
            revoked: None,
        }
    }
}

/// Where the review of a break-glass elevation stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", rename_all_fields = "camelCase")]
#[non_exhaustive]
pub enum ReviewState {
    Pending,
    Closed { by: String, at: u64, note: String },
}

/// An elevation taken back before its time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Revocation {
    pub by: String,
    pub at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl Revocation {
    pub fn new(by: impl Into<String>, at: u64, reason: Option<String>) -> Self {
        Self {
            by: by.into(),
            at,
            reason,
        }
    }
}

impl PendingRequest {
    /// The request is an elevation that is approved, not revoked and inside its window at `now`.
    pub fn elevation_active(&self, now: u64) -> bool {
        let Some(info) = &self.elevation else {
            return false;
        };
        matches!(self.status, PendingStatus::Approved { at, .. } if now >= at)
            && info.revoked.is_none()
            && info.valid_until.is_some_and(|until| now < until)
    }
}

/// The outcome of [`Elevations::request`].
#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::large_enum_variant)]
#[non_exhaustive]
pub enum Elevated {
    /// Waiting for an approver.
    Pending(PendingRequest),
    /// Break-glass: applied at once. The grants are to persist, as for [`Approvals::approve`].
    Active(Approved),
}

/// An elevation revoked and the grants to persist.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Revoked {
    pub grants: Vec<Grant>,
    pub request: PendingRequest,
}

/// The elevation flow over a [`Governance`], an [`ElevationPolicy`] and a [`PendingStore`].
pub struct Elevations<'a> {
    governance: &'a Governance,
    policy: &'a ElevationPolicy,
    store: &'a dyn PendingStore,
    impact: Option<&'a ImpactOptions<'a>>,
    #[cfg(feature = "audit")]
    call_mode: Option<FailMode>,
}

impl<'a> Elevations<'a> {
    pub fn new(governance: &'a Governance, policy: &'a ElevationPolicy, store: &'a dyn PendingStore) -> Self {
        Self {
            governance,
            policy,
            store,
            impact: None,
            #[cfg(feature = "audit")]
            call_mode: None,
        }
    }

    /// Computes the [`Impact`](crate::Impact) of every elevation requested or approved, as
    /// [`Approvals::with_impact`] does.
    #[must_use]
    pub fn with_impact(mut self, options: &'a ImpactOptions<'a>) -> Self {
        self.impact = Some(options);
        self
    }

    /// The [`FailMode`] of the audit records of the flow, except for break-glass, which is always
    /// [`FailMode::Closed`].
    #[cfg(feature = "audit")]
    #[must_use]
    pub fn fail_mode(mut self, mode: FailMode) -> Self {
        self.call_mode = Some(mode);
        self
    }

    /// The elevations approved, not revoked and inside their window at `now`.
    pub fn active(&self, now: u64) -> Result<Vec<PendingRequest>, PendingError> {
        Ok(self
            .store
            .list()?
            .into_iter()
            .filter(|r| r.elevation_active(now))
            .collect())
    }

    /// The break-glass elevations nobody reviewed yet, oldest first.
    pub fn pending_reviews(&self) -> Result<Vec<PendingRequest>, PendingError> {
        Ok(self
            .store
            .list()?
            .into_iter()
            .filter(|r| {
                r.elevation
                    .as_ref()
                    .is_some_and(|info| info.break_glass && info.review == Some(ReviewState::Pending))
            })
            .collect())
    }

    /// Closes every pending request due at `now`, as [`Approvals::expire_due`] does. An approved
    /// elevation needs no closing: its window ends by itself.
    pub fn expire_due(&self, now: u64, meta: &Attributes) -> Result<Vec<PendingRequest>, ApprovalError> {
        let policy = ApprovalPolicy::new();
        self.approvals(&policy, false).expire_due(now, meta)
    }

    /// `req.actor` asks for the elevation. Refused, with the refusal audited, when the policy does not
    /// list it, the duration is over the maximum, a required justification is missing or the
    /// invariants refuse. Without break-glass, it waits for an approver; with it, see the
    /// [module](self).
    pub fn request(
        &self,
        review: &Review<'_>,
        req: &ElevationRequest,
        expires_at: Option<u64>,
    ) -> Result<Elevated, ApprovalError> {
        crate::obs::approval("elevation_request", || self.request_inner(review, req, expires_at))
    }

    fn request_inner(
        &self,
        review: &Review<'_>,
        req: &ElevationRequest,
        expires_at: Option<u64>,
    ) -> Result<Elevated, ApprovalError> {
        let Some(rule) = self.policy.rule_for(&req.target) else {
            return Err(self.not_in_policy(review, req, expires_at));
        };
        let approval_rule = |mutation: &Mutation| ApprovalRule {
            kind: mutation.kind(),
            permission: rule.approver_permission.clone(),
            resource: rule.approver_resource.clone(),
        };
        let info = ElevationInfo {
            target: req.target.clone(),
            duration_ms: req.duration_ms,
            justification: req.justification.clone(),
            break_glass: req.break_glass,
            valid_until: None,
            review: req.break_glass.then_some(ReviewState::Pending),
            revoked: None,
        };
        let window_end = review.now.saturating_add(req.duration_ms);
        let draft = mutation_for(&req.actor, &req.target, &req.id, review.now, window_end);
        let approval_rule = approval_rule(&draft);
        let policy = ApprovalPolicy::from_rules([approval_rule.clone()]);
        let approvals = self.approvals(&policy, req.break_glass);
        let violations = self.request_violations(review, req, rule);
        if !violations.is_empty() {
            let request = placeholder(req, &draft, review.now, expires_at, &info);
            return Err(approvals.refusal(
                review,
                &req.actor,
                Step::Propose,
                &request,
                violations,
                None,
                &approval_rule,
            ));
        }
        if !req.break_glass {
            return match approvals.propose_inner(review, &req.actor, &draft, req.id.clone(), expires_at, Some(info))? {
                super::Proposed::Pending(request) => Ok(Elevated::Pending(request)),
                super::Proposed::Applied(_) => Err(ApprovalError::refused(
                    ELEVATION,
                    "a política de aprovação não cobre a elevação",
                )),
            };
        }
        self.break_glass(review, req, &approvals, &approval_rule, draft, info)
            .map(Elevated::Active)
    }

    /// A request for a role or permission the policy does not list is an attempt to escalate: it is
    /// refused and audited at the auditor's level, with no rule to take the approver permission from.
    fn not_in_policy(&self, review: &Review<'_>, req: &ElevationRequest, expires_at: Option<u64>) -> ApprovalError {
        let draft = mutation_for(
            &req.actor,
            &req.target,
            &req.id,
            review.now,
            review.now.saturating_add(req.duration_ms),
        );
        let info = ElevationInfo {
            target: req.target.clone(),
            duration_ms: req.duration_ms,
            justification: req.justification.clone(),
            break_glass: req.break_glass,
            valid_until: None,
            review: req.break_glass.then_some(ReviewState::Pending),
            revoked: None,
        };
        let request = placeholder(req, &draft, review.now, expires_at, &info);
        let rule = ApprovalRule {
            kind: draft.kind(),
            permission: String::new(),
            resource: Resource::new("", ""),
        };
        let policy = ApprovalPolicy::new();
        let violations = vec![Violation::new(
            NOT_IN_POLICY,
            "a política não prevê a elevação deste papel ou permissão",
        )];
        let mut meta = elevation_meta(review.meta, &req.id, &info);
        meta.insert("refusal".into(), Value::Str(NOT_IN_POLICY.into()));
        let at = Review { meta: &meta, ..*review };
        self.approvals(&policy, false)
            .refusal(&at, &req.actor, Step::Propose, &request, violations, None, &rule)
    }

    fn request_violations(&self, review: &Review<'_>, req: &ElevationRequest, rule: &ElevationRule) -> Vec<Violation> {
        let mut violations = Vec::new();
        if req.id.is_empty() {
            violations.push(Violation::new("mutation", "o pedido precisa de um id"));
        }
        if req.actor.id.is_none() {
            violations.push(Violation::new(
                ELEVATION_ACTOR,
                "quem pede a elevação precisa ser identificado",
            ));
        }
        let limit = if req.break_glass {
            match rule.break_glass {
                Some(bg) => Some(bg.max_duration_ms.min(rule.max_duration_ms)),
                None => {
                    violations.push(Violation::new(
                        BREAK_GLASS,
                        "a política não permite break-glass para esta elevação",
                    ));
                    None
                }
            }
        } else {
            Some(rule.max_duration_ms)
        };
        if req.duration_ms == 0 {
            violations.push(Violation::new(
                ELEVATION_DURATION,
                "a duração precisa ser maior que zero",
            ));
        } else if let Some(limit) = limit
            && req.duration_ms > limit
        {
            violations.push(Violation::new(
                ELEVATION_DURATION,
                format!("a duração {} ms passa do máximo de {limit} ms", req.duration_ms),
            ));
        }
        if review.now.checked_add(req.duration_ms).is_none() {
            violations.push(Violation::new(
                ELEVATION_DURATION,
                "a duração não cabe na linha do tempo",
            ));
        }
        let justified = req.justification.as_deref().is_some_and(|text| !text.trim().is_empty());
        if (rule.require_justification || req.break_glass) && !justified {
            violations.push(Violation::new(
                ELEVATION_JUSTIFICATION,
                "a elevação exige uma justificativa",
            ));
        }
        if req.break_glass
            && let Err(violation) = self.forensic_gate()
        {
            violations.push(violation);
        }
        violations
    }

    /// Break-glass needs the trail to be forensic: no auditor, or a lower level, denies it.
    #[cfg(feature = "audit")]
    fn forensic_gate(&self) -> Result<(), Violation> {
        match self.governance.auditor() {
            Some(auditor) if auditor.level() >= AuditLevel::Forensic => Ok(()),
            _ => Err(Violation::new(
                BREAK_GLASS_AUDIT,
                "break-glass exige um auditor no nível forensic",
            )),
        }
    }

    #[cfg(not(feature = "audit"))]
    fn forensic_gate(&self) -> Result<(), Violation> {
        Err(Violation::new(
            BREAK_GLASS_AUDIT,
            "break-glass exige um auditor no nível forensic",
        ))
    }

    fn break_glass(
        &self,
        review: &Review<'_>,
        req: &ElevationRequest,
        approvals: &Approvals<'_>,
        approval_rule: &ApprovalRule,
        mutation: Mutation,
        mut info: ElevationInfo,
    ) -> Result<Approved, ApprovalError> {
        if self.store.get(&req.id)?.is_some() {
            return Err(PendingError::Duplicate(req.id.clone()).into());
        }
        let until = review.now.saturating_add(req.duration_ms);
        info.valid_until = Some(until);
        let mut request = placeholder(req, &mutation, review.now, None, &info);
        request.status = PendingStatus::Approved {
            by: subject_label(&req.actor),
            at: review.now,
        };
        if let Err(violations) = approvals.judge(review, &req.actor, &mutation) {
            return Err(approvals.refusal(
                review,
                &req.actor,
                Step::Propose,
                &request,
                violations,
                None,
                approval_rule,
            ));
        }
        let mut meta = elevation_meta(review.meta, &req.id, &info);
        meta.insert("approved_by".into(), Value::Str(subject_label(&req.actor)));
        let at_review = Review { meta: &meta, ..*review };
        approvals.record(
            &at_review,
            &req.actor,
            Step::Approve,
            &request,
            None,
            None,
            approval_rule,
        )?;
        request.impact = approvals.impact_now(review, &req.actor, &mutation);
        let grants = approvals.apply_directly(&at_review, &req.actor, &mutation)?;
        self.store.insert(request.clone())?;
        Ok(Approved {
            grants,
            request,
            proposed_impact: None,
        })
    }

    /// `approver` approves request `id`: [`Approvals::approve`], with the window opening now and
    /// lasting the requested duration. Refused when the policy now allows less than was asked.
    pub fn approve(&self, review: &Review<'_>, approver: &Subject, id: &str) -> Result<Approved, ApprovalError> {
        crate::obs::approval("elevation_approve", || self.approve_inner(review, approver, id))
    }

    fn approve_inner(&self, review: &Review<'_>, approver: &Subject, id: &str) -> Result<Approved, ApprovalError> {
        let (request, info, rule) = self.open(id)?;
        let mutation = mutation_for(
            &request.actor,
            &info.target,
            &request.id,
            review.now,
            review.now.saturating_add(info.duration_ms),
        );
        let approval_rule = ApprovalRule {
            kind: mutation.kind(),
            permission: rule.approver_permission.clone(),
            resource: rule.approver_resource.clone(),
        };
        let policy = ApprovalPolicy::from_rules([approval_rule.clone()]);
        let approvals = self.approvals(&policy, false);
        let until = review.now.checked_add(info.duration_ms);
        let mut violations = Vec::new();
        if info.duration_ms > rule.max_duration_ms || until.is_none() {
            violations.push(Violation::new(
                ELEVATION_DURATION,
                format!(
                    "a duração {} ms passa do máximo de {} ms da política",
                    info.duration_ms, rule.max_duration_ms
                ),
            ));
        }
        if !violations.is_empty() {
            return Err(approvals.refusal(
                review,
                approver,
                Step::Approve,
                &request,
                violations,
                None,
                &approval_rule,
            ));
        }
        if !request.is_due(review.now) {
            let mut opened = request.clone();
            opened.mutation = mutation;
            if let Some(opened_info) = opened.elevation.as_mut() {
                opened_info.valid_until = until;
            }
            self.store.update(opened)?;
        }
        let meta = elevation_meta(review.meta, id, &info);
        approvals.approve(&Review { meta: &meta, ..*review }, approver, id)
    }

    /// `approver` refuses request `id`, with a `reason`: [`Approvals::reject`].
    pub fn reject(
        &self,
        review: &Review<'_>,
        approver: &Subject,
        id: &str,
        reason: &str,
    ) -> Result<PendingRequest, ApprovalError> {
        crate::obs::approval("elevation_reject", || {
            let (request, info, rule) = self.open(id)?;
            let policy = ApprovalPolicy::from_rules([ApprovalRule {
                kind: request.mutation.kind(),
                permission: rule.approver_permission.clone(),
                resource: rule.approver_resource.clone(),
            }]);
            let meta = elevation_meta(review.meta, id, &info);
            self.approvals(&policy, false)
                .reject(&Review { meta: &meta, ..*review }, approver, id, reason)
        })
    }

    /// Takes the elevation back before its time. `by` is the actor, or someone who holds the approver
    /// permission of the rule. The grant is removed (or the role revoked) through the governance, with
    /// the invariants judging the change as `by`, and the request keeps the [`Revocation`]. A
    /// request that is not approved, was already revoked or already ended is refused.
    pub fn revoke(
        &self,
        review: &Review<'_>,
        by: &Subject,
        id: &str,
        reason: Option<&str>,
    ) -> Result<Revoked, ApprovalError> {
        crate::obs::approval("elevation_revoke", || self.revoke_inner(review, by, id, reason))
    }

    fn revoke_inner(
        &self,
        review: &Review<'_>,
        by: &Subject,
        id: &str,
        reason: Option<&str>,
    ) -> Result<Revoked, ApprovalError> {
        let (request, info, rule) = self.lookup(id)?;
        if !matches!(request.status, PendingStatus::Approved { .. }) {
            return Err(ApprovalError::refused(
                ELEVATION_STATE,
                "só uma elevação aprovada pode ser revogada",
            ));
        }
        if info.revoked.is_some() {
            return Err(ApprovalError::refused(ELEVATION_STATE, "a elevação já foi revogada"));
        }
        if info.valid_until.is_none_or(|until| review.now >= until) {
            return Err(ApprovalError::refused(ELEVATION_STATE, "a elevação já terminou"));
        }
        if by.id.is_none() {
            return Err(ApprovalError::refused(
                ELEVATION_ACTOR,
                "quem revoga a elevação precisa ser identificado",
            ));
        }
        if !same_subject(by, &request.actor) && !self.holds_approver_permission(review, by, rule) {
            return Err(ApprovalError::refused(
                ELEVATION,
                format!("falta a permissão {}", rule.approver_permission),
            ));
        }
        let mutation = match &request.mutation {
            Mutation::Add(grant) => Mutation::Remove { id: grant.id.clone() },
            Mutation::AssignRole { subject, role } => Mutation::RevokeRole {
                subject: subject.clone(),
                role: role.clone(),
            },
            Mutation::Remove { .. } | Mutation::RevokeRole { .. } => {
                return Err(ApprovalError::refused(
                    ELEVATION_STATE,
                    "o pedido não carrega uma elevação aplicável",
                ));
            }
        };
        let policy = ApprovalPolicy::new();
        let approvals = self.approvals(&policy, false);
        let mut meta = elevation_meta(review.meta, id, &info);
        meta.insert("revoked_by".into(), Value::Str(subject_label(by)));
        if let Some(reason) = reason {
            meta.insert("reason".into(), Value::Str(reason.to_string()));
        }
        let grants = approvals.apply_directly(&Review { meta: &meta, ..*review }, by, &mutation)?;
        let mut request = request;
        if let Some(info) = request.elevation.as_mut() {
            info.revoked = Some(Revocation {
                by: subject_label(by),
                at: review.now,
                reason: reason.map(str::to_string),
            });
        }
        self.store.annotate(request.clone())?;
        Ok(Revoked { grants, request })
    }

    /// Closes the review of a break-glass elevation, with a `note` on what was found. `reviewer` must
    /// be someone other than the actor and hold the approver permission of the rule. The record is
    /// forensic and written under [`FailMode::Closed`]: if it cannot be written the review stays open.
    pub fn close_review(
        &self,
        review: &Review<'_>,
        reviewer: &Subject,
        id: &str,
        note: &str,
    ) -> Result<PendingRequest, ApprovalError> {
        crate::obs::approval("elevation_review", || {
            self.close_review_inner(review, reviewer, id, note)
        })
    }

    fn close_review_inner(
        &self,
        review: &Review<'_>,
        reviewer: &Subject,
        id: &str,
        note: &str,
    ) -> Result<PendingRequest, ApprovalError> {
        let (request, info, rule) = self.lookup(id)?;
        let approval_rule = ApprovalRule {
            kind: request.mutation.kind(),
            permission: rule.approver_permission.clone(),
            resource: rule.approver_resource.clone(),
        };
        let policy = ApprovalPolicy::new();
        let approvals = self.approvals(&policy, true);
        let mut violations = Vec::new();
        if !(info.break_glass && info.review == Some(ReviewState::Pending)) {
            violations.push(Violation::new(REVIEW, "não há revisão aberta para este pedido"));
        }
        if reviewer.id.is_none() {
            violations.push(Violation::new(REVIEW, "quem revisa precisa ser identificado"));
        } else if same_subject(reviewer, &request.actor) {
            violations.push(Violation::new(
                REVIEW,
                "quem usou o break-glass não revisa o próprio uso",
            ));
        }
        if !self.holds_approver_permission(review, reviewer, rule) {
            violations.push(Violation::new(
                REVIEW,
                format!("falta a permissão {}", rule.approver_permission),
            ));
        }
        if note.trim().is_empty() {
            violations.push(Violation::new(REVIEW, "o fechamento da revisão precisa de uma nota"));
        }
        if let Err(violation) = self.forensic_gate() {
            violations.push(violation);
        }
        if !violations.is_empty() {
            return Err(approvals.refusal(
                review,
                reviewer,
                Step::ReviewClose,
                &request,
                violations,
                Some(note),
                &approval_rule,
            ));
        }
        approvals.record(
            review,
            reviewer,
            Step::ReviewClose,
            &request,
            None,
            Some(note),
            &approval_rule,
        )?;
        let mut request = request;
        if let Some(info) = request.elevation.as_mut() {
            info.review = Some(ReviewState::Closed {
                by: subject_label(reviewer),
                at: review.now,
                note: note.to_string(),
            });
        }
        self.store.annotate(request.clone())?;
        Ok(request)
    }

    fn holds_approver_permission(&self, review: &Review<'_>, who: &Subject, rule: &ElevationRule) -> bool {
        let ctx = Context::new(&review.current).at(review.now);
        let ctx = match review.tuples {
            Some(tuples) => ctx.with_tuples(tuples),
            None => ctx,
        };
        review.engine.check(
            &ctx,
            &Request::new(who, &rule.approver_permission, &rule.approver_resource),
        )
    }

    /// The request, its elevation and its rule, only while it is still pending.
    fn open(&self, id: &str) -> Result<(PendingRequest, ElevationInfo, &ElevationRule), ApprovalError> {
        let found = self.lookup(id)?;
        if !found.0.is_pending() {
            return Err(PendingError::NotPending(id.to_string()).into());
        }
        Ok(found)
    }

    fn lookup(&self, id: &str) -> Result<(PendingRequest, ElevationInfo, &ElevationRule), ApprovalError> {
        let request = self
            .store
            .get(id)?
            .ok_or_else(|| PendingError::Unknown(id.to_string()))?;
        let info = request
            .elevation
            .clone()
            .ok_or_else(|| ApprovalError::refused(ELEVATION, format!("o pedido {id} não é uma elevação")))?;
        let rule = self.policy.rule_for(&info.target).ok_or_else(|| {
            ApprovalError::refused(
                ELEVATION,
                "a política não prevê mais a elevação deste papel ou permissão",
            )
        })?;
        Ok((request, info, rule))
    }

    fn approvals<'p>(&self, policy: &'p ApprovalPolicy, forensic: bool) -> Approvals<'p>
    where
        'a: 'p,
    {
        let approvals = Approvals {
            governance: self.governance,
            policy,
            store: self.store,
            impact: self.impact,
            #[cfg(feature = "audit")]
            call_mode: self.call_mode,
        };
        #[cfg(feature = "audit")]
        let approvals = if forensic {
            approvals.fail_mode(FailMode::Closed)
        } else {
            approvals
        };
        #[cfg(not(feature = "audit"))]
        let _ = forensic;
        approvals
    }
}

impl Approvals<'_> {
    /// Audits a refused step and returns the refusal; a record that cannot be written wins.
    #[allow(clippy::too_many_arguments)]
    fn refusal(
        &self,
        review: &Review<'_>,
        actor: &Subject,
        step: Step,
        request: &PendingRequest,
        violations: Vec<Violation>,
        reason: Option<&str>,
        rule: &ApprovalRule,
    ) -> ApprovalError {
        match self.record(review, actor, step, request, Some(violations.as_slice()), reason, rule) {
            Ok(()) => ApprovalError::Refused(violations),
            Err(audit) => audit,
        }
    }
}

fn placeholder(
    req: &ElevationRequest,
    mutation: &Mutation,
    now: u64,
    expires_at: Option<u64>,
    info: &ElevationInfo,
) -> PendingRequest {
    PendingRequest::new(req.id.clone(), req.actor.clone(), mutation.clone(), now)
        .expiring_at(expires_at)
        .with_elevation(info.clone())
}

fn elevation_meta(base: &Attributes, id: &str, info: &ElevationInfo) -> Attributes {
    let mut meta = base.clone();
    meta.insert("request_id".into(), Value::Str(id.to_string()));
    meta.insert("elevation".into(), Value::Bool(true));
    if info.break_glass {
        meta.insert("break_glass".into(), Value::Bool(true));
    }
    if let Some(justification) = &info.justification {
        meta.insert("justification".into(), Value::Str(justification.clone()));
    }
    meta
}

/// The change an elevation is: an allow grant, or a role assignment, in `[from, until)`.
fn mutation_for(actor: &Subject, target: &ElevationTarget, id: &str, from: u64, until: u64) -> Mutation {
    match target {
        ElevationTarget::Role { role, scope } => Mutation::AssignRole {
            subject: actor.clone(),
            role: RoleAssignment {
                role: role.clone(),
                scope: scope.clone(),
                valid_from: Some(from),
                valid_until: Some(until),
            },
        },
        ElevationTarget::Permission {
            permission,
            target,
            scope,
        } => {
            let holder = actor.id.clone().unwrap_or_default();
            let grant = Grant::allow(
                format!("elevation:{id}"),
                SubjectMatcher::user(holder),
                permission.clone(),
                target.clone(),
            )
            .valid_between(from, until);
            Mutation::Add(match scope {
                Some(scope) => grant.scoped(scope.clone()),
                None => grant,
            })
        }
    }
}
