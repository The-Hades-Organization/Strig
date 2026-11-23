//! Audit trail of permission changes (feature `audit`).
//!
//! Every grant change, ReBAC tuple change or role assignment becomes an [`AuditRecord`], accepted
//! or refused. The [`AuditLevel`] decides how much of each record is kept, and therefore the
//! storage cost ([`AuditLevel::estimate_bytes`]). The destination is an [`AuditSink`]:
//! memory, a JSON Lines file or your own implementation (table, queue, SIEM).
//!
//! At the [`AuditLevel::Forensic`] level the records form a SHA-256 hash chain: each one carries
//! the hash of the previous one, so deleting or editing a record breaks verification
//! ([`verify_chain`]).

use std::fmt;
use std::io::Write;
use std::sync::{Arc, Mutex, MutexGuard};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::attr::Attributes;
use crate::decision::{Decision, Reason, Request};
use crate::engine::{Context, Engine};
use crate::explain::Explanation;
use crate::governance::{Mutation, Suggestion, Violation};
use crate::grant::{Effect, Grant, SubjectMatcher, TargetSelector};
use crate::rebac::Tuple;
use crate::resource::{Anchor, Resource};
use crate::subject::{RoleAssignment, Subject};

/// How much of each change is recorded. Each level includes everything from the previous one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditLevel {
    /// Who, when, what (object id) and whether it was applied.
    Minimal,
    /// Plus a summary of the change (permission, subject, target, effect, scope) and the names of the
    /// invariants that refused it.
    Standard,
    /// Plus the whole object (grant with condition, tuple), the full actor, the violation messages
    /// and the application metadata (ip, request id, reason).
    Detailed,
    /// Plus the digest of the grant set before and after, and the hash chain.
    Forensic,
}

impl AuditLevel {
    pub const ALL: [AuditLevel; 4] = [
        AuditLevel::Minimal,
        AuditLevel::Standard,
        AuditLevel::Detailed,
        AuditLevel::Forensic,
    ];

    /// Typical size of a record in compact JSON, in bytes, measured on the reference record of
    /// [`reference_record`] (grant with a scope and a two-clause condition, actor with two roles and
    /// three metadata entries). The test `estimates_match_reference_records` keeps these numbers
    /// honest.
    pub const fn typical_record_bytes(self) -> u64 {
        match self {
            AuditLevel::Minimal => 174,
            AuditLevel::Standard => 387,
            AuditLevel::Detailed => 1_096,
            AuditLevel::Forensic => 1_414,
        }
    }

    /// Like [`AuditLevel::typical_record_bytes`], for decision records, measured on
    /// [`reference_decision_record`] (three grants in the source, one with a condition).
    pub const fn typical_decision_bytes(self) -> u64 {
        match self {
            AuditLevel::Minimal => 284,
            AuditLevel::Standard => 668,
            AuditLevel::Detailed => 1_238,
            AuditLevel::Forensic => 3_581,
        }
    }

    pub const fn estimate_decision_bytes(self, records: u64) -> u64 {
        (self.typical_decision_bytes() + 1) * records
    }

    /// Storage estimate for `records` records in JSON Lines, with no compression and no index. In a
    /// database, add the per-row overhead (in Postgres, about 28 bytes between the tuple header and the
    /// item pointer, plus whatever indexes you create).
    pub const fn estimate_bytes(self, records: u64) -> u64 {
        (self.typical_record_bytes() + 1) * records
    }
}

impl fmt::Display for AuditLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            AuditLevel::Minimal => "minimal",
            AuditLevel::Standard => "standard",
            AuditLevel::Detailed => "detailed",
            AuditLevel::Forensic => "forensic",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    GrantAdd,
    GrantRemove,
    TupleAdd,
    TupleRemove,
    RoleAssign,
    RoleRevoke,
    /// An access decision (`Engine::decide`), not a change.
    Decision,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Applied,
    Rejected,
    Allowed,
    Denied,
}

/// Summary of a decision, kept from [`AuditLevel::Standard`] upward.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionSummary {
    pub permission: String,
    /// Resource path as text (`document:d1/project:p1`).
    pub resource: String,
    pub reason: Reason,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matched: Vec<String>,
    /// From `detailed` upward.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

fn path_text(resource: &Resource) -> String {
    resource
        .path
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("/")
}

/// Summary of a grant, kept from [`AuditLevel::Standard`] upward.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GrantSummary {
    pub permission: String,
    pub subject: SubjectMatcher,
    pub target: TargetSelector,
    pub effect: Effect,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<Anchor>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub conditional: bool,
}

impl From<&Grant> for GrantSummary {
    fn from(grant: &Grant) -> Self {
        Self {
            permission: grant.permission.clone(),
            subject: grant.subject.clone(),
            target: grant.target.clone(),
            effect: grant.effect,
            scope: grant.scope.clone(),
            conditional: grant.condition.is_some(),
        }
    }
}

/// Recorded role assignment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleChange {
    /// Subject id, or `<kind>:<anonymous>` when it has no id.
    pub subject: String,
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<Anchor>,
}

impl RoleChange {
    fn of(subject: &Subject, role: &RoleAssignment) -> Self {
        Self {
            subject: subject
                .id
                .clone()
                .unwrap_or_else(|| format!("{}:<anonymous>", subject.kind)),
            role: role.role.clone(),
            scope: role.scope.clone(),
        }
    }
}

/// One record of the trail. The optional fields appear depending on the level.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Milliseconds since the Unix epoch.
    pub at: u64,
    pub level: AuditLevel,
    /// Actor id, or its kind when anonymous.
    pub actor: String,
    pub action: AuditAction,
    /// Grant id, the tuple's `object#relation@subject`, or `role@subject` for a role change,
    /// with the scope after the role when there is one (`role#scope@subject`).
    pub object: String,
    pub outcome: AuditOutcome,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<GrantSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<RoleChange>,
    /// Names of the invariants (standard) or `name: message` (detailed and above).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub violations: Vec<String>,
    /// Compensating changes the refusing invariants proposed (see [`Violation::suggestion`]), from
    /// `standard` upward: the subject id and the role, nothing else. Nothing was applied.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suggestions: Vec<Suggestion>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<DecisionSummary>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full_grant: Option<Grant>,
    /// Full resource of a decision, from `detailed` upward. With `actor_detail`, it is enough to
    /// re-evaluate the decision against another policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<Resource>,
    /// Full trace of the decision, at `forensic`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explanation: Option<Box<Explanation>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tuple: Option<Tuple>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_detail: Option<Subject>,
    #[serde(default, skip_serializing_if = "Attributes::is_empty")]
    pub meta: Attributes,

    /// Digest of the grant set before the change. For a role change, the digest of the subject's
    /// roles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before_digest: Option<String>,
    /// Digest of the grant set after the change (equal to the previous one on a refusal). For a role
    /// change, the digest of the subject's roles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("falha ao gravar auditoria: {0}")]
    Sink(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// Destination of the records. An implementation that cannot write returns an error, and
/// governance refuses the change: no record, no change.
pub trait AuditSink: Send + Sync {
    fn write(&self, record: &AuditRecord) -> Result<(), AuditError>;
}

impl<F: Fn(&AuditRecord) -> Result<(), AuditError> + Send + Sync> AuditSink for F {
    fn write(&self, record: &AuditRecord) -> Result<(), AuditError> {
        self(record)
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// In-memory records, for tests and for callers who drain the trail themselves.
#[derive(Debug, Default)]
pub struct MemoryAuditLog {
    records: Mutex<Vec<AuditRecord>>,
}

impl MemoryAuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn records(&self) -> Vec<AuditRecord> {
        lock(&self.records).clone()
    }

    pub fn drain(&self) -> Vec<AuditRecord> {
        std::mem::take(&mut *lock(&self.records))
    }
}

impl AuditSink for MemoryAuditLog {
    fn write(&self, record: &AuditRecord) -> Result<(), AuditError> {
        lock(&self.records).push(record.clone());
        Ok(())
    }
}

/// One JSON record per line on a `Write` (file, socket, stdout).
pub struct JsonLinesAudit<W> {
    out: Mutex<W>,
}

impl<W: Write + Send> JsonLinesAudit<W> {
    pub fn new(out: W) -> Self {
        Self { out: Mutex::new(out) }
    }

    pub fn into_inner(self) -> W {
        self.out.into_inner().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl<W: Write + Send> AuditSink for JsonLinesAudit<W> {
    fn write(&self, record: &AuditRecord) -> Result<(), AuditError> {
        let mut line = serde_json::to_vec(record)?;
        line.push(b'\n');
        let mut out = lock(&self.out);
        out.write_all(&line)?;
        out.flush()?;
        Ok(())
    }
}

pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
fn system_clock() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// `wasm32-unknown-unknown` has no system clock; use [`Auditor::with_clock`].
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
fn system_clock() -> u64 {
    0
}

/// Builds the records at the configured level and hands them to the sink.
pub struct Auditor {
    level: AuditLevel,
    sink: Arc<dyn AuditSink>,
    clock: Clock,
    last_hash: Mutex<Option<String>>,
}

impl fmt::Debug for Auditor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Auditor")
            .field("level", &self.level)
            .finish_non_exhaustive()
    }
}

impl Auditor {
    pub fn new(level: AuditLevel, sink: Arc<dyn AuditSink>) -> Self {
        Self {
            level,
            sink,
            clock: Arc::new(system_clock),
            last_hash: Mutex::new(None),
        }
    }

    pub fn with_clock(mut self, clock: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        self.clock = Arc::new(clock);
        self
    }

    /// Resumes a forensic chain from the hash of the last record already written.
    pub fn resume_chain(self, last_hash: impl Into<String>) -> Self {
        *lock(&self.last_hash) = Some(last_hash.into());
        self
    }

    pub fn level(&self) -> AuditLevel {
        self.level
    }

    fn base(&self, actor: &Subject, action: AuditAction, object: String, outcome: AuditOutcome) -> AuditRecord {
        AuditRecord {
            at: (self.clock)(),
            level: self.level,
            actor: actor.id.clone().unwrap_or_else(|| actor.kind.clone()),
            action,
            object,
            outcome,
            grant: None,
            role: None,
            violations: Vec::new(),
            suggestions: Vec::new(),
            decision: None,
            full_grant: None,
            resource: None,
            explanation: None,
            tuple: None,
            actor_detail: None,
            meta: Attributes::new(),
            before_digest: None,
            after_digest: None,
            prev_hash: None,
            hash: None,
        }
    }

    /// Decides and records. At the `forensic` level it uses [`Engine::explain`] and keeps the trace; at
    /// the other levels, [`Engine::decide`]. The decision is returned even if the record fails: the
    /// caller chooses whether to deny access in that case.
    pub fn decide(
        &self,
        engine: &Engine,
        ctx: &Context<'_>,
        request: &Request<'_>,
        meta: &Attributes,
    ) -> (Decision, Result<AuditRecord, AuditError>) {
        if self.level >= AuditLevel::Forensic {
            let explanation = engine.explain(ctx, request);
            let record = self.explained(&explanation, meta);
            (explanation.decision, record)
        } else {
            let decision = engine.decide(ctx, request);
            let record = self.decision(request, &decision, meta);
            (decision, record)
        }
    }

    /// Records a decision that was already made. At `forensic`, prefer [`Auditor::explained`].
    pub fn decision(
        &self,
        request: &Request<'_>,
        decision: &Decision,
        meta: &Attributes,
    ) -> Result<AuditRecord, AuditError> {
        self.emit(self.decision_record(request.subject, request.permission, request.resource, decision, meta))
    }

    /// Records a decision with the full trace.
    pub fn explained(&self, explanation: &Explanation, meta: &Attributes) -> Result<AuditRecord, AuditError> {
        let mut record = self.decision_record(
            &explanation.subject,
            &explanation.permission,
            &explanation.resource,
            &explanation.decision,
            meta,
        );
        if self.level >= AuditLevel::Forensic {
            record.explanation = Some(Box::new(explanation.clone()));
        }
        self.emit(record)
    }

    fn decision_record(
        &self,
        subject: &Subject,
        permission: &str,
        resource: &Resource,
        decision: &Decision,
        meta: &Attributes,
    ) -> AuditRecord {
        let outcome = if decision.is_allowed() {
            AuditOutcome::Allowed
        } else {
            AuditOutcome::Denied
        };
        let path = path_text(resource);
        let object = format!("{permission}@{path}");
        let mut record = self.base(subject, AuditAction::Decision, object, outcome);
        if self.level >= AuditLevel::Standard {
            record.decision = Some(DecisionSummary {
                permission: permission.to_string(),
                resource: path,
                reason: decision.reason.clone(),
                matched: decision.matched.clone(),
                warnings: if self.level >= AuditLevel::Detailed {
                    decision.warnings.clone()
                } else {
                    Vec::new()
                },
            });
        }
        if self.level >= AuditLevel::Detailed {
            record.resource = Some(resource.clone());
        }
        self.detail(&mut record, subject, meta);
        record
    }

    fn detail(&self, record: &mut AuditRecord, actor: &Subject, meta: &Attributes) {
        if self.level >= AuditLevel::Detailed {
            record.actor_detail = Some(actor.clone());
            record.meta = meta.clone();
        }
    }

    /// Records a change decided by governance. A role change is emitted as
    /// `role_assign`/`role_revoke`, like [`Auditor::role_change`], with the violations.
    pub fn grant_mutation(
        &self,
        actor: &Subject,
        mutation: &Mutation,
        before: &[Grant],
        result: &Result<Vec<Grant>, Vec<Violation>>,
        meta: &Attributes,
    ) -> Result<AuditRecord, AuditError> {
        let (outcome, violations) = match result {
            Ok(_) => (AuditOutcome::Applied, &[][..]),
            Err(violations) => (AuditOutcome::Rejected, violations.as_slice()),
        };
        let (action, object, grant) = match mutation {
            Mutation::Add(grant) => (AuditAction::GrantAdd, grant.id.clone(), Some(grant)),
            Mutation::Remove { id } => (
                AuditAction::GrantRemove,
                id.clone(),
                before.iter().find(|g| &g.id == id),
            ),
            Mutation::AssignRole { subject, role } | Mutation::RevokeRole { subject, role } => {
                let assigned = matches!(mutation, Mutation::AssignRole { .. });
                let change = RoleChange::of(subject, role);
                let before = role_set_digest(&subject.roles);
                let after = match result {
                    Ok(_) => {
                        let roles = mutation.subject_after().map(|s| s.roles);
                        role_set_digest(&roles.unwrap_or_default())
                    }
                    Err(_) => before.clone(),
                };
                let digests = Some((before, after));
                return self.role_record(actor, assigned, &change, outcome, violations, digests, meta);
            }
        };
        let mut record = self.base(actor, action, object, outcome);
        if self.level >= AuditLevel::Standard {
            record.grant = grant.map(GrantSummary::from);
            record.violations = self.violation_texts(violations);
            record.suggestions = suggestions_of(violations);
        }
        if self.level >= AuditLevel::Detailed {
            record.full_grant = grant.cloned();
        }
        self.detail(&mut record, actor, meta);
        if self.level >= AuditLevel::Forensic {
            record.before_digest = Some(grant_set_digest(before));
            record.after_digest = Some(match result {
                Ok(after) => grant_set_digest(after),
                Err(_) => grant_set_digest(before),
            });
        }
        self.emit(record)
    }

    /// Records the writing or removal of a ReBAC tuple.
    pub fn tuple_change(
        &self,
        actor: &Subject,
        added: bool,
        tuple: &Tuple,
        outcome: AuditOutcome,
        meta: &Attributes,
    ) -> Result<AuditRecord, AuditError> {
        let action = if added {
            AuditAction::TupleAdd
        } else {
            AuditAction::TupleRemove
        };
        let mut record = self.base(actor, action, tuple.to_string(), outcome);
        if self.level >= AuditLevel::Detailed {
            record.tuple = Some(tuple.clone());
        }
        self.detail(&mut record, actor, meta);
        self.emit(record)
    }

    /// Records the assignment or revocation of a role.
    pub fn role_change(
        &self,
        actor: &Subject,
        assigned: bool,
        change: &RoleChange,
        outcome: AuditOutcome,
        meta: &Attributes,
    ) -> Result<AuditRecord, AuditError> {
        self.role_record(actor, assigned, change, outcome, &[], None, meta)
    }

    #[allow(clippy::too_many_arguments)]
    fn role_record(
        &self,
        actor: &Subject,
        assigned: bool,
        change: &RoleChange,
        outcome: AuditOutcome,
        violations: &[Violation],
        digests: Option<(String, String)>,
        meta: &Attributes,
    ) -> Result<AuditRecord, AuditError> {
        let action = if assigned {
            AuditAction::RoleAssign
        } else {
            AuditAction::RoleRevoke
        };
        let object = match &change.scope {
            Some(scope) => format!("{}#{scope}@{}", change.role, change.subject),
            None => format!("{}@{}", change.role, change.subject),
        };
        let mut record = self.base(actor, action, object, outcome);
        if self.level >= AuditLevel::Standard {
            record.role = Some(change.clone());
            record.violations = self.violation_texts(violations);
            record.suggestions = suggestions_of(violations);
        }
        self.detail(&mut record, actor, meta);
        if self.level >= AuditLevel::Forensic
            && let Some((before, after)) = digests
        {
            record.before_digest = Some(before);
            record.after_digest = Some(after);
        }
        self.emit(record)
    }

    /// Names of the invariants at `standard`; name and message from `detailed` upward.
    fn violation_texts(&self, violations: &[Violation]) -> Vec<String> {
        violations
            .iter()
            .map(|v| {
                if self.level >= AuditLevel::Detailed {
                    v.to_string()
                } else {
                    v.invariant.clone()
                }
            })
            .collect()
    }

    fn emit(&self, mut record: AuditRecord) -> Result<AuditRecord, AuditError> {
        if self.level < AuditLevel::Forensic {
            self.sink.write(&record)?;
            return Ok(record);
        }
        let mut last = lock(&self.last_hash);
        record.prev_hash = last.clone();
        record.hash = Some(record_hash(&record)?);
        self.sink.write(&record)?;
        *last = record.hash.clone();
        Ok(record)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// SHA-256 digest of a grant set, independent of order.
pub fn grant_set_digest(grants: &[Grant]) -> String {
    let mut lines: Vec<String> = grants
        .iter()
        .map(|g| serde_json::to_string(g).unwrap_or_default())
        .collect();
    lines.sort();
    let mut hasher = Sha256::new();
    for line in lines {
        hasher.update(line.as_bytes());
        hasher.update(b"\n");
    }
    hex(&hasher.finalize())
}

/// SHA-256 digest of a subject's roles, independent of order.
fn role_set_digest(roles: &[RoleAssignment]) -> String {
    let mut lines: Vec<String> = roles
        .iter()
        .map(|r| serde_json::to_string(r).unwrap_or_default())
        .collect();
    lines.sort();
    let mut hasher = Sha256::new();
    for line in lines {
        hasher.update(line.as_bytes());
        hasher.update(b"\n");
    }
    hex(&hasher.finalize())
}

/// Hash of a record: SHA-256 of the JSON with `hash` empty and `prev_hash` filled in.
pub fn record_hash(record: &AuditRecord) -> Result<String, AuditError> {
    let mut unsigned = record.clone();
    unsigned.hash = None;
    Ok(hex(&Sha256::digest(serde_json::to_vec(&unsigned)?)))
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChainError {
    #[error("registro {index}: hash não confere")]
    Tampered { index: usize },
    #[error("registro {index}: elo quebrado com o anterior")]
    Broken { index: usize },
    #[error("registro {index}: sem hash, não é nível forensic")]
    Unchained { index: usize },
}

/// Checks a sequence of forensic records, in the order they were written.
pub fn verify_chain(records: &[AuditRecord]) -> Result<(), ChainError> {
    let mut previous: Option<&str> = None;
    for (index, record) in records.iter().enumerate() {
        let Some(hash) = record.hash.as_deref() else {
            return Err(ChainError::Unchained { index });
        };
        if index > 0 && record.prev_hash.as_deref() != previous {
            return Err(ChainError::Broken { index });
        }
        if record_hash(record).ok().as_deref() != Some(hash) {
            return Err(ChainError::Tampered { index });
        }
        previous = Some(hash);
    }
    Ok(())
}

/// The reference record used in the storage estimates: the most common grant change (role with a
/// scope and a short condition), made by an actor with two roles and three request metadata
/// entries.
pub fn reference_record(level: AuditLevel) -> AuditRecord {
    use crate::condition::{Condition, Operand};

    let actor = Subject::user("8f14e45f-ceea-467a-9575-0cbd1e4e7c21")
        .with_role_in("admin", Anchor::new("org", "c9f0f895-fb98-4b91-8f1c-3b0b1e6f2a10"))
        .with_role("auditor");
    let grant = Grant::allow(
        "0b8a1e2c-5f6d-4a3b-9c8d-7e6f5a4b3c2d",
        SubjectMatcher::role("editor"),
        "document.export",
        TargetSelector::kind("project"),
    )
    .scoped(Anchor::new("org", "c9f0f895-fb98-4b91-8f1c-3b0b1e6f2a10"))
    .when(Condition::all([
        Condition::eq(Operand::attr("subject.plan"), Operand::lit("enterprise")),
        Condition::lt(Operand::attr("env.hour"), Operand::lit(18)),
    ]));
    let before: Vec<Grant> = Vec::new();
    let mut meta = Attributes::new();
    meta.insert("ip".into(), "203.0.113.42".into());
    meta.insert("request_id".into(), "req-01HZX3K9QW8E7R6T5Y4U3I2O1P".into());
    meta.insert("reason".into(), "ticket SUP-1234".into());

    let auditor = Auditor::new(level, Arc::new(MemoryAuditLog::new()))
        .with_clock(|| 1_763_700_000_000)
        .resume_chain("a".repeat(64));
    let result = Ok(vec![grant.clone()]);
    auditor
        .grant_mutation(&actor, &Mutation::Add(grant), &before, &result, &meta)
        .expect("registro de referência")
}

/// The reference decision record: a subject with two roles, a resource with three steps, three
/// grants in the source (one with a two-clause condition, one for another permission, one out of
/// scope) and three metadata entries.
pub fn reference_decision_record(level: AuditLevel) -> AuditRecord {
    use crate::catalog::{Catalog, PermissionDef};
    use crate::condition::{Condition, Operand};

    let org = "c9f0f895-fb98-4b91-8f1c-3b0b1e6f2a10";
    let catalog = Catalog::builder()
        .target_kinds(["project", "document"])
        .broad_target("org")
        .permission(PermissionDef::new("document.export").targets(["project", "document"]))
        .permission(PermissionDef::new("document.edit").targets(["project", "document"]))
        .build()
        .expect("catálogo de referência");
    let engine = Engine::builder(catalog).build().expect("motor de referência");
    let grants = vec![
        Grant::allow(
            "0b8a1e2c-5f6d-4a3b-9c8d-7e6f5a4b3c2d",
            SubjectMatcher::role("editor"),
            "document.export",
            TargetSelector::kind("project"),
        )
        .scoped(Anchor::new("org", org))
        .when(Condition::all([
            Condition::eq(Operand::attr("subject.plan"), Operand::lit("enterprise")),
            Condition::lt(Operand::attr("env.hour"), Operand::lit(18)),
        ])),
        Grant::allow(
            "1c9b2f3d-6a7e-4b4c-8d9e-8f7a6b5c4d3e",
            SubjectMatcher::role("editor"),
            "document.edit",
            TargetSelector::kind("project"),
        ),
        Grant::deny(
            "2d0c3a4e-7b8f-4c5d-9eaf-9a8b7c6d5e4f",
            SubjectMatcher::Any,
            "document.export",
            TargetSelector::kind("org"),
        )
        .scoped(Anchor::new("org", "other")),
    ];
    let subject = Subject::user("8f14e45f-ceea-467a-9575-0cbd1e4e7c21")
        .with_role_in("editor", Anchor::new("org", org))
        .with_role("auditor")
        .with_attr("plan", "enterprise");
    let resource = Resource::new("document", "5e6f7a8b-9c0d-4e1f-a2b3-c4d5e6f7a8b9")
        .within("project", "3a4b5c6d-7e8f-4a9b-8c0d-1e2f3a4b5c6d")
        .within("org", org);
    let mut env = Attributes::new();
    env.insert("hour".into(), 10.into());
    let mut meta = Attributes::new();
    meta.insert("ip".into(), "203.0.113.42".into());
    meta.insert("request_id".into(), "req-01HZX3K9QW8E7R6T5Y4U3I2O1P".into());
    meta.insert("route".into(), "POST /documents/:id/export".into());

    let auditor = Auditor::new(level, Arc::new(MemoryAuditLog::new()))
        .with_clock(|| 1_763_700_000_000)
        .resume_chain("a".repeat(64));
    let ctx = Context::new(&grants).with_env(&env);
    let request = Request::new(&subject, "document.export", &resource);
    let (_, record) = auditor.decide(&engine, &ctx, &request, &meta);
    record.expect("registro de referência")
}

fn suggestions_of(violations: &[Violation]) -> Vec<Suggestion> {
    violations
        .iter()
        .filter_map(|v| v.suggestion.as_deref().cloned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::ObjectRef;

    #[test]
    fn decision_records_by_level() {
        let minimal = reference_decision_record(AuditLevel::Minimal);
        assert_eq!(minimal.outcome, AuditOutcome::Allowed);
        assert!(minimal.object.starts_with("document.export@document:"));
        assert!(minimal.decision.is_none());
        let standard = reference_decision_record(AuditLevel::Standard);
        assert_eq!(standard.decision.as_ref().unwrap().matched.len(), 1);
        let detailed = reference_decision_record(AuditLevel::Detailed);
        assert!(detailed.resource.is_some() && detailed.actor_detail.is_some());
        let forensic = reference_decision_record(AuditLevel::Forensic);
        let explanation = forensic.explanation.as_ref().unwrap();
        assert_eq!(explanation.grants.len(), 3);
        assert!(forensic.hash.is_some());
        let back: AuditRecord = serde_json::from_str(&serde_json::to_string(&forensic).unwrap()).unwrap();
        assert_eq!(back, forensic);
    }

    #[test]
    fn decision_estimates_match_reference_records() {
        let report: Vec<(AuditLevel, u64, u64)> = AuditLevel::ALL
            .into_iter()
            .map(|level| {
                let actual = serde_json::to_vec(&reference_decision_record(level)).unwrap().len() as u64;
                (level, actual, level.typical_decision_bytes())
            })
            .collect();
        let drifted = report
            .iter()
            .any(|(_, actual, typical)| actual.abs_diff(*typical) as f64 / *typical as f64 > 0.10);
        assert!(!drifted, "medido x documentado: {report:?}");
    }

    fn actor() -> Subject {
        Subject::user("alice").with_role("admin")
    }

    fn grant(id: &str) -> Grant {
        Grant::allow(
            id,
            SubjectMatcher::role("editor"),
            "doc.edit",
            TargetSelector::kind("doc"),
        )
    }

    #[test]
    fn levels_add_fields_progressively() {
        let minimal = reference_record(AuditLevel::Minimal);
        assert!(minimal.grant.is_none() && minimal.full_grant.is_none() && minimal.hash.is_none());
        let standard = reference_record(AuditLevel::Standard);
        assert!(standard.grant.as_ref().is_some_and(|g| g.conditional));
        assert!(standard.full_grant.is_none() && standard.meta.is_empty());
        let detailed = reference_record(AuditLevel::Detailed);
        assert!(detailed.full_grant.is_some() && detailed.actor_detail.is_some());
        assert_eq!(detailed.meta.len(), 3);
        assert!(detailed.hash.is_none());
        let forensic = reference_record(AuditLevel::Forensic);
        assert!(forensic.hash.is_some() && forensic.before_digest.is_some());
    }

    #[test]
    fn estimates_match_reference_records() {
        for level in AuditLevel::ALL {
            let actual = serde_json::to_vec(&reference_record(level)).unwrap().len() as u64;
            let typical = level.typical_record_bytes();
            let drift = actual.abs_diff(typical) as f64 / typical as f64;
            assert!(drift <= 0.10, "{level}: medido {actual} B, documentado {typical} B");
        }
        assert!(AuditLevel::Minimal.estimate_bytes(1_000_000) < AuditLevel::Forensic.estimate_bytes(1_000_000));
    }

    #[test]
    fn rejected_mutation_keeps_violations() {
        let log = Arc::new(MemoryAuditLog::new());
        let auditor = Auditor::new(AuditLevel::Standard, log.clone());
        let result = Err(vec![Violation::new("forbid", "não pode")]);
        auditor
            .grant_mutation(&actor(), &Mutation::Add(grant("g1")), &[], &result, &Attributes::new())
            .unwrap();
        let records = log.records();
        assert_eq!(records[0].outcome, AuditOutcome::Rejected);
        assert_eq!(records[0].violations, ["forbid"]);
    }

    #[test]
    fn forensic_chain_detects_tampering() {
        let log = Arc::new(MemoryAuditLog::new());
        let auditor = Auditor::new(AuditLevel::Forensic, log.clone()).with_clock(|| 1);
        let mut current = Vec::new();
        for id in ["g1", "g2", "g3"] {
            let next = {
                let mut v = current.clone();
                v.push(grant(id));
                v
            };
            let result = Ok(next.clone());
            auditor
                .grant_mutation(
                    &actor(),
                    &Mutation::Add(grant(id)),
                    &current,
                    &result,
                    &Attributes::new(),
                )
                .unwrap();
            current = next;
        }
        let tuple = Tuple::new(ObjectRef::new("doc", "d1"), "viewer", ObjectRef::new("user", "bob"));
        auditor
            .tuple_change(&actor(), true, &tuple, AuditOutcome::Applied, &Attributes::new())
            .unwrap();
        let records = log.records();
        assert_eq!(verify_chain(&records), Ok(()));
        assert_eq!(records[0].after_digest, records[1].before_digest);

        let mut edited = records.clone();
        edited[1].object = "g9".into();
        assert_eq!(verify_chain(&edited), Err(ChainError::Tampered { index: 1 }));

        let mut removed = records.clone();
        removed.remove(1);
        assert_eq!(verify_chain(&removed), Err(ChainError::Broken { index: 1 }));
    }

    #[test]
    fn json_lines_sink_writes_one_record_per_line() {
        let sink = Arc::new(JsonLinesAudit::new(Vec::new()));
        let auditor = Auditor::new(AuditLevel::Minimal, sink.clone());
        let change = RoleChange {
            subject: "bob".into(),
            role: "editor".into(),
            scope: None,
        };
        auditor
            .role_change(&actor(), true, &change, AuditOutcome::Applied, &Attributes::new())
            .unwrap();
        auditor
            .role_change(&actor(), false, &change, AuditOutcome::Applied, &Attributes::new())
            .unwrap();
        drop(auditor);
        let sink = Arc::try_unwrap(sink).ok().unwrap();
        let text = String::from_utf8(sink.into_inner()).unwrap();
        let lines: Vec<AuditRecord> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[1].action, AuditAction::RoleRevoke);
        assert_eq!(lines[0].object, "editor@bob");
    }
}
