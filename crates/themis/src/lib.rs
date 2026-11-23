//! Themis: governance and authorization decisions.
//!
//! A single engine resolves three access models over the same permission catalog:
//!
//! - **RBAC**: roles with inheritance ([`RoleGraph`]) and assignment scoped to a resource
//!   ([`RoleAssignment`]).
//! - **ABAC**: serializable conditions over attributes of the subject, the resource and the
//!   environment ([`Condition`]), with custom functions you can register ([`ConditionRegistry`]).
//! - **ReBAC**: Zanzibar-style relations ([`RelationSchema`], [`TupleStore`]), used as the
//!   subject of a grant ([`SubjectMatcher::Relation`]).
//!
//! A decision goes through three stages: overrides ([`Override`]), collection of the applicable
//! grants and combination by a [`Strategy`]. The default strategy ([`MostSpecific`]) lets the most
//! specific target decide and, within it, `deny` beats `allow`.
//!
//! Grant changes and role assignments go through [`Governance`], which applies invariants
//! (no self-management, no leaving a scope without an administrator, prohibitions) before the
//! change is persisted and, with the `audit` feature, records each decision in an audit trail
//! ([`audit`]).
//!
//! The crate does no IO and does not depend on an async runtime, and it compiles to WebAssembly.
//! Real time, caching and transports live in `themis-sync` and the adapters.
//!
//! See the [repository README](https://github.com/The-Hades-Organization/Themis) for the full guide.

mod graph;

pub mod attr;
#[cfg(feature = "audit")]
pub mod audit;
pub mod catalog;
pub mod condition;
pub mod decision;
pub mod engine;
#[cfg(feature = "exclusive")]
pub mod exclusive;
pub mod explain;
pub mod governance;
pub mod grant;
pub mod overrides;
pub mod query;
pub mod rbac;
pub mod rebac;
pub mod resource;
pub mod spec;
pub mod strategy;
pub mod subject;
pub mod template;
pub mod validity;

pub use attr::{Attributes, Value};
#[cfg(feature = "audit")]
pub use audit::{
    AuditAction, AuditError, AuditLevel, AuditOutcome, AuditRecord, AuditSink, Auditor, JsonLinesAudit, MemoryAuditLog,
    RoleChange,
};
pub use catalog::{
    Catalog, CatalogBuilder, CatalogError, CatalogErrors, CatalogExport, CatalogRule, FnRule, PermissionDef,
    RequireMeta,
};
pub use condition::{Condition, ConditionError, ConditionRegistry, EvalContext, Operand};
pub use decision::{Decision, Reason, Request};
pub use engine::{CapabilitySet, Context, Engine, EngineBuilder, EngineError, GrantError};
#[cfg(feature = "exclusive")]
pub use exclusive::{
    Acquisition, Claim, ExclusiveError, ExclusivePermissions, ExclusiveRegistry, ExclusiveStore, Lease,
    MemoryExclusiveStore, Preemption, StoreError, Terms, priority_from_attr,
};
pub use explain::{
    ConditionTrace, Explanation, GrantTrace, OverrideOutcome, OverrideStep, PrerequisiteStep, TraceResult, Verdict,
    trace_condition,
};
pub use governance::{
    Bypass, CatalogConformance, Forbid, Governance, GovernanceAt, Invariant, ManagementOnly, Mutation, NoEscalation,
    NoLockout, NoSelfManagement, NonDelegable, Prerequisites, Proposal, RequirePermission, Suggestion, Violation,
};
pub use grant::{Effect, Grant, GrantIndex, GrantSource, SubjectMatcher, TargetSelector};
pub use overrides::{
    FnOverride, Override, OverrideGate, OverrideReach, PermissionHolder, ReachRequest, ResourceOwner, SubjectsRequest,
};
pub use query::{
    AccessFilter, AccessVia, CheckAnswer, Expr, FilterOutcome, FilterResidual, FilterResolution, FilterShape,
    InMemorySubjects, PartyAccess, PathLayout, QueryContext, QueryError, QueryLimits, SubjectRef, SubjectResolver,
    WhoCan, WhoCanEntry, WhoCanExcept,
};
pub use rbac::{RbacError, RoleGraph};
pub use rebac::{InMemoryTuples, RebacError, RelationSchema, Rewrite, Tuple, TupleIndex, TupleStore, TupleSubject};
pub use resource::{Anchor, GLOBAL, ObjectRef, Resource};
pub use spec::{
    EngineSpec, InvariantSpec, OverrideRule, OverrideSpec, RelationSpec, ReserveSpec, RoleSpec, SpecError, StrategySpec,
};
pub use strategy::{
    Candidate, DenyOverrides, FirstApplicable, MostSpecific, NativeStrategy, PermitOverrides, Strategy,
};
pub use subject::{ANONYMOUS, AUTHENTICATED, RoleAssignment, Subject};
pub use template::{Materialized, RoleTemplate, TemplateGrant};
pub use validity::{Validity, ValidityError, next_boundary};
