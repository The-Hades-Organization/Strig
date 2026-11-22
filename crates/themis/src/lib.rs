//! Themis: governança e decisões de autorização.
//!
//! Um único motor resolve três modelos de acesso sobre o mesmo catálogo de permissões:
//!
//! - **RBAC**: papéis com herança ([`RoleGraph`]) e atribuição escopada a um recurso
//!   ([`RoleAssignment`]).
//! - **ABAC**: condições serializáveis sobre atributos do sujeito, do recurso e do ambiente
//!   ([`Condition`]), com funções próprias registráveis ([`ConditionRegistry`]).
//! - **ReBAC**: relações no estilo Zanzibar ([`RelationSchema`], [`TupleStore`]), usadas como
//!   sujeito de um grant ([`SubjectMatcher::Relation`]).
//!
//! A decisão passa por três estágios: overrides ([`Override`]), coleta dos grants aplicáveis e
//! combinação por uma [`Strategy`]. A estratégia padrão ([`MostSpecific`]) faz o alvo mais
//! específico decidir e, nele, `deny` vencer `allow`.
//!
//! Mudanças de grant e de atribuição de papel passam por [`Governance`], que aplica invariantes
//! (sem autogestão, sem deixar o escopo sem administrador, proibições) antes de a mudança ser
//! persistida e, com a feature `audit`, registra cada decisão numa trilha de auditoria
//! ([`audit`]).
//!
//! O crate não faz IO nem depende de runtime assíncrono, e compila para WebAssembly. Tempo
//! real, cache e transportes ficam em `themis-sync` e nos adaptadores.

mod graph;

pub mod attr;
#[cfg(feature = "audit")]
pub mod audit;
pub mod catalog;
pub mod condition;
pub mod decision;
pub mod engine;
pub mod explain;
pub mod governance;
pub mod grant;
pub mod overrides;
pub mod rbac;
pub mod rebac;
pub mod resource;
pub mod spec;
pub mod strategy;
pub mod subject;

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
pub use explain::{
    ConditionTrace, Explanation, GrantTrace, OverrideOutcome, OverrideStep, TraceResult, Verdict, trace_condition,
};
pub use governance::{
    CatalogConformance, Forbid, Governance, Invariant, Mutation, NoLockout, NoSelfManagement, Proposal,
    RequirePermission, Violation,
};
pub use grant::{Effect, Grant, GrantSource, SubjectMatcher, TargetSelector};
pub use overrides::{FnOverride, Override, PermissionHolder, ResourceOwner};
pub use rbac::{RbacError, RoleGraph};
pub use rebac::{InMemoryTuples, RebacError, RelationSchema, Rewrite, Tuple, TupleStore, TupleSubject};
pub use resource::{Anchor, GLOBAL, ObjectRef, Resource};
pub use spec::{
    EngineSpec, InvariantSpec, OverrideRule, OverrideSpec, RelationSpec, RoleSpec, SpecError, StrategySpec,
};
pub use strategy::{Candidate, DenyOverrides, FirstApplicable, MostSpecific, PermitOverrides, Strategy};
pub use subject::{ANONYMOUS, AUTHENTICATED, RoleAssignment, Subject};
