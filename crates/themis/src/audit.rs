//! Trilha de auditoria das mudanças de permissão (feature `audit`).
//!
//! Cada mudança de grant, tupla ReBAC ou atribuição de papel vira um [`AuditRecord`], aceito
//! ou recusado. O [`AuditLevel`] decide quanto de cada registro se guarda, e com isso o
//! custo de armazenamento ([`AuditLevel::estimate_bytes`]). O destino é um [`AuditSink`]:
//! memória, arquivo JSON Lines ou uma implementação própria (tabela, fila, SIEM).
//!
//! No nível [`AuditLevel::Forensic`] os registros formam uma cadeia de hashes SHA-256: cada
//! um carrega o hash do anterior, então apagar ou editar um registro quebra a verificação
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
use crate::governance::{Mutation, Violation};
use crate::grant::{Effect, Grant, SubjectMatcher, TargetSelector};
use crate::rebac::Tuple;
use crate::resource::{Anchor, Resource};
use crate::subject::Subject;

/// Quanto de cada mudança se registra. Cada nível inclui tudo do anterior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditLevel {
    /// Quem, quando, o quê (id do objeto) e se foi aplicado.
    Minimal,
    /// Mais o resumo da mudança (permissão, sujeito, alvo, efeito, escopo) e os nomes dos
    /// invariantes que recusaram.
    Standard,
    /// Mais o objeto inteiro (grant com condição, tupla), o ator completo, as mensagens das
    /// violações e os metadados da aplicação (ip, request id, motivo).
    Detailed,
    /// Mais o digest do conjunto de grants antes e depois e a cadeia de hashes.
    Forensic,
}

impl AuditLevel {
    pub const ALL: [AuditLevel; 4] = [
        AuditLevel::Minimal,
        AuditLevel::Standard,
        AuditLevel::Detailed,
        AuditLevel::Forensic,
    ];

    /// Tamanho típico de um registro em JSON compacto, em bytes, medido sobre o registro de
    /// referência de [`reference_record`] (grant com escopo e condição de duas cláusulas, ator
    /// com dois papéis e três metadados). O teste `estimates_match_reference_records` mantém
    /// estes números honestos.
    pub const fn typical_record_bytes(self) -> u64 {
        match self {
            AuditLevel::Minimal => 174,
            AuditLevel::Standard => 387,
            AuditLevel::Detailed => 1_096,
            AuditLevel::Forensic => 1_414,
        }
    }

    /// Como [`AuditLevel::typical_record_bytes`], para registros de decisão, medido sobre
    /// [`reference_decision_record`] (três grants na fonte, um com condição).
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

    /// Estimativa de armazenamento para `records` registros em JSON Lines, sem compressão e sem
    /// índice. Num banco, some o overhead por linha (no Postgres, uns 28 bytes entre cabeçalho de
    /// tupla e ponteiro de item, mais os índices que você criar).
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
    /// Uma decisão de acesso (`Engine::decide`), não uma mudança.
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

/// Resumo de uma decisão, guardado a partir de [`AuditLevel::Standard`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionSummary {
    pub permission: String,
    /// Caminho do recurso em texto (`document:d1/project:p1`).
    pub resource: String,
    pub reason: Reason,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matched: Vec<String>,
    /// A partir de `detailed`.
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

/// Resumo de um grant, guardado a partir de [`AuditLevel::Standard`].
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

/// Atribuição de papel registrada.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleChange {
    pub subject: String,
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<Anchor>,
}

/// Um registro da trilha. Os campos opcionais aparecem conforme o nível.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Milissegundos desde a época Unix.
    pub at: u64,
    pub level: AuditLevel,
    /// Id do ator, ou o tipo dele quando anônimo.
    pub actor: String,
    pub action: AuditAction,
    /// Id do grant, `objeto#relação@sujeito` da tupla, ou `papel@sujeito`.
    pub object: String,
    pub outcome: AuditOutcome,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<GrantSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<RoleChange>,
    /// Nomes dos invariantes (standard) ou `nome: mensagem` (detailed em diante).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub violations: Vec<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<DecisionSummary>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full_grant: Option<Grant>,
    /// Recurso completo de uma decisão, a partir de `detailed`. Com `actor_detail`, basta para
    /// reavaliar a decisão contra outra política.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<Resource>,
    /// Rastro completo da decisão, em `forensic`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explanation: Option<Box<Explanation>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tuple: Option<Tuple>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_detail: Option<Subject>,
    #[serde(default, skip_serializing_if = "Attributes::is_empty")]
    pub meta: Attributes,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before_digest: Option<String>,
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

/// Destino dos registros. Uma implementação que não consegue gravar devolve erro, e a
/// governança recusa a mudança: sem registro, sem mudança.
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

/// Registros em memória, para testes e para quem drena a trilha por conta própria.
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

/// Um registro JSON por linha num `Write` (arquivo, socket, stdout).
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

/// Em `wasm32-unknown-unknown` não há relógio do sistema; use [`Auditor::with_clock`].
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
fn system_clock() -> u64 {
    0
}

/// Monta os registros no nível configurado e entrega ao sink.
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

    /// Retoma uma cadeia forense a partir do hash do último registro já gravado.
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

    /// Decide e registra. No nível `forensic` usa [`Engine::explain`] e guarda o rastro; nos
    /// outros, [`Engine::decide`]. A decisão volta mesmo se o registro falhar: quem chama
    /// escolhe se nega o acesso nesse caso.
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

    /// Registra uma decisão já tomada. Em `forensic`, prefira [`Auditor::explained`].
    pub fn decision(
        &self,
        request: &Request<'_>,
        decision: &Decision,
        meta: &Attributes,
    ) -> Result<AuditRecord, AuditError> {
        self.emit(self.decision_record(request.subject, request.permission, request.resource, decision, meta))
    }

    /// Registra uma decisão com o rastro completo.
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

    /// Registra uma mudança de grant decidida pela governança.
    pub fn grant_mutation(
        &self,
        actor: &Subject,
        mutation: &Mutation,
        before: &[Grant],
        result: &Result<Vec<Grant>, Vec<Violation>>,
        meta: &Attributes,
    ) -> Result<AuditRecord, AuditError> {
        let (action, object, grant) = match mutation {
            Mutation::Add(grant) => (AuditAction::GrantAdd, grant.id.clone(), Some(grant)),
            Mutation::Remove { id } => (
                AuditAction::GrantRemove,
                id.clone(),
                before.iter().find(|g| &g.id == id),
            ),
        };
        let outcome = match result {
            Ok(_) => AuditOutcome::Applied,
            Err(_) => AuditOutcome::Rejected,
        };
        let mut record = self.base(actor, action, object, outcome);
        if self.level >= AuditLevel::Standard {
            record.grant = grant.map(GrantSummary::from);
            if let Err(violations) = result {
                record.violations = violations
                    .iter()
                    .map(|v| match self.level {
                        AuditLevel::Standard => v.invariant.clone(),
                        _ => v.to_string(),
                    })
                    .collect();
            }
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

    /// Registra a gravação ou remoção de uma tupla ReBAC.
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

    /// Registra a atribuição ou revogação de um papel.
    pub fn role_change(
        &self,
        actor: &Subject,
        assigned: bool,
        change: &RoleChange,
        outcome: AuditOutcome,
        meta: &Attributes,
    ) -> Result<AuditRecord, AuditError> {
        let action = if assigned {
            AuditAction::RoleAssign
        } else {
            AuditAction::RoleRevoke
        };
        let mut record = self.base(actor, action, format!("{}@{}", change.role, change.subject), outcome);
        if self.level >= AuditLevel::Standard {
            record.role = Some(change.clone());
        }
        self.detail(&mut record, actor, meta);
        self.emit(record)
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

/// Digest SHA-256 de um conjunto de grants, independente da ordem.
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

/// Hash de um registro: SHA-256 do JSON com `hash` vazio e `prev_hash` preenchido.
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

/// Confere uma sequência de registros forenses, na ordem em que foram gravados.
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

/// O registro de referência usado nas estimativas de armazenamento: a mudança de grant mais
/// comum (papel com escopo e condição curta), feita por um ator com dois papéis e três
/// metadados de requisição.
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

/// O registro de decisão de referência: sujeito com dois papéis, recurso com três degraus, três
/// grants na fonte (um com condição de duas cláusulas, um de outra permissão, um fora do
/// escopo) e três metadados.
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
