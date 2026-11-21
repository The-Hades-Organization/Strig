use std::path::Path;

use themis::audit::{ChainError, verify_chain};
use themis::{AuditAction, AuditLevel, AuditOutcome, AuditRecord, Effect, Explanation};

use crate::inspector::Inspector;
use crate::scenario::{LoadError, read};

/// Uma trilha de auditoria lida de um arquivo JSON Lines.
#[derive(Debug, Clone, Default)]
pub struct Trail {
    pub records: Vec<AuditRecord>,
}

/// Resultado da conferência da cadeia de hashes dos registros `forensic`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainStatus {
    /// Nenhum registro forense.
    Absent,
    Intact {
        records: usize,
    },
    Broken(ChainError),
}

/// Uma decisão auditada reavaliada contra a política e os grants atuais.
#[derive(Debug, Clone)]
pub struct Replay {
    pub recorded: AuditOutcome,
    pub now: Explanation,
}

impl Replay {
    /// A decisão de hoje difere da registrada.
    pub fn changed(&self) -> bool {
        let allowed_now = self.now.decision.effect == Effect::Allow;
        allowed_now != (self.recorded == AuditOutcome::Allowed)
    }
}

impl Trail {
    pub fn parse(text: &str, origin: &str) -> Result<Self, LoadError> {
        let mut records = Vec::new();
        for (i, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let record = serde_json::from_str(line).map_err(|source| LoadError::Line {
                path: origin.to_string(),
                line: i + 1,
                source,
            })?;
            records.push(record);
        }
        Ok(Self { records })
    }

    pub fn load(path: &Path) -> Result<Self, LoadError> {
        Self::parse(&read(path)?, &path.display().to_string())
    }

    /// Confere a cadeia dos registros `forensic`, na ordem do arquivo.
    pub fn chain(&self) -> ChainStatus {
        let chained: Vec<AuditRecord> = self
            .records
            .iter()
            .filter(|r| r.level == AuditLevel::Forensic)
            .cloned()
            .collect();
        if chained.is_empty() {
            return ChainStatus::Absent;
        }
        match verify_chain(&chained) {
            Ok(()) => ChainStatus::Intact { records: chained.len() },
            Err(error) => ChainStatus::Broken(error),
        }
    }

    /// Reavalia uma decisão registrada. Precisa de `detailed` ou mais (sujeito e recurso
    /// completos); devolve `None` para outros registros.
    pub fn replay(record: &AuditRecord, inspector: &Inspector) -> Option<Replay> {
        if record.action != AuditAction::Decision {
            return None;
        }
        let subject = record
            .actor_detail
            .as_ref()
            .or(record.explanation.as_ref().map(|e| &e.subject))?;
        let resource = record
            .resource
            .as_ref()
            .or(record.explanation.as_ref().map(|e| &e.resource))?;
        let permission = record
            .decision
            .as_ref()
            .map(|d| d.permission.as_str())
            .or(record.explanation.as_ref().map(|e| e.permission.as_str()))?;
        Some(Replay {
            recorded: record.outcome,
            now: inspector.explain(subject, permission, resource),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::inspector::tests::inspector;
    use themis::{Attributes, Auditor, Context, JsonLinesAudit, Request};

    fn audit_file(level: AuditLevel) -> String {
        let inspector = inspector();
        let sink = Arc::new(JsonLinesAudit::new(Vec::new()));
        let auditor = Auditor::new(level, sink.clone()).with_clock(|| 1);
        let grants = inspector.active_grants();
        let ctx = Context::new(&grants);
        for (subject, permission, resource) in [("beto", "document.view", "secret"), ("ana", "project.edit", "roadmap")]
        {
            let request = Request::new(
                inspector.subject(subject).unwrap(),
                permission,
                inspector.resource(resource).unwrap(),
            );
            let (_, record) = auditor.decide(inspector.engine(), &ctx, &request, &Attributes::new());
            record.unwrap();
        }
        drop(auditor);
        let sink = Arc::try_unwrap(sink).ok().unwrap();
        String::from_utf8(sink.into_inner()).unwrap()
    }

    #[test]
    fn forensic_trail_keeps_explanations_and_chain() {
        let trail = Trail::parse(&audit_file(AuditLevel::Forensic), "t").unwrap();
        assert_eq!(trail.records.len(), 2);
        assert_eq!(trail.chain(), ChainStatus::Intact { records: 2 });
        assert!(trail.records[0].explanation.is_some());

        let mut tampered = trail.clone();
        tampered.records[0].outcome = AuditOutcome::Allowed;
        assert!(matches!(tampered.chain(), ChainStatus::Broken(_)));
    }

    #[test]
    fn replay_detects_policy_change() {
        let trail = Trail::parse(&audit_file(AuditLevel::Detailed), "t").unwrap();
        assert_eq!(trail.chain(), ChainStatus::Absent);
        let mut inspector = inspector();
        let replay = Trail::replay(&trail.records[0], &inspector).unwrap();
        assert!(!replay.changed());

        inspector.toggle("no-secret");
        let replay = Trail::replay(&trail.records[0], &inspector).unwrap();
        assert!(replay.changed(), "sem o deny, beto passa a ver o documento");
    }

    #[test]
    fn minimal_records_cannot_be_replayed() {
        let trail = Trail::parse(&audit_file(AuditLevel::Minimal), "t").unwrap();
        assert!(Trail::replay(&trail.records[0], &inspector()).is_none());
    }
}
