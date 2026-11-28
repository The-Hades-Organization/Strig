//! The audit format is frozen: a trail written at each level is committed under `tests/frozen/`, and
//! the writer must reproduce it byte for byte while the reader must verify it and write it back unchanged.
//! Regenerate on purpose with `STRIG_UPDATE_FROZEN=1 cargo test -p strig --test frozen_audit`; a diff
//! in the files is a breaking change of the audit format (see `docs/versioning.md`).

mod support;

use std::path::PathBuf;
use std::sync::Arc;

use strig::audit::{Auditor, MemoryAuditLog};
use strig::{
    AUDIT_FORMAT, Attributes, AuditLevel, AuditOutcome, AuditRecord, CatalogConformance, Context, Governance,
    Mutation, NoSelfManagement, ObjectRef, Request, RoleAssignment, Subject, Tuple, verify_chain,
};
use support::*;

const LEVELS: [(AuditLevel, &str); 4] = [
    (AuditLevel::Minimal, "minimal"),
    (AuditLevel::Standard, "standard"),
    (AuditLevel::Detailed, "detailed"),
    (AuditLevel::Forensic, "forensic"),
];

fn admin() -> Subject {
    Subject::user("admin").with_role_in("admin", org())
}

fn trail(level: AuditLevel) -> Vec<AuditRecord> {
    let engine = engine();
    let log = Arc::new(MemoryAuditLog::new());
    let auditor = Arc::new(
        Auditor::new(level, log.clone())
            .with_clock(|| 1_700_000_000_000)
            .resume_chain("0".repeat(64)),
    );
    let gov = Governance::new()
        .with(CatalogConformance)
        .with(NoSelfManagement)
        .audited(auditor.clone());
    let grants = vec![
        role_grant("admin-manage", "admin", "org.manage", true, at_org()),
        role_grant("member-view", "member", "project.view", true, at_org()),
    ];
    let mut meta = Attributes::new();
    meta.insert("ip".into(), "203.0.113.42".into());
    meta.insert("reason".into(), "ticket \"SUP-1\" é".into());
    let add = Mutation::Add(role_grant("m-edit", "member", "project.edit", true, at_org()));
    gov.apply_with(&engine, &admin(), &grants, &add, None, &meta).unwrap();
    let member = RoleAssignment::in_scope("member", org());
    let holder = Subject::user("u1").with_role_in("viewer", org());
    let assign = Mutation::AssignRole {
        subject: holder,
        role: member.clone(),
    };
    gov.apply_with(&engine, &admin(), &grants, &assign, None, &meta)
        .unwrap();
    let selfish = Mutation::AssignRole {
        subject: admin(),
        role: member,
    };
    gov.apply_with(&engine, &admin(), &grants, &selfish, None, &meta)
        .unwrap_err();
    let tuple = Tuple::new(ObjectRef::new("doc", "d1"), "viewer", ObjectRef::new("user", "bob"));
    auditor
        .tuple_change(&admin(), true, &tuple, AuditOutcome::Applied, &meta)
        .unwrap();
    auditor
        .tuple_change(&admin(), false, &tuple, AuditOutcome::Applied, &meta)
        .unwrap();
    let subject = Subject::user("u1").with_role_in("member", org());
    let project = project();
    let ctx = Context::new(&grants);
    for key in ["project.view", "project.delete"] {
        auditor.decide(&engine, &ctx, &Request::new(&subject, key, &project), &meta).1.unwrap();
    }
    log.records()
}

fn lines(records: &[AuditRecord]) -> String {
    records
        .iter()
        .map(|r| serde_json::to_string(r).unwrap() + "\n")
        .collect()
}

fn path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/frozen")
        .join(format!("audit-{name}.jsonl"))
}

#[test]
fn the_format_version_is_the_one_the_documents_name() {
    assert_eq!(AUDIT_FORMAT, 1);
}

#[test]
fn the_writer_reproduces_the_committed_trail_of_every_level() {
    for (level, name) in LEVELS {
        let written = lines(&trail(level));
        let file = path(name);
        if std::env::var_os("STRIG_UPDATE_FROZEN").is_some() {
            std::fs::write(&file, &written).unwrap();
        }
        let frozen = std::fs::read_to_string(&file)
            .unwrap_or_else(|e| panic!("{}: {e}; run with STRIG_UPDATE_FROZEN=1 to create it", file.display()));
        assert_eq!(
            written, frozen,
            "the audit format of level {name} changed: this is a breaking change; update on purpose with STRIG_UPDATE_FROZEN=1"
        );
    }
}

#[test]
fn the_reader_verifies_and_rewrites_the_committed_trail_unchanged() {
    for (_, name) in LEVELS {
        let frozen = std::fs::read_to_string(path(name)).unwrap();
        let records: Vec<AuditRecord> = frozen.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert!(records.len() >= 6, "{name}");
        if name == "forensic" {
            assert_eq!(verify_chain(&records), Ok(()), "{name}");
        }
        assert_eq!(lines(&records), frozen, "{name}: read then written is not identical");
    }
}
