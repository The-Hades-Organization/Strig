//! The conformance report and the Merkle proofs over a trail written by a real `Governance`.

mod support;

use std::sync::Arc;

use strig::audit::{Auditor, MemoryAuditLog};
use strig::audit_report::{Anchors, BreakKind, ConformanceReport, TimestampCheck};
use strig::merkle::{self, MerkleTree};
use strig::{
    Attributes, AuditLevel, AuditRecord, CatalogConformance, Governance, Mutation, NoSelfManagement, RoleAssignment,
    Subject,
};
use support::*;

fn in_org(role: &str) -> RoleAssignment {
    RoleAssignment::in_scope(role, org())
}

fn assign(subject: Subject, role: RoleAssignment) -> Mutation {
    Mutation::AssignRole { subject, role }
}

fn admin() -> Subject {
    Subject::user("admin").with_role_in("admin", org())
}

fn trail() -> Vec<AuditRecord> {
    let engine = engine();
    let log = Arc::new(MemoryAuditLog::new());
    let gov = Governance::new()
        .with(CatalogConformance)
        .with(NoSelfManagement)
        .audited(Arc::new(
            Auditor::new(AuditLevel::Forensic, log.clone()).with_clock(|| 1_700_000_000_000),
        ));
    let grants = vec![
        role_grant("admin-manage", "admin", "org.manage", true, at_org()),
        role_grant("member-view", "member", "project.view", true, at_org()),
    ];
    let meta = Attributes::new();
    let add = Mutation::Add(role_grant("m-edit", "member", "project.edit", true, at_org()));
    gov.apply_with(&engine, &admin(), &grants, &add, None, &meta).unwrap();
    let holder = Subject::user("u1").with_role_in("viewer", org());
    gov.apply_with(
        &engine,
        &admin(),
        &grants,
        &assign(holder, in_org("member")),
        None,
        &meta,
    )
    .unwrap();
    gov.apply_with(
        &engine,
        &admin(),
        &grants,
        &assign(admin(), in_org("member")),
        None,
        &meta,
    )
    .unwrap_err();
    log.records()
}

fn lines(records: &[AuditRecord]) -> String {
    records
        .iter()
        .map(|r| serde_json::to_string(r).unwrap() + "\n")
        .collect()
}

#[test]
fn summarizes_a_real_trail() {
    let records = trail();
    let report = ConformanceReport::from_json_lines(&lines(&records), &Anchors::default());
    assert_eq!(report.records, 3);
    assert!(report.is_conforming());
    assert_eq!(report.chain.head, records.last().unwrap().hash);
    assert_eq!(report.by_action["grant_add"]["applied"], 1);
    assert_eq!(report.by_action["role_assign"]["applied"], 1);
    assert_eq!(report.by_action["role_assign"]["rejected"], 1);
    assert_eq!(report.changes_by_actor["admin"], 2);
    assert_eq!(report.refusals_by_invariant["no_self_management"], 1);
    let period = report.period.as_ref().unwrap();
    assert_eq!((period.from_ms, period.to_ms), (1_700_000_000_000, 1_700_000_000_000));
    assert_eq!(period.from, "2023-11-14T22:13:20.000Z");
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["chain"]["ok"], true);
    assert_eq!(json["by_action"]["grant_add"]["applied"], 1);
}

#[test]
fn an_edited_record_is_one_tampered_break() {
    let mut records = trail();
    records[1].actor = "mallory".into();
    let report = ConformanceReport::build(&records, &Anchors::default());
    assert!(!report.is_conforming());
    assert_eq!(report.chain.breaks.len(), 1);
    assert_eq!(
        (report.chain.breaks[0].index, report.chain.breaks[0].kind),
        (1, BreakKind::Tampered)
    );
}

#[test]
fn a_removed_record_is_a_broken_link() {
    let mut records = trail();
    records.remove(1);
    let report = ConformanceReport::build(&records, &Anchors::default());
    assert_eq!(report.chain.breaks.len(), 1);
    assert_eq!(
        (report.chain.breaks[0].index, report.chain.breaks[0].kind),
        (1, BreakKind::Broken)
    );
}

#[test]
fn a_trail_without_hashes_is_unchained() {
    let mut records = trail();
    for record in &mut records {
        record.hash = None;
        record.prev_hash = None;
    }
    let report = ConformanceReport::build(&records, &Anchors::default());
    assert!(report.chain.breaks.iter().all(|b| b.kind == BreakKind::Unchained));
    assert_eq!(report.chain.breaks.len(), 3);
    assert!(!report.chain.ok);
}

#[test]
fn anchors_catch_a_cut_tail_and_a_foreign_start() {
    let records = trail();
    let head = records.last().unwrap().hash.clone().unwrap();
    let start = records[0].hash.clone().unwrap();
    let whole = ConformanceReport::build(&records, &Anchors::default().head(head.clone()));
    assert!(whole.is_conforming());
    let cut = ConformanceReport::build(&records[..2], &Anchors::default().head(head.clone()));
    assert!(!cut.is_conforming());
    assert!(cut.chain.ok, "the cut chain still verifies inside");
    assert!(!cut.anchors[0].ok);
    let segment = ConformanceReport::build(&records[1..], &Anchors::default().head(head).start(start));
    assert!(segment.is_conforming());
    let foreign = ConformanceReport::build(&records[1..], &Anchors::default().start("aa"));
    assert!(!foreign.is_conforming());
}

#[test]
fn unreadable_lines_are_reported_with_their_number() {
    let text = format!("{}not json\n\n", lines(&trail()));
    let report = ConformanceReport::from_json_lines(&text, &Anchors::default());
    assert_eq!(report.records, 3);
    assert_eq!(report.unreadable_lines.len(), 1);
    assert_eq!(report.unreadable_lines[0].line, 4);
    assert!(!report.is_conforming());
}

#[test]
fn a_failed_timestamp_makes_the_report_nonconforming() {
    let records = trail();
    let ok = TimestampCheck::verified("a.tsr", 1_795_868_280, "1.2.3".into(), "01".into());
    let report = ConformanceReport::build(&records, &Anchors::default()).with_timestamps(vec![ok.clone()]);
    assert!(report.is_conforming());
    let bad = TimestampCheck::failed("b.tsr", "IMPRINT_MISMATCH");
    let report = ConformanceReport::build(&records, &Anchors::default()).with_timestamps(vec![ok, bad]);
    assert!(!report.is_conforming());
}

#[test]
fn merkle_proofs_over_the_trail_hand_one_record_to_an_auditor() {
    let records = trail();
    let tree = MerkleTree::from_records(&records).unwrap();
    let root = tree.root();
    for (index, record) in records.iter().enumerate() {
        let proof = tree.inclusion_proof(index).unwrap();
        let leaf = merkle::record_leaf(record).unwrap();
        assert_eq!(merkle::verify_inclusion(&leaf, index as u64, 3, &proof, &root), Ok(()));
    }
    let mut edited = records[1].clone();
    edited.actor = "mallory".into();
    let proof = tree.inclusion_proof(1).unwrap();
    assert!(merkle::verify_inclusion(&merkle::record_leaf(&edited).unwrap(), 1, 3, &proof, &root).is_err());

    let earlier = tree.root_at(2).unwrap();
    let consistency = tree.consistency_proof(2).unwrap();
    assert_eq!(merkle::verify_consistency(2, 3, &earlier, &root, &consistency), Ok(()));
}
