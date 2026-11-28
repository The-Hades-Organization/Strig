//! Spans and metrics of the engine: what is emitted, and that nothing identifying leaves with it.

mod support;

use std::collections::BTreeMap;
use std::io;
use std::sync::{Arc, Mutex};

use metrics_util::debugging::{DebugValue, DebuggingRecorder};
use strig::audit::{AuditLevel, Auditor, FailMode, MemoryAuditLog};
use strig::{
    ApprovalPolicy, Approvals, Attributes, CatalogConformance, Context, Engine, Governance, Grant, MemoryPendingStore,
    Mutation, MutationKind, NoSelfManagement, QueryContext, Request, RequirePermission, Review, Subject,
};
use support::*;

const SECRET_USER: &str = "u-secret-4417";
const SECRET_DOC: &str = "doc-secret-9921";
const SECRET_ATTR: &str = "attr-secret-5503";

type Samples = BTreeMap<String, Vec<(BTreeMap<String, String>, f64)>>;

#[derive(Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);

impl io::Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn admin() -> Subject {
    Subject::user("admin").with_role_in("admin", org())
}

fn base_grants() -> Vec<Grant> {
    vec![
        role_grant("admin-manage", "admin", "org.manage", true, at_org()),
        role_grant("member-view", "member", "project.view", true, at_org()),
    ]
}

fn governance(auditor: Arc<Auditor>) -> Governance {
    Governance::new()
        .with(CatalogConformance)
        .with(RequirePermission::new("org.roles.edit", project()))
        .with(NoSelfManagement)
        .audited(auditor)
}

fn run_scenario(engine: &Engine) {
    let grants = base_grants();
    let ctx = Context::new(&grants);
    let subject = Subject::user(SECRET_USER)
        .with_role_in("member", org())
        .with_attr("badge", SECRET_ATTR);
    let resource = document(SECRET_DOC, "invoice").with_attr("owner_note", SECRET_ATTR);

    for permission in ["document.view", "project.edit", "no.such.permission"] {
        engine.decide(&ctx, &Request::new(&subject, permission, &resource));
    }
    engine.check(&ctx, &Request::new(&subject, "document.view", &resource));
    engine.explain(&ctx, &Request::new(&subject, "document.view", &resource));

    let query = QueryContext::new(&grants);
    engine.list(&query, &subject, "document.view", "document");
    engine.who_can(&query, "project.view");

    let auditor =
        Arc::new(Auditor::new(AuditLevel::Forensic, Arc::new(MemoryAuditLog::new())).with_fail_mode(FailMode::Closed));
    let gov = governance(auditor);
    let ok = Mutation::Add(role_grant("m-edit", "member", "project.edit", true, at_org()));
    gov.apply(engine, &admin(), &grants, &ok, None).expect("valid change");
    let unknown = Mutation::Add(role_grant("x", "member", "project.nope", true, at_org()));
    gov.apply(engine, &admin(), &grants, &unknown, None).unwrap_err();
    let own = Mutation::Add(role_grant("self", "admin", "project.delete", false, at_org()));
    gov.apply(engine, &admin(), &grants, &own, None).unwrap_err();

    let policy = ApprovalPolicy::new().require(MutationKind::Add, "org.manage", project());
    let store = MemoryPendingStore::new();
    let plain = governance(Arc::new(Auditor::new(
        AuditLevel::Standard,
        Arc::new(MemoryAuditLog::new()),
    )));
    let flow = Approvals::new(&plain, &policy, &store);
    let meta = Attributes::new();
    let review = Review::new(engine, &grants, 1_000, &meta);
    flow.propose(&review, &admin(), &ok, "r1", None).expect("proposed");
    flow.approve(&review, &admin(), "r1").unwrap_err();
}

fn samples_of(snapshotter: &metrics_util::debugging::Snapshotter) -> Samples {
    let mut samples = Samples::new();
    for (composite, _, _, value) in snapshotter.snapshot().into_vec() {
        let key = composite.key();
        let labels = key
            .labels()
            .map(|label| (label.key().to_string(), label.value().to_string()))
            .collect();
        let number = match value {
            DebugValue::Counter(count) => count as f64,
            DebugValue::Gauge(gauge) => gauge.into_inner(),
            DebugValue::Histogram(values) => values.len() as f64,
        };
        samples
            .entry(key.name().to_string())
            .or_default()
            .push((labels, number));
    }
    samples
}

fn collect(engine: &Engine) -> (Samples, String) {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let buffer = Buffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer({
            let buffer = buffer.clone();
            move || buffer.clone()
        })
        .with_max_level(tracing::Level::TRACE)
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
        .finish();
    metrics::with_local_recorder(&recorder, || {
        tracing::subscriber::with_default(subscriber, || run_scenario(engine))
    });

    let samples = samples_of(&snapshotter);
    let output = String::from_utf8(buffer.0.lock().unwrap().clone()).expect("utf-8 output");
    (samples, output)
}

fn count(samples: &Samples, name: &str, wanted: &[(&str, &str)]) -> f64 {
    samples
        .get(name)
        .into_iter()
        .flatten()
        .filter(|(labels, _)| {
            wanted
                .iter()
                .all(|(k, v)| labels.get(*k).map(String::as_str) == Some(*v))
        })
        .map(|(_, value)| *value)
        .sum()
}

#[test]
fn decisions_are_counted_by_effect_and_reason() {
    let (samples, _) = collect(&engine());
    assert_eq!(
        count(
            &samples,
            "strig_decisions_total",
            &[("effect", "allow"), ("reason", "grant")]
        ),
        3.0
    );
    assert_eq!(
        count(
            &samples,
            "strig_decisions_total",
            &[("effect", "deny"), ("reason", "no_applicable_grant")]
        ),
        1.0
    );
    assert_eq!(
        count(
            &samples,
            "strig_decisions_total",
            &[("reason", "unknown_permission"), ("permission", "unknown")]
        ),
        1.0
    );
    assert_eq!(
        count(&samples, "strig_decisions_total", &[("operation", "explain")]),
        1.0
    );
}

#[test]
fn latency_is_recorded_per_operation() {
    let (samples, _) = collect(&engine());
    assert_eq!(
        count(&samples, "strig_decision_duration_seconds", &[("operation", "decide")]),
        4.0
    );
    assert_eq!(
        count(&samples, "strig_query_duration_seconds", &[("operation", "list")]),
        1.0
    );
    assert_eq!(
        count(&samples, "strig_query_duration_seconds", &[("operation", "who_can")]),
        1.0
    );
}

#[test]
fn mutations_and_invariants_are_counted() {
    let (samples, _) = collect(&engine());
    assert_eq!(count(&samples, "strig_mutations_total", &[("outcome", "applied")]), 1.0);
    assert_eq!(count(&samples, "strig_mutations_total", &[("outcome", "refused")]), 2.0);
    assert_eq!(
        count(
            &samples,
            "strig_mutation_violations_total",
            &[("invariant", "catalog_conformance")]
        ),
        1.0
    );
    assert!(
        count(
            &samples,
            "strig_mutation_violations_total",
            &[("invariant", "no_self_management")]
        ) >= 1.0
    );
}

#[test]
fn approvals_and_the_audit_trail_are_counted() {
    let (samples, _) = collect(&engine());
    assert_eq!(
        count(
            &samples,
            "strig_approvals_total",
            &[("step", "propose"), ("outcome", "ok")]
        ),
        1.0
    );
    assert_eq!(
        count(
            &samples,
            "strig_approvals_total",
            &[("step", "approve"), ("outcome", "refused")]
        ),
        1.0
    );
    assert!(count(&samples, "strig_audit_writes_total", &[("status", "written")]) >= 3.0);
}

#[test]
fn no_label_and_no_span_carries_identifying_data() {
    let (samples, output) = collect(&engine());
    let allowed_labels = [
        "operation",
        "effect",
        "reason",
        "permission",
        "invariant",
        "outcome",
        "step",
        "status",
    ];
    for (name, entries) in &samples {
        for (labels, _) in entries {
            for (key, value) in labels {
                assert!(allowed_labels.contains(&key.as_str()), "{name}: unexpected label {key}");
                for secret in [SECRET_USER, SECRET_DOC, SECRET_ATTR, "admin", "o1", "p1"] {
                    assert!(!value.contains(secret), "{name}: label {key}={value} carries {secret}");
                }
            }
        }
    }
    assert!(!output.is_empty(), "the scenario emits spans");
    for secret in [SECRET_USER, SECRET_DOC, SECRET_ATTR] {
        assert!(!output.contains(secret), "span output carries {secret}");
    }
}

#[test]
fn the_audit_retry_queue_reports_failures_and_drops() {
    use strig::audit::RetryPolicy;
    let sink = |_: &strig::audit::AuditRecord| Err(strig::audit::AuditError::Sink("down".into()));
    let auditor = Arc::new(
        Auditor::new(AuditLevel::Standard, Arc::new(sink))
            .with_fail_mode(FailMode::Open)
            .with_retry(RetryPolicy {
                capacity: 1,
                ..RetryPolicy::default()
            }),
    );
    let engine = engine();
    let grants = base_grants();
    let gov = governance(auditor);
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, || {
        for id in ["a", "b", "c"] {
            let add = Mutation::Add(role_grant(id, "member", "project.edit", true, at_org()));
            gov.apply(&engine, &admin(), &grants, &add, None)
                .expect("open mode lets it through");
        }
    });
    let samples = samples_of(&snapshotter);
    assert_eq!(
        count(&samples, "strig_audit_writes_total", &[("status", "pending")]),
        1.0
    );
    assert_eq!(
        count(&samples, "strig_audit_writes_total", &[("status", "dropped")]),
        2.0
    );
    assert_eq!(count(&samples, "strig_audit_dropped_total", &[]), 2.0);
    assert_eq!(count(&samples, "strig_audit_pending", &[]), 1.0);
    assert!(count(&samples, "strig_audit_write_failures_total", &[]) >= 1.0);
}
