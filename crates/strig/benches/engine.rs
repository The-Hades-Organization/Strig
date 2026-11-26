//! Reproducible criterion suite: `cargo bench -p strig --bench engine`.
//!
//! Covers a plain decision, a decision with conditions and relations, listing with a filter,
//! and governed changes with and without the audit trail. Numbers and method: `docs/benchmarks.md`.

use std::hint::black_box;
use std::io;
use std::sync::Arc;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use strig::{
    Anchor, Attributes, AuditLevel, Auditor, Catalog, CatalogConformance, Condition, Context, Engine, Governance,
    Grant, InMemoryTuples, JsonLinesAudit, Mutation, NoSelfManagement, ObjectRef, Operand, PermissionDef, QueryContext,
    RelationSchema, Request, Resource, Rewrite, Subject, SubjectMatcher, TargetSelector, Tuple,
};

const ROWS: usize = 10_000;
const PROJECTS: usize = 50;
const NOISE_GRANTS: usize = 1_000;
// 2024-01-01 12:00 UTC, a Monday.
const NOW: u64 = 1_704_110_400_000;

fn catalog() -> Catalog {
    Catalog::builder()
        .target_kinds(["document", "project"])
        .broad_target("org")
        .permission(PermissionDef::new("document.view").targets(["project", "document"]))
        .permission(PermissionDef::new("document.edit").targets(["project", "document"]))
        .build()
        .expect("catalog")
}

fn org() -> Anchor {
    Anchor::new("org", "o1")
}

fn member() -> Subject {
    Subject::user("u1").with_role_in("member", org())
}

fn document(n: usize) -> Resource {
    let mut doc = Resource::new("document", format!("d{n}"))
        .within("project", format!("p{}", n % PROJECTS))
        .within("org", "o1");
    if n % 3 < 1 {
        doc = doc.with_attr("status", "draft");
    }
    doc
}

fn simple_grants() -> Vec<Grant> {
    vec![
        Grant::allow(
            "view",
            SubjectMatcher::role("member"),
            "document.view",
            TargetSelector::exact("org", "o1"),
        )
        .scoped(org()),
    ]
}

fn rich_grants() -> Vec<Grant> {
    let mut grants = simple_grants();
    grants.push(
        Grant::allow(
            "edit-drafts",
            SubjectMatcher::role("member"),
            "document.edit",
            TargetSelector::exact("org", "o1"),
        )
        .scoped(org())
        .when(Condition::all([
            Condition::eq(Operand::attr("resource.status"), Operand::lit("draft")),
            Condition::time_between("09:00", "18:00"),
        ])),
    );
    grants.push(Grant::allow(
        "editors",
        SubjectMatcher::relation("editor"),
        "document.edit",
        TargetSelector::kind("project"),
    ));
    for project in (0..PROJECTS).step_by(5) {
        grants.push(Grant::deny(
            format!("lock-{project}"),
            SubjectMatcher::role("member"),
            "document.view",
            TargetSelector::exact("project", format!("p{project}")),
        ));
    }
    for n in 0..NOISE_GRANTS {
        grants.push(Grant::allow(
            format!("noise-{n}"),
            SubjectMatcher::role("member"),
            "document.view",
            TargetSelector::exact("project", format!("q{n}")),
        ));
    }
    grants
}

fn tuples() -> InMemoryTuples {
    (0..PROJECTS)
        .map(|n| {
            Tuple::new(
                ObjectRef::new("project", format!("p{n}")),
                "editor",
                ObjectRef::new("user", "u1"),
            )
        })
        .collect()
}

fn plain_engine() -> Engine {
    Engine::builder(catalog()).build().expect("engine")
}

fn relation_engine() -> Engine {
    Engine::builder(catalog())
        .relations(RelationSchema::new().relation("project", "editor", Rewrite::This))
        .build()
        .expect("engine")
}

fn decide(c: &mut Criterion) {
    let (engine, grants, subject, doc) = (plain_engine(), simple_grants(), member(), document(1));
    let ctx = Context::new(&grants);
    c.bench_function("decide/simple", |b| {
        b.iter(|| engine.decide(&ctx, black_box(&Request::new(&subject, "document.view", &doc))))
    });

    let (engine, grants, store) = (relation_engine(), rich_grants(), tuples());
    let qctx = QueryContext::new(&grants).with_tuples(&store).at(NOW);
    let ctx = qctx.context();
    let draft = document(3);
    c.bench_function("decide/conditions_and_relations", |b| {
        b.iter(|| engine.decide(&ctx, black_box(&Request::new(&subject, "document.edit", &draft))))
    });
}

fn list(c: &mut Criterion) {
    let (engine, grants, store, subject) = (relation_engine(), rich_grants(), tuples(), member());
    let qctx = QueryContext::new(&grants).with_tuples(&store).at(NOW);
    let ctx = qctx.context();
    let docs: Vec<Resource> = (0..ROWS).map(document).collect();
    c.bench_function("list/plan", |b| {
        b.iter(|| engine.list(&qctx, &subject, "document.edit", "document"))
    });
    let filter = engine.list(&qctx, &subject, "document.edit", "document");
    c.bench_function("list/resolve_10k_rows", |b| {
        b.iter(|| filter.resolve_with(&engine, &ctx, black_box(&docs)).len())
    });
}

fn governance(auditor: Option<Arc<Auditor>>) -> Governance {
    let governance = Governance::new().with(CatalogConformance).with(NoSelfManagement);
    match auditor {
        Some(auditor) => governance.audited(auditor),
        None => governance,
    }
}

fn apply(c: &mut Criterion) {
    let (engine, actor) = (plain_engine(), Subject::user("root"));
    let current = simple_grants();
    let meta = Attributes::new();
    let change = |n: u64| {
        Mutation::Add(Grant::allow(
            format!("new-{n}"),
            SubjectMatcher::Any,
            "document.edit",
            TargetSelector::kind("document"),
        ))
    };

    let plain = governance(None);
    c.bench_function("apply/governance", |b| {
        b.iter_batched(
            || change(1),
            |mutation| plain.apply_with(&engine, &actor, &current, &mutation, None, &meta),
            BatchSize::SmallInput,
        )
    });

    let auditor = Arc::new(Auditor::new(
        AuditLevel::Standard,
        Arc::new(JsonLinesAudit::new(io::sink())),
    ));
    let audited = governance(Some(auditor));
    c.bench_function("apply/governance_with_audit", |b| {
        b.iter_batched(
            || change(1),
            |mutation| audited.apply_with(&engine, &actor, &current, &mutation, None, &meta),
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, decide, list, apply);
criterion_main!(benches);
