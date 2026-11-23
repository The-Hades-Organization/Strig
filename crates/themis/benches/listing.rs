//! Listing against checking row by row.
//!
//! `cargo bench -p themis-auth --bench listing` prints, for growing tables, the time to plan the
//! filter, to resolve it over the resources in memory, and to run `Engine::check` on each of them.

use std::hint::black_box;
use std::time::{Duration, Instant};

use themis::{
    Anchor, Catalog, Condition, Engine, Grant, InMemoryTuples, ObjectRef, Operand, PathLayout, PermissionDef,
    QueryContext, RelationSchema, Request, Resource, ResourceOwner, Rewrite, Subject, SubjectMatcher, TargetSelector,
    Tuple,
};

const SIZES: [usize; 3] = [1_000, 10_000, 100_000];
const PROJECTS: usize = 50;
const RUNS: u32 = 5;

fn catalog() -> Catalog {
    Catalog::builder()
        .target_kinds(["document", "project"])
        .broad_target("org")
        .permission(PermissionDef::new("document.view").targets(["project", "document"]))
        .permission(PermissionDef::new("document.edit").targets(["project", "document"]))
        .build()
        .expect("catalog")
}

fn resources(count: usize) -> Vec<Resource> {
    (0..count)
        .map(|n| {
            let mut doc = Resource::new("document", format!("d{n}"))
                .within("project", format!("p{}", n % PROJECTS))
                .within("org", "o1");
            if n % 7 == 0 {
                doc = doc.with_attr("owner", "u1");
            }
            if n % 3 == 0 {
                doc = doc.with_attr("status", "draft");
            }
            doc
        })
        .collect()
}

fn grants() -> Vec<Grant> {
    let org = Anchor::new("org", "o1");
    let mut grants = vec![
        Grant::allow(
            "view",
            SubjectMatcher::role("member"),
            "document.view",
            TargetSelector::exact("org", "o1"),
        )
        .scoped(org.clone()),
        Grant::allow(
            "edit-drafts",
            SubjectMatcher::role("member"),
            "document.edit",
            TargetSelector::exact("org", "o1"),
        )
        .scoped(org)
        .when(Condition::eq(Operand::attr("resource.status"), Operand::lit("draft"))),
        Grant::allow(
            "editors",
            SubjectMatcher::relation("editor"),
            "document.edit",
            TargetSelector::kind("project"),
        ),
    ];
    for project in (0..PROJECTS).step_by(5) {
        grants.push(Grant::deny(
            format!("lock-{project}"),
            SubjectMatcher::role("member"),
            "document.view",
            TargetSelector::exact("project", format!("p{project}")),
        ));
    }
    grants
}

fn tuples() -> InMemoryTuples {
    (0..PROJECTS)
        .step_by(2)
        .map(|project| {
            Tuple::new(
                ObjectRef::new("project", format!("p{project}")),
                "editor",
                ObjectRef::new("user", "u1"),
            )
        })
        .collect()
}

fn median(mut samples: Vec<Duration>) -> Duration {
    samples.sort();
    samples[samples.len() / 2]
}

fn time<T>(mut run: impl FnMut() -> T) -> Duration {
    median(
        (0..RUNS)
            .map(|_| {
                let start = Instant::now();
                black_box(run());
                start.elapsed()
            })
            .collect(),
    )
}

fn main() {
    let schema = RelationSchema::new().relation("project", "editor", Rewrite::This);
    let engine = Engine::builder(catalog())
        .override_with(ResourceOwner::new("owner"))
        .relations(schema)
        .build()
        .expect("engine");
    let (grants, store) = (grants(), tuples());
    let qctx = QueryContext::new(&grants).with_tuples(&store);
    let ctx = qctx.context();
    let subject = Subject::user("u1").with_role_in("member", Anchor::new("org", "o1"));
    let layout = PathLayout::new("document").within("project").within("org");

    println!(
        "{:>8} {:>12} {:>14} {:>16} {:>10}",
        "rows", "plan", "resolve", "check per row", "speedup"
    );
    for size in SIZES {
        let docs = resources(size);
        let plan = time(|| engine.list(&qctx, &subject, "document.edit", "document"));
        let filter = engine.list(&qctx, &subject, "document.edit", "document");
        let resolve = time(|| filter.resolve_with(&engine, &ctx, &docs).len());
        let per_row = time(|| {
            docs.iter()
                .filter(|doc| engine.check(&ctx, &Request::new(&subject, "document.edit", doc)))
                .count()
        });
        let listed = filter.resolve_with(&engine, &ctx, &docs).len();
        let checked = docs
            .iter()
            .filter(|doc| engine.check(&ctx, &Request::new(&subject, "document.edit", doc)))
            .count();
        assert_eq!(listed, checked, "the listing and the row-by-row check disagree");
        let speedup = per_row.as_secs_f64() / (plan + resolve).as_secs_f64();
        println!(
            "{size:>8} {plan:>12.2?} {resolve:>14.2?} {per_row:>16.2?} {speedup:>9.1}x   ({listed} allowed, exact={})",
            filter.is_exact(&layout)
        );
    }
}
