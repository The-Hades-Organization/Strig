//! Listing and reverse queries against checking row by row.
//!
//! `cargo bench -p themis-auth --bench listing` prints, for growing tables, grant sets and tuple
//! sets, under two strategies, the time to plan the filter, to resolve it over the resources in
//! memory, to run `Engine::check` on each of them, and to answer `who_can_on` and `access_of`.
//! The last ratio compares the per-row `check` loop with plan plus resolve: both decide row by
//! row in memory, so it shows the cost of the shared work done once, not a table read.
//!
//! A second table gives the cost of one `Engine::check` for a single grant guarded by each kind of
//! condition, to show what the text, set, network and time conditions add over `eq`.

use std::hint::black_box;
use std::time::{Duration, Instant};

use themis::{
    Anchor, Catalog, Condition, Engine, FirstApplicable, Grant, InMemoryTuples, ObjectRef, Operand, PathLayout,
    PermissionDef, QueryContext, RelationSchema, Request, Resource, ResourceOwner, Rewrite, Subject, SubjectMatcher,
    TargetSelector, Tuple,
};

const SIZES: [usize; 3] = [1_000, 10_000, 100_000];
const GRANT_COUNTS: [usize; 2] = [1_000, 10_000];
const TUPLE_COUNTS: [usize; 2] = [25, 2_000];
const PROJECTS: usize = 50;
const REVERSE_ROWS: usize = 10_000;
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

fn grants(extra: usize) -> Vec<Grant> {
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
    // Grants that never reach the benchmarked permission or kind: the cost of a bigger table.
    for n in 0..extra {
        grants.push(Grant::allow(
            format!("noise-{n}"),
            SubjectMatcher::role("member"),
            "document.view",
            TargetSelector::exact("project", format!("q{n}")),
        ));
    }
    grants
}

fn tuples(count: usize) -> InMemoryTuples {
    (0..count)
        .map(|n| {
            let project = if n < PROJECTS / 2 { n * 2 } else { PROJECTS + n };
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

fn engine(first_applicable: bool) -> Engine {
    let schema = RelationSchema::new().relation("project", "editor", Rewrite::This);
    let builder = Engine::builder(catalog())
        .override_with(ResourceOwner::new("owner"))
        .relations(schema);
    let builder = if first_applicable {
        builder.strategy(FirstApplicable)
    } else {
        builder
    };
    builder.build().expect("engine")
}

const CONDITION_ROWS: usize = 100_000;

/// Median time of `check` per decision with one allow guarded by `condition`.
fn condition_cost(condition: Condition, docs: &[Resource], subject: &Subject) -> Duration {
    let engine = Engine::builder(catalog()).build().expect("engine");
    let grants = vec![
        Grant::allow(
            "g",
            SubjectMatcher::role("member"),
            "document.edit",
            TargetSelector::exact("org", "o1"),
        )
        .scoped(Anchor::new("org", "o1"))
        .when(condition),
    ];
    // 2024-01-01 12:00 UTC, a Monday.
    let ctx = themis::Context::new(&grants).at(1_704_110_400_000);
    let total = time(|| {
        docs.iter()
            .filter(|doc| engine.check(&ctx, &Request::new(subject, "document.edit", doc)))
            .count()
    });
    total / u32::try_from(docs.len()).expect("row count fits")
}

fn condition_table(subject: &Subject) {
    let docs: Vec<Resource> = resources(CONDITION_ROWS)
        .into_iter()
        .map(|doc| {
            doc.with_attr("name", "invoice-2024-v2.md")
                .with_attr("tags", vec!["docs", "ops"])
                .with_attr("ip", "10.20.30.40")
        })
        .collect();
    let lit = |text: &str| Operand::lit(text);
    let cases = [
        (
            "eq",
            Condition::eq(Operand::attr("resource.name"), lit("invoice-2024-v2.md")),
        ),
        (
            "starts_with",
            Condition::starts_with(Operand::attr("resource.name"), lit("invoice")),
        ),
        (
            "ends_with",
            Condition::ends_with(Operand::attr("resource.name"), lit(".md")),
        ),
        (
            "contains",
            Condition::contains(Operand::attr("resource.name"), lit("-v2")),
        ),
        (
            "any_in",
            Condition::any_in(Operand::attr("resource.tags"), Operand::lit(vec!["ops", "dev"])),
        ),
        (
            "all_in",
            Condition::all_in(Operand::attr("resource.tags"), Operand::lit(vec!["docs", "ops", "dev"])),
        ),
        (
            "ip_in",
            Condition::ip_in(Operand::attr("resource.ip"), lit("10.0.0.0/8")),
        ),
        (
            "ip_in (4 cidrs)",
            Condition::ip_in(
                Operand::attr("resource.ip"),
                Operand::lit(vec!["192.168.0.0/16", "172.16.0.0/12", "2001:db8::/32", "10.0.0.0/8"]),
            ),
        ),
        ("time_between", Condition::time_between("09:00", "17:30")),
        ("weekday_in", Condition::weekday_in(["mon", "tue", "wed", "thu", "fri"])),
    ];
    println!("\n{:>16} {:>12}", "condition", "check/decision");
    for (name, condition) in cases {
        let cost = condition_cost(condition, &docs, subject);
        println!("{name:>16} {cost:>12.2?}");
    }
}

fn main() {
    let subject = Subject::user("u1").with_role_in("member", Anchor::new("org", "o1"));
    let layout = PathLayout::new("document").within("project").within("org");

    println!(
        "{:>8} {:>7} {:>6} {:>9} {:>10} {:>10} {:>12} {:>10} {:>10} {:>8}",
        "rows", "grants", "tuples", "strategy", "plan", "resolve", "check/row", "who_can_on", "access_of", "ratio"
    );
    for (strategy, first_applicable) in [("default", false), ("first", true)] {
        let engine = engine(first_applicable);
        for grant_count in GRANT_COUNTS {
            for tuple_count in TUPLE_COUNTS {
                let (grants, store) = (grants(grant_count), tuples(tuple_count));
                let qctx = QueryContext::new(&grants).with_tuples(&store);
                let ctx = qctx.context();
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
                    let (who, access) = if size == REVERSE_ROWS {
                        let doc = &docs[0];
                        (
                            time(|| engine.who_can_on(&qctx, "document.edit", doc).unwrap().entries.len()),
                            time(|| engine.access_of(&qctx, doc).unwrap().len()),
                        )
                    } else {
                        (Duration::ZERO, Duration::ZERO)
                    };
                    let ratio = per_row.as_secs_f64() / (plan + resolve).as_secs_f64();
                    println!(
                        "{size:>8} {grant_count:>7} {tuple_count:>6} {strategy:>9} {plan:>10.2?} {resolve:>10.2?} {per_row:>12.2?} {who:>10.2?} {access:>10.2?} {ratio:>7.1}x   ({listed} allowed, exact={})",
                        filter.is_exact(&layout)
                    );
                }
            }
        }
    }
    condition_table(&subject);
}
