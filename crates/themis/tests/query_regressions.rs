//! Regressions of the listing: each test pins a case where the filter once disagreed with
//! `Engine::check` or opened access.

mod support;

use support::*;
use themis::{
    Anchor, Candidate, DenyOverrides, Engine, Expr, FilterResidual, FirstApplicable, Grant, PathLayout, PermissionHolder,
    QueryContext, QueryError, QueryLimits, Request, Resource,
    Strategy, Subject, SubjectMatcher, TargetSelector,
};

fn layout() -> PathLayout {
    PathLayout::new("document")
        .within("doc_type")
        .within("project")
        .within("org")
}

/// Combines like a plain "first candidate wins", under the name of a strategy of the crate.
struct FirstWins;

impl Strategy for FirstWins {
    fn name(&self) -> &'static str {
        "deny_overrides"
    }

    fn combine(&self, candidates: &[Candidate]) -> Option<usize> {
        (!candidates.is_empty()).then_some(0)
    }
}

#[test]
fn a_strategy_that_borrows_a_native_name_stays_a_residue() {
    let grants = vec![Grant::allow(
        "view",
        SubjectMatcher::user("u1"),
        "document.view",
        TargetSelector::exact("org", ORG),
    )];
    let qctx = QueryContext::new(&grants);
    let engine = Engine::builder(catalog()).strategy(FirstWins).build().unwrap();
    let filter = engine.list(&qctx, &Subject::user("u1"), "document.view", "document");
    assert!(
        filter
            .residual()
            .iter()
            .any(|r| matches!(r, FilterResidual::Strategy { name } if name == "deny_overrides"))
    );
    assert!(!filter.is_exact(&layout()));
}

#[test]
fn a_strategy_of_the_crate_needs_no_residue() {
    let grants = vec![Grant::allow(
        "view",
        SubjectMatcher::user("u1"),
        "document.view",
        TargetSelector::exact("org", ORG),
    )];
    let qctx = QueryContext::new(&grants);
    let engine = Engine::builder(catalog()).strategy(DenyOverrides).build().unwrap();
    let filter = engine.list(&qctx, &Subject::user("u1"), "document.view", "document");
    assert!(filter.residual().is_empty());
    assert!(filter.is_exact(&layout()));
}

#[test]
fn a_grant_outside_the_layout_is_a_residue_never_an_allow() {
    // The layout leaves out `project`, where the deny sits.
    let layout = PathLayout::new("document").within("org");
    let grants = vec![
        role_grant("view", "member", "document.view", true, at_org()),
        role_grant(
            "no-p1",
            "member",
            "document.view",
            false,
            TargetSelector::exact("project", PROJECT),
        ),
    ];
    let qctx = QueryContext::new(&grants);
    let ctx = qctx.context();
    let engine = Engine::builder(catalog()).strategy(DenyOverrides).build().unwrap();
    let subject = Subject::user("u1").with_role_in("member", org());
    let doc = document("d1", "invoice");
    assert!(!engine.check(&ctx, &Request::new(&subject, "document.view", &doc)));

    let filter = engine.list(&qctx, &subject, "document.view", "document");
    assert!(!filter.is_exact(&layout));
    let residuals = filter.residual_for(&layout);
    assert!(matches!(
        residuals.last(),
        Some(FilterResidual::OutsideLayout { grant_ids }) if grant_ids == &["no-p1".to_string()]
    ));
    // Whatever the row says about the residue, the expression never settles it as an allow.
    let expr = filter.expr(&layout);
    let unknown = |i: usize| match residuals.get(i) {
        Some(FilterResidual::OutsideLayout { .. }) => None,
        _ => Some(false),
    };
    assert_ne!(expr.holds(&doc, &unknown), Some(true));
    assert_eq!(filter.resolve([&doc]).allowed, Vec::<String>::new());
}

#[test]
fn a_nested_override_condition_is_listed_as_a_residue_of_the_outer_filter() {
    let layout = layout();
    let grants = vec![
        Grant::allow(
            "manage-drafts",
            SubjectMatcher::user("u1"),
            "org.manage",
            TargetSelector::exact("org", ORG),
        )
        .when(themis::Condition::eq(
            themis::Operand::attr("resource.status"),
            themis::Operand::lit("draft"),
        )),
    ];
    let qctx = QueryContext::new(&grants);
    let ctx = qctx.context();
    let engine = Engine::builder(catalog())
        .override_with(PermissionHolder::new("org.manage"))
        .build()
        .unwrap();
    let subject = Subject::user("u1");
    let filter = engine.list(&qctx, &subject, "document.view", "document");
    assert!(
        filter
            .residual()
            .iter()
            .any(|r| matches!(r, FilterResidual::Condition { grant_id, .. } if grant_id == "manage-drafts"))
    );
    let residuals = filter.residual_for(&layout);
    let expr = filter.expr(&layout);
    for status in ["draft", "published"] {
        let doc = document("d1", "invoice").with_attr("status", status);
        let expected = engine.check(&ctx, &Request::new(&subject, "document.view", &doc));
        let by_row = |i: usize| match residuals.get(i)? {
            FilterResidual::Condition { condition, .. } => condition
                .evaluate(
                    &themis::EvalContext {
                        subject: &subject,
                        resource: &doc,
                        env: &themis::Attributes::new(),
                    },
                    &themis::ConditionRegistry::new(),
                )
                .ok(),
            _ => None,
        };
        assert_eq!(expr.holds(&doc, &by_row), Some(expected), "status {status}");
    }
}

fn node_count(expr: &Expr) -> usize {
    match expr {
        Expr::Not(inner) => 1 + node_count(inner),
        Expr::And(items) | Expr::Or(items) => 1 + items.iter().map(node_count).sum::<usize>(),
        _ => 1,
    }
}

/// `n` grants to `u1` on distinct projects, alternating allow and deny.
fn alternating(n: usize) -> Vec<Grant> {
    (0..n)
        .map(|i| {
            let target = TargetSelector::exact("project", format!("p{i}"));
            if i % 2 == 0 {
                Grant::allow(format!("g{i}"), SubjectMatcher::user("u1"), "document.view", target)
            } else {
                Grant::deny(format!("g{i}"), SubjectMatcher::user("u1"), "document.view", target)
            }
        })
        .collect()
}

fn first_applicable_engine() -> Engine {
    Engine::builder(catalog()).strategy(FirstApplicable).build().unwrap()
}

#[test]
fn first_applicable_expression_grows_with_the_grants_not_with_their_square() {
    let layout = layout();
    let engine = first_applicable_engine();
    let subject = Subject::user("u1");
    let size = |n: usize| {
        let grants = alternating(n);
        let qctx = QueryContext::new(&grants);
        let filter = engine.list(&qctx, &subject, "document.view", "document");
        assert!(filter.is_exact(&layout), "{n} grants stay structural");
        node_count(&filter.expr(&layout))
    };
    let (small, large) = (size(100), size(200));
    assert!(large < small * 3, "{small} nodes for 100 grants, {large} for 200");
}

#[test]
fn first_applicable_with_too_many_alternations_falls_back_to_the_row() {
    let layout = layout();
    let engine = first_applicable_engine();
    let grants = alternating(600);
    let qctx = QueryContext::new(&grants);
    let ctx = qctx.context();
    let subject = Subject::user("u1");
    let filter = engine.list(&qctx, &subject, "document.view", "document");
    assert!(
        filter
            .residual()
            .iter()
            .any(|r| matches!(r, FilterResidual::Strategy { .. }))
    );
    assert!(!filter.is_exact(&layout));
    let docs: Vec<Resource> = (0..8)
        .map(|i| {
            Resource::new("document", format!("d{i}"))
                .within("doc_type", "invoice")
                .within("project", format!("p{i}"))
                .within("org", ORG)
        })
        .collect();
    let settled = filter.resolve_with(&engine, &ctx, &docs);
    let expected: Vec<String> = docs
        .iter()
        .filter(|d| engine.check(&ctx, &Request::new(&subject, "document.view", d)))
        .filter_map(|d| d.primary().and_then(|a| a.id.clone()))
        .collect();
    assert_eq!(settled, expected);
}

#[test]
fn first_applicable_follows_the_order_of_the_grants_in_every_arrangement() {
    let layout = layout();
    let engine = first_applicable_engine();
    let subject = Subject::user("u1");
    let base = [
        Grant::allow(
            "allow-org",
            SubjectMatcher::user("u1"),
            "document.view",
            TargetSelector::exact("org", ORG),
        ),
        Grant::deny(
            "deny-p1",
            SubjectMatcher::user("u1"),
            "document.view",
            TargetSelector::exact("project", "p1"),
        ),
        Grant::allow(
            "allow-p1",
            SubjectMatcher::user("u1"),
            "document.view",
            TargetSelector::exact("project", "p1"),
        ),
        Grant::deny(
            "deny-org",
            SubjectMatcher::user("u1"),
            "document.view",
            TargetSelector::exact("org", ORG),
        ),
    ];
    let docs: Vec<Resource> = ["p1", "p2"]
        .iter()
        .enumerate()
        .map(|(i, project)| {
            Resource::new("document", format!("d{i}"))
                .within("doc_type", "invoice")
                .within("project", *project)
                .within("org", ORG)
        })
        .collect();
    for order in permutations(base.len()) {
        let grants: Vec<Grant> = order.iter().map(|&i| base[i].clone()).collect();
        let qctx = QueryContext::new(&grants);
        let ctx = qctx.context();
        let filter = engine.list(&qctx, &subject, "document.view", "document");
        let expr = filter.expr(&layout);
        for doc in &docs {
            let expected = engine.check(&ctx, &Request::new(&subject, "document.view", doc));
            assert_eq!(expr.holds(doc, &|_| None), Some(expected), "order {order:?}");
        }
    }
}

fn permutations(n: usize) -> Vec<Vec<usize>> {
    if n == 0 {
        return vec![Vec::new()];
    }
    let mut out = Vec::new();
    for rest in permutations(n - 1) {
        for at in 0..=rest.len() {
            let mut order = rest.clone();
            order.insert(at, n - 1);
            out.push(order);
        }
    }
    out
}

#[test]
fn simplifying_thousands_of_ids_merges_them_into_one_set() {
    let step = |i: usize| Expr::Within(Anchor::new("project", format!("p{i}")));
    let any = Expr::Or((0..20_000).map(step).collect()).simplify();
    let Expr::AnchorIn { ids, .. } = &any else {
        panic!("one id set expected, got {any:?}");
    };
    assert_eq!(ids.len(), 20_000);
    // The same ids, each twice, intersect to themselves; a disjoint set intersects to nothing.
    let all = Expr::And((0..20_000).chain(0..20_000).map(step).collect()).simplify();
    assert_eq!(all, Expr::False);
    let one = Expr::And(vec![step(1), step(1)]).simplify();
    assert!(matches!(one, Expr::AnchorIn { ids, .. } if ids.len() == 1));
}

fn depth_zero_engine() -> Engine {
    use themis::{RelationSchema, Rewrite};
    let schema = RelationSchema::new().relation(
        "project",
        "viewer",
        Rewrite::union([Rewrite::This, Rewrite::computed("editor")]),
    );
    Engine::builder(catalog())
        .relations(schema)
        .max_relation_depth(0)
        .build()
        .unwrap()
}

fn relation_store() -> themis::InMemoryTuples {
    use themis::{ObjectRef, Tuple};
    [Tuple::new(
        ObjectRef::new("project", PROJECT),
        "viewer",
        ObjectRef::new("user", "erin"),
    )]
    .into_iter()
    .collect()
}

#[test]
fn a_deny_through_a_relation_that_is_too_deep_fails_the_query() {
    let grants = vec![
        Grant::allow("all", SubjectMatcher::Any, "document.view", TargetSelector::global()),
        Grant::deny(
            "deny-viewers",
            SubjectMatcher::relation("viewer"),
            "document.view",
            TargetSelector::exact("project", PROJECT),
        ),
    ];
    let store = relation_store();
    let qctx = QueryContext::new(&grants).with_tuples(&store);
    let engine = depth_zero_engine();
    let error = engine
        .who_can_on(&qctx, "document.view", &document("d1", "invoice"))
        .unwrap_err();
    assert_eq!(
        error,
        QueryError::RelationDepthExceeded {
            grant_id: "deny-viewers".into()
        }
    );
}

#[test]
fn an_allow_through_a_relation_that_is_too_deep_names_nobody() {
    let grants = vec![Grant::allow(
        "viewers",
        SubjectMatcher::relation("viewer"),
        "document.view",
        TargetSelector::exact("project", PROJECT),
    )];
    let store = relation_store();
    let qctx = QueryContext::new(&grants).with_tuples(&store);
    let who = depth_zero_engine()
        .who_can_on(&qctx, "document.view", &document("d1", "invoice"))
        .unwrap();
    assert_eq!(who.subjects().count(), 0);
}

#[test]
fn a_query_past_its_limits_fails_instead_of_answering_in_part() {
    let grants: Vec<Grant> = (0..5)
        .map(|i| {
            Grant::allow(
                format!("g{i}"),
                SubjectMatcher::user(format!("u{i}")),
                "document.view",
                TargetSelector::exact("org", ORG),
            )
        })
        .collect();
    let engine = Engine::builder(catalog()).build().unwrap();
    let doc = document("d1", "invoice");
    let tight = QueryContext::new(&grants).with_limits(QueryLimits::default().with_max_parties(4));
    assert_eq!(
        engine.who_can_on(&tight, "document.view", &doc).unwrap_err(),
        QueryError::LimitExceeded {
            what: "parties",
            limit: 4
        }
    );
    assert_eq!(
        engine.access_of(&tight, &doc).unwrap_err(),
        QueryError::LimitExceeded {
            what: "parties",
            limit: 4
        }
    );
    let few = QueryContext::new(&grants).with_limits(QueryLimits::default().with_max_decisions(3));
    assert!(matches!(
        engine.who_can_on(&few, "document.view", &doc),
        Err(QueryError::LimitExceeded { what: "decisions", .. })
    ));
    let roomy = QueryContext::new(&grants);
    assert_eq!(
        engine.who_can_on(&roomy, "document.view", &doc).unwrap().subjects().count(),
        5
    );
}
