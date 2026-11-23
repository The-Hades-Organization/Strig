//! Regressions of the listing: each test pins a case where the filter once disagreed with
//! `Engine::check` or opened access.

mod support;

use support::*;
use themis::{
    Candidate, DenyOverrides, Engine, FilterResidual, Grant, PathLayout, PermissionHolder, QueryContext, Request,
    Resource, Strategy, Subject, SubjectMatcher, TargetSelector,
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
