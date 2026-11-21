//! Precedência da estratégia padrão, overrides e pré-carga de capacidades.

mod support;

use support::*;
use themis::{
    AUTHENTICATED, Anchor, Context, Effect, Grant, Reason, Request, Resource, Subject, SubjectMatcher, TargetSelector,
};

fn member() -> Subject {
    Subject::user("u1").with_role_in("member", org())
}

fn can(grants: &[Grant], subject: &Subject, key: &str, resource: &Resource) -> bool {
    engine().check(&Context::new(&grants), &Request::new(subject, key, resource))
}

#[test]
fn default_deny_when_no_grants() {
    assert!(!can(&[], &member(), "project.view", &project()));
}

#[test]
fn general_grant_implies_specific() {
    let grants = vec![role_grant("g1", "member", "document.export", true, at_org())];
    assert!(can(
        &grants,
        &member(),
        "document.invoice.export",
        &document("d1", "invoice")
    ));
}

#[test]
fn deny_beats_allow_at_same_level() {
    let grants = vec![
        role_grant("g1", "member", "project.view", true, at_org()),
        role_grant("g2", "member", "project.view", false, at_org()),
    ];
    assert!(!can(&grants, &member(), "project.view", &project()));
}

#[test]
fn more_specific_allow_overrides_broader_deny() {
    let grants = vec![
        role_grant("g1", "member", "document.view", false, at_org()),
        role_grant(
            "g2",
            "member",
            "document.report.view",
            true,
            TargetSelector::exact("doc_type", "report"),
        ),
    ];
    assert!(can(
        &grants,
        &member(),
        "document.report.view",
        &document("d1", "report")
    ));
}

#[test]
fn facet_deny_hides_only_that_facet() {
    let grants = vec![
        role_grant("g1", "member", "document.view", true, at_org()),
        role_grant(
            "g2",
            "member",
            "document.contract.view",
            false,
            TargetSelector::exact("doc_type", "contract"),
        ),
    ];
    assert!(!can(
        &grants,
        &member(),
        "document.contract.view",
        &document("d1", "contract")
    ));
    assert!(can(
        &grants,
        &member(),
        "document.report.view",
        &document("d2", "report")
    ));
}

#[test]
fn principal_baseline_allows_view_not_edit() {
    let grants = vec![Grant::allow(
        "public-baseline",
        SubjectMatcher::principal(AUTHENTICATED),
        "project.view",
        TargetSelector::exact("project", PROJECT),
    )];
    let stranger = Subject::user("u9");
    assert!(can(&grants, &stranger, "project.view", &project()));
    assert!(!can(&grants, &stranger, "project.edit", &project()));
    assert!(!can(&grants, &Subject::anonymous(), "project.view", &project()));
}

#[test]
fn owner_can_everything() {
    let owned = project().with_attr("owner", "u1");
    let decision = engine().decide(
        &Context::new(&Vec::new()),
        &Request::new(&member(), "project.delete", &owned),
    );
    assert_eq!(decision.effect, Effect::Allow);
    assert_eq!(
        decision.reason,
        Reason::Override {
            name: "resource_owner".into()
        }
    );
}

#[test]
fn permission_holder_can_everything() {
    let grants = vec![role_grant("g1", "admin", "org.manage", true, at_org())];
    let admin = Subject::user("u2").with_role_in("admin", org());
    assert!(can(
        &grants,
        &admin,
        "document.contract.export",
        &document("d1", "contract")
    ));
    assert!(!can(&grants, &member(), "project.view", &project()));
}

#[test]
fn role_from_another_scope_does_not_leak() {
    let grants = vec![role_grant("g1", "member", "project.view", true, at_org())];
    let outsider = Subject::user("u3").with_role_in("member", Anchor::new("org", "o2"));
    assert!(!can(&grants, &outsider, "project.view", &project()));
}

#[test]
fn instance_target_beats_facet_target() {
    let grants = vec![
        role_grant(
            "g1",
            "member",
            "document.invoice.export",
            false,
            TargetSelector::exact("doc_type", "invoice"),
        ),
        role_grant(
            "g2",
            "member",
            "document.invoice.export",
            true,
            TargetSelector::exact("document", "d7"),
        ),
    ];
    assert!(can(
        &grants,
        &member(),
        "document.invoice.export",
        &document("d7", "invoice")
    ));
    assert!(!can(
        &grants,
        &member(),
        "document.invoice.export",
        &document("d8", "invoice")
    ));
}

#[test]
fn any_registered_target_kind_is_honored() {
    let thread = Resource::new("thread", "c1")
        .within("project", PROJECT)
        .within("org", ORG);
    let grants = vec![
        role_grant("g1", "member", "thread.post", true, at_org()),
        Grant::deny(
            "g2",
            SubjectMatcher::user("u1"),
            "thread.post",
            TargetSelector::exact("thread", "c1"),
        )
        .scoped(org()),
    ];
    assert!(!can(&grants, &member(), "thread.post", &thread));
    let other = Resource::new("thread", "c2")
        .within("project", PROJECT)
        .within("org", ORG);
    assert!(can(&grants, &member(), "thread.post", &other));
}

#[test]
fn capability_set_answers_like_the_source() {
    let grants = vec![
        role_grant("g1", "member", "document.view", true, at_org()),
        role_grant(
            "g2",
            "member",
            "document.contract.view",
            false,
            TargetSelector::exact("doc_type", "contract"),
        ),
        role_grant("g3", "other", "project.edit", true, at_org()),
    ];
    let engine = engine();
    let caps = engine.capabilities(&Context::new(&grants), &member(), &project());
    assert_eq!(caps.grants.len(), 2);

    let ctx = Context::new(&caps);
    let subject = member();
    for (ty, expected) in [("contract", false), ("report", true)] {
        let key = format!("document.{ty}.view");
        assert_eq!(
            engine.check(&ctx, &Request::new(&subject, &key, &document("d", ty))),
            expected
        );
    }

    let json = serde_json::to_string(&caps).unwrap();
    let back: themis::CapabilitySet = serde_json::from_str(&json).unwrap();
    assert_eq!(back, caps);
}
