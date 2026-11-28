//! Elevations as changes and expiry notices.

use std::time::Duration;

use strig::{
    Anchor, Attributes, CatalogConformance, ElevationPolicy, ElevationRequest, ElevationRule, ElevationTarget,
    Elevations, Governance, MemoryPendingStore, PendingStore, Resource, Review, Subject, TargetSelector,
};
use strig_sync::{ChangeKind, Hub, elevation_change};

fn catalog() -> strig::Catalog {
    strig::Catalog::builder()
        .target_kinds(["project"])
        .broad_target("org")
        .permission(strig::PermissionDef::new("project.edit").targets(["project"]))
        .permission(strig::PermissionDef::new("org.manage").targets(["org"]))
        .build()
        .unwrap()
}

#[tokio::test(start_paused = true)]
async fn an_approval_is_a_change_and_its_end_an_expiry_notice() {
    let engine = strig::Engine::builder(catalog())
        .override_with(strig::PermissionHolder::new("org.manage"))
        .build()
        .unwrap();
    let org = Anchor::new("org", "o1");
    let target =
        ElevationTarget::permission("project.edit", TargetSelector::exact("project", "p1")).scoped(org.clone());
    let approver_scope = Resource::new("project", "p1").within("org", "o1");
    let policy = ElevationPolicy::new().with(ElevationRule::new(target.key(), 1_000, "org.manage", approver_scope));
    let governance = Governance::new().with(CatalogConformance);
    let store = MemoryPendingStore::new();
    let flow = Elevations::new(&governance, &policy, &store);
    let meta = Attributes::new();
    let admin_grant = strig::Grant::allow(
        "g",
        strig::SubjectMatcher::role("admin"),
        "org.manage",
        TargetSelector::exact("org", "o1"),
    )
    .scoped(org.clone());
    let grants = vec![admin_grant];
    let review = |now| Review::new(&engine, &grants, now, &meta);

    let ana = Subject::user("ana");
    flow.request(
        &review(1_000),
        &ElevationRequest::new("e1", ana.clone(), target, 1_000),
        None,
    )
    .unwrap();
    let approver = Subject::user("bia").with_role_in("admin", org.clone());
    let approved = flow.approve(&review(1_000), &approver, "e1").unwrap();

    let change = elevation_change(&approved.request).unwrap();
    assert_eq!(change.kind, ChangeKind::Grants);
    assert_eq!(change.subject.as_deref(), Some("ana"));
    assert_eq!(change.scope, org);
    assert_eq!(change.id.as_deref(), Some("e1"));

    let hub = Hub::new();
    let mut rx = hub.subscribe();
    let published = hub.elevation_approved(&approved.request, 1_000).await.unwrap().unwrap();
    assert_eq!(published.id.as_deref(), Some("e1"));
    assert_eq!(rx.recv().await.unwrap().id.as_deref(), Some("e1"));

    tokio::time::sleep(Duration::from_millis(999)).await;
    assert!(rx.try_recv().is_err(), "nada antes do prazo");
    tokio::time::sleep(Duration::from_millis(2)).await;
    let expiry = rx.try_recv().expect("aviso de expiração no instante");
    assert_eq!(expiry.subject.as_deref(), Some("ana"));
    assert_eq!(expiry.kind, ChangeKind::Grants);
    assert!(store.get("e1").unwrap().is_some());
}

#[tokio::test]
async fn a_request_that_is_no_elevation_is_ignored() {
    let request = strig::PendingRequest::new("r", Subject::user("ana"), strig::Mutation::Remove { id: "g".into() }, 0);
    assert!(elevation_change(&request).is_none());
    assert!(Hub::new().elevation_approved(&request, 0).await.unwrap().is_none());
}
