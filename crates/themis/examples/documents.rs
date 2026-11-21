//! RBAC, ABAC e ReBAC juntos sobre um domínio de documentos.
//!
//! `cargo run -p themis --example documents`

use themis::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let catalog = Catalog::builder()
        .target_kinds(["project", "doc_type", "document"])
        .broad_target("org")
        .permission(PermissionDef::new("project.view").targets(["project"]))
        .permission(PermissionDef::new("project.edit").targets(["project"]))
        .permission(PermissionDef::new("document.export").targets(["project", "document"]))
        .permission(
            PermissionDef::new("document.invoice.export")
                .targets(["doc_type", "document"])
                .implied_by(["document.export"]),
        )
        .build()?;

    let roles = RoleGraph::builder().inherit("maintainer", "member").build()?;
    let relations = RelationSchema::new()
        .relation(
            "project",
            "editor",
            Rewrite::union([Rewrite::This, Rewrite::computed("owner")]),
        )
        .relation(
            "project",
            "viewer",
            Rewrite::union([Rewrite::computed("editor"), Rewrite::from_parent("parent", "member")]),
        );
    let engine = Engine::builder(catalog).roles(roles).relations(relations).build()?;

    let org = Anchor::new("org", "acme");
    let grants = vec![
        Grant::allow(
            "rel-edit",
            SubjectMatcher::relation("editor"),
            "project.edit",
            TargetSelector::kind("project"),
        ),
        Grant::allow(
            "rel-view",
            SubjectMatcher::relation("viewer"),
            "project.view",
            TargetSelector::kind("project"),
        ),
        Grant::allow(
            "export",
            SubjectMatcher::role("member"),
            "document.export",
            TargetSelector::kind("org"),
        )
        .scoped(org.clone())
        .when(Condition::eq(Operand::attr("subject.plan"), Operand::lit("pro"))),
    ];
    let tuples: InMemoryTuples = [
        Tuple::new(
            ObjectRef::new("project", "roadmap"),
            "owner",
            ObjectRef::new("user", "alice"),
        ),
        Tuple::new(
            ObjectRef::new("project", "roadmap"),
            "editor",
            ObjectRef::new("user", "bob"),
        ),
        Tuple::new(
            ObjectRef::new("project", "roadmap"),
            "parent",
            ObjectRef::new("org", "acme"),
        ),
        Tuple::new(ObjectRef::new("org", "acme"), "member", ObjectRef::new("user", "carol")),
    ]
    .into_iter()
    .collect();
    let ctx = Context::new(&grants).with_tuples(&tuples);

    let project = Resource::new("project", "roadmap").within("org", "acme");
    let invoice = Resource::new("document", "inv-7")
        .within("doc_type", "invoice")
        .within("project", "roadmap")
        .within("org", "acme");

    let people = [
        (
            "bob edita (relação editor)",
            Subject::user("bob"),
            "project.edit",
            &project,
        ),
        (
            "carol vê (membro da org pai)",
            Subject::user("carol"),
            "project.view",
            &project,
        ),
        ("carol não edita", Subject::user("carol"), "project.edit", &project),
        (
            "dave exporta fatura (maintainer herda member, plano pro)",
            Subject::user("dave")
                .with_role_in("maintainer", org.clone())
                .with_attr("plan", "pro"),
            "document.invoice.export",
            &invoice,
        ),
        (
            "erin não exporta (plano free)",
            Subject::user("erin")
                .with_role_in("member", org)
                .with_attr("plan", "free"),
            "document.invoice.export",
            &invoice,
        ),
    ];
    for (label, subject, key, resource) in people {
        let decision = engine.decide(&ctx, &Request::new(&subject, key, resource));
        println!("{:<60} {:?}  {:?}", label, decision.effect, decision.reason);
    }
    Ok(())
}
