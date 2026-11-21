#![allow(dead_code)]

//! Domínio de exemplo dos testes: organização → projeto → tipo de documento → documento.

use themis::{
    Anchor, Catalog, Engine, Grant, PermissionDef, PermissionHolder, RequireMeta, Resource, ResourceOwner,
    SubjectMatcher, TargetSelector,
};

pub const ORG: &str = "o1";
pub const PROJECT: &str = "p1";
pub const DOC_TYPES: &[&str] = &["invoice", "report", "contract"];

fn view(key: impl Into<String>) -> PermissionDef {
    PermissionDef::new(key).meta("visibility", "hide")
}

pub fn catalog() -> Catalog {
    let mut builder = Catalog::builder()
        .target_kinds(["document", "doc_type", "project", "thread"])
        .broad_target("org")
        .rule(
            RequireMeta::new("visibility")
                .for_suffix(".view")
                .one_of(["hide", "redact"]),
        )
        .permission(view("project.view").targets(["project"]))
        .permission(PermissionDef::new("project.edit").targets(["project"]))
        .permission(PermissionDef::new("project.manage").targets(["project"]))
        .permission(
            PermissionDef::new("project.delete")
                .targets(["project"])
                .implied_by(["project.manage"]),
        )
        .permission(view("document.view").targets(["project"]).implied_by(["project.view"]))
        .permission(
            PermissionDef::new("document.edit")
                .targets(["project", "document"])
                .implied_by(["project.edit"]),
        )
        .permission(PermissionDef::new("document.export").targets(["project", "document"]))
        .permission(PermissionDef::new("org.manage").targets(["org"]))
        .permission(
            PermissionDef::new("org.invite")
                .targets(["org"])
                .implied_by(["org.manage"]),
        )
        .permission(
            PermissionDef::new("org.roles.edit")
                .targets(["org"])
                .implied_by(["org.manage"]),
        )
        .permission(PermissionDef::new("thread.post").targets(["org", "project", "thread"]));
    for ty in DOC_TYPES {
        builder = builder
            .permission(
                view(format!("document.{ty}.view"))
                    .targets(["doc_type", "document", "project"])
                    .implied_by(["document.view"]),
            )
            .permission(
                PermissionDef::new(format!("document.{ty}.export"))
                    .targets(["doc_type", "document", "project"])
                    .implied_by(["document.export"]),
            );
    }
    builder.build().expect("catálogo de exemplo")
}

/// Dono do recurso e quem tem `org.manage` passam direto.
pub fn engine() -> Engine {
    Engine::builder(catalog())
        .override_with(ResourceOwner::new("owner"))
        .override_with(PermissionHolder::new("org.manage"))
        .build()
        .expect("motor")
}

pub fn org() -> Anchor {
    Anchor::new("org", ORG)
}

pub fn project() -> Resource {
    Resource::new("project", PROJECT).within("org", ORG)
}

pub fn document(id: &str, ty: &str) -> Resource {
    Resource::new("document", id)
        .within("doc_type", ty)
        .within("project", PROJECT)
        .within("org", ORG)
}

/// Grant de papel restrito à organização.
pub fn role_grant(id: &str, role: &str, key: &str, allow: bool, target: TargetSelector) -> Grant {
    let grant = if allow {
        Grant::allow(id, SubjectMatcher::role(role), key, target)
    } else {
        Grant::deny(id, SubjectMatcher::role(role), key, target)
    };
    grant.scoped(org())
}

pub fn at_org() -> TargetSelector {
    TargetSelector::exact("org", ORG)
}
