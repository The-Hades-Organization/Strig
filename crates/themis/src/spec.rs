//! Declarative configuration of the engine and of governance, in JSON, TOML or YAML.
//!
//! Use it to load the policy from a file and for the bindings (`themis-node`), which cannot
//! pass Rust closures. Everything the spec builds can be extended later in code:
//! [`EngineSpec::builder`] returns the [`EngineBuilder`] to add condition functions,
//! custom overrides or another strategy.

use serde::{Deserialize, Serialize};

use crate::catalog::{Catalog, CatalogErrors, CatalogExport};
use crate::engine::{Engine, EngineBuilder, EngineError};
use crate::governance::{
    Bypass, CatalogConformance, Forbid, Governance, ManagementOnly, NoEscalation, NoLockout, NoSelfManagement,
    NonDelegable, Prerequisites, RequirePermission,
};
use crate::grant::SubjectMatcher;
use crate::overrides::{PermissionHolder, ResourceOwner};
use crate::rbac::{RbacError, RoleGraph};
use crate::rebac::{RelationSchema, Rewrite};
use crate::resource::Resource;
use crate::strategy::{DenyOverrides, FirstApplicable, MostSpecific, PermitOverrides};
use crate::subject::{RoleAssignment, Subject};

#[derive(Debug, thiserror::Error)]
pub enum SpecError {
    #[error(transparent)]
    Catalog(#[from] CatalogErrors),
    #[error(transparent)]
    Roles(#[from] RbacError),
    #[error(transparent)]
    Engine(#[from] EngineError),
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EngineSpec {
    pub catalog: CatalogExport,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<RoleSpec>,
    /// `None` turns ReBAC off; `Some(vec![])` turns it on with every relation holding only its own
    /// tuples.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relations: Option<Vec<RelationSpec>>,
    #[serde(default)]
    pub strategy: StrategySpec,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub overrides: Vec<OverrideSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_relation_depth: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleSpec {
    pub role: String,
    pub inherits: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationSpec {
    pub kind: String,
    pub relation: String,
    pub rewrite: Rewrite,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StrategySpec {
    #[default]
    MostSpecific,
    DenyOverrides,
    PermitOverrides,
    FirstApplicable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OverrideRule {
    /// [`ResourceOwner`]: the subject's id is in the resource's `attr` attribute.
    ResourceOwner { attr: String },
    /// [`PermissionHolder`]: the subject has `permission` on the resource.
    PermissionHolder { permission: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverrideSpec {
    #[serde(flatten)]
    pub rule: OverrideRule,
    /// Permissions (and the ones they grant) outside the reach of this override.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub except: Vec<String>,
}

impl EngineSpec {
    pub fn builder(&self) -> Result<EngineBuilder, SpecError> {
        let catalog = Catalog::from_export(self.catalog.clone())?;
        let mut roles = RoleGraph::builder();
        for spec in &self.roles {
            for parent in &spec.inherits {
                roles = roles.inherit(spec.role.clone(), parent.clone());
            }
        }
        let mut builder = Engine::builder(catalog).roles(roles.build()?);
        if let Some(relations) = &self.relations {
            let schema = relations.iter().fold(RelationSchema::new(), |schema, r| {
                schema.relation(r.kind.clone(), r.relation.clone(), r.rewrite.clone())
            });
            builder = builder.relations(schema);
        }
        builder = match self.strategy {
            StrategySpec::MostSpecific => builder.strategy(MostSpecific),
            StrategySpec::DenyOverrides => builder.strategy(DenyOverrides),
            StrategySpec::PermitOverrides => builder.strategy(PermitOverrides),
            StrategySpec::FirstApplicable => builder.strategy(FirstApplicable),
        };
        for spec in &self.overrides {
            let except = spec.except.clone();
            builder = match &spec.rule {
                OverrideRule::ResourceOwner { attr } => builder.override_except(ResourceOwner::new(attr), except),
                OverrideRule::PermissionHolder { permission } => {
                    builder.override_except(PermissionHolder::new(permission), except)
                }
            };
        }
        if let Some(depth) = self.max_relation_depth {
            builder = builder.max_relation_depth(depth);
        }
        Ok(builder)
    }

    pub fn build(&self) -> Result<Engine, SpecError> {
        Ok(self.builder()?.build()?)
    }
}

/// Ready-made governance invariants, in declarative form.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InvariantSpec {
    CatalogConformance,
    NoSelfManagement,
    RequirePermission {
        permission: String,
        resource: Resource,
    },
    NoLockout {
        permissions: Vec<String>,
        members: Vec<Subject>,
        resource: Resource,
        /// Reserve whose administrator-role assignment the refusal proposes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reserve: Option<ReserveSpec>,
    },
    /// [`Prerequisites`]: a permission is only held together with its `depends_on` ones.
    Prerequisites,
    /// [`NonDelegable`]: only whoever holds `manager` grants a non-delegable permission.
    NonDelegable { manager: String },
    /// [`ManagementOnly`]: management-only permissions go only to the listed roles.
    ManagementOnly { roles: Vec<String> },
    /// [`NoEscalation`]: the actor only grants what they hold, unless they hold the bypass.
    NoEscalation {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bypass: Option<Bypass>,
    },
    Forbid {
        subject: SubjectMatcher,
        permissions: Vec<String>,
    },
}

/// Reserve of [`InvariantSpec::NoLockout`]: the administrator role and the subjects that may receive it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReserveSpec {
    pub admin_role: RoleAssignment,
    pub subjects: Vec<Subject>,
}

impl InvariantSpec {
    pub fn add_to(&self, governance: Governance) -> Governance {
        match self.clone() {
            InvariantSpec::CatalogConformance => governance.with(CatalogConformance),
            InvariantSpec::NoSelfManagement => governance.with(NoSelfManagement),
            InvariantSpec::RequirePermission { permission, resource } => {
                governance.with(RequirePermission::new(permission, resource))
            }
            InvariantSpec::NoLockout {
                permissions,
                members,
                resource,
                reserve,
            } => {
                let lockout = NoLockout::new(permissions, members, resource);
                governance.with(match reserve {
                    Some(r) => lockout.with_reserve(r.admin_role, r.subjects),
                    None => lockout,
                })
            }
            InvariantSpec::Prerequisites => governance.with(Prerequisites),
            InvariantSpec::NonDelegable { manager } => governance.with(NonDelegable::new(manager)),
            InvariantSpec::ManagementOnly { roles } => governance.with(ManagementOnly::new(roles)),
            InvariantSpec::NoEscalation { bypass } => {
                let invariant = NoEscalation::new();
                governance.with(match bypass {
                    Some(b) => invariant.bypass(b),
                    None => invariant,
                })
            }
            InvariantSpec::Forbid { subject, permissions } => governance.with(Forbid::new(subject, permissions)),
        }
    }
}

impl<'a> FromIterator<&'a InvariantSpec> for Governance {
    fn from_iter<I: IntoIterator<Item = &'a InvariantSpec>>(iter: I) -> Self {
        iter.into_iter().fold(Governance::new(), |g, spec| spec.add_to(g))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Context, Grant, Request, TargetSelector};

    const SPEC: &str = r#"{
        "catalog": {
            "targetKinds": ["project", "document"],
            "broadTargets": ["org"],
            "permissions": [
                {"key": "project.view", "targets": ["project"]},
                {"key": "project.delete", "targets": ["project"]},
                {"key": "document.view", "targets": ["project", "document"], "impliedBy": ["project.view"]}
            ]
        },
        "roles": [{"role": "admin", "inherits": ["member"]}],
        "relations": [
            {"kind": "project", "relation": "viewer",
             "rewrite": {"rewrite": "union", "of": [{"rewrite": "this"}, {"rewrite": "computed", "relation": "owner"}]}}
        ],
        "strategy": "deny_overrides",
        "overrides": [{"kind": "resource_owner", "attr": "owner", "except": ["project.delete"]}],
        "maxRelationDepth": 8
    }"#;

    #[test]
    fn builds_engine_from_json() {
        let spec: EngineSpec = serde_json::from_str(SPEC).unwrap();
        let engine = spec.build().unwrap();
        let grants = vec![Grant::allow(
            "g",
            SubjectMatcher::role("member"),
            "project.view",
            TargetSelector::kind("project"),
        )];
        let admin = Subject::user("a").with_role("admin");
        let doc = Resource::new("document", "d1").within("project", "p1");
        assert!(engine.check(&Context::new(&grants), &Request::new(&admin, "document.view", &doc)));

        let owned = Resource::new("project", "p1").with_attr("owner", "o");
        let owner = Subject::user("o");
        let none: Vec<Grant> = Vec::new();
        assert!(engine.check(&Context::new(&none), &Request::new(&owner, "project.view", &owned)));
        assert!(!engine.check(&Context::new(&none), &Request::new(&owner, "project.delete", &owned)));

        let back: EngineSpec = serde_json::from_str(&serde_json::to_string(&spec).unwrap()).unwrap();
        assert_eq!(back, spec);
    }

    #[test]
    fn invariants_from_json() {
        let specs: Vec<InvariantSpec> = serde_json::from_str(
            r#"[{"kind": "catalog_conformance"}, {"kind": "forbid", "subject": {"kind": "any"}, "permissions": ["project.delete"]}]"#,
        )
        .unwrap();
        let governance: Governance = specs.iter().collect();
        assert_eq!(governance.len(), 2);
    }
}
