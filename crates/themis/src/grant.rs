use serde::{Deserialize, Serialize};

use crate::condition::Condition;
use crate::resource::{Anchor, GLOBAL, Resource};
use crate::subject::Subject;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Allow,
    Deny,
}

/// Whom a grant applies to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SubjectMatcher {
    /// A subject by id.
    User { id: String },
    /// Whoever has the role, directly or inherited through the [`crate::RoleGraph`].
    Role { id: String },
    /// Whoever carries the principal (`authenticated`, `anonymous` or a custom one).
    Principal { name: String },
    /// Whoever has the ReBAC relation on the step matched by the grant's target.
    Relation { relation: String },
    /// Any subject.
    Any,
}

impl SubjectMatcher {
    pub fn user(id: impl Into<String>) -> Self {
        Self::User { id: id.into() }
    }

    pub fn role(id: impl Into<String>) -> Self {
        Self::Role { id: id.into() }
    }

    pub fn principal(name: impl Into<String>) -> Self {
        Self::Principal { name: name.into() }
    }

    pub fn relation(relation: impl Into<String>) -> Self {
        Self::Relation {
            relation: relation.into(),
        }
    }
}

/// Where a grant is anchored in the resource path. Without `id`, it matches any instance of the kind.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TargetSelector {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

impl TargetSelector {
    pub fn global() -> Self {
        Self::kind(GLOBAL)
    }

    pub fn kind(kind: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            id: None,
        }
    }

    pub fn exact(kind: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            id: Some(id.into()),
        }
    }

    pub fn matches(&self, anchor: &Anchor) -> bool {
        self.kind == anchor.kind && (self.id.is_none() || self.id == anchor.id)
    }
}

impl From<&Anchor> for TargetSelector {
    fn from(anchor: &Anchor) -> Self {
        Self {
            kind: anchor.kind.clone(),
            id: anchor.id.clone(),
        }
    }
}

/// Grant or denial of a catalog permission.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Grant {
    pub id: String,
    pub subject: SubjectMatcher,
    pub permission: String,
    pub target: TargetSelector,
    pub effect: Effect,
    /// Restricts the grant to resources whose path goes through this step (the owning team, for
    /// example).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<Anchor>,
    /// ABAC condition; the grant only applies when it is true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<Condition>,
}

impl Grant {
    pub fn new(
        id: impl Into<String>,
        effect: Effect,
        subject: SubjectMatcher,
        permission: impl Into<String>,
        target: TargetSelector,
    ) -> Self {
        Self {
            id: id.into(),
            subject,
            permission: permission.into(),
            target,
            effect,
            scope: None,
            condition: None,
        }
    }

    pub fn allow(
        id: impl Into<String>,
        subject: SubjectMatcher,
        permission: impl Into<String>,
        target: TargetSelector,
    ) -> Self {
        Self::new(id, Effect::Allow, subject, permission, target)
    }

    pub fn deny(
        id: impl Into<String>,
        subject: SubjectMatcher,
        permission: impl Into<String>,
        target: TargetSelector,
    ) -> Self {
        Self::new(id, Effect::Deny, subject, permission, target)
    }

    pub fn scoped(mut self, scope: Anchor) -> Self {
        self.scope = Some(scope);
        self
    }

    pub fn when(mut self, condition: Condition) -> Self {
        self.condition = Some(condition);
        self
    }
}

/// Source of the grants consulted in a decision.
///
/// The implementation may deliver extra grants (the engine filters by permission, target, scope,
/// subject and condition); delivering fewer changes the decision. A database-backed source uses
/// `subject` and `resource` to build the query.
pub trait GrantSource {
    fn visit(&self, subject: &Subject, resource: &Resource, visitor: &mut dyn FnMut(&Grant));
}

impl GrantSource for [Grant] {
    fn visit(&self, _: &Subject, _: &Resource, visitor: &mut dyn FnMut(&Grant)) {
        self.iter().for_each(visitor);
    }
}

impl GrantSource for Vec<Grant> {
    fn visit(&self, subject: &Subject, resource: &Resource, visitor: &mut dyn FnMut(&Grant)) {
        self.as_slice().visit(subject, resource, visitor);
    }
}

impl<T: GrantSource + ?Sized> GrantSource for &T {
    fn visit(&self, subject: &Subject, resource: &Resource, visitor: &mut dyn FnMut(&Grant)) {
        (**self).visit(subject, resource, visitor);
    }
}

/// Chains two sources, such as database grants plus a synthetic baseline row.
impl<A: GrantSource, B: GrantSource> GrantSource for (A, B) {
    fn visit(&self, subject: &Subject, resource: &Resource, visitor: &mut dyn FnMut(&Grant)) {
        self.0.visit(subject, resource, visitor);
        self.1.visit(subject, resource, visitor);
    }
}

/// A [`GrantSource`] that can also be asked from the other side: by permission, by target kind or
/// by subject, without a resource at hand. Listing and the reverse queries (`who can`) use it; a
/// database implementation answers each method with one indexed query.
///
/// Like [`GrantSource`], an implementation may deliver extra grants and must not deliver fewer.
pub trait GrantIndex: GrantSource {
    /// Grants of any of the given permission keys.
    fn visit_by_permission(&self, permissions: &[&str], visitor: &mut dyn FnMut(&Grant));

    /// Grants whose target is of the given kind (`global` for the implicit step).
    fn visit_by_target_kind(&self, kind: &str, visitor: &mut dyn FnMut(&Grant));

    /// Grants to exactly this subject matcher.
    fn visit_by_subject(&self, subject: &SubjectMatcher, visitor: &mut dyn FnMut(&Grant));
}

impl GrantIndex for [Grant] {
    fn visit_by_permission(&self, permissions: &[&str], visitor: &mut dyn FnMut(&Grant)) {
        self.iter()
            .filter(|g| permissions.contains(&g.permission.as_str()))
            .for_each(visitor);
    }

    fn visit_by_target_kind(&self, kind: &str, visitor: &mut dyn FnMut(&Grant)) {
        self.iter().filter(|g| g.target.kind == kind).for_each(visitor);
    }

    fn visit_by_subject(&self, subject: &SubjectMatcher, visitor: &mut dyn FnMut(&Grant)) {
        self.iter().filter(|g| &g.subject == subject).for_each(visitor);
    }
}

impl GrantIndex for Vec<Grant> {
    fn visit_by_permission(&self, permissions: &[&str], visitor: &mut dyn FnMut(&Grant)) {
        self.as_slice().visit_by_permission(permissions, visitor);
    }

    fn visit_by_target_kind(&self, kind: &str, visitor: &mut dyn FnMut(&Grant)) {
        self.as_slice().visit_by_target_kind(kind, visitor);
    }

    fn visit_by_subject(&self, subject: &SubjectMatcher, visitor: &mut dyn FnMut(&Grant)) {
        self.as_slice().visit_by_subject(subject, visitor);
    }
}

impl<T: GrantIndex + ?Sized> GrantIndex for &T {
    fn visit_by_permission(&self, permissions: &[&str], visitor: &mut dyn FnMut(&Grant)) {
        (**self).visit_by_permission(permissions, visitor);
    }

    fn visit_by_target_kind(&self, kind: &str, visitor: &mut dyn FnMut(&Grant)) {
        (**self).visit_by_target_kind(kind, visitor);
    }

    fn visit_by_subject(&self, subject: &SubjectMatcher, visitor: &mut dyn FnMut(&Grant)) {
        (**self).visit_by_subject(subject, visitor);
    }
}

impl<A: GrantIndex, B: GrantIndex> GrantIndex for (A, B) {
    fn visit_by_permission(&self, permissions: &[&str], visitor: &mut dyn FnMut(&Grant)) {
        self.0.visit_by_permission(permissions, visitor);
        self.1.visit_by_permission(permissions, visitor);
    }

    fn visit_by_target_kind(&self, kind: &str, visitor: &mut dyn FnMut(&Grant)) {
        self.0.visit_by_target_kind(kind, visitor);
        self.1.visit_by_target_kind(kind, visitor);
    }

    fn visit_by_subject(&self, subject: &SubjectMatcher, visitor: &mut dyn FnMut(&Grant)) {
        self.0.visit_by_subject(subject, visitor);
        self.1.visit_by_subject(subject, visitor);
    }
}
