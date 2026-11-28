use serde::{Deserialize, Serialize};

use crate::condition::Condition;
use crate::resource::{Anchor, GLOBAL, Resource};
use crate::subject::Subject;
use crate::validity::{Validity, ValidityError};

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
    /// Start of the validity window, in milliseconds since the Unix epoch (inclusive).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<u64>,
    /// End of the validity window, in milliseconds since the Unix epoch (exclusive).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<u64>,
    /// Fields of the resource the grant is restricted to. Empty means the whole resource. A `deny`
    /// with fields takes away only those fields; an `allow` with fields gives only those. See
    /// [`crate::field`] for how they combine with the strategies.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
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
            valid_from: None,
            valid_until: None,
            fields: Vec::new(),
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

    /// Restricts the grant to these fields of the resource.
    #[must_use]
    pub fn fields<I, S>(mut self, fields: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.fields.extend(fields.into_iter().map(Into::into));
        self
    }

    /// Does the grant name fields, instead of covering the whole resource?
    pub fn is_field_restricted(&self) -> bool {
        !self.fields.is_empty()
    }

    /// Does the grant reach `field`? A grant without fields reaches every field.
    pub fn covers_field(&self, field: &str) -> bool {
        self.fields.is_empty() || self.fields.iter().any(|f| f == field)
    }

    pub fn scoped(mut self, scope: Anchor) -> Self {
        self.scope = Some(scope);
        self
    }

    pub fn when(mut self, condition: Condition) -> Self {
        self.condition = Some(condition);
        self
    }

    /// The grant only exists from `from` on (milliseconds since the Unix epoch, inclusive).
    pub fn valid_from(mut self, from: u64) -> Self {
        self.valid_from = Some(from);
        self
    }

    /// The grant stops existing at `until` (milliseconds since the Unix epoch, exclusive).
    pub fn valid_until(mut self, until: u64) -> Self {
        self.valid_until = Some(until);
        self
    }

    /// The grant exists in `[from, until)`. An inverted window is refused by
    /// [`crate::Engine::validate_grant`]; [`Grant::try_valid_between`] refuses it right here.
    pub fn valid_between(self, from: u64, until: u64) -> Self {
        self.valid_from(from).valid_until(until)
    }

    /// Like [`Grant::valid_between`], refusing a window that ends before it starts.
    ///
    /// # Errors
    /// [`ValidityError::Inverted`] when `until` is not after `from`.
    pub fn try_valid_between(self, from: u64, until: u64) -> Result<Self, ValidityError> {
        Validity::between(from, until).map(|_| self.valid_between(from, until))
    }

    /// The validity window of the grant.
    pub fn validity(&self) -> Validity {
        Validity {
            valid_from: self.valid_from,
            valid_until: self.valid_until,
        }
    }

    /// Is the grant in force at `now`? Without an instant, a grant with a window holds only if it
    /// is a `deny` (fail closed).
    pub fn in_force(&self, now: Option<u64>) -> bool {
        self.validity().in_force(now, self.effect == Effect::Deny)
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
///
/// Order is part of the contract: every `visit_by_*` method hands out grants in the same relative
/// order as [`GrantSource::visit`]. [`crate::FirstApplicable`] decides by the first grant that
/// applies, so a listing that read the grants in another order would disagree with
/// [`crate::Engine::check`].
pub trait GrantIndex: GrantSource {
    /// Grants of any of the given permission keys, in the order of [`GrantSource::visit`].
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
