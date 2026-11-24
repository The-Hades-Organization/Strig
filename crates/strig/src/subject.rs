use serde::{Deserialize, Serialize};

use crate::attr::{Attributes, Value};
use crate::resource::{Anchor, ObjectRef, Resource};
use crate::validity::{Validity, ValidityError};

/// Principal of every identified user.
pub const AUTHENTICATED: &str = "authenticated";
/// Principal of whoever arrives without an identity.
pub const ANONYMOUS: &str = "anonymous";

/// Role assigned to a subject, optionally restricted to a scope (a role in an organization
/// holds only for resources whose path goes through it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleAssignment {
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<Anchor>,
    /// Start of the validity window, in milliseconds since the Unix epoch (inclusive).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<u64>,
    /// End of the validity window, in milliseconds since the Unix epoch (exclusive).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<u64>,
}

impl RoleAssignment {
    /// Unscoped role with no window.
    pub fn new(role: impl Into<String>) -> Self {
        Self {
            role: role.into(),
            scope: None,
            valid_from: None,
            valid_until: None,
        }
    }

    /// Role restricted to the resources whose path goes through `scope`.
    pub fn in_scope(role: impl Into<String>, scope: Anchor) -> Self {
        Self {
            scope: Some(scope),
            ..Self::new(role)
        }
    }

    /// The assignment only exists from `from` on (milliseconds since the Unix epoch, inclusive).
    pub fn valid_from(mut self, from: u64) -> Self {
        self.valid_from = Some(from);
        self
    }

    /// The assignment stops existing at `until` (milliseconds since the Unix epoch, exclusive).
    pub fn valid_until(mut self, until: u64) -> Self {
        self.valid_until = Some(until);
        self
    }

    /// The assignment exists in `[from, until)`. [`RoleAssignment::check_window`] refuses an
    /// inverted window.
    pub fn valid_between(self, from: u64, until: u64) -> Self {
        self.valid_from(from).valid_until(until)
    }

    /// The validity window of the assignment.
    pub fn validity(&self) -> Validity {
        Validity {
            valid_from: self.valid_from,
            valid_until: self.valid_until,
        }
    }

    fn in_scope_of(&self, resource: &Resource) -> bool {
        self.scope.as_ref().is_none_or(|scope| resource.contains(scope))
    }

    /// # Errors
    /// [`ValidityError::Inverted`] when the window ends before it starts.
    pub fn check_window(&self) -> Result<(), ValidityError> {
        self.validity().check()
    }
}

/// Who requests the access.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Subject {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<RoleAssignment>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub principals: Vec<String>,
    #[serde(default, skip_serializing_if = "Attributes::is_empty")]
    pub attrs: Attributes,
}

impl Subject {
    /// Identified user, with the principal [`AUTHENTICATED`].
    pub fn user(id: impl Into<String>) -> Self {
        Self::of_kind("user", id).with_principal(AUTHENTICATED)
    }

    /// Visitor without an identity, with the principal [`ANONYMOUS`].
    pub fn anonymous() -> Self {
        Self {
            kind: "user".to_string(),
            id: None,
            roles: Vec::new(),
            principals: vec![ANONYMOUS.to_string()],
            attrs: Attributes::new(),
        }
    }

    /// Subject of another kind (service account, device), with no principal.
    pub fn of_kind(kind: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            id: Some(id.into()),
            roles: Vec::new(),
            principals: Vec::new(),
            attrs: Attributes::new(),
        }
    }

    pub fn with_role(mut self, role: impl Into<String>) -> Self {
        self.roles.push(RoleAssignment::new(role));
        self
    }

    /// Adds a prepared assignment, such as one with a validity window.
    pub fn with_assignment(mut self, assignment: RoleAssignment) -> Self {
        self.roles.push(assignment);
        self
    }

    pub fn with_role_in(mut self, role: impl Into<String>, scope: Anchor) -> Self {
        self.roles.push(RoleAssignment::in_scope(role, scope));
        self
    }

    pub fn with_principal(mut self, principal: impl Into<String>) -> Self {
        self.principals.push(principal.into());
        self
    }

    pub fn with_attr(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.attrs.insert(key.into(), value.into());
        self
    }

    pub fn object_ref(&self) -> Option<ObjectRef> {
        self.id.as_ref().map(|id| ObjectRef::new(self.kind.clone(), id.clone()))
    }

    /// Direct roles that hold for the resource: unscoped, or with a scope in its path. Assignments
    /// with a validity window are left out, because there is no instant to check them against;
    /// see [`Subject::roles_at`].
    pub fn roles_for<'a>(&'a self, resource: &'a Resource) -> impl Iterator<Item = &'a str> {
        self.roles_at(resource, None)
    }

    /// Direct roles that hold for the resource at `now`: scope in the path and inside the
    /// validity window. Without `now`, assignments with a window do not hold.
    pub fn roles_at<'a>(&'a self, resource: &'a Resource, now: Option<u64>) -> impl Iterator<Item = &'a str> {
        self.roles
            .iter()
            .filter(move |r| r.in_scope_of(resource) && r.validity().in_force(now, false))
            .map(|r| r.role.as_str())
    }

    /// Direct roles for the resource, counting the assignments whose window could not be checked
    /// (no `now`). A `deny` keyed on a role uses this set: an error never opens access.
    pub(crate) fn roles_for_denial<'a>(
        &'a self,
        resource: &'a Resource,
        now: Option<u64>,
    ) -> impl Iterator<Item = &'a str> {
        self.roles
            .iter()
            .filter(move |r| r.in_scope_of(resource) && r.validity().in_force(now, true))
            .map(|r| r.role.as_str())
    }

    pub fn has_principal(&self, principal: &str) -> bool {
        self.principals.iter().any(|p| p == principal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoped_role_applies_only_inside_scope() {
        let s = Subject::user("u")
            .with_role_in("editor", Anchor::new("org", "o1"))
            .with_role("viewer");
        let inside = Resource::new("project", "p").within("org", "o1");
        let outside = Resource::new("project", "p").within("org", "o2");
        assert_eq!(s.roles_for(&inside).collect::<Vec<_>>(), ["editor", "viewer"]);
        assert_eq!(s.roles_for(&outside).collect::<Vec<_>>(), ["viewer"]);
    }
}
