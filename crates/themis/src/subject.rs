use serde::{Deserialize, Serialize};

use crate::attr::{Attributes, Value};
use crate::resource::{Anchor, ObjectRef, Resource};

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
        self.roles.push(RoleAssignment {
            role: role.into(),
            scope: None,
        });
        self
    }

    pub fn with_role_in(mut self, role: impl Into<String>, scope: Anchor) -> Self {
        self.roles.push(RoleAssignment {
            role: role.into(),
            scope: Some(scope),
        });
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

    /// Direct roles that hold for the resource: unscoped, or with a scope in its path.
    pub fn roles_for<'a>(&'a self, resource: &'a Resource) -> impl Iterator<Item = &'a str> {
        self.roles
            .iter()
            .filter(|r| r.scope.as_ref().is_none_or(|scope| resource.contains(scope)))
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
