use serde::{Deserialize, Serialize};

use crate::attr::{Attributes, Value};
use crate::resource::{Anchor, ObjectRef, Resource};

/// Principal de todo usuário identificado.
pub const AUTHENTICATED: &str = "authenticated";
/// Principal de quem chega sem identidade.
pub const ANONYMOUS: &str = "anonymous";

/// Papel atribuído a um sujeito, opcionalmente restrito a um escopo (o papel numa organização
/// vale só para recursos cujo caminho passa por ela).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleAssignment {
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<Anchor>,
}

/// Quem pede o acesso.
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
    /// Usuário identificado, com o principal [`AUTHENTICATED`].
    pub fn user(id: impl Into<String>) -> Self {
        Self::of_kind("user", id).with_principal(AUTHENTICATED)
    }

    /// Visitante sem identidade, com o principal [`ANONYMOUS`].
    pub fn anonymous() -> Self {
        Self {
            kind: "user".to_string(),
            id: None,
            roles: Vec::new(),
            principals: vec![ANONYMOUS.to_string()],
            attrs: Attributes::new(),
        }
    }

    /// Sujeito de outro tipo (conta de serviço, dispositivo), sem principal.
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

    /// Papéis diretos que valem para o recurso: sem escopo, ou com escopo no caminho dele.
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
