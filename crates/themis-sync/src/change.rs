use serde::{Deserialize, Serialize};
use themis::{Anchor, Resource};

/// O que mudou.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Grants,
    Tuples,
    Roles,
    Catalog,
    /// Mudança da aplicação que também invalida permissões (plano do cliente, flag).
    Custom,
    /// O nó perdeu mudanças (reconexão do transporte, assinante atrasado): tudo que estiver em
    /// cache deve ser recarregado.
    Resync,
}

/// Aviso de que as permissões sob `scope` mudaram. Não carrega os grants: quem recebe
/// recarrega da fonte, então o aviso é pequeno e cabe em qualquer transporte (o `pg_notify`
/// aceita até 8000 bytes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    pub kind: ChangeKind,
    /// Degrau afetado. `global` afeta todos os recursos.
    pub scope: Anchor,
    /// Restringe o aviso a um sujeito (mudança de papel de uma pessoa).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Id do objeto mudado (grant, tupla), informativo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Nó que publicou. Preenchido pelo hub.
    #[serde(default)]
    pub origin: String,
    /// Sequência por origem. Preenchida pelo hub.
    #[serde(default)]
    pub seq: u64,
    /// Milissegundos desde a época Unix. Preenchido pelo hub.
    #[serde(default)]
    pub at: u64,
}

impl Change {
    pub fn new(kind: ChangeKind, scope: Anchor) -> Self {
        Self {
            kind,
            scope,
            subject: None,
            id: None,
            origin: String::new(),
            seq: 0,
            at: 0,
        }
    }

    pub fn grants(scope: Anchor) -> Self {
        Self::new(ChangeKind::Grants, scope)
    }

    pub fn tuples(scope: Anchor) -> Self {
        Self::new(ChangeKind::Tuples, scope)
    }

    pub fn roles(subject: impl Into<String>, scope: Anchor) -> Self {
        Self::new(ChangeKind::Roles, scope).for_subject(subject)
    }

    pub fn catalog() -> Self {
        Self::new(ChangeKind::Catalog, Anchor::global())
    }

    pub fn resync() -> Self {
        Self::new(ChangeKind::Resync, Anchor::global())
    }

    pub fn for_subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// A mudança afeta as permissões de `subject` sobre `scope`?
    pub fn affects(&self, subject: Option<&str>, scope: &Resource) -> bool {
        if self.kind == ChangeKind::Resync {
            return true;
        }
        if let Some(target) = &self.subject
            && subject != Some(target.as_str())
        {
            return false;
        }
        scope.contains(&self.scope)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("Change sempre serializa")
    }

    pub fn from_json(text: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_and_subject_filter() {
        let doc = Resource::new("document", "d1").within("project", "p1");
        assert!(Change::grants(Anchor::new("project", "p1")).affects(Some("u"), &doc));
        assert!(!Change::grants(Anchor::new("project", "p2")).affects(Some("u"), &doc));
        assert!(Change::catalog().affects(None, &doc));
        let roles = Change::roles("alice", Anchor::new("project", "p1"));
        assert!(roles.affects(Some("alice"), &doc));
        assert!(!roles.affects(Some("bob"), &doc));
    }

    #[test]
    fn json_round_trip() {
        let change = Change::grants(Anchor::new("org", "o1")).with_id("g1");
        assert_eq!(Change::from_json(&change.to_json()).unwrap(), change);
        assert_eq!(
            change.to_json(),
            r#"{"kind":"grants","scope":{"kind":"org","id":"o1"},"id":"g1","origin":"","seq":0,"at":0}"#
        );
    }
}
