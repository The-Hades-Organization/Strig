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

/// A quem um grant se aplica.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SubjectMatcher {
    /// Um sujeito pelo id.
    User { id: String },
    /// Quem tem o papel, direto ou herdado pelo [`crate::RoleGraph`].
    Role { id: String },
    /// Quem carrega o principal (`authenticated`, `anonymous` ou um próprio).
    Principal { name: String },
    /// Quem tem a relação ReBAC sobre o degrau casado pelo alvo do grant.
    Relation { relation: String },
    /// Qualquer sujeito.
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

/// Onde um grant se ancora no caminho do recurso. Sem `id`, casa qualquer instância do tipo.
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

/// Concessão ou negação de uma permissão do catálogo.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Grant {
    pub id: String,
    pub subject: SubjectMatcher,
    pub permission: String,
    pub target: TargetSelector,
    pub effect: Effect,
    /// Restringe o grant a recursos cujo caminho passa por este degrau (o time dono, por
    /// exemplo).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<Anchor>,
    /// Condição ABAC; o grant só se aplica quando ela é verdadeira.
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

/// Origem dos grants consultados numa decisão.
///
/// A implementação pode entregar grants a mais (o motor filtra por permissão, alvo, escopo,
/// sujeito e condição); entregar a menos muda a decisão. Uma fonte apoiada em banco usa
/// `subject` e `resource` para montar a consulta.
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

/// Encadeia duas fontes, como grants do banco mais uma linha de base sintética.
impl<A: GrantSource, B: GrantSource> GrantSource for (A, B) {
    fn visit(&self, subject: &Subject, resource: &Resource, visitor: &mut dyn FnMut(&Grant)) {
        self.0.visit(subject, resource, visitor);
        self.1.visit(subject, resource, visitor);
    }
}
