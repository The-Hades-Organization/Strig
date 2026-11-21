use std::fmt;
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

use crate::attr::{Attributes, Value};
use crate::grant::TargetSelector;

/// Tipo de alvo implícito no fim de todo caminho de recurso.
pub const GLOBAL: &str = "global";

static GLOBAL_ANCHOR: LazyLock<Anchor> = LazyLock::new(Anchor::global);

/// Objeto identificado, usado pelo ReBAC (`document:42`, `user:alice`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ObjectRef {
    pub kind: String,
    pub id: String,
}

impl ObjectRef {
    pub fn new(kind: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            id: id.into(),
        }
    }
}

impl fmt::Display for ObjectRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.kind, self.id)
    }
}

/// Um degrau do caminho de especificidade de um recurso.
///
/// `id` identifica a instância (`project:42`) ou uma faceta (`doc_type:invoice`). Sem `id`, o
/// degrau representa o tipo inteiro, como o `global`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Anchor {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

impl Anchor {
    pub fn new(kind: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            id: Some(id.into()),
        }
    }

    pub fn kind_only(kind: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            id: None,
        }
    }

    pub fn global() -> Self {
        Self::kind_only(GLOBAL)
    }

    pub fn is_global(&self) -> bool {
        self.kind == GLOBAL
    }

    pub fn object_ref(&self) -> Option<ObjectRef> {
        self.id.as_ref().map(|id| ObjectRef::new(self.kind.clone(), id.clone()))
    }
}

impl fmt::Display for Anchor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.id {
            Some(id) => write!(f, "{}:{}", self.kind, id),
            None => f.write_str(&self.kind),
        }
    }
}

/// Recurso sob decisão.
///
/// `path` vai do degrau mais específico para o mais amplo, por exemplo
/// `[document:7, doc_type:invoice, project:42, org:9]`. O `global` é implícito no fim. A posição
/// no caminho é a especificidade usada pela estratégia de combinação: índice menor, alvo mais
/// específico.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Resource {
    pub path: Vec<Anchor>,
    #[serde(default, skip_serializing_if = "Attributes::is_empty")]
    pub attrs: Attributes,
}

impl Resource {
    pub fn new(kind: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            path: vec![Anchor::new(kind, id)],
            attrs: Attributes::new(),
        }
    }

    /// Recurso sem degrau próprio: só alvos `global` se aplicam.
    pub fn global() -> Self {
        Self::default()
    }

    /// Acrescenta um degrau mais amplo ao fim do caminho.
    pub fn within(mut self, kind: impl Into<String>, id: impl Into<String>) -> Self {
        self.path.push(Anchor::new(kind, id));
        self
    }

    pub fn with_attr(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.attrs.insert(key.into(), value.into());
        self
    }

    /// Degrau mais específico, que dá o tipo e o id do recurso.
    pub fn primary(&self) -> Option<&Anchor> {
        self.path.first()
    }

    pub fn contains(&self, anchor: &Anchor) -> bool {
        anchor.is_global() || self.path.iter().any(|a| a == anchor)
    }

    /// Primeiro degrau casado pelo seletor e sua posição. O `global` implícito fica na
    /// posição `path.len()`.
    pub fn locate(&self, selector: &TargetSelector) -> Option<(usize, &Anchor)> {
        self.anchors().find(|(_, anchor)| selector.matches(anchor))
    }

    /// Degraus do caminho com a posição de cada um, terminando no `global` implícito.
    pub fn anchors(&self) -> impl Iterator<Item = (usize, &Anchor)> {
        let explicit_global = self.path.iter().any(Anchor::is_global);
        let tail = (!explicit_global).then_some(&*GLOBAL_ANCHOR);
        self.path.iter().chain(tail).enumerate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document() -> Resource {
        Resource::new("document", "d1")
            .within("doc_type", "invoice")
            .within("project", "p1")
            .within("org", "o1")
    }

    #[test]
    fn global_is_last_anchor() {
        let r = document();
        let (rank, anchor) = r.locate(&TargetSelector::global()).unwrap();
        assert_eq!(rank, 4);
        assert!(anchor.is_global());
    }

    #[test]
    fn selector_without_id_matches_any_instance_of_kind() {
        let r = document();
        let (rank, anchor) = r.locate(&TargetSelector::kind("project")).unwrap();
        assert_eq!(rank, 2);
        assert_eq!(anchor.id.as_deref(), Some("p1"));
    }

    #[test]
    fn selector_with_other_id_does_not_match() {
        assert!(document().locate(&TargetSelector::exact("project", "p2")).is_none());
    }
}
