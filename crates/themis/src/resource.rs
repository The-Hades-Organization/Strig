use std::fmt;
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

use crate::attr::{Attributes, Value};
use crate::grant::TargetSelector;

/// Implicit target kind at the end of every resource path.
pub const GLOBAL: &str = "global";

static GLOBAL_ANCHOR: LazyLock<Anchor> = LazyLock::new(Anchor::global);

/// Identified object, used by ReBAC (`document:42`, `user:alice`).
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

/// One step of a resource's specificity path.
///
/// `id` identifies the instance (`project:42`) or a facet (`doc_type:invoice`). Without `id`, the
/// step represents the whole kind, like `global`.
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

/// Resource under decision.
///
/// `path` goes from the most specific step to the broadest, for example
/// `[document:7, doc_type:invoice, project:42, org:9]`. The `global` is implicit at the end. The
/// position in the path is the specificity used by the combination strategy: lower index, more
/// specific target.
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

    /// Resource with no step of its own: only `global` targets apply.
    pub fn global() -> Self {
        Self::default()
    }

    /// Adds a broader step at the end of the path.
    pub fn within(mut self, kind: impl Into<String>, id: impl Into<String>) -> Self {
        self.path.push(Anchor::new(kind, id));
        self
    }

    pub fn with_attr(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.attrs.insert(key.into(), value.into());
        self
    }

    /// Most specific step, which gives the resource's kind and id.
    pub fn primary(&self) -> Option<&Anchor> {
        self.path.first()
    }

    pub fn contains(&self, anchor: &Anchor) -> bool {
        anchor.is_global() || self.path.iter().any(|a| a == anchor)
    }

    /// First step matched by the selector and its position. The implicit `global` sits at
    /// position `path.len()`.
    pub fn locate(&self, selector: &TargetSelector) -> Option<(usize, &Anchor)> {
        self.anchors().find(|(_, anchor)| selector.matches(anchor))
    }

    /// Steps of the path with the position of each, ending in the implicit `global`.
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
