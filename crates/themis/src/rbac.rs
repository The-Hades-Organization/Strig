use std::collections::{BTreeMap, BTreeSet};

use crate::graph;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RbacError {
    #[error("ciclo de herança de papéis: {}", .0.join(" -> "))]
    Cycle(Vec<String>),
}

/// Herança entre papéis: quem tem `admin` também tem tudo que `editor` tem.
#[derive(Debug, Clone, Default)]
pub struct RoleGraph {
    inherits: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Default)]
pub struct RoleGraphBuilder {
    inherits: BTreeMap<String, Vec<String>>,
}

impl RoleGraphBuilder {
    /// `role` herda os grants de `parent`.
    pub fn inherit(mut self, role: impl Into<String>, parent: impl Into<String>) -> Self {
        let parent = parent.into();
        self.inherits.entry(parent.clone()).or_default();
        self.inherits.entry(role.into()).or_default().push(parent);
        self
    }

    pub fn build(self) -> Result<RoleGraph, RbacError> {
        match graph::find_cycle(&self.inherits) {
            Some(cycle) => Err(RbacError::Cycle(cycle)),
            None => Ok(RoleGraph {
                inherits: self.inherits,
            }),
        }
    }
}

impl RoleGraph {
    pub fn builder() -> RoleGraphBuilder {
        RoleGraphBuilder::default()
    }

    /// Papéis diretos mais todos os herdados.
    pub fn expand<'a>(&self, roles: impl IntoIterator<Item = &'a str>) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for role in roles {
            if out.contains(role) {
                continue;
            }
            out.extend(graph::reachable(role, &self.inherits));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_transitively() {
        let g = RoleGraph::builder()
            .inherit("admin", "editor")
            .inherit("editor", "viewer")
            .build()
            .unwrap();
        assert_eq!(
            g.expand(["admin"]).into_iter().collect::<Vec<_>>(),
            ["admin", "editor", "viewer"]
        );
        assert_eq!(g.expand(["guest"]).into_iter().collect::<Vec<_>>(), ["guest"]);
    }

    #[test]
    fn rejects_cycle() {
        let err = RoleGraph::builder()
            .inherit("a", "b")
            .inherit("b", "a")
            .build()
            .unwrap_err();
        assert!(matches!(err, RbacError::Cycle(_)));
    }
}
