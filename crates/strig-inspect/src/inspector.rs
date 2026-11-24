use std::collections::BTreeSet;

use strig::{Context, Effect, Engine, Explanation, Grant, InMemoryTuples, Request, Resource, Subject};

use crate::scenario::{LoadError, Scenario};

/// Um cenário carregado e o motor montado a partir dele, com um conjunto de grants que pode ser
/// alterado para simular ("e se este grant não existisse?", "e se eu concedesse aquilo?").
pub struct Inspector {
    scenario: Scenario,
    engine: Engine,
    tuples: InMemoryTuples,
    disabled: BTreeSet<String>,
    added: Vec<Grant>,
}

/// Linha × coluna de uma matriz de acesso.
#[derive(Debug, Clone, PartialEq)]
pub struct Matrix {
    pub resource: String,
    pub permissions: Vec<String>,
    pub subjects: Vec<String>,
    /// `cells[permissão][sujeito]`: efeito com os grants simulados.
    pub cells: Vec<Vec<Effect>>,
    /// O mesmo, com os grants originais do cenário.
    pub baseline: Vec<Vec<Effect>>,
}

impl Matrix {
    pub fn changed(&self, permission: usize, subject: usize) -> bool {
        self.cells[permission][subject] != self.baseline[permission][subject]
    }

    /// Células que a simulação mudou: (permissão, sujeito, antes, depois).
    pub fn changes(&self) -> Vec<(&str, &str, Effect, Effect)> {
        let mut out = Vec::new();
        for (p, row) in self.cells.iter().enumerate() {
            for (s, effect) in row.iter().enumerate() {
                if self.changed(p, s) {
                    out.push((
                        self.permissions[p].as_str(),
                        self.subjects[s].as_str(),
                        self.baseline[p][s],
                        *effect,
                    ));
                }
            }
        }
        out
    }
}

#[derive(Debug, thiserror::Error)]
pub enum InspectError {
    #[error("unknown subject in the scenario: {0}")]
    UnknownSubject(String),
    #[error("unknown resource in the scenario: {0}")]
    UnknownResource(String),
}

impl Inspector {
    pub fn new(scenario: Scenario) -> Result<Self, LoadError> {
        let engine = scenario.spec.build()?;
        let tuples = scenario.tuples.iter().cloned().collect();
        Ok(Self {
            scenario,
            engine,
            tuples,
            disabled: BTreeSet::new(),
            added: Vec::new(),
        })
    }

    /// Troca o cenário mantendo a simulação (grants desligados e acrescentados).
    pub fn replace(&mut self, scenario: Scenario) -> Result<(), LoadError> {
        let mut next = Self::new(scenario)?;
        next.disabled = std::mem::take(&mut self.disabled);
        next.added = std::mem::take(&mut self.added);
        *self = next;
        Ok(())
    }

    pub fn scenario(&self) -> &Scenario {
        &self.scenario
    }

    /// As relações do cenário, para montar um `Context` igual ao que a avaliação usa.
    pub fn tuples(&self) -> &InMemoryTuples {
        &self.tuples
    }

    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    pub fn permissions(&self) -> Vec<String> {
        self.engine.catalog().all().iter().map(|d| d.key.clone()).collect()
    }

    pub fn subject(&self, name: &str) -> Result<&Subject, InspectError> {
        self.scenario
            .subjects
            .get(name)
            .ok_or_else(|| InspectError::UnknownSubject(name.to_string()))
    }

    pub fn resource(&self, name: &str) -> Result<&Resource, InspectError> {
        self.scenario
            .resources
            .get(name)
            .ok_or_else(|| InspectError::UnknownResource(name.to_string()))
    }

    // Simulação

    pub fn is_enabled(&self, grant_id: &str) -> bool {
        !self.disabled.contains(grant_id)
    }

    pub fn toggle(&mut self, grant_id: &str) {
        if !self.disabled.remove(grant_id) {
            self.disabled.insert(grant_id.to_string());
        }
    }

    /// Acrescenta um grant só na simulação. Um id repetido substitui o anterior.
    pub fn add(&mut self, grant: Grant) {
        self.added.retain(|g| g.id != grant.id);
        self.added.push(grant);
    }

    pub fn added(&self) -> &[Grant] {
        &self.added
    }

    pub fn reset(&mut self) {
        self.disabled.clear();
        self.added.clear();
    }

    pub fn is_simulating(&self) -> bool {
        !self.disabled.is_empty() || !self.added.is_empty()
    }

    /// Os grants em vigor na simulação.
    pub fn active_grants(&self) -> Vec<Grant> {
        self.scenario
            .grants
            .iter()
            .filter(|g| self.is_enabled(&g.id))
            .chain(&self.added)
            .cloned()
            .collect()
    }

    // Avaliação

    fn explain_with(&self, grants: &[Grant], subject: &Subject, permission: &str, resource: &Resource) -> Explanation {
        let ctx = Context::new(&grants)
            .with_tuples(&self.tuples)
            .with_env(&self.scenario.env);
        self.engine.explain(&ctx, &Request::new(subject, permission, resource))
    }

    pub fn explain(&self, subject: &Subject, permission: &str, resource: &Resource) -> Explanation {
        self.explain_with(&self.active_grants(), subject, permission, resource)
    }

    /// Como [`Inspector::explain`], com os grants originais do cenário.
    pub fn explain_baseline(&self, subject: &Subject, permission: &str, resource: &Resource) -> Explanation {
        self.explain_with(&self.scenario.grants, subject, permission, resource)
    }

    pub fn explain_named(&self, subject: &str, permission: &str, resource: &str) -> Result<Explanation, InspectError> {
        Ok(self.explain(self.subject(subject)?, permission, self.resource(resource)?))
    }

    fn decide_all(&self, grants: &[Grant], resource: &Resource, permissions: &[String]) -> Vec<Vec<Effect>> {
        let ctx = Context::new(&grants)
            .with_tuples(&self.tuples)
            .with_env(&self.scenario.env);
        permissions
            .iter()
            .map(|permission| {
                self.scenario
                    .subjects
                    .values()
                    .map(|subject| {
                        self.engine
                            .decide(&ctx, &Request::new(subject, permission, resource))
                            .effect
                    })
                    .collect()
            })
            .collect()
    }

    /// Cada permissão do catálogo para cada sujeito do cenário sobre `resource`.
    pub fn matrix(&self, resource: &str) -> Result<Matrix, InspectError> {
        let target = self.resource(resource)?;
        let permissions = self.permissions();
        Ok(Matrix {
            resource: resource.to_string(),
            subjects: self.scenario.subjects.keys().cloned().collect(),
            cells: self.decide_all(&self.active_grants(), target, &permissions),
            baseline: self.decide_all(&self.scenario.grants, target, &permissions),
            permissions,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use strig::{Reason, SubjectMatcher, TargetSelector, Verdict};

    pub(crate) const SCENARIO: &str = r#"{
      "spec": {
        "catalog": {
          "targetKinds": ["project", "document"],
          "broadTargets": ["org"],
          "permissions": [
            {"key": "project.view", "targets": ["project"]},
            {"key": "project.edit", "targets": ["project"]},
            {"key": "document.view", "targets": ["project", "document"], "impliedBy": ["project.view"]}
          ]
        },
        "roles": [{"role": "admin", "inherits": ["member"]}],
        "overrides": [{"kind": "resource_owner", "attr": "owner"}]
      },
      "grants": [
        {"id": "members-view", "subject": {"kind": "role", "id": "member"}, "permission": "project.view",
         "target": {"kind": "org"}, "effect": "allow", "scope": {"kind": "org", "id": "acme"}},
        {"id": "no-secret", "subject": {"kind": "any"}, "permission": "document.view",
         "target": {"kind": "document", "id": "secret"}, "effect": "deny"},
        {"id": "pro-edit", "subject": {"kind": "role", "id": "member"}, "permission": "project.edit",
         "target": {"kind": "project"}, "effect": "allow",
         "condition": {"op": "eq", "left": {"attr": "subject.plan"}, "right": "pro"}}
      ],
      "subjects": {
        "ana": {"kind": "user", "id": "ana", "roles": [{"role": "admin", "scope": {"kind": "org", "id": "acme"}}], "attrs": {"plan": "pro"}},
        "ben": {"kind": "user", "id": "ben", "roles": [{"role": "member", "scope": {"kind": "org", "id": "acme"}}], "attrs": {"plan": "free"}},
        "visitor": {"kind": "user", "principals": ["anonymous"]}
      },
      "resources": {
        "roadmap": {"path": [{"kind": "project", "id": "roadmap"}, {"kind": "org", "id": "acme"}]},
        "secret": {"path": [{"kind": "document", "id": "secret"}, {"kind": "project", "id": "roadmap"}, {"kind": "org", "id": "acme"}]}
      }
    }"#;

    pub(crate) fn inspector() -> Inspector {
        Inspector::new(Scenario::from_json(SCENARIO, "teste").unwrap()).unwrap()
    }

    #[test]
    fn explanation_shows_each_grant_fate() {
        let inspector = inspector();
        let e = inspector.explain_named("ben", "document.view", "secret").unwrap();
        assert!(!e.decision.is_allowed());
        let verdicts: Vec<_> = e.grants.iter().map(|g| (g.grant.id.as_str(), &g.verdict)).collect();
        assert_eq!(verdicts[0], ("members-view", &Verdict::Candidate));
        assert_eq!(verdicts[1], ("no-secret", &Verdict::Candidate));
        assert_eq!(verdicts[2], ("pro-edit", &Verdict::PermissionUnrelated));
        assert_eq!(e.decisive().unwrap().grant.id, "no-secret");
        assert_eq!(e.roles, ["member"]);

        let edit = inspector.explain_named("ben", "project.edit", "roadmap").unwrap();
        assert_eq!(edit.grants[2].verdict, Verdict::ConditionFalse);
        assert!(edit.grants[2].condition.is_some());
    }

    #[test]
    fn explanation_equals_decide() {
        let inspector = inspector();
        let grants = inspector.active_grants();
        let ctx = Context::new(&grants);
        for subject in inspector.scenario().subjects.values() {
            for resource in inspector.scenario().resources.values() {
                for permission in inspector.permissions() {
                    let request = Request::new(subject, &permission, resource);
                    assert_eq!(
                        inspector.engine().explain(&ctx, &request).decision,
                        inspector.engine().decide(&ctx, &request)
                    );
                }
            }
        }
    }

    #[test]
    fn simulation_changes_the_matrix() {
        let mut inspector = inspector();
        let before = inspector.matrix("secret").unwrap();
        assert!(before.changes().is_empty());

        inspector.toggle("no-secret");
        inspector.add(Grant::allow(
            "sim-edit",
            SubjectMatcher::user("ben"),
            "project.edit",
            TargetSelector::kind("project"),
        ));
        let after = inspector.matrix("secret").unwrap();
        let changes = after.changes();
        assert!(changes.contains(&("document.view", "ben", Effect::Deny, Effect::Allow)));
        assert!(changes.contains(&("project.edit", "ben", Effect::Deny, Effect::Allow)));
        assert!(!changes.iter().any(|c| c.1 == "visitor"));

        let e = inspector.explain_named("ben", "document.view", "secret").unwrap();
        assert!(matches!(e.decision.reason, Reason::Grant { ref grant_id, .. } if grant_id == "members-view"));
        inspector.reset();
        assert!(!inspector.is_simulating());
    }
}
