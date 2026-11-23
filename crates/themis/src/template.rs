//! Role templates: a versioned set of model grants that is copied, never linked.
//!
//! [`RoleTemplate::materialize`] produces ordinary grants with the template id and version in the
//! metadata of the change. Changing the template afterwards does not touch what was already
//! materialized: the copies are plain grants, edited and removed like any other.

use serde::{Deserialize, Serialize};

use crate::attr::Attributes;
use crate::condition::Condition;
use crate::engine::Engine;
use crate::governance::{Governance, Mutation, Violation};
use crate::grant::{Effect, Grant, SubjectMatcher, TargetSelector};
use crate::rebac::TupleStore;
use crate::resource::Anchor;
use crate::subject::Subject;

/// Metadata key with the id of the template a change was materialized from.
pub const META_TEMPLATE: &str = "template";
/// Metadata key with the version of the template a change was materialized from.
pub const META_TEMPLATE_VERSION: &str = "template_version";

/// Model of one grant: everything but the subject, which is chosen at materialization.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TemplateGrant {
    /// Unique inside the template; the materialized grant id is `<prefix>:<id>`.
    pub id: String,
    pub permission: String,
    pub target: TargetSelector,
    #[serde(default = "default_effect")]
    pub effect: Effect,
    /// Fixed scope of this grant; without it, the scope given to `materialize` applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<Anchor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<Condition>,
}

fn default_effect() -> Effect {
    Effect::Allow
}

impl TemplateGrant {
    /// An `allow` of `permission` on `target`.
    pub fn allow(id: impl Into<String>, permission: impl Into<String>, target: TargetSelector) -> Self {
        Self {
            id: id.into(),
            permission: permission.into(),
            target,
            effect: Effect::Allow,
            scope: None,
            condition: None,
        }
    }

    #[must_use]
    pub fn scoped(mut self, scope: Anchor) -> Self {
        self.scope = Some(scope);
        self
    }

    #[must_use]
    pub fn when(mut self, condition: Condition) -> Self {
        self.condition = Some(condition);
        self
    }
}

/// Versioned set of model grants.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoleTemplate {
    pub id: String,
    pub version: u32,
    pub grants: Vec<TemplateGrant>,
}

impl RoleTemplate {
    pub fn new(id: impl Into<String>, version: u32) -> Self {
        Self {
            id: id.into(),
            version,
            grants: Vec::new(),
        }
    }

    #[must_use]
    pub fn grant(mut self, grant: TemplateGrant) -> Self {
        self.grants.push(grant);
        self
    }

    /// Copies the template into new grants for `subject`, ids prefixed with `id_prefix`. The result is
    /// detached from the template: nothing is stored that points back to it except the provenance in
    /// [`Materialized::meta`].
    ///
    /// `scope` applies to every model grant that has no scope of its own. With `None`, those grants
    /// have no scope at all and take effect everywhere their target does: a template meant for one
    /// project, materialized without a scope, comes out wider than intended. Pass a scope, and install
    /// [`NoEscalation`](crate::NoEscalation) to bound what an actor can hand out.
    ///
    /// The grant id is `<id_prefix>:<template grant id>`, so `a` + `b:c` and `a:b` + `c` collide; a
    /// repeated id, inside the template or against the current set, is refused when the change is applied.
    pub fn materialize(&self, subject: SubjectMatcher, scope: Option<Anchor>, id_prefix: &str) -> Materialized {
        let mutations = self
            .grants
            .iter()
            .map(|model| {
                let mut grant = Grant::new(
                    format!("{id_prefix}:{}", model.id),
                    model.effect,
                    subject.clone(),
                    model.permission.clone(),
                    model.target.clone(),
                );
                grant.scope = model.scope.clone().or_else(|| scope.clone());
                grant.condition = model.condition.clone();
                Mutation::Add(grant)
            })
            .collect();
        let mut meta = Attributes::new();
        meta.insert(META_TEMPLATE.to_string(), self.id.as_str().into());
        meta.insert(META_TEMPLATE_VERSION.to_string(), self.version.into());
        Materialized {
            template: self.id.clone(),
            template_version: self.version,
            mutations,
            meta,
        }
    }
}

/// Result of [`RoleTemplate::materialize`]: ordinary changes plus their provenance.
///
/// The provenance is declared by whoever builds the value, and this type is `Deserialize`: it is a
/// trace for the audit, not proof of origin. The invariants judge each change on its own merits
/// whatever the `meta` says. Writing [`Materialized::mutations`] straight to storage, instead of going
/// through [`Materialized::apply`], skips the invariants.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Materialized {
    pub template: String,
    pub template_version: u32,
    pub mutations: Vec<Mutation>,
    /// Provenance (`template`, `template_version`), sent as the metadata of each change.
    pub meta: Attributes,
}

impl Materialized {
    /// The changes in the order [`Materialized::apply`] sends them: a grant comes after the grants
    /// of the permissions it depends on (`depends_on`), since [`Prerequisites`](crate::Prerequisites)
    /// judges each change with only the earlier ones in place. Otherwise the order of the template is
    /// kept. Whoever applies the changes by other means follows this order.
    pub fn ordered(&self, engine: &Engine) -> Vec<&Mutation> {
        let depth = |m: &Mutation| match m {
            Mutation::Add(grant) => engine.catalog().prerequisites(&grant.permission).count(),
            _ => 0,
        };
        let mut ordered: Vec<&Mutation> = self.mutations.iter().collect();
        // A prerequisite closure is acyclic, so a permission always has more of them than each of its
        // own prerequisites: sorting by that count (stable) puts the prerequisites first.
        ordered.sort_by_key(|m| depth(m));
        ordered
    }

    /// Applies the changes in the order of [`Materialized::ordered`], each one through `governance` as
    /// an ordinary change: every grant is checked against the invariants with the earlier ones already in
    /// place, and the provenance goes to the audit as the change metadata.
    ///
    /// The whole batch is checked first, and only then recorded: the audit never says `applied` about a
    /// change the caller will discard. If one change is refused, only that refusal is recorded. If the
    /// audit itself fails halfway through the recording, the earlier records stay and the error comes
    /// back; the caller writes nothing, so the trail is then ahead of the stored set.
    ///
    /// # Errors
    ///
    /// The violations of the first refused change. Nothing is applied in that case: the caller
    /// writes the returned set only on `Ok`.
    pub fn apply(
        &self,
        governance: &Governance,
        engine: &Engine,
        actor: &Subject,
        current: &[Grant],
        tuples: Option<&dyn TupleStore>,
    ) -> Result<Vec<Grant>, Vec<Violation>> {
        let ordered = self.ordered(engine);
        let mut grants = current.to_vec();
        for mutation in &ordered {
            match governance.evaluate(engine, actor, &grants, mutation, tuples) {
                Ok(next) => grants = next,
                Err(violations) => {
                    return governance
                        .apply_with(engine, actor, &grants, mutation, tuples, &self.meta)
                        .and(Err(violations));
                }
            }
        }
        let mut grants = current.to_vec();
        for mutation in ordered {
            grants = governance.apply_with(engine, actor, &grants, mutation, tuples, &self.meta)?;
        }
        Ok(grants)
    }
}
