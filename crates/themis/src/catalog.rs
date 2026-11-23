use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::attr::{Attributes, Value};
use crate::graph;
use crate::resource::GLOBAL;

/// Definition of an atomic permission.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionDef {
    pub key: String,
    /// Target kinds a grant of this permission can anchor to, besides the broad ones.
    pub targets: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// More general permissions that grant this one. A grant on any of them holds here.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub implied_by: Vec<String>,
    /// Prerequisites: holding this permission requires holding each of these on the same resource.
    /// The opposite direction of `implied_by`. Checked by the engine in every decision and by the
    /// [`Prerequisites`](crate::Prerequisites) invariant in governance.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<String>,
    /// Whoever merely holds the permission cannot grant it to others; only an actor with the
    /// management permission configured in [`NonDelegable`](crate::NonDelegable) can.
    #[serde(default, skip_serializing_if = "is_false")]
    pub non_delegable: bool,
    /// Can only be granted to the roles declared as management roles in
    /// [`ManagementOnly`](crate::ManagementOnly), never to a user, principal or common role.
    #[serde(default, skip_serializing_if = "is_false")]
    pub management_only: bool,
    /// Holds only through an override. A grant that cites it is refused by catalog conformance
    /// ([`GrantError::OverrideOnly`](crate::GrantError::OverrideOnly)) and ignored by the decision.
    #[serde(default, skip_serializing_if = "is_false")]
    pub override_only: bool,
    /// Application metadata (UI group, display level, sensitivity). The engine does not read it;
    /// catalog rules ([`CatalogRule`]) can require it.
    #[serde(default, skip_serializing_if = "Attributes::is_empty")]
    pub meta: Attributes,
}

impl PermissionDef {
    pub fn new(key: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            targets: Vec::new(),
            label: None,
            description: None,
            implied_by: Vec::new(),
            depends_on: Vec::new(),
            non_delegable: false,
            management_only: false,
            override_only: false,
            meta: Attributes::new(),
        }
    }

    pub fn targets<I, S>(mut self, targets: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.targets.extend(targets.into_iter().map(Into::into));
        self
    }

    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    pub fn implied_by<I, S>(mut self, parents: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.implied_by.extend(parents.into_iter().map(Into::into));
        self
    }

    /// Holding this permission requires holding each of `prerequisites` on the same resource.
    #[must_use]
    pub fn depends_on<I, S>(mut self, prerequisites: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.depends_on.extend(prerequisites.into_iter().map(Into::into));
        self
    }

    /// Marks the permission as not delegable by whoever merely holds it.
    #[must_use]
    pub fn non_delegable(mut self) -> Self {
        self.non_delegable = true;
        self
    }

    /// Marks the permission as grantable only to management roles.
    #[must_use]
    pub fn management_only(mut self) -> Self {
        self.management_only = true;
        self
    }

    /// Marks the permission as valid only through an override.
    #[must_use]
    pub fn override_only(mut self) -> Self {
        self.override_only = true;
        self
    }

    pub fn meta(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.meta.insert(key.into(), value.into());
        self
    }
}

fn is_false(flag: &bool) -> bool {
    !*flag
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CatalogError {
    #[error("chave inválida '{0}': use segmentos [a-z0-9_] separados por ponto")]
    InvalidKey(String),
    #[error("chave duplicada '{0}'")]
    DuplicateKey(String),
    #[error("'{key}' é implicada por chave inexistente '{parent}'")]
    UnknownParent { key: String, parent: String },
    #[error("'{key}' depende de chave inexistente '{prerequisite}'")]
    UnknownPrerequisite { key: String, prerequisite: String },
    #[error("ciclo de pré-requisitos: {}", .0.join(" -> "))]
    PrerequisiteCycle(Vec<String>),
    #[error("'{key}' mira tipo de alvo não registrado '{target}'")]
    UnknownTarget { key: String, target: String },
    #[error("'{0}' não declara nenhum alvo")]
    NoTargets(String),
    #[error("ciclo de implicação: {}", .0.join(" -> "))]
    Cycle(Vec<String>),
    #[error("'{key}' viola a regra {rule}: {message}")]
    Rule { rule: String, key: String, message: String },
}

/// All the errors of a catalog, at once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogErrors(pub Vec<CatalogError>);

impl fmt::Display for CatalogErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "catálogo inválido ({} erro(s)):", self.0.len())?;
        for error in &self.0 {
            writeln!(f, "  - {error}")?;
        }
        Ok(())
    }
}

impl std::error::Error for CatalogErrors {}

/// Application-specific validation over each permission, run in
/// [`CatalogBuilder::build`] alongside the structural validations.
pub trait CatalogRule {
    fn name(&self) -> &str;
    /// Returns the error message if `def` violates the rule.
    fn check(&self, def: &PermissionDef) -> Option<String>;
}

/// Requires the metadata key `meta` on permissions whose key ends with `suffix` (all of them, with
/// no suffix), optionally restricted to a list of values.
#[derive(Debug, Clone)]
pub struct RequireMeta {
    name: String,
    meta: String,
    suffix: Option<String>,
    allowed: Vec<Value>,
}

impl RequireMeta {
    pub fn new(meta: impl Into<String>) -> Self {
        let meta = meta.into();
        Self {
            name: format!("require_meta:{meta}"),
            meta,
            suffix: None,
            allowed: Vec::new(),
        }
    }

    pub fn for_suffix(mut self, suffix: impl Into<String>) -> Self {
        self.suffix = Some(suffix.into());
        self
    }

    pub fn one_of<I, V>(mut self, values: I) -> Self
    where
        I: IntoIterator<Item = V>,
        V: Into<Value>,
    {
        self.allowed = values.into_iter().map(Into::into).collect();
        self
    }
}

impl CatalogRule for RequireMeta {
    fn name(&self) -> &str {
        &self.name
    }

    fn check(&self, def: &PermissionDef) -> Option<String> {
        if self.suffix.as_ref().is_some_and(|s| !def.key.ends_with(s.as_str())) {
            return None;
        }
        match def.meta.get(&self.meta) {
            None => Some(format!("falta o metadado '{}'", self.meta)),
            Some(value) if !self.allowed.is_empty() && !self.allowed.contains(value) => {
                Some(format!("'{}' fora dos valores aceitos: {value:?}", self.meta))
            }
            Some(_) => None,
        }
    }
}

/// Rule built from a closure.
pub struct FnRule<F> {
    name: String,
    f: F,
}

impl<F: Fn(&PermissionDef) -> Option<String>> FnRule<F> {
    pub fn new(name: impl Into<String>, f: F) -> Self {
        Self { name: name.into(), f }
    }
}

impl<F: Fn(&PermissionDef) -> Option<String>> CatalogRule for FnRule<F> {
    fn name(&self) -> &str {
        &self.name
    }

    fn check(&self, def: &PermissionDef) -> Option<String> {
        (self.f)(def)
    }
}

/// Serializable form of the catalog, to generate frontend types or load from configuration.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogExport {
    pub target_kinds: Vec<String>,
    #[serde(default)]
    pub broad_targets: Vec<String>,
    pub permissions: Vec<PermissionDef>,
}

#[derive(Default)]
pub struct CatalogBuilder {
    target_kinds: Vec<String>,
    broad_targets: Vec<String>,
    rules: Vec<Box<dyn CatalogRule>>,
    defs: Vec<PermissionDef>,
}

impl fmt::Debug for CatalogBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CatalogBuilder")
            .field("target_kinds", &self.target_kinds)
            .field("broad_targets", &self.broad_targets)
            .field("rules", &self.rules.iter().map(|r| r.name()).collect::<Vec<_>>())
            .field("defs", &self.defs.len())
            .finish()
    }
}

impl CatalogBuilder {
    pub fn target_kind(mut self, kind: impl Into<String>) -> Self {
        self.target_kinds.push(kind.into());
        self
    }

    pub fn target_kinds<I, S>(mut self, kinds: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.target_kinds.extend(kinds.into_iter().map(Into::into));
        self
    }

    /// Target kind accepted by any permission, such as the organization or the tenant. `global`
    /// is already broad.
    pub fn broad_target(mut self, kind: impl Into<String>) -> Self {
        self.broad_targets.push(kind.into());
        self
    }

    pub fn rule(mut self, rule: impl CatalogRule + 'static) -> Self {
        self.rules.push(Box::new(rule));
        self
    }

    pub fn permission(mut self, def: PermissionDef) -> Self {
        self.defs.push(def);
        self
    }

    /// Adds the permissions of a module at once.
    pub fn permissions(mut self, defs: impl IntoIterator<Item = PermissionDef>) -> Self {
        self.defs.extend(defs);
        self
    }

    pub fn build(self) -> Result<Catalog, CatalogErrors> {
        let mut broad_targets: BTreeSet<String> = self.broad_targets.into_iter().collect();
        broad_targets.insert(GLOBAL.to_string());
        let mut target_kinds: BTreeSet<String> = self.target_kinds.into_iter().collect();
        target_kinds.extend(broad_targets.iter().cloned());

        let mut errors = Vec::new();
        let mut index = HashMap::new();
        for (i, def) in self.defs.iter().enumerate() {
            if !valid_key(&def.key) {
                errors.push(CatalogError::InvalidKey(def.key.clone()));
            }
            if index.insert(def.key.clone(), i).is_some() {
                errors.push(CatalogError::DuplicateKey(def.key.clone()));
            }
            if def.targets.is_empty() {
                errors.push(CatalogError::NoTargets(def.key.clone()));
            }
            for target in def.targets.iter().filter(|t| !target_kinds.contains(*t)) {
                errors.push(CatalogError::UnknownTarget {
                    key: def.key.clone(),
                    target: target.clone(),
                });
            }
            for rule in &self.rules {
                if let Some(message) = rule.check(def) {
                    errors.push(CatalogError::Rule {
                        rule: rule.name().to_string(),
                        key: def.key.clone(),
                        message,
                    });
                }
            }
        }
        for def in &self.defs {
            for parent in def.implied_by.iter().filter(|p| !index.contains_key(*p)) {
                errors.push(CatalogError::UnknownParent {
                    key: def.key.clone(),
                    parent: parent.clone(),
                });
            }
        }
        for def in &self.defs {
            for prerequisite in def.depends_on.iter().filter(|p| !index.contains_key(*p)) {
                errors.push(CatalogError::UnknownPrerequisite {
                    key: def.key.clone(),
                    prerequisite: prerequisite.clone(),
                });
            }
        }
        if !errors.is_empty() {
            return Err(CatalogErrors(errors));
        }

        let parents: BTreeMap<String, Vec<String>> = self
            .defs
            .iter()
            .map(|d| (d.key.clone(), d.implied_by.clone()))
            .collect();
        if let Some(cycle) = graph::find_cycle(&parents) {
            return Err(CatalogErrors(vec![CatalogError::Cycle(cycle)]));
        }
        let requires: BTreeMap<String, Vec<String>> = self
            .defs
            .iter()
            .map(|d| (d.key.clone(), d.depends_on.clone()))
            .collect();
        if let Some(cycle) = graph::find_cycle(&requires) {
            return Err(CatalogErrors(vec![CatalogError::PrerequisiteCycle(cycle)]));
        }
        let required = requires
            .keys()
            .filter_map(|k| {
                let mut set = graph::reachable(k, &requires);
                set.remove(k);
                (!set.is_empty()).then(|| (k.clone(), set))
            })
            .collect();
        let effective = parents
            .keys()
            .map(|k| (k.clone(), graph::reachable(k, &parents)))
            .collect();

        let mut children: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for def in &self.defs {
            for parent in &def.implied_by {
                children.entry(parent.clone()).or_default().push(def.key.clone());
            }
        }

        Ok(Catalog {
            defs: self.defs,
            index,
            effective,
            required,
            children,
            target_kinds,
            broad_targets,
        })
    }
}

fn valid_key(key: &str) -> bool {
    !key.is_empty()
        && key.split('.').all(|segment| {
            !segment.is_empty()
                && segment
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        })
}

/// Validated, immutable catalog of permissions.
#[derive(Debug, Clone)]
pub struct Catalog {
    defs: Vec<PermissionDef>,
    index: HashMap<String, usize>,
    effective: HashMap<String, BTreeSet<String>>,
    /// Prerequisites of each permission, transitively; permissions with none are absent.
    required: HashMap<String, BTreeSet<String>>,
    children: BTreeMap<String, Vec<String>>,
    target_kinds: BTreeSet<String>,
    broad_targets: BTreeSet<String>,
}

impl Catalog {
    pub fn builder() -> CatalogBuilder {
        CatalogBuilder::default()
    }

    /// Builder preloaded with an export, to add rules before validating.
    pub fn builder_from(export: CatalogExport) -> CatalogBuilder {
        let mut builder = Self::builder().target_kinds(export.target_kinds);
        for kind in export.broad_targets {
            builder = builder.broad_target(kind);
        }
        builder.permissions(export.permissions)
    }

    pub fn from_export(export: CatalogExport) -> Result<Self, CatalogErrors> {
        Self::builder_from(export).build()
    }

    pub fn export(&self) -> CatalogExport {
        CatalogExport {
            target_kinds: self.target_kinds.iter().cloned().collect(),
            broad_targets: self.broad_targets.iter().cloned().collect(),
            permissions: self.defs.clone(),
        }
    }

    pub fn get(&self, key: &str) -> Option<&PermissionDef> {
        self.index.get(key).map(|i| &self.defs[*i])
    }

    pub fn contains(&self, key: &str) -> bool {
        self.index.contains_key(key)
    }

    pub fn all(&self) -> &[PermissionDef] {
        &self.defs
    }

    pub fn len(&self) -> usize {
        self.defs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.defs.is_empty()
    }

    /// The key and every permission that grants it, transitively.
    pub fn effective(&self, key: &str) -> Option<&BTreeSet<String>> {
        self.effective.get(key)
    }

    /// Every permission that holding `key` requires, transitively and without `key` itself.
    /// Empty when `key` has no prerequisites or is not in the catalog.
    pub fn prerequisites(&self, key: &str) -> impl Iterator<Item = &str> {
        self.required.get(key).into_iter().flatten().map(String::as_str)
    }

    /// `key` has at least one prerequisite.
    pub fn has_prerequisites(&self, key: &str) -> bool {
        self.required.contains_key(key)
    }

    /// `key` is in the catalog and is marked [`PermissionDef::override_only`].
    pub fn is_override_only(&self, key: &str) -> bool {
        self.get(key).is_some_and(|d| d.override_only)
    }

    /// `general` grants `specific` (or is the same key).
    pub fn implies(&self, general: &str, specific: &str) -> bool {
        self.effective(specific).is_some_and(|set| set.contains(general))
    }

    /// Permissions granted directly by `key`.
    pub fn children(&self, key: &str) -> &[String] {
        self.children.get(key).map(Vec::as_slice).unwrap_or(&[])
    }

    /// All permissions granted by `key`, transitively, not including itself.
    pub fn descendants(&self, key: &str) -> BTreeSet<String> {
        let mut set = graph::reachable(key, &self.children);
        set.remove(key);
        set
    }

    pub fn is_target_kind(&self, kind: &str) -> bool {
        self.target_kinds.contains(kind)
    }

    pub fn is_broad_target(&self, kind: &str) -> bool {
        self.broad_targets.contains(kind)
    }

    /// A grant of `key` can anchor to `kind`.
    pub fn allows_target(&self, key: &str, kind: &str) -> bool {
        self.is_broad_target(kind) || self.get(key).is_some_and(|d| d.targets.iter().any(|t| t == kind))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> CatalogBuilder {
        Catalog::builder()
            .target_kinds(["project", "document"])
            .broad_target("org")
    }

    #[test]
    fn effective_contains_key_and_ancestors() {
        let cat = base()
            .permission(PermissionDef::new("project.view").targets(["project"]))
            .permission(
                PermissionDef::new("document.view")
                    .targets(["project"])
                    .implied_by(["project.view"]),
            )
            .permission(
                PermissionDef::new("document.report.view")
                    .targets(["document"])
                    .implied_by(["document.view"]),
            )
            .build()
            .unwrap();
        let eff = cat.effective("document.report.view").unwrap();
        assert_eq!(eff.len(), 3);
        assert!(cat.implies("project.view", "document.report.view"));
        assert!(!cat.implies("document.report.view", "project.view"));
        assert_eq!(cat.descendants("project.view").len(), 2);
        assert_eq!(cat.children("project.view"), ["document.view"]);
    }

    #[test]
    fn collects_every_error() {
        let errors = base()
            .rule(
                RequireMeta::new("visibility")
                    .for_suffix(".view")
                    .one_of(["hide", "redact"]),
            )
            .permission(PermissionDef::new("Bad Key").targets(["project"]))
            .permission(
                PermissionDef::new("a.edit")
                    .targets(["nowhere"])
                    .implied_by(["missing"]),
            )
            .permission(PermissionDef::new("a.edit").targets(["project"]))
            .permission(PermissionDef::new("a.view").targets(["project"]))
            .permission(
                PermissionDef::new("b.view")
                    .targets(["project"])
                    .meta("visibility", "blur"),
            )
            .permission(PermissionDef::new("a.run"))
            .build()
            .unwrap_err();
        let has = |pred: fn(&CatalogError) -> bool| errors.0.iter().any(pred);
        assert!(has(|e| matches!(e, CatalogError::InvalidKey(_))));
        assert!(has(|e| matches!(e, CatalogError::DuplicateKey(_))));
        assert!(has(|e| matches!(e, CatalogError::UnknownTarget { .. })));
        assert!(has(|e| matches!(e, CatalogError::UnknownParent { .. })));
        assert!(has(|e| matches!(e, CatalogError::NoTargets(_))));
        let rule_errors: Vec<_> = errors
            .0
            .iter()
            .filter_map(|e| match e {
                CatalogError::Rule { key, .. } => Some(key.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(rule_errors, ["a.view", "b.view"]);
    }

    #[test]
    fn closure_rule() {
        let errors = base()
            .rule(FnRule::new("has_label", |def: &PermissionDef| {
                def.label.is_none().then(|| "sem rótulo".to_string())
            }))
            .permission(PermissionDef::new("a.edit").targets(["project"]))
            .build()
            .unwrap_err();
        assert!(matches!(&errors.0[..], [CatalogError::Rule { rule, .. }] if rule == "has_label"));
    }

    #[test]
    fn rejects_implication_cycle() {
        let errors = base()
            .permission(PermissionDef::new("a.x").targets(["project"]).implied_by(["a.y"]))
            .permission(PermissionDef::new("a.y").targets(["project"]).implied_by(["a.x"]))
            .build()
            .unwrap_err();
        assert!(matches!(errors.0.as_slice(), [CatalogError::Cycle(_)]));
    }

    #[test]
    fn broad_targets_accept_any_permission() {
        let cat = base()
            .permission(PermissionDef::new("a.edit").targets(["project"]))
            .build()
            .unwrap();
        assert!(cat.allows_target("a.edit", "org"));
        assert!(cat.allows_target("a.edit", GLOBAL));
        assert!(!cat.allows_target("a.edit", "document"));
    }

    #[test]
    fn export_round_trip() {
        let cat = base()
            .permission(
                PermissionDef::new("a.edit")
                    .targets(["project"])
                    .label("Editar")
                    .meta("group", "a"),
            )
            .build()
            .unwrap();
        let json = serde_json::to_string(&cat.export()).unwrap();
        let back = Catalog::from_export(serde_json::from_str(&json).unwrap()).unwrap();
        assert_eq!(back.export(), cat.export());
    }

    #[test]
    fn prerequisites_are_transitive() {
        let cat = base()
            .permission(PermissionDef::new("a.view").targets(["project"]))
            .permission(PermissionDef::new("a.edit").targets(["project"]).depends_on(["a.view"]))
            .permission(PermissionDef::new("a.publish").targets(["project"]).depends_on(["a.edit"]))
            .build()
            .unwrap();
        assert_eq!(cat.prerequisites("a.publish").collect::<Vec<_>>(), ["a.edit", "a.view"]);
        assert!(cat.has_prerequisites("a.edit") && !cat.has_prerequisites("a.view"));
        assert_eq!(cat.prerequisites("missing").count(), 0);
    }

    #[test]
    fn rejects_unknown_prerequisite() {
        let errors = base()
            .permission(PermissionDef::new("a.edit").targets(["project"]).depends_on(["a.nope"]))
            .build()
            .unwrap_err();
        assert!(matches!(
            errors.0.as_slice(),
            [CatalogError::UnknownPrerequisite { key, prerequisite }] if key == "a.edit" && prerequisite == "a.nope"
        ));
    }

    #[test]
    fn rejects_prerequisite_cycle_and_self_dependency() {
        let cycle = base()
            .permission(PermissionDef::new("a.x").targets(["project"]).depends_on(["a.y"]))
            .permission(PermissionDef::new("a.y").targets(["project"]).depends_on(["a.x"]))
            .build()
            .unwrap_err();
        assert!(matches!(cycle.0.as_slice(), [CatalogError::PrerequisiteCycle(_)]));
        let itself = base()
            .permission(PermissionDef::new("a.x").targets(["project"]).depends_on(["a.x"]))
            .build()
            .unwrap_err();
        assert!(matches!(itself.0.as_slice(), [CatalogError::PrerequisiteCycle(_)]));
    }

    #[test]
    fn attributes_survive_export_round_trip() {
        let cat = base()
            .permission(PermissionDef::new("a.view").targets(["project"]))
            .permission(
                PermissionDef::new("a.admin")
                    .targets(["project"])
                    .depends_on(["a.view"])
                    .non_delegable()
                    .management_only()
                    .override_only(),
            )
            .build()
            .unwrap();
        let json = serde_json::to_string(&cat.export()).unwrap();
        assert!(json.contains("\"nonDelegable\":true") && json.contains("\"dependsOn\":[\"a.view\"]"));
        assert!(!json.contains("\"overrideOnly\":false"));
        let back = Catalog::from_export(serde_json::from_str(&json).unwrap()).unwrap();
        let def = back.get("a.admin").unwrap();
        assert!(def.non_delegable && def.management_only && def.override_only);
        assert!(back.is_override_only("a.admin") && !back.is_override_only("a.view"));
    }
}
