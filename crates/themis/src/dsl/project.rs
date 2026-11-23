//! A project: several sources, each in its own syntax, gathered into one validated policy.

use std::collections::BTreeMap;

use crate::dsl::error::{Diagnostic, Diagnostics, Location};
use crate::dsl::policy::{Language, Origins, Policy, ids};
use crate::dsl::validate::{invariant_kind, validate};
use crate::dsl::{Parsed, parse_unvalidated};
use crate::{InvariantSpec, OverrideRule};

/// The policy a [`Project`] builds and where each of its elements was declared.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Built {
    /// The merged policy: its JSON is the same whatever the syntaxes of the sources.
    pub policy: Policy,
    /// Where each element was declared, with the file of each.
    pub origins: Origins,
}

/// Several sources, each in its own syntax, gathered into one policy.
///
/// A source holds one syntax only. Two sources may not declare the same permission, grant,
/// relation or override differently, and may not give one subject attributes that disagree: each
/// such clash is reported with the position on both sides.
///
/// ```
/// use themis::dsl::Project;
///
/// let mut project = Project::new();
/// project
///     .add_source("kinds.themis", "language blocks\n\ntarget_kinds = [org]\n")
///     .unwrap();
/// project
///     .add_source(
///         "read.themis",
///         "language blocks\n\npermission org.read {\n  targets = [org]\n}\n",
///     )
///     .unwrap();
/// let built = project.build().unwrap();
/// assert_eq!(built.policy.catalog.permissions.len(), 1);
/// ```
#[derive(Debug, Default)]
pub struct Project {
    sources: Vec<Source>,
}

#[derive(Debug)]
struct Source {
    name: String,
    parsed: Parsed,
}

impl Project {
    /// An empty project.
    pub fn new() -> Self {
        Self::default()
    }

    /// How many sources the project holds.
    pub fn len(&self) -> usize {
        self.sources.len()
    }

    /// True when no source was added.
    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    /// Reads one source and adds it. `name` is the file name used in positions; it is never
    /// opened. The source is checked on its own syntax here and as part of the whole in
    /// [`Project::build`].
    ///
    /// # Errors
    /// Every syntax error of the source, or the repeated name; the project is left as it was.
    pub fn add_source(&mut self, name: &str, text: &str) -> Result<Language, Diagnostics> {
        if self.sources.iter().any(|s| s.name == name) {
            let found = Diagnostic::new(
                Some(Location::new(name, 1, 1, 1)),
                format!("the source `{name}` was already added"),
            )
            .with_hint("give each source of the project its own name");
            return Err(Diagnostics::new(vec![found]));
        }
        let parsed = parse_unvalidated(name, text)?;
        let language = parsed.language;
        self.sources.push(Source {
            name: name.to_string(),
            parsed,
        });
        Ok(language)
    }

    /// Merges the sources, in the order they were added, and validates the result.
    ///
    /// # Errors
    /// The clashes between sources, each with both positions; when there are none, the errors of
    /// the validation of the whole.
    pub fn build(&self) -> Result<Built, Diagnostics> {
        let mut merge = Merge::default();
        for source in &self.sources {
            merge.add(&source.parsed);
        }
        if !merge.clashes.is_empty() {
            return Err(Diagnostics::new(merge.clashes));
        }
        let found = validate(&merge.policy, Some(&merge.origins));
        if !found.is_empty() {
            return Err(Diagnostics::new(found));
        }
        Ok(Built {
            policy: merge.policy,
            origins: merge.origins,
        })
    }
}

#[derive(Default)]
struct Merge {
    policy: Policy,
    origins: Origins,
    clashes: Vec<Diagnostic>,
    /// The invariants kept, with the id each one has in the merged policy.
    invariant_ids: Vec<String>,
    invariants_per_kind: BTreeMap<&'static str, usize>,
}

impl Merge {
    fn add(&mut self, from: &Parsed) {
        let renamed = self.invariants(from);
        self.kinds(from);
        self.permissions(from);
        self.roles(from);
        self.subjects(from);
        self.grants(from);
        self.relations(from);
        self.settings(from);
        self.overrides(from);
        self.tuples(from);
        for (id, at) in from.origins.iter() {
            self.origins.insert(remap(id, &renamed), at.clone());
        }
        for note in &from.policy.notes {
            let mut note = note.clone();
            note.anchor.element = remap(&note.anchor.element, &renamed);
            self.policy.notes.push(note);
        }
    }

    fn clash(&mut self, id: &str, from: &Parsed, message: String, hint: &str) {
        let at = from.origins.get(id).cloned();
        let first = self.origins.get(id).cloned();
        self.clashes
            .push(Diagnostic::new(at, message).with_hint(hint).with_related(first));
    }

    fn kinds(&mut self, from: &Parsed) {
        let catalog = &mut self.policy.catalog;
        for kind in &from.policy.catalog.target_kinds {
            if !catalog.target_kinds.contains(kind) {
                catalog.target_kinds.push(kind.clone());
            }
        }
        for target in &from.policy.catalog.broad_targets {
            if !catalog.broad_targets.contains(target) {
                catalog.broad_targets.push(target.clone());
            }
        }
    }

    fn permissions(&mut self, from: &Parsed) {
        for def in &from.policy.catalog.permissions {
            let declared = self.policy.catalog.permissions.iter().any(|known| known.key == def.key);
            if declared {
                let message = format!("the permission `{}` is declared twice", def.key);
                self.clash(
                    &ids::permission(&def.key),
                    from,
                    message,
                    "declare each permission in one source only",
                );
            } else {
                self.policy.catalog.permissions.push(def.clone());
            }
        }
    }

    fn roles(&mut self, from: &Parsed) {
        for role in &from.policy.roles {
            match self.policy.roles.iter().find(|known| known.role == role.role) {
                None => self.policy.roles.push(role.clone()),
                Some(known) if known == role => {}
                Some(_) => {
                    let message = format!("the role `{}` is declared twice, differently", role.role);
                    self.clash(
                        &ids::role(&role.role),
                        from,
                        message,
                        "declare each role in one source only",
                    );
                }
            }
        }
    }

    fn subjects(&mut self, from: &Parsed) {
        for subject in &from.policy.subjects {
            let id = subject
                .id
                .as_deref()
                .map(|sid| ids::subject(&subject.kind, sid))
                .unwrap_or_default();
            let known = self
                .policy
                .subjects
                .iter()
                .position(|s| s.kind == subject.kind && s.id == subject.id);
            let Some(at) = known else {
                self.policy.subjects.push(subject.clone());
                continue;
            };
            let disagreement = subject.attrs.iter().find_map(|(name, value)| {
                self.policy.subjects[at]
                    .attrs
                    .get(name)
                    .filter(|other| *other != value)
                    .map(|_| name.clone())
            });
            if let Some(name) = disagreement {
                let message = format!(
                    "the subject `{}:{}` has two values for the attribute `{name}`",
                    subject.kind,
                    subject.id.as_deref().unwrap_or_default()
                );
                self.clash(&id, from, message, "give the attribute one value");
                continue;
            }
            let merged = &mut self.policy.subjects[at];
            for (name, value) in &subject.attrs {
                merged.attrs.insert(name.clone(), value.clone());
            }
            for principal in &subject.principals {
                if !merged.principals.contains(principal) {
                    merged.principals.push(principal.clone());
                }
            }
            for assignment in &subject.roles {
                if !merged.roles.contains(assignment) {
                    merged.roles.push(assignment.clone());
                }
            }
        }
    }

    fn grants(&mut self, from: &Parsed) {
        for grant in &from.policy.grants {
            if self.policy.grants.iter().any(|known| known.id == grant.id) {
                let message = format!("the grant `{}` is declared twice", grant.id);
                self.clash(
                    &ids::grant(&grant.id),
                    from,
                    message,
                    "give each grant an id of its own",
                );
            } else {
                self.policy.grants.push(grant.clone());
            }
        }
    }

    fn relations(&mut self, from: &Parsed) {
        let Some(incoming) = &from.policy.relations else {
            return;
        };
        for relation in incoming {
            let known = self.policy.relations.get_or_insert_with(Vec::new);
            let declared = known
                .iter()
                .any(|r| r.kind == relation.kind && r.relation == relation.relation);
            if declared {
                let message = format!(
                    "the relation `{}#{}` is declared twice",
                    relation.kind, relation.relation
                );
                self.clash(
                    &ids::relation(&relation.kind, &relation.relation),
                    from,
                    message,
                    "declare each relation in one source only",
                );
            } else {
                known.push(relation.clone());
            }
        }
    }

    /// `strategy` and `max_depth` count only where a source declares them.
    fn settings(&mut self, from: &Parsed) {
        if from.origins.exact(ids::STRATEGY).is_some() {
            let declared = self.origins.exact(ids::STRATEGY).is_some();
            if !declared {
                self.policy.strategy = from.policy.strategy;
            } else if self.policy.strategy != from.policy.strategy {
                self.clash(
                    ids::STRATEGY,
                    from,
                    "the strategy is set to two different values".to_string(),
                    "set the strategy in one source only",
                );
            }
        }
        if from.origins.exact(ids::MAX_DEPTH).is_some() {
            let declared = self.origins.exact(ids::MAX_DEPTH).is_some();
            if !declared {
                self.policy.max_relation_depth = from.policy.max_relation_depth;
            } else if self.policy.max_relation_depth != from.policy.max_relation_depth {
                self.clash(
                    ids::MAX_DEPTH,
                    from,
                    "max_depth is set to two different values".to_string(),
                    "set max_depth in one source only",
                );
            }
        }
    }

    fn overrides(&mut self, from: &Parsed) {
        for spec in &from.policy.overrides {
            let (id, name) = match &spec.rule {
                OverrideRule::ResourceOwner { attr } => (ids::override_owner(attr), attr.clone()),
                OverrideRule::PermissionHolder { permission } => (ids::override_holder(permission), permission.clone()),
            };
            match self.policy.overrides.iter().find(|known| known.rule == spec.rule) {
                None => self.policy.overrides.push(spec.clone()),
                Some(known) if known == spec => {}
                Some(_) => {
                    let message = format!("the override on `{name}` is declared twice, differently");
                    self.clash(&id, from, message, "declare each override in one source only");
                }
            }
        }
    }

    fn tuples(&mut self, from: &Parsed) {
        for tuple in &from.policy.tuples {
            if !self.policy.tuples.contains(tuple) {
                self.policy.tuples.push(tuple.clone());
            }
        }
    }

    /// Keeps the invariants this policy does not hold yet and numbers them per kind across
    /// the sources. Returns how the ids of this source map to the merged ones.
    fn invariants(&mut self, from: &Parsed) -> Vec<(String, String)> {
        let mut renamed = Vec::new();
        let mut local: BTreeMap<&'static str, usize> = BTreeMap::new();
        for spec in &from.policy.invariants {
            let kind = invariant_kind(spec);
            let ordinal = local.entry(kind).or_insert(0);
            *ordinal += 1;
            let old = ids::invariant(kind, *ordinal);
            let kept = self
                .policy
                .invariants
                .iter()
                .position(|known: &InvariantSpec| known == spec);
            let new = match kept.and_then(|at| self.invariant_ids.get(at)) {
                Some(existing) => existing.clone(),
                None => {
                    let count = self.invariants_per_kind.entry(kind).or_insert(0);
                    *count += 1;
                    let id = ids::invariant(kind, *count);
                    self.policy.invariants.push(spec.clone());
                    self.invariant_ids.push(id.clone());
                    id
                }
            };
            renamed.push((old, new));
        }
        renamed
    }
}

/// The merged id of an element: the invariants are the only ones renumbered.
fn remap(id: &str, renamed: &[(String, String)]) -> String {
    for (old, new) in renamed {
        if id == old {
            return new.clone();
        }
        if let Some(rest) = id.strip_prefix(old.as_str()).and_then(|r| r.strip_prefix('/')) {
            return format!("{new}/{rest}");
        }
    }
    id.to_string()
}
