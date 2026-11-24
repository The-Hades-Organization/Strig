//! A project: several sources, each in its own syntax, gathered into one validated policy.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::OverrideRule;
use crate::dsl::error::{Diagnostic, Diagnostics, Location, MAX_DIAGNOSTICS, capped};
use crate::dsl::policy::{Language, Origins, Policy, ids};
use crate::dsl::validate::{invariant_kind, validate};
use crate::dsl::{MAX_SOURCE_BYTES, Parsed, parse_unvalidated};

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
/// A source holds one syntax only (its first line says which), and sources of different syntaxes
/// join in one project. Two sources may not declare the same thing: a permission, role, grant,
/// relation, override, tuple, invariant or kind, an attribute or role of one subject, or a
/// setting. Repeating it word for word is a clash too. Each clash is reported with the position
/// on both sides.
///
/// ```
/// use strig::dsl::Project;
///
/// let mut project = Project::new();
/// project
///     .add_source("kinds.strig", "language blocks\n\ntarget_kinds = [org]\n")
///     .unwrap();
/// project
///     .add_source(
///         "read.strig",
///         "language blocks\n\npermission org.read {\n  targets = [org]\n}\n",
///     )
///     .unwrap();
/// let built = project.build().unwrap();
/// assert_eq!(built.policy.catalog.permissions.len(), 1);
/// ```
#[derive(Debug, Default)]
pub struct Project {
    sources: Vec<Source>,
    bytes: usize,
}

/// The most sources a project takes.
pub const MAX_SOURCES: usize = 10_000;
/// The most bytes all the sources of a project may hold together.
pub const MAX_PROJECT_BYTES: usize = 16 * MAX_SOURCE_BYTES;

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
        if self.sources.len() >= MAX_SOURCES {
            let found = Diagnostic::new(
                Some(Location::new(name, 1, 1, 1)),
                format!("a project holds at most {MAX_SOURCES} sources"),
            );
            return Err(Diagnostics::new(vec![found]));
        }
        if self.bytes.saturating_add(text.len()) > MAX_PROJECT_BYTES {
            let found = Diagnostic::new(
                Some(Location::new(name, 1, 1, 1)),
                format!("the sources of a project hold at most {MAX_PROJECT_BYTES} bytes together"),
            );
            return Err(Diagnostics::new(vec![found]));
        }
        let parsed = parse_unvalidated(name, text)?;
        self.bytes += text.len();
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
            return Err(Diagnostics::new(capped(merge.clashes, merge.hidden)));
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
    /// Clashes past the cap: counted, not kept.
    hidden: usize,
    kinds: HashSet<String>,
    broad: HashSet<String>,
    permissions: HashSet<String>,
    roles: HashSet<String>,
    grants: HashSet<String>,
    relations: HashSet<(String, String)>,
    overrides: HashSet<String>,
    tuples: HashSet<String>,
    subjects: HashMap<(String, Option<String>), usize>,
    /// The role of a subject, by the index of the subject in the merged policy.
    assigned: HashSet<(usize, String)>,
    /// The invariants kept, by what they say, with the id each one has in the merged policy.
    invariants: HashMap<String, String>,
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
        if self.clashes.len() > MAX_DIAGNOSTICS {
            self.hidden += 1;
            return;
        }
        let at = from.origins.get(id).cloned();
        let first = self.origins.get(id).cloned();
        self.clashes
            .push(Diagnostic::new(at, message).with_hint(hint).with_related(first));
    }

    fn kinds(&mut self, from: &Parsed) {
        for kind in &from.policy.catalog.target_kinds {
            if self.kinds.insert(kind.clone()) {
                self.policy.catalog.target_kinds.push(kind.clone());
            } else {
                let message = format!("the kind `{kind}` is listed in target_kinds twice");
                self.clash(ids::TARGET_KINDS, from, message, "list each kind in one source only");
            }
        }
        for target in &from.policy.catalog.broad_targets {
            if self.broad.insert(target.clone()) {
                self.policy.catalog.broad_targets.push(target.clone());
            } else {
                let message = format!("the kind `{target}` is listed in broad_targets twice");
                self.clash(ids::BROAD_TARGETS, from, message, "list each kind in one source only");
            }
        }
    }

    fn permissions(&mut self, from: &Parsed) {
        for def in &from.policy.catalog.permissions {
            if self.permissions.insert(def.key.clone()) {
                self.policy.catalog.permissions.push(def.clone());
            } else {
                let message = format!("the permission `{}` is declared twice", def.key);
                self.clash(
                    &ids::permission(&def.key),
                    from,
                    message,
                    "declare each permission in one source only",
                );
            }
        }
    }

    fn roles(&mut self, from: &Parsed) {
        for role in &from.policy.roles {
            if self.roles.insert(role.role.clone()) {
                self.policy.roles.push(role.clone());
            } else {
                let message = format!("the role `{}` is declared twice", role.role);
                self.clash(
                    &ids::role(&role.role),
                    from,
                    message,
                    "declare each role in one source only",
                );
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
            let key = (subject.kind.clone(), subject.id.clone());
            let Some(&at) = self.subjects.get(&key) else {
                let at = self.policy.subjects.len();
                for assignment in &subject.roles {
                    self.assigned.insert((at, assignment.role.clone()));
                }
                self.subjects.insert(key, at);
                self.policy.subjects.push(subject.clone());
                continue;
            };
            let label = format!("{}:{}", subject.kind, subject.id.as_deref().unwrap_or_default());
            for name in subject.attrs.keys() {
                if self.policy.subjects[at].attrs.contains_key(name) {
                    let message = format!("the subject `{label}` has the attribute `{name}` in two sources");
                    self.clash(&id, from, message, "give each attribute in one source only");
                } else if let Some(value) = subject.attrs.get(name) {
                    self.policy.subjects[at].attrs.insert(name.clone(), value.clone());
                }
            }
            for principal in &subject.principals {
                if self.policy.subjects[at].principals.contains(principal) {
                    let message = format!("the subject `{label}` has the principal `{principal}` in two sources");
                    self.clash(&id, from, message, "list each principal in one source only");
                } else {
                    self.policy.subjects[at].principals.push(principal.clone());
                }
            }
            for assignment in &subject.roles {
                if self.assigned.insert((at, assignment.role.clone())) {
                    self.policy.subjects[at].roles.push(assignment.clone());
                } else {
                    let message = format!(
                        "the subject `{label}` is given the role `{}` in two sources",
                        assignment.role
                    );
                    self.clash(
                        &ids::assign(&id, &assignment.role),
                        from,
                        message,
                        "assign each role to a subject in one source only",
                    );
                }
            }
        }
    }

    fn grants(&mut self, from: &Parsed) {
        for grant in &from.policy.grants {
            if self.grants.insert(grant.id.clone()) {
                self.policy.grants.push(grant.clone());
            } else {
                let message = format!("the grant `{}` is declared twice", grant.id);
                self.clash(
                    &ids::grant(&grant.id),
                    from,
                    message,
                    "give each grant an id of its own",
                );
            }
        }
    }

    fn relations(&mut self, from: &Parsed) {
        let Some(incoming) = &from.policy.relations else {
            return;
        };
        for relation in incoming {
            let known = self.policy.relations.get_or_insert_with(Vec::new);
            if self
                .relations
                .insert((relation.kind.clone(), relation.relation.clone()))
            {
                known.push(relation.clone());
            } else {
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
            }
        }
    }

    /// `strategy` and `max_depth` count only where a source declares them, and only one may.
    fn settings(&mut self, from: &Parsed) {
        if from.origins.exact(ids::STRATEGY).is_some() {
            if self.origins.exact(ids::STRATEGY).is_none() {
                self.policy.strategy = from.policy.strategy;
            } else {
                self.clash(
                    ids::STRATEGY,
                    from,
                    "the strategy is set in two sources".to_string(),
                    "set the strategy in one source only",
                );
            }
        }
        if from.origins.exact(ids::MAX_DEPTH).is_some() {
            if self.origins.exact(ids::MAX_DEPTH).is_none() {
                self.policy.max_relation_depth = from.policy.max_relation_depth;
            } else {
                self.clash(
                    ids::MAX_DEPTH,
                    from,
                    "max_depth is set in two sources".to_string(),
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
            if self.overrides.insert(id.clone()) {
                self.policy.overrides.push(spec.clone());
            } else {
                let message = format!("the override on `{name}` is declared twice");
                self.clash(&id, from, message, "declare each override in one source only");
            }
        }
    }

    fn tuples(&mut self, from: &Parsed) {
        for tuple in &from.policy.tuples {
            let text = tuple.to_string();
            if self.tuples.contains(&text) {
                let message = format!("the tuple `{text}` is declared twice");
                self.clash(
                    &ids::tuple(&text),
                    from,
                    message,
                    "declare each tuple in one source only",
                );
            } else {
                self.tuples.insert(text);
                self.policy.tuples.push(tuple.clone());
            }
        }
    }

    /// Keeps the invariants this policy does not hold yet and numbers them per kind across
    /// the sources. Returns how the ids of this source map to the merged ones.
    fn invariants(&mut self, from: &Parsed) -> HashMap<String, String> {
        let mut renamed = HashMap::new();
        let mut local: BTreeMap<&'static str, usize> = BTreeMap::new();
        for spec in &from.policy.invariants {
            let kind = invariant_kind(spec);
            let ordinal = local.entry(kind).or_insert(0);
            *ordinal += 1;
            let old = ids::invariant(kind, *ordinal);
            let said = format!("{spec:?}");
            let new = match self.invariants.get(&said) {
                Some(existing) => {
                    let existing = existing.clone();
                    let message = format!("the invariant `{kind}` is declared twice");
                    self.clash(&old, from, message, "declare each invariant in one source only");
                    existing
                }
                None => {
                    let count = self.invariants_per_kind.entry(kind).or_insert(0);
                    *count += 1;
                    let id = ids::invariant(kind, *count);
                    self.policy.invariants.push(spec.clone());
                    self.invariants.insert(said, id.clone());
                    id
                }
            };
            renamed.insert(old, new);
        }
        renamed
    }
}

/// The merged id of an element: the invariants are the only ones renumbered. An invariant id has
/// no `/` of its own, so the element is what comes before the first one.
fn remap(id: &str, renamed: &HashMap<String, String>) -> String {
    let (element, rest) = match id.split_once('/') {
        Some((element, rest)) => (element, Some(rest)),
        None => (id, None),
    };
    match (renamed.get(element), rest) {
        (Some(new), Some(rest)) => format!("{new}/{rest}"),
        (Some(new), None) => new.clone(),
        (None, _) => id.to_string(),
    }
}
