//! The policy as the language sees it: the real types of the crate gathered in one value, the
//! comments of the source (`notes`) and the source positions kept on the side.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::{
    CatalogExport, EngineSpec, Grant, InvariantSpec, OverrideSpec, RelationSpec, RoleSpec, StrategySpec, Subject, Tuple,
};

use super::error::Location;

/// The syntax a source is written in. Every file declares it on its first line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Language {
    /// Braced blocks of `field = value` lines.
    Blocks,
    /// One rule per line.
    Rules,
    /// Policy grouped by who acts.
    Actors,
}

impl Language {
    /// The word that declares the syntax.
    pub const fn name(self) -> &'static str {
        match self {
            Language::Blocks => "blocks",
            Language::Rules => "rules",
            Language::Actors => "actors",
        }
    }
}

impl fmt::Display for Language {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for Language {
    type Err = ();

    fn from_str(text: &str) -> Result<Self, ()> {
        match text {
            "blocks" => Ok(Language::Blocks),
            "rules" => Ok(Language::Rules),
            "actors" => Ok(Language::Actors),
            _ => Err(()),
        }
    }
}

/// Where a comment sits relative to the element it is anchored to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Placement {
    /// On the lines right above the element.
    Before,
    /// On the lines right below the element.
    After,
    /// On the same line as the element: the one comment on the line that opens it.
    Inline,
    /// Inside the element, past its first line: a second comment on the line that opens it, one on
    /// the line of a field of it, or lines indented under it. Comments of one element keep their
    /// order, and the field they sat on (see [`NoteOrigin::field`]) is only a hint.
    Inside,
}

/// The element a comment is attached to and its side. The element is named by its id (see [`ids`]),
/// never by a field of it, so every syntax gives the same anchor to the same comment.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NoteAnchor {
    pub element: String,
    pub placement: Placement,
}

/// Where a comment was read: kept for messages, never compared by [`Policy::equivalent`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteOrigin {
    pub file: String,
    pub language: Language,
    pub line: u32,
    pub column: u32,
    /// The field of the element the comment was written next to (`when`, `label`), if it was
    /// next to one: a hint for the printer to put it back in the same place. The anchor does not
    /// carry it, so a syntax with no such field anchors the comment on the same element.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

/// A comment of the source, kept so the text can be rebuilt from the JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Note {
    pub text: String,
    pub anchor: NoteAnchor,
    pub origin: NoteOrigin,
}

/// A whole policy: the engine spec, the facts and rules around it, and the notes. It serializes to
/// the canonical JSON, the same for every syntax.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Policy {
    pub catalog: CatalogExport,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<RoleSpec>,
    /// `Some` only when the source has a `relation` block, as in [`EngineSpec`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relations: Option<Vec<RelationSpec>>,
    #[serde(default)]
    pub strategy: StrategySpec,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub overrides: Vec<OverrideSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_relation_depth: Option<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subjects: Vec<Subject>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grants: Vec<Grant>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tuples: Vec<Tuple>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub invariants: Vec<InvariantSpec>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<Note>,
}

impl Policy {
    /// The engine part of the policy, ready for [`EngineSpec::builder`].
    pub fn engine_spec(&self) -> EngineSpec {
        EngineSpec {
            catalog: self.catalog.clone(),
            roles: self.roles.clone(),
            relations: self.relations.clone(),
            strategy: self.strategy,
            overrides: self.overrides.clone(),
            max_relation_depth: self.max_relation_depth,
        }
    }

    /// The canonical JSON of the policy.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Reads the canonical JSON. It does not validate: call [`Policy::validate`].
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// True when both describe the same policy and carry the same comments on the same elements.
    /// The order of roles, subjects, tuples, relations and kinds does not count, and neither do
    /// the source positions of the notes.
    ///
    /// Comments on the same element and side keep their order: swapping two is a difference.
    pub fn equivalent(&self, other: &Policy) -> bool {
        self.clone().canonical().canonical_value() == other.clone().canonical().canonical_value()
    }

    /// The policy with what has no meaning in its order put in a fixed one: the kinds, the roles
    /// (and what each inherits), the relations, the subjects and the tuples are sorted, and the
    /// notes are grouped by anchor with the comments of one anchor in the order they were written.
    /// Every syntax reads into this order, so the same policy has the same JSON in all of them.
    #[must_use]
    pub fn canonical(mut self) -> Policy {
        self.catalog.target_kinds.sort();
        self.catalog.broad_targets.sort();
        self.roles.sort_by(|a, b| a.role.cmp(&b.role));
        for role in &mut self.roles {
            role.inherits.sort();
        }
        if let Some(relations) = &mut self.relations {
            relations.sort_by(|a, b| (&a.kind, &a.relation).cmp(&(&b.kind, &b.relation)));
        }
        self.subjects.sort_by_cached_key(json_key);
        self.tuples.sort_by_cached_key(json_key);
        // Stable: the notes of one anchor stay in the order they were written.
        self.notes.sort_by(|a, b| a.anchor.cmp(&b.anchor));
        self
    }

    /// The JSON value of the policy as it is, with the origin of the notes left out.
    pub(crate) fn canonical_value(&self) -> serde_json::Value {
        let mut value = serde_json::to_value(self).unwrap_or(serde_json::Value::Null);
        if let Some(notes) = value.get_mut("notes").and_then(serde_json::Value::as_array_mut) {
            for note in notes {
                if let Some(map) = note.as_object_mut() {
                    map.remove("origin");
                }
            }
        }
        value
    }
}

fn json_key<T: Serialize>(item: &T) -> String {
    serde_json::to_value(item).map(|v| v.to_string()).unwrap_or_default()
}

/// Element ids: the stable names notes are anchored with, and the keys of [`Origins`].
pub mod ids {
    pub const LANGUAGE: &str = "language";
    pub const TARGET_KINDS: &str = "target_kinds";
    pub const BROAD_TARGETS: &str = "broad_targets";
    pub const STRATEGY: &str = "strategy";
    pub const MAX_DEPTH: &str = "max_depth";
    pub const TUPLES: &str = "tuples";
    pub const RELATIONS: &str = "relations";

    pub fn permission(key: &str) -> String {
        format!("permission:{key}")
    }

    pub fn role(name: &str) -> String {
        format!("role:{name}")
    }

    pub fn subject(kind: &str, id: &str) -> String {
        format!("subject:{kind}:{id}")
    }

    pub fn assign(subject: &str, role: &str) -> String {
        format!("{subject}/assign:{role}")
    }

    pub fn grant(id: &str) -> String {
        format!("grant:{id}")
    }

    pub fn relation(kind: &str, relation: &str) -> String {
        format!("relation:{kind}#{relation}")
    }

    pub fn tuple(text: &str) -> String {
        format!("tuple:{text}")
    }

    pub fn override_owner(attr: &str) -> String {
        format!("override:resource_owner:{attr}")
    }

    pub fn override_holder(permission: &str) -> String {
        format!("override:permission_holder:{permission}")
    }

    pub fn invariant(kind: &str, ordinal: usize) -> String {
        format!("invariant:{kind}:{ordinal}")
    }

    pub fn field(element: &str, field: &str) -> String {
        format!("{element}/{field}")
    }

    /// Splits the id of an extent into its element and the field under it, if any:
    /// `grant:g/when` is the element `grant:g` and the field `when`, while a role assignment
    /// (`subject:user:a/assign:r`) is an element of its own.
    pub fn split(id: &str) -> (&str, Option<&str>) {
        let mut from = 0;
        while let Some(slash) = id[from..].find('/') {
            let at = from + slash;
            let rest = &id[at + 1..];
            if rest.starts_with("assign:") {
                from = at + 1;
            } else {
                return (&id[..at], Some(rest));
            }
        }
        (id, None)
    }
}

/// Source positions by element id. Looking an id up falls back to its parent (the id without
/// the last `/segment`), so every element has a place to point at.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Origins(BTreeMap<String, Location>);

impl Origins {
    pub(crate) fn insert(&mut self, id: String, location: Location) {
        self.0.entry(id).or_insert(location);
    }

    pub(crate) fn rename_prefix(&mut self, from: &str, to: &str) {
        let below = format!("{from}/");
        let moved: Vec<String> = self
            .0
            .range::<str, _>((std::ops::Bound::Included(from), std::ops::Bound::Unbounded))
            .map(|(id, _)| id)
            .take_while(|id| id.starts_with(from))
            .filter(|id| id.as_str() == from || id.starts_with(&below))
            .cloned()
            .collect();
        for id in moved {
            if let Some(at) = self.0.remove(&id) {
                self.0.insert(format!("{to}{}", &id[from.len()..]), at);
            }
        }
    }

    /// The position of an element or, failing that, of the closest parent that has one.
    pub fn get(&self, id: &str) -> Option<&Location> {
        let mut current = id;
        loop {
            if let Some(found) = self.0.get(current) {
                return Some(found);
            }
            current = current.rsplit_once('/')?.0;
        }
    }

    /// The position exactly as recorded, with no fallback.
    pub fn exact(&self, id: &str) -> Option<&Location> {
        self.0.get(id)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &Location)> {
        self.0.iter().map(|(id, at)| (id.as_str(), at))
    }
}
