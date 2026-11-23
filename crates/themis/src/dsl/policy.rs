//! The policy as the language sees it: the real types of the crate gathered in one value, the
//! comments of the source (`notes`) and the source positions kept on the side.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::{
    CatalogExport, EngineSpec, Grant, InvariantSpec, OverrideSpec, RelationSpec, RoleSpec,
    StrategySpec, Subject, Tuple,
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
    /// On the same line as the element.
    Inline,
}

/// The element a comment is attached to and its side. See [`ids`] for the element ids.
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
    pub fn equivalent(&self, other: &Policy) -> bool {
        self.normalized() == other.normalized()
    }

    fn normalized(&self) -> serde_json::Value {
        let mut policy = self.clone();
        policy.catalog.target_kinds.sort();
        policy.catalog.broad_targets.sort();
        policy.roles.sort_by(|a, b| a.role.cmp(&b.role));
        for role in &mut policy.roles {
            role.inherits.sort();
        }
        if let Some(relations) = &mut policy.relations {
            relations.sort_by(|a, b| (&a.kind, &a.relation).cmp(&(&b.kind, &b.relation)));
        }
        let mut notes: Vec<_> = policy
            .notes
            .drain(..)
            .map(|note| (note.anchor, note.text))
            .collect();
        notes.sort();
        let mut value = serde_json::to_value(&policy).unwrap_or(serde_json::Value::Null);
        sort_array(&mut value, "subjects");
        sort_array(&mut value, "tuples");
        if let Some(map) = value.as_object_mut() {
            map.insert(
                "notes".to_string(),
                serde_json::to_value(&notes).unwrap_or(serde_json::Value::Null),
            );
        }
        value
    }
}

fn sort_array(value: &mut serde_json::Value, key: &str) {
    if let Some(items) = value.get_mut(key).and_then(serde_json::Value::as_array_mut) {
        items.sort_by_key(ToString::to_string);
    }
}

/// Element ids: the stable names notes are anchored with, and the keys of [`Origins`].
pub mod ids {
    pub const LANGUAGE: &str = "language";
    pub const TARGET_KINDS: &str = "target_kinds";
    pub const BROAD_TARGETS: &str = "broad_targets";
    pub const STRATEGY: &str = "strategy";
    pub const MAX_DEPTH: &str = "max_depth";
    pub const TUPLES: &str = "tuples";

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
            .keys()
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
