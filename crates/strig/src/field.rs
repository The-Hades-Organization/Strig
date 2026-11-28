//! Field-level permissions: a grant that names fields gives or takes away only those fields of
//! the resource.
//!
//! # Semantics
//!
//! A grant without fields covers the whole resource, as it always did. A grant with fields covers
//! only those. A question about one field ([`crate::Request::field`]) is answered by the same
//! machinery as a question about the resource: only the grants that cover the field are
//! candidates, and the strategy (`MostSpecific`, `DenyOverrides`, ...) picks among them. So the
//! strategies need no new rule, and `implied_by` and `depends_on` keep their meaning: a grant of
//! `document.manage` restricted to `title` gives `document.edit` on `title` only, and a
//! prerequisite is judged on the same field.
//!
//! A question about the resource as a whole (no field) is answered like this:
//!
//! 1. Only grants without fields can allow it: a field-restricted `allow` is never enough to act
//!    on the whole resource.
//! 2. A field-restricted `deny` blocks it as soon as the strategy would deny any of its fields:
//!    the whole resource is allowed only if every field is.
//!
//! Policies without fields are decided exactly as before.
//!
//! Everything fails closed. A condition that cannot be evaluated drops an `allow` and keeps a
//! `deny`, per field too. If the catalog declares the fields of a permission
//! ([`crate::PermissionDef::fields`]), a field outside the list is denied.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::decision::Reason;

/// The fields of a resource a subject may use for a permission, as [`crate::Engine::allowed_fields`]
/// answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum FieldSet {
    /// Every field.
    All,
    /// Every field but these. Only possible when the catalog does not declare the fields of the
    /// permission, so the engine cannot list "the rest".
    AllExcept { fields: BTreeSet<String> },
    /// Exactly these fields.
    Only { fields: BTreeSet<String> },
    /// No field: the permission is denied.
    None,
}

impl FieldSet {
    /// Is `field` in the set?
    pub fn contains(&self, field: &str) -> bool {
        match self {
            FieldSet::All => true,
            FieldSet::AllExcept { fields } => !fields.contains(field),
            FieldSet::Only { fields } => fields.contains(field),
            FieldSet::None => false,
        }
    }

    /// Is no field allowed?
    pub fn is_none(&self) -> bool {
        matches!(self, FieldSet::None)
    }

    /// Is every field allowed?
    pub fn is_all(&self) -> bool {
        matches!(self, FieldSet::All)
    }

    pub(crate) fn only(fields: BTreeSet<String>) -> Self {
        if fields.is_empty() {
            FieldSet::None
        } else {
            FieldSet::Only { fields }
        }
    }

    pub(crate) fn all_except(fields: BTreeSet<String>) -> Self {
        if fields.is_empty() {
            FieldSet::All
        } else {
            FieldSet::AllExcept { fields }
        }
    }
}

/// Why one field came out allowed or denied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct FieldVerdict {
    /// The field, or `None` for every field no grant and no catalog entry names ("the rest").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    pub allowed: bool,
    pub reason: Reason,
    /// Ids of the `allow` grants that applied to the field, in source order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub granted_by: Vec<String>,
    /// Ids of the `deny` grants that applied to the field, in source order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_by: Vec<String>,
}

/// The per-field trace of [`crate::Engine::explain_fields`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct FieldExplanation {
    pub permission: String,
    pub allowed: FieldSet,
    /// The name of the override that decided every field alike, if one did. The grants are not
    /// consulted then, so `fields` is empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden_by: Option<String>,
    pub fields: Vec<FieldVerdict>,
}
