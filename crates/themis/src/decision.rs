use serde::{Deserialize, Serialize};

use crate::grant::Effect;
use crate::resource::Resource;
use crate::subject::Subject;

/// Question put to the engine: can `subject` `permission` on `resource`?
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    pub subject: &'a Subject,
    pub permission: &'a str,
    pub resource: &'a Resource,
}

impl<'a> Request<'a> {
    pub fn new(subject: &'a Subject, permission: &'a str, resource: &'a Resource) -> Self {
        Self {
            subject,
            permission,
            resource,
        }
    }
}

/// Why the decision came out the way it did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Reason {
    /// An override decided before the grants.
    Override { name: String },
    /// A grant decided, chosen by the strategy.
    Grant {
        grant_id: String,
        permission: String,
        rank: usize,
        strategy: String,
    },
    /// No grant applied: default-deny.
    NoApplicableGrant,
    /// The requested permission is not in the catalog.
    UnknownPermission,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub effect: Effect,
    pub reason: Reason,
    /// Ids of all the grants that applied, in source order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matched: Vec<String>,
    /// Problems that did not prevent the decision (condition with a missing attribute, ReBAC without a store).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl Decision {
    pub fn is_allowed(&self) -> bool {
        self.effect == Effect::Allow
    }

    pub(crate) fn deny(reason: Reason) -> Self {
        Self {
            effect: Effect::Deny,
            reason,
            matched: Vec::new(),
            warnings: Vec::new(),
        }
    }
}
