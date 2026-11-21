use serde::{Deserialize, Serialize};

use crate::grant::Effect;
use crate::resource::Resource;
use crate::subject::Subject;

/// Pergunta feita ao motor: `subject` pode `permission` sobre `resource`?
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

/// Por que a decisão saiu como saiu.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Reason {
    /// Um override decidiu antes dos grants.
    Override { name: String },
    /// Um grant decidiu, escolhido pela estratégia.
    Grant {
        grant_id: String,
        permission: String,
        rank: usize,
        strategy: String,
    },
    /// Nenhum grant se aplicou: default-deny.
    NoApplicableGrant,
    /// A permissão pedida não está no catálogo.
    UnknownPermission,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub effect: Effect,
    pub reason: Reason,
    /// Ids de todos os grants que se aplicaram, na ordem da fonte.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matched: Vec<String>,
    /// Problemas que não impediram a decisão (condição com atributo ausente, ReBAC sem store).
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
