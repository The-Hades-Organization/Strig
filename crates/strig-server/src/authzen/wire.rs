//! The JSON of the AuthZEN API. Unknown fields are ignored, as the spec requires of receivers.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub(crate) type Properties = Map<String, Value>;

/// A Subject or a Resource (`type`, `id`, `properties`). The `id` is required where the spec
/// requires it and left out of the search entity; the handlers check that.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Entity {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub properties: Option<Properties>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Action {
    pub name: String,
}

/// `POST /access/v1/evaluation`.
#[derive(Debug, Deserialize)]
pub(crate) struct EvaluationRequest {
    pub subject: Entity,
    pub action: Action,
    pub resource: Entity,
    #[serde(default)]
    pub context: Option<Properties>,
}

/// An item of `evaluations`: every key falls back to the top-level default.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct EvaluationItem {
    #[serde(default)]
    pub subject: Option<Entity>,
    #[serde(default)]
    pub action: Option<Action>,
    #[serde(default)]
    pub resource: Option<Entity>,
    #[serde(default)]
    pub context: Option<Properties>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct EvaluationOptions {
    #[serde(default)]
    pub evaluations_semantic: Option<String>,
}

/// `POST /access/v1/evaluations`.
#[derive(Debug, Deserialize)]
pub(crate) struct EvaluationsRequest {
    #[serde(flatten)]
    pub defaults: EvaluationItem,
    #[serde(default)]
    pub evaluations: Option<Vec<EvaluationItem>>,
    #[serde(default)]
    pub options: Option<EvaluationOptions>,
}

#[derive(Debug, Serialize, PartialEq)]
pub(crate) struct DecisionOut {
    pub decision: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<Properties>,
}

#[derive(Debug, Serialize)]
pub(crate) struct EvaluationsOut {
    pub evaluations: Vec<DecisionOut>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct PageIn {
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub limit: Option<u64>,
}

/// The three search requests: which entities are required depends on the endpoint.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct SearchRequest {
    #[serde(default)]
    pub subject: Option<Entity>,
    #[serde(default)]
    pub action: Option<Action>,
    #[serde(default)]
    pub resource: Option<Entity>,
    #[serde(default)]
    pub context: Option<Properties>,
    #[serde(default)]
    pub page: Option<PageIn>,
}

#[derive(Debug, Serialize)]
pub(crate) struct PageOut {
    pub next_token: String,
    pub count: usize,
    pub total: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct SearchOut<T> {
    pub page: PageOut,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<Properties>,
    pub results: Vec<T>,
}

/// A result of the Subject or the Resource Search.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(crate) struct EntityOut {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
}

/// A result of the Action Search.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(crate) struct ActionOut {
    pub name: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct MetadataOut {
    pub policy_decision_point: String,
    pub access_evaluation_endpoint: String,
    pub access_evaluations_endpoint: String,
    pub search_subject_endpoint: String,
    pub search_action_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search_resource_endpoint: Option<String>,
}
