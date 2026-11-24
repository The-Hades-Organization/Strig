use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use strig::{Attributes, EngineSpec, Grant, Resource, Subject, Tuple};

/// Tudo que uma avaliação precisa, num arquivo JSON: a política (`spec`), os dados (`grants`,
/// `tuples`, `env`) e os sujeitos e recursos que se quer examinar, por nome.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    pub spec: EngineSpec,
    #[serde(default)]
    pub grants: Vec<Grant>,
    #[serde(default)]
    pub tuples: Vec<Tuple>,
    #[serde(default)]
    pub env: Attributes,
    #[serde(default)]
    pub subjects: BTreeMap<String, Subject>,
    #[serde(default)]
    pub resources: BTreeMap<String, Resource>,
}

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("{path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{path}: JSON inválido: {source}")]
    Json {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("{path}: linha {line}: {source}")]
    Line {
        path: String,
        line: usize,
        #[source]
        source: serde_json::Error,
    },
    #[error("política inválida: {0}")]
    Spec(#[from] strig::SpecError),
}

pub(crate) fn read(path: &Path) -> Result<String, LoadError> {
    std::fs::read_to_string(path).map_err(|source| LoadError::Io {
        path: path.display().to_string(),
        source,
    })
}

impl Scenario {
    pub fn from_json(text: &str, origin: &str) -> Result<Self, LoadError> {
        serde_json::from_str(text).map_err(|source| LoadError::Json {
            path: origin.to_string(),
            source,
        })
    }

    pub fn load(path: &Path) -> Result<Self, LoadError> {
        Self::from_json(&read(path)?, &path.display().to_string())
    }
}
