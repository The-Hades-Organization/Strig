//! Erros do binding: uma mensagem e um `code` estável, que chega ao JavaScript como
//! `error.code`.

use std::fmt;

use strig::{ExclusiveError, QueryError};

/// Falha de uma chamada ao binding. `code` é parte do contrato e não muda entre versões; a
/// mensagem é para leitura humana.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingError {
    pub code: &'static str,
    pub message: String,
}

pub type BindingResult<T> = Result<T, BindingError>;

impl BindingError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// Argumento escalar que não é aceito: tipo errado, fora do intervalo, não finito. Igual nos
    /// dois alvos, e nunca coagido a um valor.
    pub fn invalid_argument(what: &str, cause: impl fmt::Display) -> Self {
        Self::new("INVALID_ARGUMENT", format!("{what} inválido: {cause}"))
    }

    /// Resultado do núcleo que esta versão do binding não sabe traduzir: falha, nunca um valor
    /// inventado (uma variante nova do núcleo cai aqui até o binding aprender a respondê-la).
    pub fn unsupported(what: &str) -> Self {
        Self::new("INTERNAL", format!("{what}: resultado desconhecido do núcleo"))
    }

    /// Entrada que não tem a forma esperada.
    pub fn invalid_input(what: &str, cause: impl fmt::Display) -> Self {
        Self::new("INVALID_INPUT", format!("{what} inválido: {cause}"))
    }
}

impl fmt::Display for BindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for BindingError {}

impl From<QueryError> for BindingError {
    fn from(error: QueryError) -> Self {
        let code = match &error {
            QueryError::UnknownSubject(_) => "UNKNOWN_SUBJECT",
            QueryError::LimitExceeded { .. } => "QUERY_LIMIT_EXCEEDED",
            QueryError::RelationDepthExceeded { .. } => "RELATION_DEPTH_EXCEEDED",
            _ => "QUERY_ERROR",
        };
        Self::new(code, error.to_string())
    }
}

impl From<ExclusiveError> for BindingError {
    fn from(error: ExclusiveError) -> Self {
        let code = match &error {
            ExclusiveError::ZeroTtl => "EXCLUSIVE_ZERO_TTL",
            ExclusiveError::NotHeld(_) => "EXCLUSIVE_NOT_HELD",
            ExclusiveError::NotHolder { .. } => "EXCLUSIVE_NOT_HOLDER",
            ExclusiveError::AnonymousSubject => "EXCLUSIVE_ANONYMOUS_SUBJECT",
            ExclusiveError::UnidentifiedResource => "EXCLUSIVE_UNIDENTIFIED_RESOURCE",
            ExclusiveError::TtlTooLong(_) => "EXCLUSIVE_TTL_TOO_LONG",
            ExclusiveError::Denied(_) => "EXCLUSIVE_DENIED",
            ExclusiveError::UnknownPermission(_) => "EXCLUSIVE_UNKNOWN_PERMISSION",
            ExclusiveError::Store(_) => "EXCLUSIVE_STORE",
            // O binding não liga a auditoria da posse: `Audit` não chega aqui. Uma variante nova do
            // núcleo cai neste código, que o `ErrorCode` documenta como o resto.
            _ => "EXCLUSIVE_ERROR",
        };
        Self::new(code, error.to_string())
    }
}
