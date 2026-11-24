//! Visualizador de avaliações da Themis.
//!
//! A biblioteca não depende de interface: [`Inspector`] carrega um [`Scenario`] (política,
//! grants, sujeitos e recursos nomeados), explica decisões, simula outro conjunto de grants e
//! monta a matriz de acesso; [`Trail`] lê uma trilha de auditoria, confere a cadeia de hashes e
//! reavalia decisões registradas. Com a feature `gui`, o binário `themis-inspect` abre tudo
//! isso numa janela gpui; sem ela, sobram os comandos de terminal.

pub mod fmt;
pub mod inspector;
pub mod render;
pub mod scenario;
pub mod trail;

#[cfg(feature = "gui")]
pub mod gui;

pub use inspector::{InspectError, Inspector, Matrix};
pub use scenario::{LoadError, Scenario};
pub use trail::{ChainStatus, Replay, Trail};
