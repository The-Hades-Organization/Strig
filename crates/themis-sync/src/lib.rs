//! Tempo real para a Themis: avisos de mudança de permissão entre instâncias e até o cliente.
//!
//! - [`Hub`]: ponto único de mudanças de uma instância. Entrega local (sessões, caches) e
//!   publica num [`Transport`].
//! - [`Transport`]: trait do meio entre instâncias. `themis-redis` e `themis-postgres` são
//!   implementações; [`MemoryTransport`] serve para testes. Outro broker entra
//!   implementando o trait.
//! - [`Session`]: sessão de um cliente, independente de framework. Produz as
//!   [`ServerMessage`] para SSE ou WebSocket; `themis-axum` liga isso ao axum.
//! - [`CapabilityCache`]: cache de [`themis::CapabilitySet`] invalidado pelo hub.

pub mod cache;
pub mod change;
pub mod hub;
pub mod protocol;
pub mod provider;
pub mod session;
pub mod transport;

pub use cache::{CapabilityCache, TtlCache};
pub use change::{Change, ChangeKind};
pub use hub::{ChangeSink, Hub, HubBuilder, RelayHandle};
pub use protocol::{ClientMessage, ServerMessage, scope_from_str, scope_to_string};
pub use provider::{BoxError, CapabilityProvider, EngineProvider, GrantLoader};
pub use session::{Session, SessionControl, SessionOptions, SessionStream};
pub use transport::{ChangeStream, MemoryTransport, Transport, TransportError};
