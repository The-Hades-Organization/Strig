//! Real time for Themis: permission change notices between instances and all the way to the client.
//!
//! - [`Hub`]: single point for an instance's changes. Delivers locally (sessions, caches) and
//!   publishes on a [`Transport`].
//! - [`Transport`]: trait for the medium between instances. `themis-redis` and `themis-postgres` are
//!   implementations; [`MemoryTransport`] is for tests. Another broker plugs in by
//!   implementing the trait.
//! - [`Session`]: a client's session, framework-independent. Produces the
//!   [`ServerMessage`]s for SSE or WebSocket; `themis-axum` wires that into axum.
//! - [`CapabilityCache`]: cache of [`themis::CapabilitySet`] invalidated by the hub.
//!
//! See the [repository README](https://github.com/The-Hades-Organization/Themis) for the full guide.

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
