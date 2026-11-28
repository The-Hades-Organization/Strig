//! Strig as the External Authorization service of an Envoy proxy.
//!
//! ```text
//! cargo run -p strig-server --features envoy --example envoy
//! envoy -c crates/strig-server/examples/envoy.yaml
//! curl -H 'authorization: Bearer <jwt of alice>' localhost:10000/documents/d1
//! ```
//!
//! Envoy validates the JWT (`jwt_authn`), copies the `sub` claim into the `x-user` header
//! (overwriting whatever the client sent) and asks this service on `127.0.0.1:9191` before
//! forwarding. `envoy.yaml` next to this file is the matching configuration. The grants live in
//! memory here; a real deployment gives `DecisionServer` its own `DecisionSource`.

use std::sync::Arc;

use strig::{Catalog, Engine, Grant, PermissionDef, SubjectMatcher, TargetSelector};
use strig_server::{DecisionServer, EnvoyConfig, MemorySource, ResourceTemplate, RouteRule, Snapshot};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let catalog = Catalog::builder()
        .target_kinds(["document"])
        .broad_target("org")
        .permission(PermissionDef::new("document.view").targets(["document"]))
        .permission(PermissionDef::new("document.delete").targets(["document"]))
        .build()?;
    let grants = vec![
        Grant::allow(
            "alice-view",
            SubjectMatcher::user("alice"),
            "document.view",
            TargetSelector::kind("document"),
        ),
        Grant::allow(
            "admins-delete",
            SubjectMatcher::role("admin"),
            "document.delete",
            TargetSelector::kind("document"),
        ),
    ];
    let source = Arc::new(MemorySource::new(Snapshot::new(
        Arc::new(Engine::builder(catalog).build()?),
        grants,
    )));

    let envoy = EnvoyConfig::default()
        .with_subject_header("x-user")?
        .with_roles_header("x-roles")?
        .with_route("GET", "/healthz", RouteRule::public())?
        .with_route(
            "GET,HEAD",
            "/documents/{id}",
            RouteRule::require("document.view", ResourceTemplate::new("document", "{id}")),
        )?
        .with_route(
            "DELETE",
            "/documents/{id}",
            RouteRule::require("document.delete", ResourceTemplate::new("document", "{id}")),
        )?
        .with_reasons(true);

    let service = DecisionServer::new(source).envoy_service(envoy);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:9191").await?;
    println!("External Authorization on {}", listener.local_addr()?);
    // Runs until the process is stopped (Ctrl-C); pass a real shutdown future to stop it cleanly.
    service.serve(listener, std::future::pending()).await?;
    Ok(())
}
