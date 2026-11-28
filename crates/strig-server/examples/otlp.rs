//! Spans and metrics of Strig exported over OpenTelemetry (OTLP/HTTP).
//!
//! Starts the decision server on a loopback port, calls it a few times through the Rust client and
//! ships what the `tracing` feature emits to a collector:
//!
//! ```text
//! docker run --rm -p 4318:4318 otel/opentelemetry-collector-contrib   # or any OTLP/HTTP endpoint
//! OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318 \
//!   cargo run -p strig-server --features tracing --example otlp
//! ```
//!
//! `tracing` carries the spans, the `metrics` facade carries the numbers, and each goes to its own
//! OpenTelemetry pipeline. Nothing here is specific to OTLP: swap the exporter and the
//! instrumentation stays as it is.

use std::sync::Arc;
use std::time::Duration;

use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::{MetricExporter, SpanExporter};
use opentelemetry_sdk::metrics::PeriodicReader;
use opentelemetry_sdk::trace::SdkTracerProvider;
use strig::{Catalog, Engine, Grant, PermissionDef, Resource, Subject, SubjectMatcher, TargetSelector};
use strig_server::client::{Client, ClientConfig};
use strig_server::wire::CheckRequest;
use strig_server::{DecisionServer, MemorySource, Snapshot};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // OTEL_EXPORTER_OTLP_ENDPOINT (default http://localhost:4318) and the other OTEL_* variables
    // are read by the exporters.
    let tracer_provider = SdkTracerProvider::builder()
        .with_batch_exporter(SpanExporter::builder().with_http().build()?)
        .build();
    let tracer = tracer_provider.tracer("strig");
    tracing_subscriber::registry()
        .with(tracing_opentelemetry::OpenTelemetryLayer::new(tracer))
        .init();

    let reader = PeriodicReader::builder(MetricExporter::builder().with_http().build()?)
        .with_interval(Duration::from_secs(5))
        .build();
    let (meter_provider, recorder) = metrics_exporter_opentelemetry::Recorder::builder("strig")
        .with_meter_provider(|builder| builder.with_reader(reader))
        .build();
    metrics::set_global_recorder(recorder)?;

    let catalog = Catalog::builder()
        .target_kinds(["document"])
        .broad_target("org")
        .permission(PermissionDef::new("document.view").targets(["document"]))
        .build()?;
    let grants = vec![Grant::allow(
        "alice-view",
        SubjectMatcher::user("alice"),
        "document.view",
        TargetSelector::kind("document"),
    )];
    let snapshot = Snapshot::new(Arc::new(Engine::builder(catalog).build()?), grants);
    let router = DecisionServer::new(Arc::new(MemorySource::new(snapshot))).router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move { axum::serve(listener, router).await });

    let client = Client::http(format!("http://{address}"), ClientConfig::default());
    let document = Resource::new("document", "d1").within("org", "o1");
    for user in ["alice", "mallory"] {
        let answer = client
            .check(&CheckRequest::new(
                Subject::user(user),
                "document.view",
                document.clone(),
            ))
            .await;
        println!("{user}: allowed = {}", answer.is_allowed());
    }

    meter_provider.force_flush()?;
    tracer_provider.force_flush()?;
    Ok(())
}
