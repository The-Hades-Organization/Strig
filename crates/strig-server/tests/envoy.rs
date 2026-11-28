//! Envoy External Authorization: allow, deny, a route with no rule, no subject, a source that is
//! down, and the limits, through a real gRPC connection.

mod support;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use strig::{Anchor, Catalog, Engine, Grant, PermissionDef, SubjectMatcher, TargetSelector};
use strig_server::envoy::{
    AttributeContext, CheckRequest, CheckResponse, HttpRequest, Metadata, Request, check_response,
};
use strig_server::{
    DecisionServer, DecisionSource, EnvoyConfig, ManualClock, MemorySource, PathResolver, ResourceTemplate, RouteRule,
    ServerConfig, Snapshot,
};
use support::{FailingSource, NOW, PanickingSource, SlowSource};
use tokio::net::TcpListener;
use tonic::client::Grpc;
use tonic::transport::Channel;
use tonic_prost::ProstCodec;

fn config() -> EnvoyConfig {
    EnvoyConfig::default()
        .with_subject_header("X-User")
        .and_then(|c| c.with_roles_header("x-roles"))
        .and_then(|c| c.with_route("GET", "/health", RouteRule::public()))
        .and_then(|c| {
            c.with_route(
                "GET,HEAD",
                "/documents/{id}",
                RouteRule::require("document.view", ResourceTemplate::new("document", "{id}")),
            )
        })
        .and_then(|c| {
            c.with_route(
                "DELETE",
                "/documents/{id}",
                RouteRule::require("document.delete", ResourceTemplate::new("document", "{id}")),
            )
        })
        .expect("config")
}

fn snapshot() -> Snapshot {
    let catalog = Catalog::builder()
        .target_kinds(["document"])
        .broad_target("org")
        .permission(PermissionDef::new("document.view").targets(["document"]))
        .permission(PermissionDef::new("document.delete").targets(["document"]))
        .build()
        .expect("catalog");
    let engine = Arc::new(Engine::builder(catalog).build().expect("engine"));
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
        Grant::allow(
            "bob-view-o1",
            SubjectMatcher::user("bob"),
            "document.view",
            TargetSelector::exact("org", "o1"),
        ),
    ];
    Snapshot::new(engine, grants)
}

struct Org1;

impl PathResolver for Org1 {
    fn broader_steps(&self, kind: &str, id: &str) -> Option<Vec<Anchor>> {
        (kind == "document" && id.starts_with('d')).then(|| vec![Anchor::new("org", "o1")])
    }
}

/// Serves `source` over gRPC on a free port and connects a client to it.
async fn start(source: Arc<dyn DecisionSource>, server: ServerConfig, config: EnvoyConfig) -> Grpc<Channel> {
    let service = DecisionServer::new(source)
        .with_clock(Arc::new(ManualClock::new(NOW)))
        .with_config(server)
        .envoy_service(config);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(service.serve(listener, std::future::pending()));
    let channel = Channel::from_shared(format!("http://{addr}"))
        .expect("uri")
        .connect()
        .await
        .expect("connect");
    Grpc::new(channel)
}

async fn memory() -> Grpc<Channel> {
    start(
        Arc::new(MemorySource::new(snapshot())),
        ServerConfig::default(),
        config(),
    )
    .await
}

fn check_of(method: &str, path: &str, headers: &[(&str, &str)]) -> CheckRequest {
    CheckRequest {
        attributes: Some(AttributeContext {
            request: Some(Request {
                http: Some(HttpRequest {
                    method: method.to_string(),
                    path: path.to_string(),
                    headers: headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
                }),
            }),
            ..AttributeContext::default()
        }),
    }
}

async fn call(client: &mut Grpc<Channel>, request: CheckRequest) -> Result<CheckResponse, tonic::Status> {
    client.ready().await.expect("ready");
    let path = "/envoy.service.auth.v3.Authorization/Check".parse().expect("path");
    client
        .unary(tonic::Request::new(request), path, ProstCodec::default())
        .await
        .map(tonic::Response::into_inner)
}

async fn check(client: &mut Grpc<Channel>, method: &str, path: &str, headers: &[(&str, &str)]) -> CheckResponse {
    call(client, check_of(method, path, headers))
        .await
        .expect("a Check response")
}

fn is_allowed(response: &CheckResponse) -> bool {
    response.status.as_ref().is_some_and(|s| s.code == 0)
        && matches!(
            response.http_response,
            Some(check_response::HttpResponse::OkResponse(_))
        )
}

/// A denial: `PERMISSION_DENIED`, HTTP 403, and the reason header if there is one.
fn denial(response: &CheckResponse) -> Option<Option<String>> {
    let status = response.status.as_ref()?;
    let Some(check_response::HttpResponse::DeniedResponse(denied)) = &response.http_response else {
        return None;
    };
    assert_eq!(status.code, 7, "PERMISSION_DENIED");
    assert_eq!(denied.status.as_ref().map(|s| s.code), Some(403));
    Some(
        denied
            .headers
            .iter()
            .filter_map(|h| h.header.as_ref())
            .find(|h| h.key == "x-strig-reason")
            .map(|h| h.value.clone()),
    )
}

#[tokio::test]
async fn allows_a_subject_that_holds_the_permission() {
    let mut client = memory().await;
    let response = check(&mut client, "GET", "/documents/d1", &[("x-user", "alice")]).await;
    assert!(is_allowed(&response), "{response:?}");
}

#[tokio::test]
async fn denies_a_subject_that_does_not_hold_it() {
    let mut client = memory().await;
    let response = check(&mut client, "GET", "/documents/d1", &[("x-user", "mallory")]).await;
    assert_eq!(denial(&response), Some(None));
    let response = check(&mut client, "DELETE", "/documents/d1", &[("x-user", "alice")]).await;
    assert_eq!(denial(&response), Some(None));
}

#[tokio::test]
async fn a_route_with_no_rule_is_a_deny() {
    let mut client = memory().await;
    for (method, path) in [("GET", "/admin"), ("POST", "/documents/d1"), ("GET", "/documents")] {
        let response = check(&mut client, method, path, &[("x-user", "alice")]).await;
        assert_eq!(denial(&response), Some(None), "{method} {path}");
    }
}

#[tokio::test]
async fn a_missing_or_unusable_subject_is_a_deny() {
    let mut client = memory().await;
    for headers in [
        vec![],
        vec![("x-user", "")],
        vec![("x-user", "  ")],
        vec![("x-user", "alice,mallory")],
        vec![("other", "alice")],
    ] {
        let response = check(&mut client, "GET", "/documents/d1", &headers).await;
        assert_eq!(denial(&response), Some(None), "{headers:?}");
    }
    let too_long = "a".repeat(EnvoyConfig::MAX_IDENTITY_BYTES + 1);
    let response = check(&mut client, "GET", "/documents/d1", &[("x-user", &too_long)]).await;
    assert!(!is_allowed(&response));
}

#[tokio::test]
async fn a_public_route_needs_no_subject() {
    let mut client = memory().await;
    assert!(is_allowed(&check(&mut client, "GET", "/health", &[]).await));
    assert!(!is_allowed(&check(&mut client, "POST", "/health", &[]).await));
}

#[tokio::test]
async fn an_untrusted_path_matches_nothing() {
    let mut client = memory().await;
    for path in [
        "/documents/../admin",
        "/documents/%2e%2e",
        "/documents/d1%2f..",
        "/documents//d1",
        "documents/d1",
    ] {
        let response = check(&mut client, "GET", path, &[("x-user", "alice")]).await;
        assert!(!is_allowed(&response), "{path}");
    }
    let response = check(&mut client, "GET", "/documents/d1?as=admin#x", &[("x-user", "alice")]).await;
    assert!(is_allowed(&response), "the query is not part of the route");
}

#[tokio::test]
async fn roles_come_from_the_roles_header() {
    let mut client = memory().await;
    let headers = [("x-user", "carol"), ("x-roles", "viewer, admin")];
    assert!(is_allowed(
        &check(&mut client, "DELETE", "/documents/d9", &headers).await
    ));
    let headers = [("x-user", "carol"), ("x-roles", "viewer")];
    assert!(!is_allowed(
        &check(&mut client, "DELETE", "/documents/d9", &headers).await
    ));
    let many = (0..=EnvoyConfig::MAX_ROLES)
        .map(|n| format!("r{n}"))
        .collect::<Vec<_>>()
        .join(",");
    let headers = [("x-user", "carol"), ("x-roles", many.as_str())];
    assert!(!is_allowed(&check(&mut client, "GET", "/documents/d9", &headers).await));
}

#[tokio::test]
async fn the_subject_can_come_from_filter_metadata() {
    use prost_types::value::Kind;

    let config = EnvoyConfig::default()
        .with_subject_metadata("envoy.filters.http.jwt_authn", ["payload", "sub"])
        .and_then(|c| {
            c.with_route(
                "GET",
                "/documents/{id}",
                RouteRule::require("document.view", ResourceTemplate::new("document", "{id}")),
            )
        })
        .expect("config");
    let mut client = start(Arc::new(MemorySource::new(snapshot())), ServerConfig::default(), config).await;

    let value = |kind| prost_types::Value { kind: Some(kind) };
    let payload = |claim: Kind| prost_types::Struct {
        fields: [("sub".to_string(), value(claim))].into(),
    };
    let metadata = |claim: Kind| Metadata {
        filter_metadata: HashMap::from([(
            "envoy.filters.http.jwt_authn".to_string(),
            prost_types::Struct {
                fields: [("payload".to_string(), value(Kind::StructValue(payload(claim))))].into(),
            },
        )]),
    };
    let with = |meta: Option<Metadata>| {
        let mut request = check_of("GET", "/documents/d1", &[]);
        request.attributes.as_mut().expect("attributes").metadata_context = meta;
        request
    };

    let ok = call(&mut client, with(Some(metadata(Kind::StringValue("alice".into())))))
        .await
        .expect("response");
    assert!(is_allowed(&ok));
    let other = call(&mut client, with(Some(metadata(Kind::StringValue("mallory".into())))))
        .await
        .expect("response");
    assert!(!is_allowed(&other));
    let not_text = call(&mut client, with(Some(metadata(Kind::NumberValue(1.0)))))
        .await
        .expect("response");
    assert!(!is_allowed(&not_text));
    let none = call(&mut client, with(None)).await.expect("response");
    assert!(!is_allowed(&none));
}

#[tokio::test]
async fn a_source_that_is_down_denies() {
    let mut client = start(Arc::new(FailingSource), ServerConfig::default(), config()).await;
    let response = check(&mut client, "GET", "/documents/d1", &[("x-user", "alice")]).await;
    assert_eq!(denial(&response), Some(None));
    assert!(
        is_allowed(&check(&mut client, "GET", "/health", &[]).await),
        "a public route decides nothing"
    );
}

#[tokio::test]
async fn a_source_that_panics_denies() {
    let mut client = start(Arc::new(PanickingSource), ServerConfig::default(), config()).await;
    let response = check(&mut client, "GET", "/documents/d1", &[("x-user", "alice")]).await;
    assert!(!is_allowed(&response));
}

#[tokio::test]
async fn a_source_slower_than_the_deadline_denies() {
    let slow = SlowSource {
        delay: Duration::from_secs(30),
        inner: MemorySource::new(snapshot()),
    };
    let server = ServerConfig::default().with_default_timeout(Duration::from_millis(100));
    let mut client = start(Arc::new(slow), server, config()).await;
    let started = std::time::Instant::now();
    let response = check(&mut client, "GET", "/documents/d1", &[("x-user", "alice")]).await;
    assert!(!is_allowed(&response));
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[tokio::test]
async fn reasons_are_fixed_codes_and_only_when_asked() {
    let source = || Arc::new(MemorySource::new(snapshot()));
    let mut client = start(source(), ServerConfig::default(), config().with_reasons(true)).await;
    let cases = [
        (
            check(&mut client, "GET", "/documents/d1", &[("x-user", "mallory")]).await,
            "denied",
        ),
        (check(&mut client, "GET", "/documents/d1", &[]).await, "no_subject"),
        (
            check(&mut client, "GET", "/nowhere", &[("x-user", "alice")]).await,
            "no_route",
        ),
        (
            call(&mut client, CheckRequest::default()).await.expect("response"),
            "bad_request",
        ),
    ];
    for (response, code) in cases {
        assert_eq!(denial(&response), Some(Some(code.to_string())));
    }
    let mut client = start(
        Arc::new(FailingSource),
        ServerConfig::default(),
        config().with_reasons(true),
    )
    .await;
    let response = check(&mut client, "GET", "/documents/d1", &[("x-user", "alice")]).await;
    assert_eq!(denial(&response), Some(Some("unavailable".to_string())));
}

#[tokio::test]
async fn a_request_without_http_attributes_is_a_deny() {
    let mut client = memory().await;
    for request in [
        CheckRequest::default(),
        CheckRequest {
            attributes: Some(AttributeContext::default()),
        },
    ] {
        let response = call(&mut client, request).await.expect("response");
        assert_eq!(denial(&response), Some(None));
    }
}

#[tokio::test]
async fn the_path_resolver_places_the_resource_and_an_unknown_one_is_a_deny() {
    let config = config().with_path_resolver(Arc::new(Org1));
    let mut client = start(Arc::new(MemorySource::new(snapshot())), ServerConfig::default(), config).await;
    assert!(is_allowed(
        &check(&mut client, "GET", "/documents/d1", &[("x-user", "bob")]).await
    ));
    assert!(!is_allowed(
        &check(&mut client, "GET", "/documents/zzz", &[("x-user", "bob")]).await
    ));
    assert!(!is_allowed(
        &check(&mut client, "GET", "/documents/zzz", &[("x-user", "alice")]).await
    ));
}

#[tokio::test]
async fn a_message_over_the_body_limit_is_refused() {
    let server = ServerConfig::default().with_max_body_bytes(256);
    let mut client = start(Arc::new(MemorySource::new(snapshot())), server, config()).await;
    let big = "a".repeat(4096);
    let result = call(&mut client, check_of("GET", "/documents/d1", &[("x-user", &big)])).await;
    assert!(result.is_err(), "Envoy then denies: failure_mode_allow stays false");
}

#[tokio::test]
async fn an_unknown_method_is_unimplemented() {
    let mut client = memory().await;
    client.ready().await.expect("ready");
    let path = "/envoy.service.auth.v3.Authorization/Other".parse().expect("path");
    let result = client
        .unary::<_, CheckResponse, _>(
            tonic::Request::new(CheckRequest::default()),
            path,
            ProstCodec::default(),
        )
        .await;
    assert_eq!(result.expect_err("unimplemented").code(), tonic::Code::Unimplemented);
}

#[tokio::test]
async fn shares_the_source_with_the_http_router() {
    let source = Arc::new(MemorySource::new(snapshot()));
    let server = DecisionServer::new(source.clone() as Arc<dyn DecisionSource>);
    let service = server.envoy_service(config());
    let _router = server.router();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(service.serve(listener, std::future::pending()));
    let channel = Channel::from_shared(format!("http://{addr}"))
        .expect("uri")
        .connect()
        .await
        .expect("connect");
    let mut client = Grpc::new(channel);
    assert!(is_allowed(
        &check(&mut client, "GET", "/documents/d1", &[("x-user", "alice")]).await
    ));
    source.replace(Snapshot::new(snapshot().engine, Vec::new()));
    assert!(!is_allowed(
        &check(&mut client, "GET", "/documents/d1", &[("x-user", "alice")]).await
    ));
}

#[cfg(feature = "tracing")]
#[tokio::test(flavor = "current_thread")]
async fn checks_are_counted_by_outcome_and_reason_without_identifying_data() {
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};

    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let _guard = metrics::set_default_local_recorder(&recorder);
    let mut client = memory().await;
    check(&mut client, "GET", "/documents/doc-secret-9921", &[("x-user", "alice")]).await;
    check(
        &mut client,
        "GET",
        "/documents/doc-secret-9921",
        &[("x-user", "u-secret-4417")],
    )
    .await;
    check(&mut client, "GET", "/nowhere", &[("x-user", "alice")]).await;

    let mut seen = Vec::new();
    for (composite, _, _, value) in snapshotter.snapshot().into_vec() {
        let key = composite.key();
        if key.name() != "strig_server_envoy_checks_total" {
            continue;
        }
        let labels: Vec<(String, String)> = key
            .labels()
            .map(|l| (l.key().to_string(), l.value().to_string()))
            .collect();
        let DebugValue::Counter(count) = value else {
            panic!("a counter")
        };
        seen.push((labels, count));
    }
    let find = |outcome: &str, reason: &str| {
        seen.iter()
            .filter(|(labels, _)| {
                labels.contains(&("outcome".into(), outcome.into()))
                    && labels.contains(&("reason".into(), reason.into()))
            })
            .map(|(_, count)| *count)
            .sum::<u64>()
    };
    assert_eq!(find("allow", "none"), 1);
    assert_eq!(find("deny", "denied"), 1);
    assert_eq!(find("deny", "no_route"), 1);
    let flat = format!("{seen:?}");
    assert!(!flat.contains("secret") && !flat.contains("alice"), "{flat}");
}
