//! The AuthZEN Authorization API 1.0: the requests and responses of the spec, the mapping to
//! Strig, and the fail-closed behavior.

mod support;

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use strig::{Anchor, Catalog, Engine, Grant, PermissionDef, Resource, SubjectMatcher, TargetSelector};
use strig_server::{
    AuthzenConfig, DecisionServer, DecisionSource, ManualClock, MemorySource, PathResolver, ResourceCatalog, Snapshot,
    SourceError,
};
use support::{FailingSource, NOW, error_code, json_post, raw_post, send};

const ISSUER: &str = "https://pdp.example.com";

fn engine() -> Arc<Engine> {
    let catalog = Catalog::builder()
        .target_kinds(["account", "document"])
        .broad_target("org")
        .permission(PermissionDef::new("can_read").targets(["account", "document"]))
        .permission(PermissionDef::new("can_write").targets(["account"]))
        .permission(PermissionDef::new("can_edit").targets(["document"]))
        .permission(PermissionDef::new("read").targets(["document"]))
        .build()
        .expect("catalog");
    Arc::new(Engine::builder(catalog).build().expect("engine"))
}

fn alice() -> SubjectMatcher {
    SubjectMatcher::user("alice@example.com")
}

fn grants() -> Vec<Grant> {
    vec![
        Grant::allow(
            "alice-read-accounts",
            alice(),
            "can_read",
            TargetSelector::kind("account"),
        ),
        Grant::allow(
            "alice-write-123",
            alice(),
            "can_write",
            TargetSelector::exact("account", "123"),
        ),
        Grant::allow(
            "bob-read-123",
            SubjectMatcher::user("bob@example.com"),
            "can_read",
            TargetSelector::exact("account", "123"),
        ),
        Grant::allow(
            "auditors-read-456",
            SubjectMatcher::role("auditor"),
            "can_read",
            TargetSelector::exact("account", "456"),
        ),
        Grant::allow(
            "editors-write",
            SubjectMatcher::role("editor"),
            "can_write",
            TargetSelector::kind("account"),
        ),
        Grant::allow("alice-read-1", alice(), "read", TargetSelector::exact("document", "1")),
        Grant::allow("alice-read-3", alice(), "read", TargetSelector::exact("document", "3")),
        Grant::allow(
            "alice-read-bx",
            alice(),
            "can_read",
            TargetSelector::exact("document", "boxcarring.md"),
        ),
        Grant::allow(
            "alice-read-ss",
            alice(),
            "can_read",
            TargetSelector::exact("document", "subject-search.md"),
        ),
        Grant::allow(
            "alice-edit-rs",
            alice(),
            "can_edit",
            TargetSelector::exact("document", "resource-search.md"),
        ),
    ]
}

fn serve(source: Arc<dyn DecisionSource>, config: AuthzenConfig) -> Router {
    DecisionServer::new(source)
        .with_clock(Arc::new(ManualClock::new(NOW)))
        .with_authzen(config)
        .router()
}

fn pdp(config: AuthzenConfig) -> Router {
    serve(Arc::new(MemorySource::new(Snapshot::new(engine(), grants()))), config)
}

fn default_pdp() -> Router {
    pdp(AuthzenConfig::default())
}

fn get(path: &str) -> Request<Body> {
    Request::get(path).body(Body::empty()).expect("request")
}

struct Accounts;

impl ResourceCatalog for Accounts {
    fn resources(&self, kind: &str) -> Result<Vec<Resource>, SourceError> {
        Ok(["789", "123", "456"]
            .iter()
            .map(|id| Resource::new(kind, *id))
            .collect())
    }
}

fn decisions(answer: &Value) -> Vec<Value> {
    answer["evaluations"]
        .as_array()
        .expect("evaluations")
        .iter()
        .map(|d| d["decision"].clone())
        .collect()
}

fn ids(answer: &Value) -> Vec<&str> {
    answer["results"]
        .as_array()
        .expect("results")
        .iter()
        .map(|r| r["id"].as_str().expect("id"))
        .collect()
}

// --- Access Evaluation (spec 6, Figure 14) -----------------------------------------------------

#[tokio::test]
async fn evaluation_answers_the_example_of_the_spec() {
    let request = json!({
        "subject": {"type": "user", "id": "alice@example.com"},
        "resource": {"type": "account", "id": "123"},
        "action": {"name": "can_read", "properties": {"method": "GET"}},
        "context": {"time": "1985-10-26T01:22-07:00"}
    });
    let (status, answer) = send(&default_pdp(), json_post("/access/v1/evaluation", &request)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(answer, json!({"decision": true}));
}

#[tokio::test]
async fn evaluation_denies_with_a_200() {
    let request = json!({
        "subject": {"type": "user", "id": "mallory"},
        "resource": {"type": "account", "id": "123"},
        "action": {"name": "can_read"}
    });
    let (status, answer) = send(&default_pdp(), json_post("/access/v1/evaluation", &request)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(answer, json!({"decision": false}));
}

#[tokio::test]
async fn an_unknown_permission_is_a_deny_never_an_allow() {
    let request = json!({
        "subject": {"type": "user", "id": "alice@example.com"},
        "resource": {"type": "account", "id": "123"},
        "action": {"name": "can_launch_missiles"}
    });
    let (status, answer) = send(&default_pdp(), json_post("/access/v1/evaluation", &request)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(answer["decision"], false);
}

#[tokio::test]
async fn unknown_fields_are_ignored() {
    let request = json!({
        "subject": {"type": "user", "id": "alice@example.com", "extra": 1},
        "resource": {"type": "account", "id": "123"},
        "action": {"name": "can_read"},
        "future": {"x": true}
    });
    let (status, answer) = send(&default_pdp(), json_post("/access/v1/evaluation", &request)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(answer["decision"], true);
}

#[tokio::test]
async fn a_malformed_evaluation_is_a_400_and_never_an_allow() {
    let ok = || {
        json!({
            "subject": {"type": "user", "id": "alice@example.com"},
            "resource": {"type": "account", "id": "123"},
            "action": {"name": "can_read"}
        })
    };
    let mut cases = Vec::new();
    for key in ["subject", "resource", "action"] {
        let mut body = ok();
        body.as_object_mut().unwrap().remove(key);
        cases.push(body);
    }
    let mut no_id = ok();
    no_id["subject"].as_object_mut().unwrap().remove("id");
    cases.push(no_id);
    let mut empty_action = ok();
    empty_action["action"]["name"] = json!("");
    cases.push(empty_action);
    let mut bad_properties = ok();
    bad_properties["subject"]["properties"] = json!({"nested": [{"object": 1}]});
    cases.push(bad_properties);
    cases.push(json!([]));
    for body in cases {
        let (status, answer) = send(&default_pdp(), json_post("/access/v1/evaluation", &body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(error_code(&answer), "invalid_request");
        assert!(answer.get("decision").is_none());
    }
    let (status, answer) = send(
        &default_pdp(),
        raw_post("/access/v1/evaluation", "application/json", "{".into()),
    )
    .await;
    assert_eq!(
        (status, error_code(&answer)),
        (StatusCode::BAD_REQUEST, "malformed_json")
    );
    let (status, _) = send(
        &default_pdp(),
        raw_post("/access/v1/evaluation", "text/plain", ok().to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn a_failing_source_is_a_500_that_is_not_an_allow() {
    let router = serve(Arc::new(FailingSource), AuthzenConfig::default());
    let request = json!({
        "subject": {"type": "user", "id": "alice@example.com"},
        "resource": {"type": "account", "id": "123"},
        "action": {"name": "can_read"}
    });
    let (status, answer) = send(&router, json_post("/access/v1/evaluation", &request)).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(error_code(&answer), "source_unavailable");
    assert!(answer.get("decision").is_none());
}

#[tokio::test]
async fn the_request_id_comes_back_on_answers_and_on_errors() {
    let router = default_pdp();
    let with_id = |body: Value| {
        Request::post("/access/v1/evaluation")
            .header("content-type", "application/json")
            .header("x-request-id", "bfe9eb29-ab87-4ca3-be83-a1d5d8305716")
            .body(Body::from(body.to_string()))
            .expect("request")
    };
    for body in [
        json!({"subject": {"type": "user", "id": "alice@example.com"}, "resource": {"type": "account", "id": "123"}, "action": {"name": "can_read"}}),
        json!({"nothing": true}),
    ] {
        use tower::ServiceExt;
        let response = router.clone().oneshot(with_id(body)).await.expect("infallible");
        assert_eq!(
            response.headers()["x-request-id"],
            "bfe9eb29-ab87-4ca3-be83-a1d5d8305716"
        );
    }
}

// --- Access Evaluations (spec 7) ---------------------------------------------------------------

fn read_documents(semantic: Option<&str>) -> Value {
    let mut body = json!({
        "subject": {"type": "user", "id": "alice@example.com"},
        "action": {"name": "read"},
        "evaluations": [
            {"resource": {"type": "document", "id": "1"}},
            {"resource": {"type": "document", "id": "2"}},
            {"resource": {"type": "document", "id": "3"}}
        ]
    });
    if let Some(semantic) = semantic {
        body["options"] = json!({"evaluations_semantic": semantic});
    }
    body
}

#[tokio::test]
async fn evaluations_with_no_default_values() {
    let doc = |id: &str| {
        json!({
            "subject": {"type": "user", "id": "alice@example.com"},
            "action": {"name": "can_read"},
            "resource": {"type": "document", "id": id},
            "context": {"time": "2024-05-31T15:22-07:00"}
        })
    };
    let body = json!({"evaluations": [doc("boxcarring.md"), doc("subject-search.md"), doc("resource-search.md")]});
    let (status, answer) = send(&default_pdp(), json_post("/access/v1/evaluations", &body)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(decisions(&answer), [json!(true), json!(true), json!(false)]);
    assert!(answer.get("decision").is_none());
}

#[tokio::test]
async fn evaluations_take_defaults_that_an_item_overrides() {
    let body = json!({
        "subject": {"type": "user", "id": "alice@example.com"},
        "context": {"time": "2024-05-31T15:22-07:00"},
        "action": {"name": "can_read"},
        "evaluations": [
            {"resource": {"type": "document", "id": "boxcarring.md"}},
            {"resource": {"type": "document", "id": "subject-search.md"}},
            {"action": {"name": "can_edit"}, "resource": {"type": "document", "id": "resource-search.md"}}
        ]
    });
    let (status, answer) = send(&default_pdp(), json_post("/access/v1/evaluations", &body)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(decisions(&answer), [json!(true), json!(true), json!(true)]);
}

#[tokio::test]
async fn execute_all_is_the_default_semantic() {
    for semantic in [None, Some("execute_all")] {
        let (status, answer) = send(
            &default_pdp(),
            json_post("/access/v1/evaluations", &read_documents(semantic)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(decisions(&answer), [json!(true), json!(false), json!(true)]);
    }
}

#[tokio::test]
async fn deny_on_first_deny_stops_at_the_denial() {
    let body = read_documents(Some("deny_on_first_deny"));
    let (status, answer) = send(&default_pdp(), json_post("/access/v1/evaluations", &body)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        answer,
        json!({"evaluations": [
            {"decision": true},
            {"decision": false, "context": {"code": "200", "reason": "deny_on_first_deny"}}
        ]})
    );
}

#[tokio::test]
async fn permit_on_first_permit_stops_at_the_permit() {
    let body = read_documents(Some("permit_on_first_permit"));
    let (status, answer) = send(&default_pdp(), json_post("/access/v1/evaluations", &body)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(answer, json!({"evaluations": [{"decision": true}]}));
}

#[tokio::test]
async fn an_unknown_semantic_or_a_missing_key_is_a_400() {
    let (status, _) = send(
        &default_pdp(),
        json_post("/access/v1/evaluations", &read_documents(Some("maybe"))),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let mut body = read_documents(None);
    body.as_object_mut().unwrap().remove("action");
    let (status, answer) = send(&default_pdp(), json_post("/access/v1/evaluations", &body)).await;
    assert_eq!(
        (status, error_code(&answer)),
        (StatusCode::BAD_REQUEST, "invalid_request")
    );
}

#[tokio::test]
async fn an_evaluations_request_without_evaluations_is_one_evaluation() {
    let body = json!({
        "subject": {"type": "user", "id": "alice@example.com"},
        "resource": {"type": "account", "id": "123"},
        "action": {"name": "can_read"}
    });
    for body in [body.clone(), {
        let mut empty = body;
        empty["evaluations"] = json!([]);
        empty
    }] {
        let (status, answer) = send(&default_pdp(), json_post("/access/v1/evaluations", &body)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(answer, json!({"decision": true}));
    }
}

#[tokio::test]
async fn an_item_that_cannot_be_mapped_is_a_deny_with_its_error() {
    let body = json!({
        "action": {"name": "can_read"},
        "resource": {"type": "account", "id": "123"},
        "evaluations": [
            {"subject": {"type": "user", "id": "alice@example.com"}},
            {"subject": {"type": "user"}}
        ]
    });
    let (status, answer) = send(&default_pdp(), json_post("/access/v1/evaluations", &body)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(answer["evaluations"][0], json!({"decision": true}));
    assert_eq!(answer["evaluations"][1]["decision"], false);
    assert_eq!(answer["evaluations"][1]["context"]["error"]["status"], 400);
}

#[tokio::test]
async fn evaluations_over_the_batch_limit_are_refused() {
    let router = DecisionServer::new(Arc::new(MemorySource::new(Snapshot::new(engine(), grants()))))
        .with_config(strig_server::ServerConfig::default().with_max_batch(2))
        .with_authzen(AuthzenConfig::default())
        .router();
    let (status, answer) = send(&router, json_post("/access/v1/evaluations", &read_documents(None))).await;
    assert_eq!(
        (status, error_code(&answer)),
        (StatusCode::BAD_REQUEST, "batch_too_large")
    );
}

// --- Search (spec 8) ---------------------------------------------------------------------------

#[tokio::test]
async fn subject_search_answers_the_example_of_the_spec() {
    let request = json!({
        "subject": {"type": "user"},
        "action": {"name": "can_read"},
        "resource": {"type": "account", "id": "123"},
        "context": {"time": "2024-10-26T01:22-07:00"}
    });
    let (status, answer) = send(&default_pdp(), json_post("/access/v1/search/subject", &request)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        answer["results"],
        json!([{"type": "user", "id": "alice@example.com"}, {"type": "user", "id": "bob@example.com"}])
    );
    assert_eq!(answer["page"]["next_token"], "");
}

#[tokio::test]
async fn subject_search_says_when_parties_it_cannot_name_are_left_out() {
    let request = json!({
        "subject": {"type": "user"},
        "action": {"name": "can_read"},
        "resource": {"type": "account", "id": "456"}
    });
    let (_, answer) = send(&default_pdp(), json_post("/access/v1/search/subject", &request)).await;
    assert_eq!(ids(&answer), ["alice@example.com"]);
    assert_eq!(answer["context"]["incomplete"], true);
}

#[tokio::test]
async fn action_search_answers_the_example_of_the_spec() {
    let request = json!({
        "subject": {"type": "user", "id": "alice@example.com"},
        "resource": {"type": "account", "id": "123"},
        "context": {"time": "2024-10-26T01:22-07:00"}
    });
    let (status, answer) = send(&default_pdp(), json_post("/access/v1/search/action", &request)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(answer["results"], json!([{"name": "can_read"}, {"name": "can_write"}]));
}

#[tokio::test]
async fn resource_search_pages_as_the_examples_of_the_spec() {
    let router = pdp(AuthzenConfig::default().with_resource_catalog(Arc::new(Accounts)));
    let mut request = json!({
        "subject": {"type": "user", "id": "alice@example.com"},
        "action": {"name": "can_read"},
        "resource": {"type": "account"},
        "page": {"limit": 2}
    });
    let (status, first) = send(&router, json_post("/access/v1/search/resource", &request)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        first["results"],
        json!([{"type": "account", "id": "123"}, {"type": "account", "id": "456"}])
    );
    assert_eq!(
        (first["page"]["count"].clone(), first["page"]["total"].clone()),
        (json!(2), json!(3))
    );
    let token = first["page"]["next_token"].as_str().expect("token").to_string();
    assert!(!token.is_empty());

    request["page"] = json!({"limit": 2, "token": token});
    let (_, second) = send(&router, json_post("/access/v1/search/resource", &request)).await;
    assert_eq!(second["results"], json!([{"type": "account", "id": "789"}]));
    assert_eq!(second["page"]["next_token"], "");
    assert_eq!(second["page"]["count"], 1);

    request["action"] = json!({"name": "can_write"});
    let (status, answer) = send(&router, json_post("/access/v1/search/resource", &request)).await;
    assert_eq!(
        (status, error_code(&answer)),
        (StatusCode::BAD_REQUEST, "invalid_request")
    );
}

#[tokio::test]
async fn resource_search_does_not_exist_without_a_catalog() {
    let request = json!({
        "subject": {"type": "user", "id": "alice@example.com"},
        "action": {"name": "can_read"},
        "resource": {"type": "account"}
    });
    let (status, answer) = send(&default_pdp(), json_post("/access/v1/search/resource", &request)).await;
    assert_eq!((status, error_code(&answer)), (StatusCode::NOT_FOUND, "not_found"));
}

#[tokio::test]
async fn a_search_without_its_required_entities_is_a_400() {
    let router = default_pdp();
    for (path, body) in [
        (
            "/access/v1/search/subject",
            json!({"action": {"name": "can_read"}, "resource": {"type": "account", "id": "1"}}),
        ),
        (
            "/access/v1/search/subject",
            json!({"subject": {"type": "user"}, "resource": {"type": "account", "id": "1"}}),
        ),
        (
            "/access/v1/search/subject",
            json!({"subject": {"type": "user"}, "action": {"name": "can_read"}}),
        ),
        (
            "/access/v1/search/action",
            json!({"subject": {"type": "user"}, "resource": {"type": "account", "id": "1"}}),
        ),
    ] {
        let (status, _) = send(&router, json_post(path, &body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path} {body}");
    }
}

// --- Metadata (spec 9) -------------------------------------------------------------------------

#[tokio::test]
async fn the_metadata_lists_the_endpoints_that_exist() {
    let config = AuthzenConfig::default()
        .with_issuer(format!("{ISSUER}/"))
        .expect("issuer");
    let (status, answer) = send(&pdp(config), get("/.well-known/authzen-configuration")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        answer,
        json!({
            "policy_decision_point": ISSUER,
            "access_evaluation_endpoint": "https://pdp.example.com/access/v1/evaluation",
            "access_evaluations_endpoint": "https://pdp.example.com/access/v1/evaluations",
            "search_subject_endpoint": "https://pdp.example.com/access/v1/search/subject",
            "search_action_endpoint": "https://pdp.example.com/access/v1/search/action"
        })
    );
    let with_resources = AuthzenConfig::default()
        .with_issuer(ISSUER)
        .expect("issuer")
        .with_resource_catalog(Arc::new(Accounts));
    let (_, answer) = send(&pdp(with_resources), get("/.well-known/authzen-configuration")).await;
    assert_eq!(
        answer["search_resource_endpoint"],
        "https://pdp.example.com/access/v1/search/resource"
    );
}

#[tokio::test]
async fn there_is_no_metadata_without_an_issuer_and_the_issuer_is_checked() {
    let (status, _) = send(&default_pdp(), get("/.well-known/authzen-configuration")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    for bad in [
        "http://pdp.example.com",
        "https://",
        "https:///x",
        "https://pdp.example.com?a=1",
        "https://pdp.example.com#f",
        "pdp.example.com",
    ] {
        assert!(AuthzenConfig::default().with_issuer(bad).is_err(), "{bad}");
    }
}

#[tokio::test]
async fn the_server_without_authzen_has_no_such_routes() {
    let router = support::memory_server(strig_server::ServerConfig::default());
    let (status, _) = send(&router, json_post("/access/v1/evaluation", &json!({}))).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// --- Mapping -----------------------------------------------------------------------------------

#[tokio::test]
async fn roles_come_from_a_property_and_the_name_is_configurable() {
    let request = |property: &str| {
        json!({
            "subject": {"type": "user", "id": "dave", "properties": {property: ["editor"]}},
            "resource": {"type": "account", "id": "123"},
            "action": {"name": "can_write"}
        })
    };
    let (_, answer) = send(&default_pdp(), json_post("/access/v1/evaluation", &request("roles"))).await;
    assert_eq!(answer["decision"], true);
    let (_, answer) = send(&default_pdp(), json_post("/access/v1/evaluation", &request("groups"))).await;
    assert_eq!(answer["decision"], false);
    let renamed = AuthzenConfig::default()
        .with_properties("groups", "principals", "path")
        .expect("names");
    let (_, answer) = send(&pdp(renamed), json_post("/access/v1/evaluation", &request("groups"))).await;
    assert_eq!(answer["decision"], true);
    assert!(AuthzenConfig::default().with_properties("a", "a", "b").is_err());
}

struct OrgOne;

impl PathResolver for OrgOne {
    fn broader_steps(&self, kind: &str, id: &str) -> Option<Vec<Anchor>> {
        (kind == "document" && id == "d1").then(|| vec![Anchor::new("org", "o1")])
    }
}

fn org_server(config: AuthzenConfig) -> Router {
    let grants = vec![Grant::allow(
        "carol-org-o1",
        SubjectMatcher::user("carol"),
        "can_read",
        TargetSelector::exact("org", "o1"),
    )];
    serve(Arc::new(MemorySource::new(Snapshot::new(engine(), grants))), config)
}

fn carol_reads(id: &str, claimed_org: &str) -> Value {
    json!({
        "subject": {"type": "user", "id": "carol"},
        "resource": {"type": "document", "id": id, "properties": {"path": [{"kind": "org", "id": claimed_org}]}},
        "action": {"name": "can_read"}
    })
}

#[tokio::test]
async fn the_path_comes_from_the_property_or_from_the_resolver_which_wins() {
    let (_, answer) = send(
        &org_server(AuthzenConfig::default()),
        json_post("/access/v1/evaluation", &carol_reads("d1", "o1")),
    )
    .await;
    assert_eq!(answer["decision"], true, "the property places the resource");
    let (_, answer) = send(
        &org_server(AuthzenConfig::default()),
        json_post("/access/v1/evaluation", &carol_reads("d1", "o9")),
    )
    .await;
    assert_eq!(answer["decision"], false);

    let resolving = || org_server(AuthzenConfig::default().with_path_resolver(Arc::new(OrgOne)));
    let (_, answer) = send(
        &resolving(),
        json_post("/access/v1/evaluation", &carol_reads("d1", "o9")),
    )
    .await;
    assert_eq!(
        answer["decision"], true,
        "the server knows d1 is in o1 whatever the caller says"
    );
    let (status, answer) = send(
        &resolving(),
        json_post("/access/v1/evaluation", &carol_reads("dx", "o1")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        answer["decision"], false,
        "a resource the resolver does not know is denied"
    );
    assert_eq!(answer["context"]["error"]["status"], 404);
}

// --- The reason --------------------------------------------------------------------------------

fn with_reason_header(body: &Value) -> Request<Body> {
    Request::post("/access/v1/evaluation")
        .header("content-type", "application/json")
        .header("x-strig-reason", "true")
        .body(Body::from(body.to_string()))
        .expect("request")
}

#[tokio::test]
async fn the_reason_needs_the_server_and_the_request_and_never_names_a_grant() {
    let allow = json!({
        "subject": {"type": "user", "id": "alice@example.com"},
        "resource": {"type": "account", "id": "123"},
        "action": {"name": "can_read"}
    });
    let deny = json!({
        "subject": {"type": "user", "id": "mallory"},
        "resource": {"type": "account", "id": "123"},
        "action": {"name": "can_read"}
    });
    let off = default_pdp();
    let (_, answer) = send(&off, with_reason_header(&allow)).await;
    assert_eq!(answer, json!({"decision": true}), "the server did not agree to explain");

    let on = pdp(AuthzenConfig::default().with_reasons(true));
    let (_, answer) = send(&on, json_post("/access/v1/evaluation", &allow)).await;
    assert_eq!(answer, json!({"decision": true}), "the request did not ask");
    let (_, answer) = send(&on, with_reason_header(&allow)).await;
    assert_eq!(answer, json!({"decision": true, "context": {"reason": "grant"}}));
    let (_, answer) = send(&on, with_reason_header(&deny)).await;
    assert_eq!(
        answer,
        json!({"decision": false, "context": {"reason": "no_applicable_grant"}})
    );
    assert!(!answer.to_string().contains("alice-read-accounts"));
}
