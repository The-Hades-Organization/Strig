//! The decision server's JSON bodies and error codes are frozen under `tests/frozen/`. Each fixture must
//! read into its type and write back to the same bytes. A diff is a breaking change of the wire format (see
//! `docs/versioning.md`). Regenerate on purpose with
//! `STRIG_UPDATE_FROZEN=1 cargo test -p strig-server --test frozen_wire`.

use std::path::PathBuf;

use serde::Serialize;
use serde::de::DeserializeOwned;
use strig_server::error::{ErrorBody, ErrorCode};
use strig_server::wire::{AccessRequest, BatchRequest, BatchResponse, CheckRequest, CheckResponse, ListRequest, WhoRequest};

fn path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/frozen")
        .join(format!("{name}.json"))
}

fn freeze<T: Serialize + DeserializeOwned>(name: &str, input: &str) {
    let typed: T = serde_json::from_str(input).unwrap_or_else(|e| panic!("{name}: {e}"));
    let written = format!("{}\n", serde_json::to_string(&typed).unwrap());
    let file = path(name);
    if std::env::var_os("STRIG_UPDATE_FROZEN").is_some() {
        std::fs::write(&file, &written).unwrap();
    }
    let frozen = std::fs::read_to_string(&file)
        .unwrap_or_else(|e| panic!("{}: {e}; run with STRIG_UPDATE_FROZEN=1 to create it", file.display()));
    assert_eq!(
        written, frozen,
        "{name}: the wire format changed, which is a breaking change; update on purpose with STRIG_UPDATE_FROZEN=1"
    );
    let again: T = serde_json::from_str(frozen.trim_end()).unwrap();
    assert_eq!(
        format!("{}\n", serde_json::to_string(&again).unwrap()),
        frozen,
        "{name}: read then written differs"
    );
}

const SUBJECT: &str = r#"{"kind":"user","id":"u1","roles":[{"role":"member"}]}"#;
const RESOURCE: &str = r#"{"path":[{"kind":"document","id":"d1"},{"kind":"project","id":"p1"}]}"#;
const ALLOW: &str = r#"{"effect":"allow","reason":{"kind":"grant","grant_id":"g1","permission":"document.view","rank":0,"strategy":"most_specific"},"matched":["g1"]}"#;
const DENY: &str = r#"{"effect":"deny","reason":{"kind":"no_applicable_grant"}}"#;

#[test]
fn the_check_bodies_are_frozen() {
    freeze::<CheckRequest>(
        "check-request",
        &format!(r#"{{"subject":{SUBJECT},"permission":"document.view","resource":{RESOURCE}}}"#),
    );
    freeze::<CheckRequest>(
        "check-request-full",
        &format!(
            r#"{{"subject":{SUBJECT},"permission":"document.view","resource":{RESOURCE},"env":{{"ip":"203.0.113.42"}},"at":1700000000000,"min_revision":"tenant@7"}}"#
        ),
    );
    freeze::<CheckResponse>(
        "check-response-allow",
        &format!(r#"{{"decision":{ALLOW},"evaluated_at":1700000000000,"requested_at":1700000000000,"revision":"tenant@7"}}"#),
    );
    freeze::<CheckResponse>(
        "check-response-deny",
        &format!(r#"{{"decision":{DENY},"evaluated_at":1700000000000}}"#),
    );
}

#[test]
fn the_batch_bodies_are_frozen() {
    let check = format!(r#"{{"subject":{SUBJECT},"permission":"document.view","resource":{RESOURCE}}}"#);
    freeze::<BatchRequest>(
        "batch-request",
        &format!(r#"{{"checks":[{check},{check}],"min_revision":"tenant@7"}}"#),
    );
    freeze::<BatchResponse>(
        "batch-response",
        &format!(
            r#"{{"results":[{{"decision":{ALLOW},"evaluated_at":1700000000000}},{{"decision":{DENY},"evaluated_at":1700000000000}}],"revision":"tenant@7"}}"#
        ),
    );
}

#[test]
fn the_query_requests_are_frozen() {
    freeze::<ListRequest>(
        "list-request",
        &format!(r#"{{"subject":{SUBJECT},"permission":"document.view","kind":"document","layout":["document","project"]}}"#),
    );
    freeze::<WhoRequest>(
        "who-request",
        &format!(r#"{{"permission":"document.view","resource":{RESOURCE},"at":1700000000000}}"#),
    );
    freeze::<AccessRequest>("access-request", &format!(r#"{{"resource":{RESOURCE}}}"#));
}

const CODES: [(&str, u16); 17] = [
    ("malformed_json", 400),
    ("invalid_request", 400),
    ("batch_too_large", 400),
    ("too_many_resources", 400),
    ("body_too_large", 413),
    ("unsupported_media_type", 415),
    ("not_found", 404),
    ("method_not_allowed", 405),
    ("source_unavailable", 503),
    ("query_limit_exceeded", 503),
    ("relation_depth_exceeded", 503),
    ("deadline_exceeded", 503),
    ("overloaded", 503),
    ("clock_unavailable", 503),
    ("revision_not_reached", 503),
    ("revision_mismatch", 503),
    ("internal", 503),
];

#[test]
fn the_error_codes_are_a_closed_list_with_their_status_and_body() {
    let mut bodies = String::new();
    for (code, status) in CODES {
        let parsed = ErrorCode::from(code);
        assert!(!matches!(parsed, ErrorCode::Unknown(_)), "{code} is not a known code");
        assert_eq!(parsed.as_str(), code);
        assert_eq!(parsed.status().as_u16(), status, "{code}");
        assert_eq!(parsed.is_fail_closed(), status == 503, "{code}");
        bodies.push_str(&serde_json::to_string(&ErrorBody::new(parsed)).unwrap());
        bodies.push('\n');
    }
    let file = path("error-bodies").with_extension("jsonl");
    if std::env::var_os("STRIG_UPDATE_FROZEN").is_some() {
        std::fs::write(&file, &bodies).unwrap();
    }
    let frozen = std::fs::read_to_string(&file)
        .unwrap_or_else(|e| panic!("{}: {e}; run with STRIG_UPDATE_FROZEN=1 to create it", file.display()));
    assert_eq!(bodies, frozen, "an error body changed, which is a breaking change");
    assert_eq!(
        ErrorCode::from("something_newer").status().as_u16(),
        503,
        "an unknown code fails closed"
    );
}
