//! Client protocol version 2 is frozen: one fixture per message under `tests/frozen/protocol-v2/`.
//! Each must read into the message below and write back to the same bytes. A diff is a breaking change
//! of the wire protocol (see `docs/versioning.md`). Regenerate on purpose with
//! `STRIG_UPDATE_FROZEN=1 cargo test -p strig-sync --test frozen_protocol`.

use std::path::PathBuf;

use strig::{Anchor, CapabilitySet, Grant, Resource, Revision, Subject, SubjectMatcher, TargetSelector};
use strig_sync::change::Change;
use strig_sync::{ClientMessage, PROTOCOL_VERSION, ServerMessage};

fn path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/frozen/protocol-v2")
        .join(format!("{name}.json"))
}

fn scope() -> Resource {
    Resource::new("document", "d1").within("project", "p1")
}

fn capabilities() -> CapabilitySet {
    CapabilitySet::new(
        Subject::user("u1").with_role("member"),
        vec![Grant::allow(
            "g1",
            SubjectMatcher::Any,
            "project.view",
            TargetSelector::kind("project"),
        )],
    )
}

fn server() -> Vec<(&'static str, ServerMessage)> {
    let mut change = Change::roles("u1", Anchor::new("project", "p1")).with_revision(Revision::new("tenant", 7));
    change.origin = "node-1".into();
    change.seq = 12;
    change.at = 1_700_000_000_000;
    vec![
        ("server-hello", ServerMessage::hello("node-1", Some("u1".into()))),
        ("server-hello-anonymous", ServerMessage::hello("node-1", None)),
        (
            "server-capabilities",
            ServerMessage::capabilities(scope(), capabilities()),
        ),
        (
            "server-capabilities-revision",
            ServerMessage::capabilities(scope(), capabilities()).with_revision(Revision::new("tenant", 7)),
        ),
        ("server-change", ServerMessage::Change { change }),
        ("server-resync", ServerMessage::Resync),
        (
            "server-error",
            ServerMessage::Error {
                message: "revision_not_reached".into(),
            },
        ),
        ("server-ping", ServerMessage::Ping),
    ]
}

fn client() -> Vec<(&'static str, ClientMessage)> {
    vec![
        (
            "client-watch",
            ClientMessage::Watch {
                scopes: vec![scope(), Resource::new("project", "p2")],
            },
        ),
        ("client-unwatch", ClientMessage::Unwatch { scopes: vec![scope()] }),
        ("client-refresh", ClientMessage::Refresh),
        (
            "client-refresh-at-least",
            ClientMessage::RefreshAtLeast {
                revision: Revision::new("tenant", 7),
            },
        ),
    ]
}

fn check(name: &str, written: &str, read_back: impl Fn(&str) -> String) {
    let file = path(name);
    let written = format!("{written}\n");
    if std::env::var_os("STRIG_UPDATE_FROZEN").is_some() {
        std::fs::write(&file, &written).unwrap();
    }
    let frozen = std::fs::read_to_string(&file)
        .unwrap_or_else(|e| panic!("{}: {e}; run with STRIG_UPDATE_FROZEN=1 to create it", file.display()));
    assert_eq!(
        written, frozen,
        "{name}: the wire format changed, which is a breaking change; update on purpose with STRIG_UPDATE_FROZEN=1"
    );
    assert_eq!(
        format!("{}\n", read_back(frozen.trim_end())),
        frozen,
        "{name}: read then written differs"
    );
}

#[test]
fn the_protocol_is_version_2() {
    assert_eq!(PROTOCOL_VERSION, 2);
}

#[test]
fn every_server_message_is_frozen() {
    for (name, message) in server() {
        check(name, &message.to_json(), |text| {
            let parsed: ServerMessage = serde_json::from_str(text).unwrap();
            assert_eq!(parsed, message, "{name}");
            parsed.to_json()
        });
    }
}

#[test]
fn every_client_message_is_frozen() {
    for (name, message) in client() {
        check(name, &serde_json::to_string(&message).unwrap(), |text| {
            let parsed = ClientMessage::from_json(text).unwrap();
            assert_eq!(parsed, message, "{name}");
            serde_json::to_string(&parsed).unwrap()
        });
    }
}

#[test]
fn every_message_type_has_a_fixture() {
    let mut types: Vec<String> = server()
        .iter()
        .map(|(_, m)| m.event_name().to_string())
        .chain(
            client()
                .iter()
                .map(|(_, m)| serde_json::to_value(m).unwrap()["type"].as_str().unwrap().to_string()),
        )
        .collect();
    types.sort();
    types.dedup();
    assert_eq!(
        types,
        [
            "capabilities",
            "change",
            "error",
            "hello",
            "ping",
            "refresh",
            "refresh_at_least",
            "resync",
            "unwatch",
            "watch"
        ]
    );
}
