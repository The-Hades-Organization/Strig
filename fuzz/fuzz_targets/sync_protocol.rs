#![no_main]

use libfuzzer_sys::fuzz_target;
use strig_sync::{ClientMessage, ServerMessage, scope_from_str, scope_to_string};

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(message) = ClientMessage::from_json(text) {
            let json = serde_json::to_string(&message).expect("a client message serializes");
            assert_eq!(ClientMessage::from_json(&json).unwrap(), message);
        }
        let scope = scope_from_str(text);
        let printed = scope_to_string(&scope);
        assert_eq!(scope_from_str(&printed), scope, "scope text must round-trip");
    }
    if let Ok(message) = serde_json::from_slice::<ServerMessage>(data) {
        let json = message.to_json();
        let back: ServerMessage = serde_json::from_str(&json).expect("a server message must be readable");
        assert_eq!(back, message);
        let sse = message.to_sse();
        assert!(sse.starts_with("event: ") && sse.ends_with("\n\n"));
        assert!(!sse.trim_end_matches('\n').contains('\n') || sse.matches('\n').count() == 3);
    }
});
