#![no_main]

use libfuzzer_sys::fuzz_target;
use strig::audit::{AuditRecord, chain_head, verify_chain, verify_chain_anchored};

fuzz_target!(|data: &[u8]| {
    let Ok(records) = serde_json::from_slice::<Vec<AuditRecord>>(data) else {
        return;
    };
    let verdict = verify_chain(&records);
    let head = chain_head(&records);
    if verdict.is_ok() {
        let start = records.first().and_then(|first| first.prev_hash.as_deref());
        assert!(verify_chain_anchored(&records, start, head).is_ok());
        if let Some(head) = head {
            let wrong = format!("{head}x");
            assert!(verify_chain_anchored(&records, start, Some(&wrong)).is_err());
        }
    }
    for cut in 0..records.len().min(8) {
        let _ = verify_chain(&records[cut..]);
    }
});
