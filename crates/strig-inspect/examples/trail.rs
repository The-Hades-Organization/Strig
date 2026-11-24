//! Gera uma trilha de auditoria forensic a partir de um cenário, para abrir na aba Auditoria.
//!
//! cargo run -p strig-inspect --no-default-features --example trail -- \
//!     crates/strig-inspect/examples/scenario.json > crates/strig-inspect/examples/audit.jsonl

use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use strig::{Attributes, AuditLevel, Auditor, Context, JsonLinesAudit, Request};
use strig_inspect::{Inspector, Scenario};

const REQUESTS: [(&str, &str, &str); 6] = [
    ("ana", "project.view", "roadmap"),
    ("ana", "document.export", "invoice-7"),
    ("ben", "document.export", "invoice-7"),
    ("ben", "document.view", "secret"),
    ("cara", "project.edit", "roadmap"),
    ("visitor", "project.view", "roadmap"),
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).ok_or("usage: trail SCENARIO.json")?;
    let inspector = Inspector::new(Scenario::load(std::path::Path::new(&path))?)?;
    let sink = Arc::new(JsonLinesAudit::new(Vec::new()));
    let clock = Arc::new(AtomicU64::new(1_795_300_000_000));
    let tick = clock.clone();
    let auditor =
        Auditor::new(AuditLevel::Forensic, sink.clone()).with_clock(move || tick.fetch_add(61_000, Ordering::Relaxed));
    let grants = inspector.active_grants();
    let ctx = Context::new(&grants)
        .with_tuples(inspector.tuples())
        .with_env(&inspector.scenario().env);
    for (subject, permission, resource) in REQUESTS {
        let request = Request::new(inspector.subject(subject)?, permission, inspector.resource(resource)?);
        let (_, record) = auditor.decide(inspector.engine(), &ctx, &request, &Attributes::new());
        record?;
    }
    drop(auditor);
    let sink = Arc::try_unwrap(sink).map_err(|_| "trail still in use")?;
    std::io::stdout().write_all(&sink.into_inner())?;
    Ok(())
}
