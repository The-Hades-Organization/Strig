//! Tamanho medido do registro de referência em cada nível de auditoria e a projeção por
//! milhão de registros.
//!
//! `cargo run -p strig --example audit_storage`

use strig::AuditLevel;
use strig::audit::reference_record;

fn main() {
    println!(
        "{:<10} {:>12} {:>14} {:>16}",
        "nível", "bytes/reg.", "por 1 milhão", "estimativa doc."
    );
    for level in AuditLevel::ALL {
        let measured = serde_json::to_vec(&reference_record(level)).expect("json").len() as u64 + 1;
        let per_million = measured as f64 * 1_000_000.0 / 1_048_576.0;
        let documented = level.estimate_bytes(1_000_000) as f64 / 1_048_576.0;
        println!("{level:<10} {measured:>12} {per_million:>11.0} MiB {documented:>12.0} MiB");
    }
}
