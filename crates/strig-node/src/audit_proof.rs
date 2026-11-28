//! Verification of audit evidence for third parties: Merkle proofs and RFC 3161 time stamps.
//! Pure functions over JSON, no network: the auditor brings the proof, the stamp and the roots.

use serde::Deserialize;
use serde_json::Value;
use strig::audit::AuditRecord;
use strig::merkle::{self, Hash, MerkleError};
use strig::timestamp::{VerifyOptions, decode_hex, pem_certificates, verify_response};

use crate::error::BindingError;
use crate::{BindingResult, parse};

fn hash_of(what: &str, text: &str) -> BindingResult<Hash> {
    merkle::from_hex(text).ok_or_else(|| BindingError::invalid_input(what, "expected 64 hexadecimal characters"))
}

fn hashes_of(what: &str, texts: &[String]) -> BindingResult<Vec<Hash>> {
    texts.iter().map(|t| hash_of(what, t)).collect()
}

fn refusal(error: &MerkleError) -> Value {
    let code = match error {
        MerkleError::IndexOutOfRange { .. } => "INDEX_OUT_OF_RANGE",
        MerkleError::ProofLength => "PROOF_LENGTH",
        MerkleError::RootMismatch => "ROOT_MISMATCH",
        MerkleError::Sizes { .. } => "SIZES",
        _ => "INVALID_PROOF",
    };
    out!({"ok": false, "code": code, "message": error.to_string()})
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InclusionInput {
    /// The audit record, whose leaf hash is computed here.
    #[serde(default)]
    record: Option<Value>,
    /// The leaf hash, hex, when the auditor holds only the hash.
    #[serde(default)]
    leaf: Option<String>,
    index: u64,
    size: u64,
    proof: Vec<String>,
    root: String,
}

/// Checks that a record (or leaf hash) is the leaf `index` of a tree of `size` leaves with root
/// `root`. Answers `{ ok: true }` or `{ ok: false, code, message }`.
pub fn verify_merkle_inclusion(input: Value) -> BindingResult<Value> {
    let input: InclusionInput = parse("input", input)?;
    let leaf = match (input.record, input.leaf) {
        (Some(record), None) => {
            let record: AuditRecord = parse("record", record)?;
            merkle::record_leaf(&record).map_err(|e| BindingError::invalid_input("record", e))?
        }
        (None, Some(leaf)) => hash_of("leaf", &leaf)?,
        _ => return Err(BindingError::invalid_input("input", "give exactly one of `record` and `leaf`")),
    };
    let proof = hashes_of("proof", &input.proof)?;
    let root = hash_of("root", &input.root)?;
    Ok(match merkle::verify_inclusion(&leaf, input.index, input.size, &proof, &root) {
        Ok(()) => out!({"ok": true}),
        Err(error) => refusal(&error),
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConsistencyInput {
    first: u64,
    second: u64,
    first_root: String,
    second_root: String,
    proof: Vec<String>,
}

/// Checks that the tree of `second` leaves extends the tree of `first` leaves: nothing before
/// `first` was changed or removed. Answers `{ ok: true }` or `{ ok: false, code, message }`.
pub fn verify_merkle_consistency(input: Value) -> BindingResult<Value> {
    let input: ConsistencyInput = parse("input", input)?;
    let proof = hashes_of("proof", &input.proof)?;
    let first_root = hash_of("firstRoot", &input.first_root)?;
    let second_root = hash_of("secondRoot", &input.second_root)?;
    Ok(match merkle::verify_consistency(input.first, input.second, &first_root, &second_root, &proof) {
        Ok(()) => out!({"ok": true}),
        Err(error) => refusal(&error),
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TimestampInput {
    /// The `TimeStampResp`, DER, base64.
    response: String,
    /// The chain head that was stamped, hex.
    head: String,
    /// PEM text with the CA certificates the auditor trusts.
    roots: String,
    /// PEM text with more certificates to complete the chain.
    #[serde(default)]
    certificates: Option<String>,
    /// The nonce sent in the request, hex.
    #[serde(default)]
    nonce: Option<String>,
    /// The policy OID the response must state.
    #[serde(default)]
    policy: Option<String>,
}

fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let (mut bits, mut count, mut padding) = (0u32, 0u32, 0u32);
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => {
                padding += 1;
                continue;
            }
            b' ' | b'\n' | b'\r' | b'\t' => continue,
            _ => return None,
        };
        if padding > 0 {
            return None;
        }
        bits = bits << 6 | u32::from(value);
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
            bits &= (1 << count) - 1;
        }
    }
    (count < 6 && padding < 3).then_some(out)
}

/// Verifies an RFC 3161 time stamp of an audit chain head against the roots the auditor trusts.
/// Answers `{ ok: true, genTime, time, serial, policy, algorithm, imprint, nonce, signerSubject }` or
/// `{ ok: false, code, message }`; without a trusted root every response is refused.
pub fn verify_timestamp(input: Value) -> BindingResult<Value> {
    let input: TimestampInput = parse("input", input)?;
    let response = base64_decode(&input.response)
        .ok_or_else(|| BindingError::invalid_input("response", "expected the DER response in base64"))?;
    let roots = pem_certificates(&input.roots);
    let mut options = VerifyOptions::for_chain_head(&input.head, roots)
        .map_err(|e| BindingError::invalid_input("head", e))?;
    if let Some(pem) = &input.certificates {
        options.certificates = pem_certificates(pem);
    }
    if let Some(nonce) = &input.nonce {
        let bytes = decode_hex(nonce)
            .filter(|b| !b.is_empty() && b.len() <= 8)
            .ok_or_else(|| BindingError::invalid_input("nonce", "expected up to 16 hexadecimal characters"))?;
        options.nonce = Some(bytes.iter().fold(0u64, |acc, b| acc << 8 | u64::from(*b)));
    }
    options.policy = input.policy;
    Ok(match verify_response(&response, &options) {
        Ok(info) => out!({
            "ok": true,
            "gen_time": info.gen_time,
            "time": strig::audit_report::format_unix_seconds(info.gen_time),
            "serial": info.serial,
            "policy": info.policy,
            "algorithm": info.algorithm.name(),
            "imprint": info.imprint,
            "nonce": info.nonce,
            "signer_subject": info.signer_subject,
        }),
        Err(error) => out!({"ok": false, "code": error.code(), "message": error.to_string()}),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips() {
        assert_eq!(base64_decode("TWFu").unwrap(), b"Man");
        assert_eq!(base64_decode("TWE=").unwrap(), b"Ma");
        assert_eq!(base64_decode("TQ==").unwrap(), b"M");
        assert_eq!(base64_decode("TW\nFu").unwrap(), b"Man");
        assert!(base64_decode("TW!u").is_none());
        assert!(base64_decode("T=Fu").is_none());
    }
}
