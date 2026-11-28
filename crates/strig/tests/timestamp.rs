//! RFC 3161 verification against a response recorded from a public TSA (FreeTSA, 2026-11-28).
//!
//! The fixture was made with `openssl ts -query -data data.txt -sha256 -cert` (nonce on) and posted to
//! `https://freetsa.org/tsr`; `cacert.pem` is the root that TSA publishes. Check it independently with
//! `openssl ts -verify -in resp.tsr -queryfile req.tsq -CAfile cacert.pem -untrusted tsa.crt`.

use sha2::{Digest, Sha256};
use strig::timestamp::{
    HashAlgorithm, TimestampError, TimestampRequest, VerifyOptions, decode_hex, pem_certificates, verify_response,
};

const RESPONSE: &[u8] = include_bytes!("fixtures/timestamp/resp.tsr");
const REQUEST: &[u8] = include_bytes!("fixtures/timestamp/req.tsq");
const DATA: &[u8] = include_bytes!("fixtures/timestamp/data.txt");
const ROOT_PEM: &str = include_str!("fixtures/timestamp/cacert.pem");
const NONCE: u64 = 0x589F_A81C_DE1D_083C;

fn root() -> Vec<Vec<u8>> {
    pem_certificates(ROOT_PEM)
}

fn options() -> VerifyOptions {
    let mut options = VerifyOptions::new(Sha256::digest(DATA).to_vec(), root());
    options.nonce = Some(NONCE);
    options
}

#[test]
fn the_recorded_response_verifies() {
    let info = verify_response(RESPONSE, &options()).unwrap();
    assert_eq!(info.gen_time, 1_795_868_280);
    assert_eq!(info.serial, "0ac20a6c");
    assert_eq!(info.policy, "1.2.3.4.1");
    assert_eq!(info.algorithm, HashAlgorithm::Sha256);
    assert_eq!(info.imprint, hex(&Sha256::digest(DATA)));
    assert_eq!(info.nonce.as_deref(), Some("589fa81cde1d083c"));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn the_request_matches_what_openssl_produced() {
    let mut request = TimestampRequest::new(HashAlgorithm::Sha256, Sha256::digest(DATA).to_vec());
    request.nonce = Some(NONCE);
    assert_eq!(request.to_der().unwrap(), REQUEST);
}

#[test]
fn a_chain_head_request_stamps_the_head_bytes() {
    let head = "087dbffda54667a64ae971f80c70bf6544b205be90c9ca9cc592ef113f4a4cb5";
    let request = TimestampRequest::for_chain_head(head, None).unwrap().to_der().unwrap();
    let digest = decode_hex(head).unwrap();
    assert!(request.windows(32).any(|w| w == digest.as_slice()));
    assert!(TimestampRequest::for_chain_head("abc", None).is_err());
    assert!(TimestampRequest::for_chain_head(&"zz".repeat(32), None).is_err());
}

#[test]
fn another_digest_is_refused() {
    let mut options = options();
    options.imprint = Sha256::digest(b"something else").to_vec();
    assert_eq!(verify_response(RESPONSE, &options), Err(TimestampError::ImprintMismatch));
}

#[test]
fn a_wrong_or_missing_nonce_is_refused() {
    let mut options = options();
    options.nonce = Some(NONCE + 1);
    assert_eq!(verify_response(RESPONSE, &options), Err(TimestampError::NonceMismatch));
}

#[test]
fn a_wrong_policy_is_refused() {
    let mut options = options();
    options.policy = Some("1.2.3.5".into());
    assert!(matches!(verify_response(RESPONSE, &options), Err(TimestampError::PolicyMismatch { .. })));
    options.policy = Some("1.2.3.4.1".into());
    assert!(verify_response(RESPONSE, &options).is_ok());
}

#[test]
fn without_a_trusted_root_everything_is_refused() {
    let mut options = options();
    options.trusted_roots.clear();
    assert!(verify_response(RESPONSE, &options).is_err());
}

#[test]
fn another_root_is_not_trusted() {
    let mut options = options();
    let mut other = root().remove(0);
    let modulus = other.windows(5).position(|w| w == [0x02, 0x82, 0x02, 0x01, 0x00]).expect("a 4096-bit RSA modulus");
    other[modulus + 100] ^= 0x01;
    options.trusted_roots = vec![other];
    assert!(verify_response(RESPONSE, &options).is_err());
}

/// Bytes whose change may go unnoticed: the `PKIStatus` value (0 granted, 1 granted with
/// modifications, both accepted), the `digestAlgorithms` set (the signer's own algorithm is what
/// counts) and the copy of the root the TSA embeds (trust comes from the root you supply, never from
/// the one in the response).
fn is_inert(index: usize) -> bool {
    index == 8 || (35..52).contains(&index) || (2096..4147).contains(&index)
}

fn flipped_bytes_that_verify(step: usize) -> Vec<usize> {
    let options = options();
    (0..RESPONSE.len())
        .step_by(step)
        .filter(|index| !is_inert(*index))
        .filter(|index| {
            let mut bytes = RESPONSE.to_vec();
            bytes[*index] ^= 0x01;
            verify_response(&bytes, &options).is_ok()
        })
        .collect()
}

#[test]
fn a_flipped_byte_does_not_verify() {
    assert_eq!(flipped_bytes_that_verify(7), Vec::<usize>::new());
}

#[test]
#[ignore = "exhaustive and slow in debug: cargo test --release -- --ignored"]
fn every_flipped_byte_does_not_verify() {
    assert_eq!(flipped_bytes_that_verify(1), Vec::<usize>::new());
}

#[test]
fn truncated_and_empty_input_is_refused() {
    let options = options();
    assert!(verify_response(&[], &options).is_err());
    for cut in [1, 10, 100, RESPONSE.len() - 1] {
        assert!(verify_response(&RESPONSE[..cut], &options).is_err(), "cut at {cut}");
    }
}

#[test]
fn a_refusal_status_is_reported() {
    let refused = [0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02];
    assert_eq!(verify_response(&refused, &options()), Err(TimestampError::NotGranted(2)));
}

