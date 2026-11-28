//! Time-stamps the head of an audit chain with a public TSA and verifies the answer.
//!
//! The core has no network: this example sends the request with `curl`, which keeps the crate free
//! of an HTTP client and TLS stack. Swap `curl` for the client you already use.
//!
//! ```text
//! cargo run -p strig --example timestamp_http --features timestamp -- \
//!     <head-hex> <tsa-url> <ca.pem> [out.tsr]
//! ```
//!
//! `<head-hex>` is the `hash` of the last audit record. The response is written to `out.tsr`
//! (default `head.tsr`), ready for `strig audit report --timestamp`.

use std::io::Write;
use std::process::{Command, Stdio};

use strig::timestamp::{TimestampRequest, VerifyOptions, pem_certificates, verify_response};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [head, url, root, rest @ ..] = args.as_slice() else {
        return Err("usage: timestamp_http <head-hex> <tsa-url> <ca.pem> [out.tsr]".into());
    };
    let out = rest.first().map_or("head.tsr", String::as_str);

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos() as u64;
    let request = TimestampRequest::for_chain_head(head, Some(nonce))?.to_der()?;

    let mut curl = Command::new("curl")
        .args(["--silent", "--show-error", "--fail", "--max-time", "30", "--header"])
        .args(["Content-Type: application/timestamp-query", "--data-binary", "@-", url])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    curl.stdin.take().ok_or("no stdin")?.write_all(&request)?;
    let answer = curl.wait_with_output()?;
    if !answer.status.success() {
        return Err("the TSA request failed".into());
    }

    let mut options = VerifyOptions::for_chain_head(head, pem_certificates(&std::fs::read_to_string(root)?))?;
    options.nonce = Some(nonce);
    let info = verify_response(&answer.stdout, &options)?;
    std::fs::write(out, &answer.stdout)?;
    println!(
        "stamped at {} (serial {}, policy {}); response saved to {out}",
        info.gen_time, info.serial, info.policy
    );
    Ok(())
}
