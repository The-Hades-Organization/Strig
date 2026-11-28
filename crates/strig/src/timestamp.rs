//! RFC 3161 time stamps for the head of the audit chain (feature `timestamp`).
//!
//! A time-stamping authority (TSA) signs a digest together with the time it saw it. Stamping the
//! head of a chain ([`crate::audit::chain_head`]) proves that every record up to it existed at that
//! time and cannot have been rewritten since, which a verifier can check without trusting the host
//! that wrote the log.
//!
//! The core does no IO: [`TimestampRequest`] builds the DER `TimeStampReq` and
//! [`verify_response`] checks the DER `TimeStampResp` you got back. Sending the request over HTTP
//! (`POST`, `Content-Type: application/timestamp-query`) is yours; `examples/timestamp_http.rs`
//! shows one way.
//!
//! What [`verify_response`] checks, failing closed on anything it does not understand:
//!
//! - the status is `granted` or `grantedWithMods` and a token is present;
//! - the `TSTInfo` imprint is the digest you stamped, with the algorithm you asked, and the nonce
//!   and the policy match when you give them;
//! - the CMS signature over the signed attributes (the `messageDigest` covers the `TSTInfo`);
//! - the certificate chain from the signer to a root **you supply**, with every signature on the
//!   way, each certificate valid at the time the TSA states, intermediates marked as CAs, and the
//!   signer's extended key usage including `id-kp-timeStamping`.
//!
//! Supported: RSA PKCS#1 v1.5 and ECDSA (P-256, P-384) with SHA-256, SHA-384 or SHA-512, DER
//! encoding (BER indefinite lengths are refused). Revocation (CRL, OCSP) is not consulted.

use std::fmt::Write as _;

use p256::ecdsa::signature::hazmat::PrehashVerifier;
use sha2_rustcrypto_010::{Digest, Sha256, Sha384, Sha512};

const MAX_CHAIN: usize = 8;
const MAX_CERTIFICATES: usize = 64;

const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const OID_SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
const OID_SHA512: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];
const OID_SIGNED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
const OID_TST_INFO: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x04];
const OID_CONTENT_TYPE: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03];
const OID_MESSAGE_DIGEST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];
const OID_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const OID_RSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
const OID_RSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
const OID_RSA_SHA512: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d];
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const OID_ECDSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
const OID_ECDSA_SHA512: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04];
const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
const OID_SUBJECT_KEY_ID: &[u8] = &[0x55, 0x1d, 0x0e];
const OID_EXT_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];
const OID_KP_TIME_STAMPING: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08];

/// Why a request could not be built or a response was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TimestampError {
    /// The bytes are not the DER structure they should be.
    #[error("malformed time stamp: {0}")]
    Malformed(&'static str),
    /// The TSA refused the request; the value is the `PKIStatus`.
    #[error("the TSA did not grant the time stamp (status {0})")]
    NotGranted(i64),
    /// The stamped digest is not the one that was asked for.
    #[error("the time stamp covers another digest")]
    ImprintMismatch,
    /// The nonce is not the one sent, or the response has none.
    #[error("the nonce does not match the request")]
    NonceMismatch,
    /// The TSA policy is not the expected one.
    #[error("the TSA policy is {found}, expected {expected}")]
    PolicyMismatch { expected: String, found: String },
    /// An algorithm, curve or key type outside the supported set.
    #[error("unsupported algorithm: {0}")]
    Unsupported(String),
    /// The CMS signature does not verify.
    #[error("the time stamp signature is invalid")]
    BadSignature,
    /// The signer certificate is not in the response nor among the certificates you gave.
    #[error("the signer certificate was not found")]
    MissingSigner,
    /// The chain does not lead to any of the roots you trust.
    #[error("the certificate chain does not lead to a trusted root")]
    UntrustedChain,
    /// A certificate of the chain was not valid at the time the TSA stated.
    #[error("a certificate of the chain was not valid at the time stamp")]
    CertificateNotValid,
    /// The signer certificate is not allowed to time-stamp.
    #[error("the signer certificate does not carry the time-stamping key usage")]
    SignerUsage,
}

impl TimestampError {
    /// A stable machine-readable code for each case.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Malformed(_) => "MALFORMED",
            Self::NotGranted(_) => "NOT_GRANTED",
            Self::ImprintMismatch => "IMPRINT_MISMATCH",
            Self::NonceMismatch => "NONCE_MISMATCH",
            Self::PolicyMismatch { .. } => "POLICY_MISMATCH",
            Self::Unsupported(_) => "UNSUPPORTED",
            Self::BadSignature => "BAD_SIGNATURE",
            Self::MissingSigner => "MISSING_SIGNER",
            Self::UntrustedChain => "UNTRUSTED_CHAIN",
            Self::CertificateNotValid => "CERTIFICATE_NOT_VALID",
            Self::SignerUsage => "SIGNER_USAGE",
        }
    }
}

type Result<T> = std::result::Result<T, TimestampError>;

/// A hash algorithm for the stamped digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum HashAlgorithm {
    /// SHA-256 (the digest of the audit chain).
    #[default]
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl HashAlgorithm {
    fn oid(self) -> &'static [u8] {
        match self {
            Self::Sha256 => OID_SHA256,
            Self::Sha384 => OID_SHA384,
            Self::Sha512 => OID_SHA512,
        }
    }

    fn from_oid(oid: &[u8]) -> Result<Self> {
        match oid {
            OID_SHA256 => Ok(Self::Sha256),
            OID_SHA384 => Ok(Self::Sha384),
            OID_SHA512 => Ok(Self::Sha512),
            other => Err(TimestampError::Unsupported(format!("hash {}", dotted(other)))),
        }
    }

    fn len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
            Self::Sha512 => Sha512::digest(data).to_vec(),
        }
    }

    /// The name used in text and JSON: `sha256`, `sha384` or `sha512`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
        write!(out, "{b:02x}").ok();
        out
    })
}

/// Decodes a hex string, for the callers that keep responses and digests as text.
pub fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 || !text.is_ascii() {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

fn dotted(oid: &[u8]) -> String {
    let mut arcs: Vec<u64> = Vec::new();
    let mut value: u64 = 0;
    for byte in oid {
        value = value.wrapping_shl(7) | u64::from(byte & 0x7f);
        if byte & 0x80 == 0 {
            arcs.push(value);
            value = 0;
        }
    }
    if arcs.is_empty() {
        return String::new();
    }
    let first = arcs.remove(0);
    let (a, b) = match first {
        0..=39 => (0, first),
        40..=79 => (1, first - 40),
        _ => (2, first - 80),
    };
    let mut parts = vec![a.to_string(), b.to_string()];
    parts.extend(arcs.iter().map(u64::to_string));
    parts.join(".")
}

fn parse_dotted(text: &str) -> Result<Vec<u8>> {
    let bad = TimestampError::Malformed("invalid OID");
    let arcs: Vec<u64> = text
        .split('.')
        .map(|part| part.parse::<u64>().map_err(|_| bad.clone()))
        .collect::<Result<_>>()?;
    if arcs.len() < 2 || arcs[0] > 2 || (arcs[0] < 2 && arcs[1] >= 40) {
        return Err(bad);
    }
    let mut out = Vec::new();
    let push = |out: &mut Vec<u8>, mut value: u64| {
        let mut chunk = vec![(value & 0x7f) as u8];
        value >>= 7;
        while value > 0 {
            chunk.push((value & 0x7f) as u8 | 0x80);
            value >>= 7;
        }
        chunk.reverse();
        out.extend(chunk);
    };
    push(&mut out, arcs[0] * 40 + arcs[1]);
    for arc in &arcs[2..] {
        push(&mut out, *arc);
    }
    Ok(out)
}

fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match content.len() {
        n if n < 0x80 => out.push(n as u8),
        n => {
            let bytes: Vec<u8> = n.to_be_bytes().iter().copied().skip_while(|b| *b == 0).collect();
            out.push(0x80 | bytes.len() as u8);
            out.extend(bytes);
        }
    }
    out.extend_from_slice(content);
    out
}

fn minimal_be(value: u64) -> Vec<u8> {
    value.to_be_bytes().iter().copied().skip_while(|b| *b == 0).collect()
}

fn der_integer(value: u64) -> Vec<u8> {
    let mut bytes = minimal_be(value);
    if bytes.is_empty() {
        bytes.push(0);
    }
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    der(0x02, &bytes)
}

/// A `TimeStampReq` (RFC 3161 §2.4.1) to send to a TSA.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TimestampRequest {
    /// Algorithm of `digest`.
    pub algorithm: HashAlgorithm,
    /// The digest to stamp.
    pub digest: Vec<u8>,
    /// A number the response must echo, to tell it from a replay. The caller supplies it: the core
    /// has no source of randomness.
    pub nonce: Option<u64>,
    /// The TSA policy you ask for, as a dotted OID.
    pub policy: Option<String>,
    /// Ask the TSA to embed its certificates, so the response is self-contained. Defaults to `true`.
    pub cert_req: bool,
}

impl TimestampRequest {
    /// A request for a digest of `algorithm`.
    pub fn new(algorithm: HashAlgorithm, digest: Vec<u8>) -> Self {
        Self { algorithm, digest, nonce: None, policy: None, cert_req: true }
    }

    /// A request to stamp the head of an audit chain: the imprint is the 32 bytes of the head hash
    /// (hex in the record) under SHA-256, with no further hashing, so
    /// `openssl ts -query -digest <head> -sha256` produces the same request.
    pub fn for_chain_head(head: &str, nonce: Option<u64>) -> Result<Self> {
        Ok(Self { nonce, ..Self::new(HashAlgorithm::Sha256, head_digest(head)?) })
    }

    /// The DER encoding.
    pub fn to_der(&self) -> Result<Vec<u8>> {
        if self.digest.len() != self.algorithm.len() {
            return Err(TimestampError::Malformed("the digest length does not fit the algorithm"));
        }
        let algorithm = der(0x30, &[der(0x06, self.algorithm.oid()), der(0x05, &[])].concat());
        let imprint = der(0x30, &[algorithm, der(0x04, &self.digest)].concat());
        let mut body = [der_integer(1), imprint].concat();
        if let Some(policy) = &self.policy {
            body.extend(der(0x06, &parse_dotted(policy)?));
        }
        if let Some(nonce) = self.nonce {
            body.extend(der_integer(nonce));
        }
        if self.cert_req {
            body.extend(der(0x01, &[0xff]));
        }
        Ok(der(0x30, &body))
    }
}

fn head_digest(head: &str) -> Result<Vec<u8>> {
    decode_hex(head)
        .filter(|bytes| bytes.len() == 32)
        .ok_or(TimestampError::Malformed("the chain head is not 64 hex characters"))
}

#[derive(Clone, Copy)]
struct Tlv<'a> {
    tag: u8,
    content: &'a [u8],
    raw: &'a [u8],
}

struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    fn peek_tag(&self) -> Option<u8> {
        self.data.first().copied()
    }

    fn next(&mut self) -> Result<Tlv<'a>> {
        let short = TimestampError::Malformed("truncated DER");
        let tag = *self.data.first().ok_or(short.clone())?;
        if tag & 0x1f == 0x1f {
            return Err(TimestampError::Malformed("multi-byte tags are not used here"));
        }
        let first = *self.data.get(1).ok_or(short.clone())?;
        let (len, header) = if first < 0x80 {
            (usize::from(first), 2)
        } else if first == 0x80 {
            return Err(TimestampError::Malformed("indefinite length (BER) is not supported"));
        } else {
            let count = usize::from(first & 0x7f);
            if count > 4 {
                return Err(TimestampError::Malformed("length too large"));
            }
            let bytes = self.data.get(2..2 + count).ok_or(short.clone())?;
            (bytes.iter().fold(0usize, |acc, b| (acc << 8) | usize::from(*b)), 2 + count)
        };
        let end = header.checked_add(len).ok_or(short.clone())?;
        let raw = self.data.get(..end).ok_or(short)?;
        self.data = &self.data[end..];
        Ok(Tlv { tag, content: &raw[header..], raw })
    }

    fn expect(&mut self, tag: u8, what: &'static str) -> Result<Tlv<'a>> {
        let tlv = self.next()?;
        if tlv.tag == tag { Ok(tlv) } else { Err(TimestampError::Malformed(what)) }
    }

    fn sequence(&mut self, what: &'static str) -> Result<Reader<'a>> {
        Ok(Reader::new(self.expect(0x30, what)?.content))
    }
}

fn integer_value(tlv: Tlv<'_>) -> Result<i64> {
    if tlv.tag != 0x02 || tlv.content.is_empty() || tlv.content.len() > 8 {
        return Err(TimestampError::Malformed("integer"));
    }
    let negative = tlv.content[0] & 0x80 != 0;
    Ok(tlv
        .content
        .iter()
        .fold(if negative { -1i64 } else { 0 }, |acc, b| (acc << 8) | i64::from(*b)))
}

fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    &bytes[start..]
}

fn civil_to_unix(year: i64, month: i64, day: i64, hour: i64, minute: i64, second: i64) -> Result<i64> {
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !(0..24).contains(&hour)
        || !(0..60).contains(&minute)
        || !(0..=60).contains(&second)
    {
        return Err(TimestampError::Malformed("date"));
    }
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Ok(days * 86_400 + hour * 3600 + minute * 60 + second)
}

fn parse_time(tlv: Tlv<'_>) -> Result<(i64, u32)> {
    let text = std::str::from_utf8(tlv.content).map_err(|_| TimestampError::Malformed("date"))?;
    let digits = |range: std::ops::Range<usize>| -> Result<i64> {
        text.get(range)
            .filter(|part| part.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|part| part.parse::<i64>().ok())
            .ok_or(TimestampError::Malformed("date"))
    };
    match tlv.tag {
        0x17 => {
            if text.len() != 13 || !text.ends_with('Z') {
                return Err(TimestampError::Malformed("UTCTime"));
            }
            let yy = digits(0..2)?;
            let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
            let seconds = civil_to_unix(year, digits(2..4)?, digits(4..6)?, digits(6..8)?, digits(8..10)?, digits(10..12)?)?;
            Ok((seconds, 0))
        }
        0x18 => {
            if text.len() < 15 || !text.ends_with('Z') {
                return Err(TimestampError::Malformed("GeneralizedTime"));
            }
            let seconds = civil_to_unix(
                digits(0..4)?,
                digits(4..6)?,
                digits(6..8)?,
                digits(8..10)?,
                digits(10..12)?,
                digits(12..14)?,
            )?;
            let fraction = &text[14..text.len() - 1];
            let millis = match fraction.strip_prefix('.') {
                None if fraction.is_empty() => 0,
                Some(f) if !f.is_empty() && f.bytes().all(|b| b.is_ascii_digit()) => {
                    format!("{f:0<3}")[..3].parse().unwrap_or(0)
                }
                _ => return Err(TimestampError::Malformed("GeneralizedTime")),
            };
            Ok((seconds, millis))
        }
        _ => Err(TimestampError::Malformed("time")),
    }
}

#[derive(Clone)]
struct Certificate<'a> {
    raw: &'a [u8],
    tbs_raw: &'a [u8],
    serial: &'a [u8],
    issuer: &'a [u8],
    subject: &'a [u8],
    not_before: i64,
    not_after: i64,
    key_algorithm: &'a [u8],
    key_params: Option<Tlv<'a>>,
    key_bits: &'a [u8],
    signature_algorithm: &'a [u8],
    signature: &'a [u8],
    key_id: Option<&'a [u8]>,
    is_ca: bool,
    time_stamping: bool,
}

impl<'a> Certificate<'a> {
    fn parse(raw: &'a [u8]) -> Result<Self> {
        let mut top = Reader::new(raw);
        let mut cert = top.sequence("certificate")?;
        let tbs = cert.expect(0x30, "tbsCertificate")?;
        let outer_algorithm = cert.expect(0x30, "signatureAlgorithm")?;
        let signature_bits = cert.expect(0x03, "signature")?;
        let mut fields = Reader::new(tbs.content);
        if fields.peek_tag() == Some(0xa0) {
            fields.next()?;
        }
        let serial = fields.expect(0x02, "serialNumber")?.content;
        let inner_algorithm = fields.expect(0x30, "tbs signature algorithm")?;
        if inner_algorithm.content != outer_algorithm.content {
            return Err(TimestampError::Malformed("certificate signature algorithms differ"));
        }
        let issuer = fields.expect(0x30, "issuer")?.raw;
        let mut validity = fields.sequence("validity")?;
        let not_before = parse_time(validity.next()?)?.0;
        let not_after = parse_time(validity.next()?)?.0;
        let subject = fields.expect(0x30, "subject")?.raw;
        let mut spki = fields.sequence("subjectPublicKeyInfo")?;
        let mut key_algorithm = spki.sequence("key algorithm")?;
        let key_oid = key_algorithm.expect(0x06, "key algorithm oid")?.content;
        let key_params = if key_algorithm.is_empty() { None } else { Some(key_algorithm.next()?) };
        let key_bits = spki.expect(0x03, "subjectPublicKey")?.content;
        if key_bits.first() != Some(&0) {
            return Err(TimestampError::Malformed("subjectPublicKey has unused bits"));
        }
        let mut key_id = None;
        let mut is_ca = false;
        let mut time_stamping = false;
        while !fields.is_empty() {
            let field = fields.next()?;
            if field.tag != 0xa3 {
                continue;
            }
            let mut extensions = Reader::new(field.content).sequence("extensions")?;
            while !extensions.is_empty() {
                let mut extension = extensions.sequence("extension")?;
                let oid = extension.expect(0x06, "extension oid")?.content;
                if extension.peek_tag() == Some(0x01) {
                    extension.next()?;
                }
                let value = extension.expect(0x04, "extension value")?.content;
                if oid == OID_BASIC_CONSTRAINTS {
                    let mut constraints = Reader::new(value).sequence("basicConstraints")?;
                    is_ca = constraints.peek_tag() == Some(0x01) && constraints.next()?.content == [0xff];
                } else if oid == OID_SUBJECT_KEY_ID {
                    key_id = Some(Reader::new(value).expect(0x04, "subjectKeyIdentifier")?.content);
                } else if oid == OID_EXT_KEY_USAGE {
                    let mut usages = Reader::new(value).sequence("extKeyUsage")?;
                    while !usages.is_empty() {
                        time_stamping |= usages.expect(0x06, "key purpose")?.content == OID_KP_TIME_STAMPING;
                    }
                }
            }
        }
        if signature_bits.content.first() != Some(&0) {
            return Err(TimestampError::Malformed("signature has unused bits"));
        }
        let signature_algorithm = Reader::new(outer_algorithm.content).expect(0x06, "signature algorithm oid")?.content;
        Ok(Self {
            raw,
            tbs_raw: tbs.raw,
            serial,
            issuer,
            subject,
            not_before,
            not_after,
            key_algorithm: key_oid,
            key_params,
            key_bits,
            signature_algorithm,
            signature: signature_bits.content.get(1..).ok_or(TimestampError::Malformed("signature"))?,
            key_id,
            is_ca,
            time_stamping,
        })
    }

    fn valid_at(&self, at: i64) -> bool {
        self.not_before <= at && at <= self.not_after
    }
}

fn verify_signature(
    key: &Certificate<'_>,
    algorithm_oid: &[u8],
    fallback: Option<HashAlgorithm>,
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    let (rsa, hash) = match algorithm_oid {
        OID_RSA_SHA256 => (true, Some(HashAlgorithm::Sha256)),
        OID_RSA_SHA384 => (true, Some(HashAlgorithm::Sha384)),
        OID_RSA_SHA512 => (true, Some(HashAlgorithm::Sha512)),
        OID_RSA => (true, fallback),
        OID_ECDSA_SHA256 => (false, Some(HashAlgorithm::Sha256)),
        OID_ECDSA_SHA384 => (false, Some(HashAlgorithm::Sha384)),
        OID_ECDSA_SHA512 => (false, Some(HashAlgorithm::Sha512)),
        OID_EC_PUBLIC_KEY => (false, fallback),
        other => return Err(TimestampError::Unsupported(format!("signature {}", dotted(other)))),
    };
    let hash = hash.ok_or_else(|| TimestampError::Unsupported("signature without a digest algorithm".into()))?;
    let digest = hash.digest(message);
    if rsa {
        verify_rsa(key, hash, &digest, signature)
    } else {
        verify_ecdsa(key, &digest, signature)
    }
}

fn verify_rsa(key: &Certificate<'_>, hash: HashAlgorithm, digest: &[u8], signature: &[u8]) -> Result<()> {
    if key.key_algorithm != OID_RSA {
        return Err(TimestampError::BadSignature);
    }
    let bits = key.key_bits.get(1..).ok_or(TimestampError::Malformed("public key"))?;
    let mut public = Reader::new(bits).sequence("RSAPublicKey")?;
    let modulus = rsa::BigUint::from_bytes_be(strip_leading_zeros(public.expect(0x02, "modulus")?.content));
    let exponent = rsa::BigUint::from_bytes_be(strip_leading_zeros(public.expect(0x02, "exponent")?.content));
    let public = rsa::RsaPublicKey::new(modulus, exponent).map_err(|_| TimestampError::BadSignature)?;
    let scheme = match hash {
        HashAlgorithm::Sha256 => rsa::Pkcs1v15Sign::new::<Sha256>(),
        HashAlgorithm::Sha384 => rsa::Pkcs1v15Sign::new::<Sha384>(),
        HashAlgorithm::Sha512 => rsa::Pkcs1v15Sign::new::<Sha512>(),
    };
    public.verify(scheme, digest, signature).map_err(|_| TimestampError::BadSignature)
}

fn fixed(bytes: &[u8], size: usize) -> Result<Vec<u8>> {
    let bytes = strip_leading_zeros(bytes);
    if bytes.len() > size {
        return Err(TimestampError::BadSignature);
    }
    Ok([vec![0; size - bytes.len()], bytes.to_vec()].concat())
}

fn verify_ecdsa(key: &Certificate<'_>, digest: &[u8], signature: &[u8]) -> Result<()> {
    if key.key_algorithm != OID_EC_PUBLIC_KEY {
        return Err(TimestampError::BadSignature);
    }
    let curve = key
        .key_params
        .filter(|p| p.tag == 0x06)
        .ok_or(TimestampError::Malformed("EC parameters"))?
        .content;
    let point = key.key_bits.get(1..).ok_or(TimestampError::Malformed("public key"))?;
    let mut pair = Reader::new(signature).sequence("ECDSA signature")?;
    let r = pair.expect(0x02, "r")?.content;
    let s = pair.expect(0x02, "s")?.content;
    let invalid = |_| TimestampError::BadSignature;
    match curve {
        OID_P256 => {
            let raw = [fixed(r, 32)?, fixed(s, 32)?].concat();
            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(point).map_err(invalid)?;
            let signature = p256::ecdsa::Signature::from_slice(&raw).map_err(invalid)?;
            key.verify_prehash(digest, &signature).map_err(invalid)
        }
        OID_P384 => {
            let raw = [fixed(r, 48)?, fixed(s, 48)?].concat();
            let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(point).map_err(invalid)?;
            let signature = p384::ecdsa::Signature::from_slice(&raw).map_err(invalid)?;
            key.verify_prehash(digest, &signature).map_err(invalid)
        }
        other => Err(TimestampError::Unsupported(format!("curve {}", dotted(other)))),
    }
}

/// What a verified time stamp states.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TimestampInfo {
    /// The time the TSA states, in seconds since the Unix epoch.
    pub gen_time: i64,
    /// Milliseconds past `gen_time`, when the TSA gave a fraction.
    pub gen_time_millis: u32,
    /// The serial number of the stamp, hex.
    pub serial: String,
    /// The TSA policy, dotted OID.
    pub policy: String,
    /// Algorithm of the stamped digest.
    pub algorithm: HashAlgorithm,
    /// The stamped digest, hex.
    pub imprint: String,
    /// The nonce, hex, when the response has one.
    pub nonce: Option<String>,
    /// The DER-encoded subject of the signer certificate, hex, to identify the TSA.
    pub signer_subject: String,
}

/// What to check besides the signature.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifyOptions {
    /// DER certificates you trust as anchors. With none, every response is refused.
    pub trusted_roots: Vec<Vec<u8>>,
    /// More DER certificates to complete the chain, for a response that did not embed them.
    pub certificates: Vec<Vec<u8>>,
    /// Algorithm the digest was stamped with.
    pub algorithm: HashAlgorithm,
    /// The digest that must have been stamped.
    pub imprint: Vec<u8>,
    /// The nonce sent in the request; the response must echo it.
    pub nonce: Option<u64>,
    /// The policy the response must state, dotted OID.
    pub policy: Option<String>,
}

impl VerifyOptions {
    /// Options for a digest stamped with SHA-256 and the roots to trust.
    pub fn new(imprint: Vec<u8>, trusted_roots: Vec<Vec<u8>>) -> Self {
        Self {
            trusted_roots,
            certificates: Vec::new(),
            algorithm: HashAlgorithm::Sha256,
            imprint,
            nonce: None,
            policy: None,
        }
    }

    /// Options for the time stamp of an audit chain head (see [`TimestampRequest::for_chain_head`]).
    pub fn for_chain_head(head: &str, trusted_roots: Vec<Vec<u8>>) -> Result<Self> {
        Ok(Self::new(head_digest(head)?, trusted_roots))
    }
}

struct SignerInfo<'a> {
    issuer: Option<&'a [u8]>,
    serial: Option<&'a [u8]>,
    key_id: Option<&'a [u8]>,
    digest: HashAlgorithm,
    signed_attrs: Tlv<'a>,
    signature_algorithm: &'a [u8],
    signature: &'a [u8],
}

fn parse_signer_info<'a>(reader: &mut Reader<'a>) -> Result<SignerInfo<'a>> {
    let mut info = reader.sequence("SignerInfo")?;
    info.expect(0x02, "SignerInfo version")?;
    let sid = info.next()?;
    let (issuer, serial, key_id) = match sid.tag {
        0x30 => {
            let mut parts = Reader::new(sid.content);
            let issuer = parts.expect(0x30, "issuer")?.raw;
            let serial = parts.expect(0x02, "serial")?.content;
            (Some(issuer), Some(serial), None)
        }
        0x80 => (None, None, Some(sid.content)),
        _ => return Err(TimestampError::Malformed("signer identifier")),
    };
    let mut digest_algorithm = info.sequence("digestAlgorithm")?;
    let digest = HashAlgorithm::from_oid(digest_algorithm.expect(0x06, "digest oid")?.content)?;
    let signed_attrs = info.expect(0xa0, "signed attributes are required")?;
    let mut signature_algorithm = info.sequence("signatureAlgorithm")?;
    let signature_algorithm = signature_algorithm.expect(0x06, "signature oid")?.content;
    let signature = info.expect(0x04, "signature")?.content;
    Ok(SignerInfo { issuer, serial, key_id, digest, signed_attrs, signature_algorithm, signature })
}

fn chain_is_trusted(signer: &Certificate<'_>, pool: &[Certificate<'_>], roots: &[Certificate<'_>], at: i64) -> Result<()> {
    let mut current = signer;
    let mut visited: Vec<&[u8]> = vec![current.raw];
    for _ in 0..MAX_CHAIN {
        if !current.valid_at(at) {
            return Err(TimestampError::CertificateNotValid);
        }
        if roots.iter().any(|root| root.raw == current.raw) {
            return Ok(());
        }
        let issuer = roots
            .iter()
            .map(|c| (c, true))
            .chain(pool.iter().map(|c| (c, false)))
            .filter(|(c, _)| c.subject == current.issuer && !visited.contains(&c.raw))
            .find(|(c, is_root)| {
                (*is_root || c.is_ca)
                    && verify_signature(c, current.signature_algorithm, None, current.tbs_raw, current.signature).is_ok()
            });
        let Some((issuer, is_root)) = issuer else {
            return Err(TimestampError::UntrustedChain);
        };
        if !issuer.valid_at(at) {
            return Err(TimestampError::CertificateNotValid);
        }
        if is_root {
            return Ok(());
        }
        visited.push(issuer.raw);
        current = issuer;
    }
    Err(TimestampError::UntrustedChain)
}

/// Checks a DER `TimeStampResp` against what you stamped and the roots you trust, and returns what
/// the TSA states. See the module documentation for the list of checks.
pub fn verify_response(response: &[u8], options: &VerifyOptions) -> Result<TimestampInfo> {
    if options.imprint.len() != options.algorithm.len() {
        return Err(TimestampError::Malformed("the expected digest does not fit its algorithm"));
    }
    let mut top = Reader::new(response);
    let mut resp = top.sequence("TimeStampResp")?;
    let mut status_info = resp.sequence("PKIStatusInfo")?;
    let status = integer_value(status_info.next()?)?;
    if status != 0 && status != 1 {
        return Err(TimestampError::NotGranted(status));
    }
    let token = resp.expect(0x30, "timeStampToken is missing")?;
    let mut content_info = Reader::new(token.content);
    if content_info.expect(0x06, "contentType")?.content != OID_SIGNED_DATA {
        return Err(TimestampError::Malformed("the token is not SignedData"));
    }
    let wrapped = content_info.expect(0xa0, "SignedData wrapper")?;
    let mut signed_data = Reader::new(wrapped.content).sequence("SignedData")?;
    if integer_value(signed_data.expect(0x02, "SignedData version")?)? != 3 {
        return Err(TimestampError::Malformed("SignedData version must be 3"));
    }
    signed_data.expect(0x31, "digestAlgorithms")?;
    let mut encapsulated = signed_data.sequence("encapContentInfo")?;
    if encapsulated.expect(0x06, "eContentType")?.content != OID_TST_INFO {
        return Err(TimestampError::Malformed("the content is not a TSTInfo"));
    }
    let econtent_wrapper = encapsulated.expect(0xa0, "eContent wrapper")?;
    let tst_info_bytes = Reader::new(econtent_wrapper.content).expect(0x04, "eContent")?.content;

    let mut embedded: Vec<&[u8]> = Vec::new();
    if signed_data.peek_tag() == Some(0xa0) {
        let mut certificates = Reader::new(signed_data.next()?.content);
        while !certificates.is_empty() {
            let cert = certificates.next()?;
            if cert.tag == 0x30 {
                embedded.push(cert.raw);
            }
        }
    }
    if signed_data.peek_tag() == Some(0xa1) {
        signed_data.next()?;
    }
    let mut signers = Reader::new(signed_data.expect(0x31, "signerInfos")?.content);
    let signer_info = parse_signer_info(&mut signers)?;
    if !signers.is_empty() {
        return Err(TimestampError::Malformed("exactly one signer is expected"));
    }

    let mut tst = Reader::new(tst_info_bytes).sequence("TSTInfo")?;
    tst.expect(0x02, "TSTInfo version")?;
    let policy = dotted(tst.expect(0x06, "policy")?.content);
    let mut imprint = tst.sequence("messageImprint")?;
    let mut imprint_algorithm = imprint.sequence("imprint algorithm")?;
    let algorithm = HashAlgorithm::from_oid(imprint_algorithm.expect(0x06, "imprint oid")?.content)?;
    let stamped = imprint.expect(0x04, "imprint digest")?.content;
    let serial = tst.expect(0x02, "serial")?.content;
    let (gen_time, gen_time_millis) = parse_time(tst.expect(0x18, "genTime")?)?;
    let mut nonce: Option<&[u8]> = None;
    while !tst.is_empty() {
        let field = tst.next()?;
        match field.tag {
            0x02 => nonce = Some(field.content),
            0x30 | 0x01 | 0xa0 | 0xa1 => {}
            _ => return Err(TimestampError::Malformed("unexpected TSTInfo field")),
        }
    }

    if algorithm != options.algorithm || stamped != options.imprint.as_slice() {
        return Err(TimestampError::ImprintMismatch);
    }
    if let Some(expected) = options.nonce {
        match nonce {
            Some(found) if strip_leading_zeros(found) == minimal_be(expected).as_slice() => {}
            _ => return Err(TimestampError::NonceMismatch),
        }
    }
    if let Some(expected) = &options.policy
        && expected != &policy
    {
        return Err(TimestampError::PolicyMismatch { expected: expected.clone(), found: policy });
    }

    let roots = options
        .trusted_roots
        .iter()
        .map(|raw| Certificate::parse(raw))
        .collect::<Result<Vec<_>>>()?;
    let mut pool = Vec::new();
    for raw in embedded.iter().copied().chain(options.certificates.iter().map(Vec::as_slice)) {
        if pool.len() >= MAX_CERTIFICATES {
            return Err(TimestampError::Malformed("too many certificates"));
        }
        pool.push(Certificate::parse(raw)?);
    }
    let signer = pool
        .iter()
        .chain(roots.iter())
        .find(|cert| match (signer_info.issuer, signer_info.serial, signer_info.key_id) {
            (Some(issuer), Some(serial), _) => cert.issuer == issuer && cert.serial == serial,
            (_, _, Some(id)) => cert.key_id == Some(id),
            _ => false,
        })
        .ok_or(TimestampError::MissingSigner)?;

    verify_signed_attributes(&signer_info, signer, tst_info_bytes)?;
    if !signer.time_stamping {
        return Err(TimestampError::SignerUsage);
    }
    chain_is_trusted(signer, &pool, &roots, gen_time)?;

    Ok(TimestampInfo {
        gen_time,
        gen_time_millis,
        serial: hex(strip_leading_zeros(serial)),
        policy,
        algorithm,
        imprint: hex(stamped),
        nonce: nonce.map(|n| hex(strip_leading_zeros(n))),
        signer_subject: hex(signer.subject),
    })
}

fn verify_signed_attributes(info: &SignerInfo<'_>, signer: &Certificate<'_>, tst_info: &[u8]) -> Result<()> {
    let mut content_type_ok = false;
    let mut digest_ok = false;
    let mut attributes = Reader::new(info.signed_attrs.content);
    while !attributes.is_empty() {
        let mut attribute = attributes.sequence("attribute")?;
        let oid = attribute.expect(0x06, "attribute oid")?.content;
        let mut values = Reader::new(attribute.expect(0x31, "attribute values")?.content);
        if oid == OID_CONTENT_TYPE {
            content_type_ok = values.expect(0x06, "contentType value")?.content == OID_TST_INFO;
        } else if oid == OID_MESSAGE_DIGEST {
            digest_ok = values.expect(0x04, "messageDigest value")?.content == info.digest.digest(tst_info).as_slice();
        }
    }
    if !content_type_ok || !digest_ok {
        return Err(TimestampError::BadSignature);
    }
    let mut signed = info.signed_attrs.raw.to_vec();
    signed[0] = 0x31;
    verify_signature(signer, info.signature_algorithm, Some(info.digest), &signed, info.signature)
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// The DER certificates in a PEM text, in order. Blocks that are not `CERTIFICATE` or are not valid
/// base64 are skipped.
pub fn pem_certificates(text: &str) -> Vec<Vec<u8>> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(BEGIN) {
        let after = &rest[start + BEGIN.len()..];
        let Some(end) = after.find(END) else { break };
        let mut bits: u32 = 0;
        let mut count = 0;
        let mut bytes = Vec::new();
        let mut valid = true;
        for byte in after[..end].bytes().filter(|b| !b.is_ascii_whitespace() && *b != b'=') {
            let Some(value) = base64_value(byte) else {
                valid = false;
                break;
            };
            bits = (bits << 6) | u32::from(value);
            count += 6;
            if count >= 8 {
                count -= 8;
                bytes.push((bits >> count) as u8);
                bits &= (1 << count) - 1;
            }
        }
        if valid && !bytes.is_empty() {
            out.push(bytes);
        }
        rest = &after[end + END.len()..];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotted_round_trips() {
        for oid in ["1.2.840.113549.1.9.16.1.4", "2.16.840.1.101.3.4.2.1", "1.3.132.0.34", "2.5.29.37"] {
            assert_eq!(dotted(&parse_dotted(oid).unwrap()), oid);
        }
        assert!(parse_dotted("3.1").is_err());
        assert!(parse_dotted("1").is_err());
        assert!(parse_dotted("1.x").is_err());
    }

    #[test]
    fn time_parsing() {
        let utc = Tlv { tag: 0x17, content: b"700101000000Z", raw: &[] };
        assert_eq!(parse_time(utc).unwrap(), (0, 0));
        let general = Tlv { tag: 0x18, content: b"20261128121800.5Z", raw: &[] };
        assert_eq!(parse_time(general).unwrap(), (1_795_868_280, 500));
        let bad = Tlv { tag: 0x18, content: b"20261328121800Z", raw: &[] };
        assert!(parse_time(bad).is_err());
    }

    #[test]
    fn integers_are_minimal_and_positive() {
        assert_eq!(der_integer(0), [0x02, 0x01, 0x00]);
        assert_eq!(der_integer(0x7f), [0x02, 0x01, 0x7f]);
        assert_eq!(der_integer(0x80), [0x02, 0x02, 0x00, 0x80]);
    }
}
