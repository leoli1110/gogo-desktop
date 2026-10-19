//! Accounts, sessions, library permissions and the audit log.
//!
//! Storage is a single SQLite file (`data/db/accounts.sqlite`). Passwords use
//! Argon2id; sign-in codes use TOTP (RFC 6238). Session tokens and reset
//! codes are stored only as SHA-256 hashes.

pub mod audit;
pub mod password;
mod store;
pub mod totp;

pub use store::*;

use rand::RngCore;
use sha2::{Digest, Sha256};

/// Current Unix time in seconds.
pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Random token of `bytes` bytes, URL-safe base64 without padding.
pub fn random_token(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    data_encoding::BASE64URL_NOPAD.encode(&buf)
}

/// Human-friendly one-time code like `K7QF-2MXP-9TRA` (Crockford-style alphabet).
pub fn random_code() -> String {
    const ALPHABET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut buf = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    let chars: String = buf.iter().map(|b| ALPHABET[(*b as usize) % ALPHABET.len()] as char).collect();
    format!("{}-{}-{}", &chars[0..4], &chars[4..8], &chars[8..12])
}

/// Normalizes a code the user typed (case, spaces and dashes don't matter).
pub fn normalize_code(code: &str) -> String {
    code.chars().filter(|c| c.is_ascii_alphanumeric()).map(|c| c.to_ascii_uppercase()).collect()
}

/// SHA-256 as lowercase hex.
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Constant-time string comparison.
pub fn ct_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}
