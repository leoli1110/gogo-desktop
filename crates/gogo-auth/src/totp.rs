//! Time-based one-time codes (RFC 6238: HMAC-SHA1, 6 digits, 30 seconds).

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha1::Sha1;

pub const PERIOD: i64 = 30;
pub const DIGITS: u32 = 6;

/// New random secret (160 bits), base32 without padding.
pub fn new_secret() -> String {
    let mut buf = [0u8; 20];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    data_encoding::BASE32_NOPAD.encode(&buf)
}

/// `otpauth://` link for authenticator apps.
pub fn otpauth_url(secret: &str, account: &str, issuer: &str) -> String {
    fn enc(s: &str) -> String {
        s.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
                _ => format!("%{b:02X}"),
            })
            .collect()
    }
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={}&period={}",
        enc(issuer),
        enc(account),
        secret,
        enc(issuer),
        DIGITS,
        PERIOD
    )
}

/// The code for a given time step.
pub fn code_at(secret: &str, step: i64) -> Option<String> {
    let key = data_encoding::BASE32_NOPAD.decode(secret.as_bytes()).ok()?;
    let mut mac = Hmac::<Sha1>::new_from_slice(&key).ok()?;
    mac.update(&(step as u64).to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let bin = ((digest[offset] as u32 & 0x7f) << 24)
        | ((digest[offset + 1] as u32) << 16)
        | ((digest[offset + 2] as u32) << 8)
        | digest[offset + 3] as u32;
    Some(format!("{:0width$}", bin % 10u32.pow(DIGITS), width = DIGITS as usize))
}

/// Checks a code, allowing one step of clock difference. Returns the matched
/// step, which must be greater than `last_used_step` (no replay).
pub fn verify(secret: &str, code: &str, now: i64, last_used_step: i64) -> Option<i64> {
    let code: String = code.chars().filter(|c| c.is_ascii_digit()).collect();
    if code.len() != DIGITS as usize {
        return None;
    }
    let current = now / PERIOD;
    for step in [current, current - 1, current + 1] {
        if step <= last_used_step {
            continue;
        }
        if let Some(expected) = code_at(secret, step) {
            if crate::ct_eq(&expected, &code) {
                return Some(step);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_vector() {
        // RFC 6238 SHA1 test key "12345678901234567890"; T=59 -> 94287082 (8 digits) -> 287082.
        let secret = data_encoding::BASE32_NOPAD.encode(b"12345678901234567890");
        assert_eq!(code_at(&secret, 59 / 30).unwrap(), "287082");
        assert_eq!(code_at(&secret, 1_111_111_109 / 30).unwrap(), "081804");
    }

    #[test]
    fn replay_is_refused() {
        let s = new_secret();
        let now = 1_760_000_000;
        let code = code_at(&s, now / PERIOD).unwrap();
        let step = verify(&s, &code, now, 0).unwrap();
        assert_eq!(verify(&s, &code, now, step), None);
        assert_eq!(verify(&s, "12", now, 0), None);
    }

    #[test]
    fn url() {
        let u = otpauth_url("ABC", "leo@pc", "Gogo Desktop");
        assert!(u.starts_with("otpauth://totp/Gogo%20Desktop:leo%40pc?secret=ABC"));
    }
}
