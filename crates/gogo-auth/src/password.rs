//! Password hashing (Argon2id) and password rules.

use argon2::password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;

/// Minimum password length (spec section 11.2.2).
pub const MIN_LEN: usize = 12;
/// Maximum password length, to bound hashing cost.
pub const MAX_LEN: usize = 256;

/// Common passwords of 12+ characters that are rejected outright. The length
/// rule already removes most short common passwords.
const COMMON: &[&str] = &[
    "password1234",
    "password12345",
    "password123456",
    "passwordpassword",
    "123456789012",
    "1234567890123",
    "12345678901234",
    "123456123456",
    "qwertyuiopas",
    "qwertyuiop12",
    "qwerty123456",
    "qwertyqwerty",
    "iloveyou1234",
    "abcdefghijkl",
    "abc123abc123",
    "letmein12345",
    "welcome12345",
    "welcome123456",
    "administrator",
    "administrator1",
    "admin1234567",
    "adminadmin12",
    "changeme1234",
    "football1234",
    "baseball1234",
    "superman1234",
    "monkey123456",
    "dragon123456",
    "sunshine1234",
    "princess1234",
    "trustno1trustno1",
    "1q2w3e4r5t6y",
    "1qaz2wsx3edc",
    "zaq12wsxcde3",
    "aaaaaaaaaaaa",
    "000000000000",
    "111111111111",
    "p@ssw0rd1234",
    "passw0rd1234",
    "gogodesktop1",
    "gogodesktop123",
    "synology1234",
];

/// Why a password was refused (shown to the user).
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum PasswordProblem {
    #[error("use at least {MIN_LEN} characters")]
    TooShort,
    #[error("use at most {MAX_LEN} characters")]
    TooLong,
    #[error("this password is too common")]
    Common,
    #[error("the password can't contain the username")]
    ContainsUsername,
    #[error("use more than one repeated character or simple sequence")]
    Trivial,
}

/// Checks the password rules.
pub fn check_rules(password: &str, username: &str) -> Result<(), PasswordProblem> {
    let n = password.chars().count();
    if n < MIN_LEN {
        return Err(PasswordProblem::TooShort);
    }
    if n > MAX_LEN {
        return Err(PasswordProblem::TooLong);
    }
    let lower = password.to_lowercase();
    if COMMON.contains(&lower.as_str()) {
        return Err(PasswordProblem::Common);
    }
    let user = username.to_lowercase();
    if user.chars().count() >= 3 && lower.contains(&user) {
        return Err(PasswordProblem::ContainsUsername);
    }
    let chars: Vec<char> = lower.chars().collect();
    let distinct: std::collections::HashSet<char> = chars.iter().copied().collect();
    let sequential = chars.windows(2).all(|w| (w[1] as i64 - w[0] as i64) == 1)
        || chars.windows(2).all(|w| (w[0] as i64 - w[1] as i64) == 1);
    if distinct.len() <= 2 || sequential {
        return Err(PasswordProblem::Trivial);
    }
    Ok(())
}

/// Hashes a password with Argon2id (default parameters: 19 MiB, 2 passes).
pub fn hash(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default().hash_password(password.as_bytes(), &salt).expect("argon2 hashing").to_string()
}

/// Verifies a password against a stored hash.
pub fn verify(password: &str, stored: &str) -> bool {
    match PasswordHash::new(stored) {
        Ok(h) => Argon2::default().verify_password(password.as_bytes(), &h).is_ok(),
        Err(_) => false,
    }
}

/// Spends about the same time as a real check, so a missing account can't be
/// told apart from a wrong password by timing.
pub fn dummy_verify(password: &str) {
    static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    let h = DUMMY.get_or_init(|| hash("dummy-password-for-timing"));
    let _ = verify(password, h);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules() {
        assert_eq!(check_rules("short", "a"), Err(PasswordProblem::TooShort));
        assert_eq!(check_rules("Password1234", "bob"), Err(PasswordProblem::Common));
        assert_eq!(check_rules("leo-is-great-2026", "leo"), Err(PasswordProblem::ContainsUsername));
        assert_eq!(check_rules("abababababab", "x"), Err(PasswordProblem::Trivial));
        assert_eq!(check_rules("abcdefghijklm", "x"), Err(PasswordProblem::Trivial));
        assert!(check_rules("correct horse battery", "leo").is_ok());
        assert!(check_rules("貓咪喜歡曬太陽的午後時光", "leo").is_ok());
    }

    #[test]
    fn hash_and_verify() {
        let h = hash("correct horse battery");
        assert!(h.starts_with("$argon2id$"));
        assert!(verify("correct horse battery", &h));
        assert!(!verify("wrong horse battery", &h));
        assert!(!verify("x", "not-a-hash"));
    }
}
