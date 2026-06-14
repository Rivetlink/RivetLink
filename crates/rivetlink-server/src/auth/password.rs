//! Argon2id password hashing and verification.

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

use crate::error::{ServerError, ServerResult};

/// Hash a plaintext password using Argon2id with random salt.
pub fn hash_password(password: &str) -> ServerResult<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| ServerError::Internal(format!("password hashing failed: {e}")))
}

/// Verify plaintext password against Argon2id hash; returns bool or error on malformed hash.
pub fn verify_password(password: &str, hash: &str) -> ServerResult<bool> {
    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| ServerError::Internal(format!("invalid password hash: {e}")))?;

    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_password() {
        let password = "secure-password-123!";
        let hash = hash_password(password).unwrap();

        assert!(hash.starts_with("$argon2"));
        assert!(verify_password(password, &hash).unwrap());
    }

    #[test]
    fn wrong_password_fails_verification() {
        let hash = hash_password("correct-password").unwrap();
        assert!(!verify_password("wrong-password", &hash).unwrap());
    }

    #[test]
    fn different_passwords_produce_different_hashes() {
        let hash_a = hash_password("password-a").unwrap();
        let hash_b = hash_password("password-b").unwrap();
        assert_ne!(hash_a, hash_b);
    }

    #[test]
    fn same_password_produces_different_hashes_due_to_salt() {
        let hash_a = hash_password("same-password").unwrap();
        let hash_b = hash_password("same-password").unwrap();
        assert_ne!(hash_a, hash_b);
        assert!(verify_password("same-password", &hash_a).unwrap());
        assert!(verify_password("same-password", &hash_b).unwrap());
    }

    #[test]
    fn empty_password_hashes_successfully() {
        let hash = hash_password("").unwrap();
        assert!(verify_password("", &hash).unwrap());
        assert!(!verify_password("not-empty", &hash).unwrap());
    }

    #[test]
    fn invalid_hash_format_returns_error() {
        let result = verify_password("password", "not-a-valid-hash");
        assert!(result.is_err());
    }
}
