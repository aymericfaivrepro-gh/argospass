//! Cryptography: deriving a key from the master password.

use argon2::{Algorithm, Argon2, Params, Version};
use std::io;

/// Encryption key size: 32 bytes (256 bits).
pub const KEY_LEN: usize = 32;

/// Salt size: 16 bytes (128 bits), per RFC 9106 recommendation.
pub const SALT_LEN: usize = 16;

/// Argon2id memory cost, in KiB (here 64 MiB).
const MEMORY_KIB: u32 = 64 * 1024;
/// Number of passes over memory.
const ITERATIONS: u32 = 3;
/// Degree of parallelism.
const PARALLELISM: u32 = 4;

/// Generates a random salt using the system cryptographic generator.
pub fn generate_salt() -> io::Result<[u8; SALT_LEN]> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(salt)
}

/// Derives a 256-bit key from the master password and salt.
pub fn derive_key(password: &str, salt: &[u8; SALT_LEN]) -> io::Result<[u8; KEY_LEN]> {
    let params = Params::new(MEMORY_KIB, ITERATIONS, PARALLELISM, Some(KEY_LEN))
        .map_err(|e| io::Error::other(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| io::Error::other(e.to_string()))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_password_and_same_salt_produce_the_same_key() {
        let salt = [7u8; SALT_LEN];
        let k1 = derive_key("correct horse", &salt).expect("derivation");
        let k2 = derive_key("correct horse", &salt).expect("derivation");
        assert_eq!(k1, k2);
    }

    #[test]
    fn different_salt_produces_a_different_key() {
        let k1 = derive_key("correct horse", &[1u8; SALT_LEN]).expect("derivation");
        let k2 = derive_key("correct horse", &[2u8; SALT_LEN]).expect("derivation");
        assert_ne!(k1, k2);
    }

    #[test]
    fn different_password_produces_a_different_key() {
        let salt = [7u8; SALT_LEN];
        let k1 = derive_key("correct horse", &salt).expect("derivation");
        let k2 = derive_key("correct hors3", &salt).expect("derivation");
        assert_ne!(k1, k2);
    }

    #[test]
    fn two_generated_salts_are_different() {
        let s1 = generate_salt().expect("generation");
        let s2 = generate_salt().expect("generation");
        assert_ne!(s1, s2);
    }
}
