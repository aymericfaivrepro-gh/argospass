//! Cryptography: deriving a key from the master password.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use std::io;

/// Encryption key size: 32 bytes (256 bits).
pub const KEY_LEN: usize = 32;

/// Salt size: 16 bytes (128 bits), per RFC 9106 recommendation.
pub const SALT_LEN: usize = 16;

/// XChaCha20-Poly1305 nonce length: 24 bytes (192 bits).
pub const NONCE_LEN: usize = 24;

/// Poly1305 authentication tag length: 16 bytes.
pub const TAG_LEN: usize = 16;

/// Argon2id memory cost, in KiB (here 64 MiB).
const MEMORY_KIB: u32 = 64 * 1024;
/// Number of passes over memory.
const ITERATIONS: u32 = 3;
/// Degree of parallelism.
const PARALLELISM: u32 = 4;
/// Key material of an unlocked vault: the salt stored in the file
/// and the key derived from the master password.
pub struct VaultKey {
    pub(crate) salt: [u8; SALT_LEN],
    pub(crate) key: [u8; KEY_LEN],
}

impl VaultKey {
    /// Creates key material for a new vault: generates a fresh salt and derives the key.
    pub fn new(password: &str) -> io::Result<Self> {
        let salt = generate_salt()?;
        Self::from_salt(password, salt)
    }

    /// Re-derives the key of an existing vault from its stored salt.
    pub fn from_salt(password: &str, salt: [u8; SALT_LEN]) -> io::Result<Self> {
        let key = derive_key(password, &salt)?;
        Ok(Self { salt, key })
    }
}
/// Fills `buf` with random bytes from the operating system's CSPRNG.
pub(crate) fn fill_random(buf: &mut [u8]) -> io::Result<()> {
    getrandom::fill(buf).map_err(|e| io::Error::other(e.to_string()))
}

/// Generates a random salt using the operating system's CSPRNG.
pub fn generate_salt() -> io::Result<[u8; SALT_LEN]> {
    let mut salt = [0u8; SALT_LEN];
    fill_random(&mut salt)?;
    Ok(salt)
}

/// Encrypts `plaintext` with `key` using XChaCha20-Poly1305.
///
/// A fresh random nonce is generated on every call.
/// Output layout: `nonce (24 bytes) || ciphertext || tag (16 bytes)`.
pub fn encrypt(key: &[u8; KEY_LEN], plaintext: &[u8]) -> io::Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));

    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce)?;

    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|_| io::Error::other("encryption failed"))?;

    let mut output = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypts data produced by [`encrypt`].
///
/// Fails if the key is wrong or if the data has been modified.
pub fn decrypt(key: &[u8; KEY_LEN], data: &[u8]) -> io::Result<Vec<u8>> {
    if data.len() < NONCE_LEN + TAG_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "encrypted data is too short",
        ));
    }

    let (nonce, ciphertext) = data.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));

    cipher
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "decryption failed: wrong password or corrupted data",
            )
        })
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
    #[test]
    fn encrypt_then_decrypt_returns_plaintext() {
        let key = [42u8; KEY_LEN];
        let encrypted = encrypt(&key, b"hello vault").expect("encryption should succeed");
        let decrypted = decrypt(&key, &encrypted).expect("decryption should succeed");
        assert_eq!(decrypted, b"hello vault");
    }

    #[test]
    fn output_has_expected_length() {
        let key = [42u8; KEY_LEN];
        let plaintext = b"hello vault";
        let encrypted = encrypt(&key, plaintext).expect("encryption should succeed");
        assert_eq!(encrypted.len(), NONCE_LEN + plaintext.len() + TAG_LEN);
    }

    #[test]
    fn same_plaintext_encrypts_differently_each_time() {
        let key = [42u8; KEY_LEN];
        let a = encrypt(&key, b"hello vault").expect("encryption should succeed");
        let b = encrypt(&key, b"hello vault").expect("encryption should succeed");
        assert_ne!(a, b);
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        let encrypted =
            encrypt(&[1u8; KEY_LEN], b"hello vault").expect("encryption should succeed");
        assert!(decrypt(&[2u8; KEY_LEN], &encrypted).is_err());
    }

    #[test]
    fn tampered_data_fails_to_decrypt() {
        let key = [42u8; KEY_LEN];
        let mut encrypted = encrypt(&key, b"hello vault").expect("encryption should succeed");
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0x01; // flip one bit
        assert!(decrypt(&key, &encrypted).is_err());
    }

    #[test]
    fn too_short_data_fails_to_decrypt() {
        let key = [42u8; KEY_LEN];
        assert!(decrypt(&key, &[0u8; 10]).is_err());
    }

    #[test]
    fn show_encryption() {
        let key = [42u8; KEY_LEN];
        for _ in 0..2 {
            let encrypted = encrypt(&key, b"hello vault").expect("encryption should succeed");
            let hex: String = encrypted.iter().map(|b| format!("{b:02x}")).collect();
            println!("{hex}");
        }
    }
}
