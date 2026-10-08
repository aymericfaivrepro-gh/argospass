//! Random password generator.

use crate::crypto::fill_random;
use std::io;

/// Default length of generated passwords.
pub const DEFAULT_LENGTH: usize = 24;

/// Minimum accepted length of generated passwords.
pub const MIN_LENGTH: usize = 8;

const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
/// Symbols that are safe to type and paste: no quotes, backslash, backtick or space.
const SYMBOLS: &[u8] = b"!#$%&()*+,-./:;<=>?@[]^_{|}~";

/// Generates a random password of `length` characters.
///
/// Uses the operating system's CSPRNG and rejection sampling,
/// so every allowed character has exactly the same probability.
pub fn generate_password(length: usize, symbols: bool) -> io::Result<String> {
    if length < MIN_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("password length must be at least {MIN_LENGTH}"),
        ));
    }

    let mut charset = Vec::new();
    charset.extend_from_slice(LOWERCASE);
    charset.extend_from_slice(UPPERCASE);
    charset.extend_from_slice(DIGITS);
    if symbols {
        charset.extend_from_slice(SYMBOLS);
    }

    let n = charset.len();
    // Largest multiple of `n` that fits in a byte: bytes at or above it are rejected.
    let limit = 256 - (256 % n);

    let mut password = String::with_capacity(length);
    let mut random_bytes = [0u8; 64];
    while password.len() < length {
        fill_random(&mut random_bytes)?;
        for &byte in &random_bytes {
            let value = byte as usize;
            if value < limit {
                password.push(charset[value % n] as char);
                if password.len() == length {
                    break;
                }
            }
        }
    }
    Ok(password)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_requested_length() {
        let password = generate_password(32, true).expect("generation should succeed");
        assert_eq!(password.len(), 32);
    }

    #[test]
    fn without_symbols_only_uses_letters_and_digits() {
        let password = generate_password(200, false).expect("generation should succeed");
        assert!(password.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn rejects_too_short_length() {
        assert!(generate_password(MIN_LENGTH - 1, true).is_err());
    }

    #[test]
    fn two_passwords_differ() {
        let a = generate_password(DEFAULT_LENGTH, true).expect("generation should succeed");
        let b = generate_password(DEFAULT_LENGTH, true).expect("generation should succeed");
        assert_ne!(a, b);
    }

    #[test]
    fn every_allowed_character_can_appear() {
        // With 10,000 draws among 90 characters, missing any of them is
        // astronomically unlikely (about 1 chance in 10^46).
        let password = generate_password(10_000, true).expect("generation should succeed");
        for &c in LOWERCASE
            .iter()
            .chain(UPPERCASE)
            .chain(DIGITS)
            .chain(SYMBOLS)
        {
            assert!(
                password.contains(c as char),
                "character {} never appeared",
                c as char
            );
        }
    }
}
