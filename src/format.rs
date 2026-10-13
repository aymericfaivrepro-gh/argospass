//! Binary layout of the vault file header.
//!
//! ```text
//! offset  size  field
//!      0     5  magic number "ARGOS"
//!      5     1  format version
//!      6     4  Argon2id memory cost in KiB (u32, little-endian)
//!     10     4  Argon2id iterations        (u32, little-endian)
//!     14     4  Argon2id parallelism       (u32, little-endian)
//!     18    16  salt
//! ```
//!
//! The header is stored in clear but authenticated: it is passed as
//! associated data (AAD) to XChaCha20-Poly1305.

use crate::crypto::{KdfParams, SALT_LEN};
use std::io;

/// Identifies an ArgosPass vault file.
pub const MAGIC: &[u8; 5] = b"ARGOS";

/// Current version of the file format.
pub const FORMAT_VERSION: u8 = 1;

const VERSION_OFFSET: usize = 5;
const MEMORY_OFFSET: usize = 6;
const ITERATIONS_OFFSET: usize = 10;
const PARALLELISM_OFFSET: usize = 14;
const SALT_OFFSET: usize = 18;

/// Total header length in bytes.
pub const HEADER_LEN: usize = SALT_OFFSET + SALT_LEN;

/// Public, authenticated information needed to derive the vault key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Argon2id parameters used to derive the key.
    pub params: KdfParams,
    /// Random salt of the vault.
    pub salt: [u8; SALT_LEN],
}

impl Header {
    /// Serializes the header to its binary layout.
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[..VERSION_OFFSET].copy_from_slice(MAGIC);
        out[VERSION_OFFSET] = FORMAT_VERSION;
        out[MEMORY_OFFSET..ITERATIONS_OFFSET]
            .copy_from_slice(&self.params.memory_kib.to_le_bytes());
        out[ITERATIONS_OFFSET..PARALLELISM_OFFSET]
            .copy_from_slice(&self.params.iterations.to_le_bytes());
        out[PARALLELISM_OFFSET..SALT_OFFSET]
            .copy_from_slice(&self.params.parallelism.to_le_bytes());
        out[SALT_OFFSET..].copy_from_slice(&self.salt);
        out
    }

    /// Parses and validates the header at the start of `data`.
    ///
    /// The values are NOT authenticated yet: they are only checked for sanity
    /// here, and authenticated later by the Poly1305 tag.
    pub fn from_bytes(data: &[u8]) -> io::Result<Self> {
        if data.len() < HEADER_LEN {
            return Err(invalid_data("file is too short to be an ArgosPass vault"));
        }
        if !data.starts_with(MAGIC) {
            return Err(invalid_data("not an ArgosPass vault (bad magic number)"));
        }

        let version = data[VERSION_OFFSET];
        if version != FORMAT_VERSION {
            return Err(invalid_data(&format!(
                "unsupported vault format version {version}"
            )));
        }

        let params = KdfParams {
            memory_kib: read_u32(data, MEMORY_OFFSET),
            iterations: read_u32(data, ITERATIONS_OFFSET),
            parallelism: read_u32(data, PARALLELISM_OFFSET),
        };
        params.validate()?;

        let salt = data[SALT_OFFSET..HEADER_LEN]
            .try_into()
            .expect("length checked above");

        Ok(Self { params, salt })
    }
}

/// Reads a little-endian `u32` at `offset`. The caller guarantees the bounds.
fn read_u32(data: &[u8], offset: usize) -> u32 {
    let bytes: [u8; 4] = data[offset..offset + 4]
        .try_into()
        .expect("length checked by the caller");
    u32::from_le_bytes(bytes)
}

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header() -> Header {
        Header {
            params: KdfParams::DEFAULT,
            salt: [7u8; SALT_LEN],
        }
    }

    #[test]
    fn round_trip() {
        let header = sample_header();
        let parsed = Header::from_bytes(&header.to_bytes()).expect("valid header");
        assert_eq!(parsed, header);
    }

    #[test]
    fn starts_with_magic_and_version() {
        let bytes = sample_header().to_bytes();
        assert_eq!(&bytes[..5], b"ARGOS");
        assert_eq!(bytes[5], FORMAT_VERSION);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = sample_header().to_bytes();
        bytes[0] = b'X';
        assert!(Header::from_bytes(&bytes).is_err());
    }

    #[test]
    fn rejects_unknown_version() {
        let mut bytes = sample_header().to_bytes();
        bytes[VERSION_OFFSET] = 99;
        assert!(Header::from_bytes(&bytes).is_err());
    }

    #[test]
    fn rejects_too_short_data() {
        let bytes = sample_header().to_bytes();
        assert!(Header::from_bytes(&bytes[..HEADER_LEN - 1]).is_err());
    }

    #[test]
    fn rejects_weak_and_excessive_params() {
        for memory_kib in [1024, u32::MAX] {
            let header = Header {
                params: KdfParams {
                    memory_kib,
                    ..KdfParams::DEFAULT
                },
                ..sample_header()
            };
            assert!(Header::from_bytes(&header.to_bytes()).is_err());
        }
    }
}
