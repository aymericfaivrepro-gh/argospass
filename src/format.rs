//! Binary layout of the vault file header.
//!
//! ```text
//! offset  size  field
//!      0     5  magic number "ARGOS"
//!      5     1  format version (4)
//!      6     4  Argon2id memory cost in KiB (u32, little-endian)
//!     10     4  Argon2id iterations        (u32, little-endian)
//!     14     4  Argon2id parallelism       (u32, little-endian)
//!     18    16  salt
//!     34    16  pepper id
//!     50    16  vault id
//! ```
//!
//! The header is stored in clear but authenticated: it is passed as
//! associated data (AAD) to XChaCha20-Poly1305. It is followed by the
//! envelope and the payload (see [`VaultKey`](crate::crypto::VaultKey)).
//!
//! Only format v4 is read. A file in an older format (v1 to v3, or the legacy
//! layout without this header) is refused: these formats did not use the
//! pepper, so accepting them would let someone who knows the master password,
//! but not the pepper, replace the vault with one of their own.

use crate::crypto::{KdfParams, SALT_LEN};
use crate::pepper::PEPPER_ID_LEN;
use crate::{Error, Result};

/// Identifies an ArgosPass vault file.
pub const MAGIC: &[u8; 5] = b"ARGOS";

/// Version of the file format: the only one that can be opened, and the one
/// of every new header.
pub const FORMAT_VERSION: u8 = 4;

/// Size of the vault id: 16 bytes.
pub const VAULT_ID_LEN: usize = 16;

const VERSION_OFFSET: usize = 5;
const MEMORY_OFFSET: usize = 6;
const ITERATIONS_OFFSET: usize = 10;
const PARALLELISM_OFFSET: usize = 14;
const SALT_OFFSET: usize = 18;
const PEPPER_ID_OFFSET: usize = 34;
const VAULT_ID_OFFSET: usize = 50;

/// Header length, in bytes.
pub const HEADER_LEN: usize = VAULT_ID_OFFSET + VAULT_ID_LEN;

/// Public, authenticated information needed to derive the vault key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Argon2id parameters used to derive the key.
    pub params: KdfParams,
    /// Random salt of the vault.
    pub salt: [u8; SALT_LEN],
    /// Id of the pepper the key is derived with (public).
    pepper_id: [u8; PEPPER_ID_LEN],
    /// Random id of the vault, kept for its whole life (public).
    vault_id: [u8; VAULT_ID_LEN],
}

impl Header {
    /// Creates a header for a key derived with the pepper whose id is
    /// `pepper_id`, in the vault whose id is `vault_id`.
    pub fn new(
        params: KdfParams,
        salt: [u8; SALT_LEN],
        pepper_id: [u8; PEPPER_ID_LEN],
        vault_id: [u8; VAULT_ID_LEN],
    ) -> Self {
        Self {
            params,
            salt,
            pepper_id,
            vault_id,
        }
    }

    /// Id of the pepper the key is derived with.
    pub fn pepper_id(&self) -> [u8; PEPPER_ID_LEN] {
        self.pepper_id
    }

    /// Id of the vault.
    pub fn vault_id(&self) -> [u8; VAULT_ID_LEN] {
        self.vault_id
    }

    /// Serializes the header to its binary layout.
    ///
    /// A header read by [`Header::from_bytes`] is reproduced byte for byte:
    /// these are the bytes the tags authenticated.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN);
        out.extend_from_slice(MAGIC);
        out.push(FORMAT_VERSION);
        out.extend_from_slice(&self.params.memory_kib.to_le_bytes());
        out.extend_from_slice(&self.params.iterations.to_le_bytes());
        out.extend_from_slice(&self.params.parallelism.to_le_bytes());
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.pepper_id);
        out.extend_from_slice(&self.vault_id);
        debug_assert_eq!(out.len(), HEADER_LEN);
        out
    }

    /// Parses and validates the header at the start of `data`.
    ///
    /// Fails with [`Error::BadMagic`] for a file that does not start with
    /// [`MAGIC`] (including a vault in the legacy layout), with
    /// [`Error::UnsupportedVersion`] for any version but [`FORMAT_VERSION`],
    /// and with [`Error::UnsupportedKdfParams`] for parameters out of bounds.
    ///
    /// The values are NOT authenticated yet: they are only checked for sanity
    /// here, and authenticated later by the Poly1305 tags.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        // The magic number and the version first: a file in another format is
        // reported as such, even if it is shorter than a v4 header.
        let Some(&version) = data.get(VERSION_OFFSET) else {
            return Err(Error::Truncated);
        };
        if !data.starts_with(MAGIC) {
            return Err(Error::BadMagic);
        }
        if version != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion(version));
        }
        // `first_chunk` gives the first HEADER_LEN bytes as an array, so the
        // fields below are read from a value whose size is known.
        let header: &[u8; HEADER_LEN] = data.first_chunk().ok_or(Error::Truncated)?;

        let params = KdfParams {
            memory_kib: u32::from_le_bytes(field(header, MEMORY_OFFSET)?),
            iterations: u32::from_le_bytes(field(header, ITERATIONS_OFFSET)?),
            parallelism: u32::from_le_bytes(field(header, PARALLELISM_OFFSET)?),
        };
        params.validate()?;

        Ok(Self {
            params,
            salt: field(header, SALT_OFFSET)?,
            pepper_id: field(header, PEPPER_ID_OFFSET)?,
            vault_id: field(header, VAULT_ID_OFFSET)?,
        })
    }
}

/// The `N` bytes of `header` that start at `offset`. `N` is a const generic:
/// the size of the array is chosen by the caller, at compile time.
///
/// Never fails for the offsets of this module, which all lie within the
/// header: an error rather than a panic all the same.
fn field<const N: usize>(header: &[u8; HEADER_LEN], offset: usize) -> Result<[u8; N]> {
    header
        .get(offset..offset + N)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(Error::Truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header() -> Header {
        Header::new(
            KdfParams::DEFAULT,
            [7u8; SALT_LEN],
            [9u8; PEPPER_ID_LEN],
            [5u8; VAULT_ID_LEN],
        )
    }

    /// The header of a vault in format `version` 1 or 2, built byte by byte
    /// (34 bytes: no pepper id, no vault id).
    fn old_header_bytes(version: u8) -> Vec<u8> {
        let mut bytes = MAGIC.to_vec();
        bytes.push(version);
        bytes.extend_from_slice(&(64 * 1024u32).to_le_bytes());
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&[7u8; SALT_LEN]);
        bytes
    }

    #[test]
    fn round_trip() {
        let header = sample_header();
        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), HEADER_LEN);
        assert_eq!(HEADER_LEN, 66);
        assert_eq!(
            &bytes[PEPPER_ID_OFFSET..VAULT_ID_OFFSET],
            &[9u8; PEPPER_ID_LEN]
        );
        assert_eq!(&bytes[VAULT_ID_OFFSET..], &[5u8; VAULT_ID_LEN]);

        let parsed = Header::from_bytes(&bytes).expect("valid header");
        assert_eq!(parsed, header);
        assert_eq!(parsed.to_bytes(), bytes);
    }

    #[test]
    fn new_headers_use_the_current_version_a_pepper_and_a_vault_id() {
        let header = sample_header();
        assert_eq!(header.pepper_id(), [9u8; PEPPER_ID_LEN]);
        assert_eq!(header.vault_id(), [5u8; VAULT_ID_LEN]);

        let bytes = header.to_bytes();
        assert_eq!(&bytes[..5], b"ARGOS");
        assert_eq!(bytes[5], FORMAT_VERSION);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = sample_header().to_bytes();
        bytes[0] = b'X';
        assert!(matches!(Header::from_bytes(&bytes), Err(Error::BadMagic)));
    }

    #[test]
    fn rejects_every_other_version() {
        for version in [0, 1, 2, 3, FORMAT_VERSION + 1, u8::MAX] {
            let mut bytes = sample_header().to_bytes();
            bytes[VERSION_OFFSET] = version;
            assert!(matches!(
                Header::from_bytes(&bytes),
                Err(Error::UnsupportedVersion(v)) if v == version
            ));
        }
    }

    #[test]
    fn older_headers_are_refused_as_such_whatever_their_length() {
        // Versions 1 and 2 had 34 bytes, version 3 had 50 (with the pepper
        // id): shorter than a v4 header, but reported as an older format, not
        // as a truncated file.
        let mut v3 = old_header_bytes(3);
        v3.extend_from_slice(&[9u8; PEPPER_ID_LEN]);
        for (version, bytes) in [(1, old_header_bytes(1)), (2, old_header_bytes(2)), (3, v3)] {
            assert!(matches!(
                Header::from_bytes(&bytes),
                Err(Error::UnsupportedVersion(v)) if v == version
            ));
        }
    }

    #[test]
    fn rejects_truncated_headers() {
        let bytes = sample_header().to_bytes();
        for len in [
            0,
            5,
            VERSION_OFFSET + 1,
            SALT_OFFSET,
            VAULT_ID_OFFSET,
            HEADER_LEN - 1,
        ] {
            assert!(matches!(
                Header::from_bytes(&bytes[..len]),
                Err(Error::Truncated)
            ));
        }
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
            assert!(matches!(
                Header::from_bytes(&header.to_bytes()),
                Err(Error::UnsupportedKdfParams(params)) if params == header.params
            ));
        }
    }
}
