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
//!     34    16  pepper id (format v3 and later only)
//! ```
//!
//! The header is stored in clear but authenticated: it is passed as
//! associated data (AAD) to XChaCha20-Poly1305.
//!
//! What follows the header depends on the format version:
//! - v1: `nonce || encrypted JSON || tag`, encrypted with the key derived from
//!   the master password. Still read, and upgraded to the current version.
//! - v2: `envelope || nonce || encrypted JSON || tag`, see
//!   [`VaultKey`](crate::crypto::VaultKey). Still read, and upgraded.
//! - v3 (current): same as v2, but the KEK is also derived from the
//!   [`Pepper`](crate::pepper::Pepper), whose id the header stores.

use crate::crypto::{KdfParams, SALT_LEN};
use crate::pepper::PEPPER_ID_LEN;
use crate::{Error, Result};

/// Identifies an ArgosPass vault file.
pub const MAGIC: &[u8; 5] = b"ARGOS";

/// Current version of the file format, used for every new header.
pub const FORMAT_VERSION: u8 = 3;

/// Oldest format version that can still be opened (and is then upgraded).
pub const OLDEST_SUPPORTED_VERSION: u8 = 1;

/// First format version whose key derivation uses a pepper.
pub const FIRST_PEPPER_VERSION: u8 = 3;

const VERSION_OFFSET: usize = 5;
const MEMORY_OFFSET: usize = 6;
const ITERATIONS_OFFSET: usize = 10;
const PARALLELISM_OFFSET: usize = 14;
const SALT_OFFSET: usize = 18;
const PEPPER_ID_OFFSET: usize = 34;

/// Header length of format versions 1 and 2, in bytes.
pub const HEADER_LEN_V2: usize = SALT_OFFSET + SALT_LEN;

/// Header length of the current format version, in bytes.
pub const HEADER_LEN: usize = PEPPER_ID_OFFSET + PEPPER_ID_LEN;

/// Public, authenticated information needed to derive the vault key.
///
/// Invariant: `pepper_id` is `Some` exactly when `version` is at least
/// [`FIRST_PEPPER_VERSION`]. The two fields are private so that only
/// [`Header::new`] and [`Header::from_bytes`] can set them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Argon2id parameters used to derive the key.
    pub params: KdfParams,
    /// Random salt of the vault.
    pub salt: [u8; SALT_LEN],
    /// Format version the header was read in, or will be written in.
    version: u8,
    /// Id of the pepper the key is derived with (public).
    pepper_id: Option<[u8; PEPPER_ID_LEN]>,
}

impl Header {
    /// Creates a header in the current format, for a key derived with the
    /// pepper whose id is `pepper_id`.
    pub fn new(params: KdfParams, salt: [u8; SALT_LEN], pepper_id: [u8; PEPPER_ID_LEN]) -> Self {
        Self {
            params,
            salt,
            version: FORMAT_VERSION,
            pepper_id: Some(pepper_id),
        }
    }

    /// Format version of the header.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Id of the pepper the key is derived with, or `None` before format v3.
    pub fn pepper_id(&self) -> Option<[u8; PEPPER_ID_LEN]> {
        self.pepper_id
    }

    /// Length of the header in its own format version, in bytes.
    pub fn encoded_len(&self) -> usize {
        if self.version >= FIRST_PEPPER_VERSION {
            HEADER_LEN
        } else {
            HEADER_LEN_V2
        }
    }

    /// Serializes the header to the binary layout of its own version.
    ///
    /// A header read by [`Header::from_bytes`] is reproduced byte for byte:
    /// the AAD of an older vault stays the same.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        out.extend_from_slice(MAGIC);
        out.push(self.version);
        out.extend_from_slice(&self.params.memory_kib.to_le_bytes());
        out.extend_from_slice(&self.params.iterations.to_le_bytes());
        out.extend_from_slice(&self.params.parallelism.to_le_bytes());
        out.extend_from_slice(&self.salt);
        if let Some(pepper_id) = &self.pepper_id {
            out.extend_from_slice(pepper_id);
        }
        debug_assert_eq!(out.len(), self.encoded_len());
        out
    }

    /// Parses and validates the header at the start of `data`.
    ///
    /// The values are NOT authenticated yet: they are only checked for sanity
    /// here, and authenticated later by the Poly1305 tag.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < HEADER_LEN_V2 {
            return Err(Error::Truncated);
        }
        if !data.starts_with(MAGIC) {
            return Err(Error::BadMagic);
        }

        let version = data[VERSION_OFFSET];
        if !(OLDEST_SUPPORTED_VERSION..=FORMAT_VERSION).contains(&version) {
            return Err(Error::UnsupportedVersion(version));
        }

        let pepper_id = if version >= FIRST_PEPPER_VERSION {
            let pepper_id = data
                .get(PEPPER_ID_OFFSET..HEADER_LEN)
                .ok_or(Error::Truncated)?;
            Some(pepper_id.try_into().expect("slice of PEPPER_ID_LEN bytes"))
        } else {
            None
        };

        let params = KdfParams {
            memory_kib: read_u32(data, MEMORY_OFFSET),
            iterations: read_u32(data, ITERATIONS_OFFSET),
            parallelism: read_u32(data, PARALLELISM_OFFSET),
        };
        params.validate()?;

        let salt = data[SALT_OFFSET..HEADER_LEN_V2]
            .try_into()
            .expect("length checked above");

        Ok(Self {
            params,
            salt,
            version,
            pepper_id,
        })
    }
}

/// Tells whether `start`, the first bytes of a vault file, belongs to a vault
/// whose key derivation needs a pepper (format v3 and later).
///
/// Nothing is authenticated or validated: only for choosing what to do when
/// the pepper file is missing.
pub(crate) fn needs_pepper(start: &[u8]) -> bool {
    start.starts_with(MAGIC)
        && start
            .get(VERSION_OFFSET)
            .is_some_and(|&version| version >= FIRST_PEPPER_VERSION)
}

/// Reads a little-endian `u32` at `offset`. The caller guarantees the bounds.
fn read_u32(data: &[u8], offset: usize) -> u32 {
    let bytes: [u8; 4] = data[offset..offset + 4]
        .try_into()
        .expect("length checked by the caller");
    u32::from_le_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header() -> Header {
        Header::new(KdfParams::DEFAULT, [7u8; SALT_LEN], [9u8; PEPPER_ID_LEN])
    }

    /// A header in format `version` 1 or 2, built byte by byte.
    fn sample_v2_bytes(version: u8) -> Vec<u8> {
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
        assert_eq!(HEADER_LEN, 50);
        assert_eq!(&bytes[PEPPER_ID_OFFSET..], &[9u8; PEPPER_ID_LEN]);

        let parsed = Header::from_bytes(&bytes).expect("valid header");
        assert_eq!(parsed, header);
        assert_eq!(parsed.encoded_len(), HEADER_LEN);
    }

    #[test]
    fn older_headers_are_reproduced_byte_for_byte() {
        for version in [1, 2] {
            let bytes = sample_v2_bytes(version);
            let header = Header::from_bytes(&bytes).expect("valid header");
            assert_eq!(header.version(), version);
            assert_eq!(header.pepper_id(), None);
            assert_eq!(header.encoded_len(), HEADER_LEN_V2);
            assert_eq!(header.to_bytes(), bytes);
        }
    }

    #[test]
    fn new_headers_use_the_current_version_and_a_pepper() {
        let header = sample_header();
        assert_eq!(header.version(), FORMAT_VERSION);
        assert!(header.pepper_id().is_some());

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
    fn rejects_unknown_version() {
        for unknown in [OLDEST_SUPPORTED_VERSION - 1, FORMAT_VERSION + 1] {
            let mut bytes = sample_header().to_bytes();
            bytes[VERSION_OFFSET] = unknown;
            assert!(matches!(
                Header::from_bytes(&bytes),
                Err(Error::UnsupportedVersion(v)) if v == unknown
            ));
        }
    }

    #[test]
    fn rejects_too_short_data() {
        let bytes = sample_v2_bytes(2);
        assert!(matches!(
            Header::from_bytes(&bytes[..HEADER_LEN_V2 - 1]),
            Err(Error::Truncated)
        ));
    }

    #[test]
    fn rejects_v3_header_without_its_pepper_id() {
        let bytes = sample_header().to_bytes();
        for len in [HEADER_LEN_V2, HEADER_LEN - 1] {
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

    #[test]
    fn needs_pepper_from_v3_on() {
        assert!(needs_pepper(&sample_header().to_bytes()));
        assert!(!needs_pepper(&sample_v2_bytes(2)));
        assert!(!needs_pepper(&sample_v2_bytes(1)));
        // Legacy layout: no magic number.
        assert!(!needs_pepper(&[0u8; 64]));
    }
}
