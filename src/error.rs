//! Errors returned by the ArgosPass library.

use crate::crypto::KdfParams;
use crate::format::{FORMAT_VERSION, OLDEST_SUPPORTED_VERSION};
use crate::generator::MIN_LENGTH;
use crate::pepper::{PEPPER_ID_LEN, PEPPER_LEN, short_id};
use std::io;
use std::path::PathBuf;

/// Everything that can go wrong in the ArgosPass library.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Reading or writing a file (or the terminal) failed.
    #[error("I/O error")]
    Io(#[from] io::Error),

    /// The vault file is shorter than its format requires.
    #[error("the vault file is truncated")]
    Truncated,

    /// The data does not start with the ArgosPass magic number.
    #[error("not an ArgosPass vault (bad magic number)")]
    BadMagic,

    /// The vault was written in a format version this build cannot read.
    #[error(
        "unsupported vault format version {0} \
         (supported: {OLDEST_SUPPORTED_VERSION} to {FORMAT_VERSION})"
    )]
    UnsupportedVersion(u8),

    /// The Argon2id parameters of the header are outside the accepted bounds.
    #[error(
        "unsupported Argon2id parameters in the vault header \
         ({} KiB, {} iterations, parallelism {})",
        .0.memory_kib, .0.iterations, .0.parallelism
    )]
    UnsupportedKdfParams(KdfParams),

    /// The master password is wrong, or the vault was modified: the
    /// authentication tag cannot tell these two cases apart.
    #[error("decryption failed: wrong master password or corrupted vault")]
    DecryptionFailed,

    /// There is no pepper file at this path.
    #[error("no pepper file at {}", .0.display())]
    PepperMissing(PathBuf),

    /// The pepper file does not have the size of a pepper.
    #[error(
        "invalid pepper file {}: {len} bytes instead of {PEPPER_LEN}",
        .path.display()
    )]
    InvalidPepper { path: PathBuf, len: u64 },

    /// The vault was created with another pepper. Detected from the public
    /// pepper id in the header, before any key derivation.
    #[error(
        "wrong pepper: the vault expects pepper {}, the pepper file is {}",
        short_id(expected),
        short_id(found)
    )]
    PepperMismatch {
        expected: [u8; PEPPER_ID_LEN],
        found: [u8; PEPPER_ID_LEN],
    },

    /// The vault needs a pepper and none was given.
    #[error("this vault needs its pepper file")]
    PepperRequired,

    /// Another pepper file is already where a pepper is being installed. It
    /// is never overwritten.
    #[error(
        "another pepper ({}) is already installed at {}",
        short_id(existing),
        .path.display()
    )]
    DifferentPepperExists {
        path: PathBuf,
        existing: [u8; PEPPER_ID_LEN],
    },

    /// A pepper recovery code could not be decoded. The reason is a fixed
    /// text (`&'static str`): no part of the code, which is the pepper, can
    /// end up in the message.
    #[error("invalid recovery code: {0}")]
    InvalidRecoveryCode(&'static str),

    /// Encryption failed (only possible for absurdly large vaults).
    #[error("encryption failed")]
    EncryptionFailed,

    /// The vault content could not be converted to or from JSON.
    ///
    /// Only the position is shown, and the error is not exposed as `source`:
    /// serde_json's own message may quote the decrypted content, that is, secrets.
    #[error("invalid vault content (line {}, column {})", .0.line(), .0.column())]
    Json(serde_json::Error),

    /// Argon2id rejected its inputs or parameters.
    #[error("key derivation failed")]
    KeyDerivation(#[from] argon2::Error),

    /// HKDF could not derive a subkey (only possible for an output longer
    /// than 8160 bytes).
    #[error("subkey derivation failed")]
    SubkeyDerivation,

    /// A protected field's name does not fit in its associated data (255
    /// bytes at most). Field names are fixed by the program, never secret.
    #[error("field name too long: {0} bytes (at most 255)")]
    FieldNameTooLong(usize),

    /// The operating system's random number generator failed.
    #[error("the system random number generator failed")]
    Random(#[from] getrandom::Error),

    /// A generated password was requested shorter than [`MIN_LENGTH`].
    #[error("password length must be at least {MIN_LENGTH} (got {length})")]
    PasswordTooShort { length: usize },

    /// No entry has this title.
    #[error("no entry named \"{0}\"")]
    EntryNotFound(String),

    /// An entry with this title already exists.
    #[error("an entry named \"{0}\" already exists")]
    EntryAlreadyExists(String),
}

/// Result type of the ArgosPass library.
pub type Result<T> = std::result::Result<T, Error>;

// Written by hand: `#[from]` would also expose the JSON error as `source`.
impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as _;

    #[test]
    fn wrapped_errors_are_exposed_as_source() {
        let error = Error::from(io::Error::other("disk on fire"));
        assert!(matches!(error, Error::Io(_)));
        let source = error.source().expect("an I/O error has a source");
        assert_eq!(source.to_string(), "disk on fire");
    }

    #[test]
    fn pepper_mismatch_shows_short_ids() {
        let error = Error::PepperMismatch {
            expected: [0xab; PEPPER_ID_LEN],
            found: [0x01; PEPPER_ID_LEN],
        };
        assert_eq!(
            error.to_string(),
            "wrong pepper: the vault expects pepper abababab, the pepper file is 01010101"
        );
    }

    #[test]
    fn json_errors_do_not_reveal_vault_content() {
        let json_error = serde_json::from_slice::<crate::Vault>(br#"{"entries":"hunter2"}"#)
            .err()
            .expect("entries must be a list");
        // serde_json quotes the offending value...
        assert!(json_error.to_string().contains("hunter2"));

        // ...but our error neither displays it nor exposes it as its source.
        let error = Error::from(json_error);
        assert!(matches!(error, Error::Json(_)));
        assert!(!error.to_string().contains("hunter2"));
        assert!(error.source().is_none());
    }
}
