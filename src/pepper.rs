//! Pepper: a random secret stored in a local file, never in the vault.
//!
//! The pepper is passed to Argon2id as its secret parameter K. Someone who
//! only gets the vault file (lost backup, leaked cloud copy) then cannot even
//! start guessing the master password: every guess also needs the pepper.
//!
//! The vault header only stores the pepper **id**, a public fingerprint, so
//! that a wrong pepper file is reported clearly instead of as a wrong password.
//!
//! A pepper can also be written as a **recovery code**, short enough to copy
//! by hand onto paper or into another computer:
//!
//! ```text
//! ARGOS-PEPPER-1-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-cccc
//! ```
//!
//! `ARGOS-PEPPER-1` is a fixed prefix (`1` is the version of the code
//! format), the 16 `xxxx` groups are the 32 pepper bytes in lowercase hex, and
//! `cccc` is the check group: the first 2 bytes of the pepper id. A typo gives
//! another pepper, whose id almost certainly does not start with these 2 bytes.

use crate::{Error, Result, create_private_dir, hex, sync_parent_dir, to_hex};
use log::{debug, info};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;
use zeroize::Zeroizing;

/// Pepper size: 32 bytes (256 bits).
pub const PEPPER_LEN: usize = 32;

/// Size of the pepper id stored in the vault header: 16 bytes.
pub const PEPPER_ID_LEN: usize = 16;

/// Domain separation for the pepper id: the id is a hash of the pepper that
/// is never used for anything else.
pub(crate) const ID_DOMAIN: &[u8] = b"ArgosPass pepper id v1";

/// Start of a recovery code. The `1` is the version of the code format.
const RECOVERY_PREFIX: &str = "ARGOS-PEPPER-1";

/// Number of pepper id bytes in the check group of a recovery code.
const RECOVERY_CHECK_LEN: usize = 2;

/// Number of bytes per group of a recovery code: 2 bytes, 4 hex digits.
const RECOVERY_GROUP_LEN: usize = 2;

/// Length of a recovery code: the prefix, then 17 groups (16 for the pepper,
/// 1 for the check) of 4 hex digits, each one preceded by a `-`.
const RECOVERY_CODE_LEN: usize = RECOVERY_PREFIX.len()
    + (PEPPER_LEN + RECOVERY_CHECK_LEN) / RECOVERY_GROUP_LEN * (1 + 2 * RECOVERY_GROUP_LEN);

// Reasons given by `Error::InvalidRecoveryCode`. They are fixed texts: the
// code is the pepper, so no part of it may end up in an error message.
const BAD_PREFIX: &str = "it must start with ARGOS-PEPPER-1";
const BAD_LENGTH: &str = "it must have 68 hex digits after ARGOS-PEPPER-1 (17 groups of 4)";
const NOT_HEX: &str = "it contains a character that is not a hex digit (0-9, a-f)";
const CHECK_MISMATCH: &str = "the check group does not match: the code has a typo";

/// A 256-bit secret, used as Argon2id's secret parameter.
///
/// Boxed so that moving it around only copies a pointer, and wiped on drop.
pub struct Pepper(Box<Zeroizing<[u8; PEPPER_LEN]>>);

/// What [`Pepper::install`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Installed {
    /// The pepper file was created.
    Created,
    /// The same pepper was already there: nothing was written.
    AlreadyPresent,
}

impl Pepper {
    /// Generates a new random pepper using the operating system's CSPRNG.
    pub fn generate() -> Result<Self> {
        // Filled in place on the heap: the pepper never touches the stack.
        let mut pepper = Box::new(Zeroizing::new([0u8; PEPPER_LEN]));
        getrandom::fill(&mut **pepper)?;
        Ok(Self(pepper))
    }

    /// Returns the public id of the pepper: the first 16 bytes of
    /// `SHA-256("ArgosPass pepper id v1" || pepper)`.
    pub fn id(&self) -> [u8; PEPPER_ID_LEN] {
        let digest = Sha256::new()
            .chain_update(ID_DOMAIN)
            .chain_update(self.as_bytes())
            .finalize();
        let mut id = [0u8; PEPPER_ID_LEN];
        id.copy_from_slice(&digest[..PEPPER_ID_LEN]);
        id
    }

    /// Reads the pepper from `path`.
    ///
    /// Fails with [`Error::PepperMissing`] if there is no file, and with
    /// [`Error::InvalidPepper`] if it is not exactly 32 bytes long.
    pub fn load(path: &Path) -> Result<Self> {
        let mut file = match fs::File::open(path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(Error::PepperMissing(path.to_path_buf()));
            }
            Err(e) => return Err(e.into()),
        };

        let metadata = file.metadata()?;
        if metadata.len() != PEPPER_LEN as u64 {
            return Err(Error::InvalidPepper {
                path: path.to_path_buf(),
                len: metadata.len(),
            });
        }
        warn_if_readable_by_others(path, &metadata);

        // Read straight into a zeroed heap buffer: no other copy is made.
        let mut pepper = Box::new(Zeroizing::new([0u8; PEPPER_LEN]));
        file.read_exact(&mut **pepper)?;

        let pepper = Self(pepper);
        debug!(
            "pepper loaded from {} (id {})",
            path.display(),
            to_hex(&pepper.id())
        );
        Ok(pepper)
    }

    /// Generates a new pepper and writes it to `path`, which must not exist:
    /// an existing pepper is never overwritten, since the vaults created with
    /// it could no longer be opened.
    ///
    /// On Unix, the file gets `600` permissions and a newly created parent
    /// directory `700`.
    pub fn create(path: &Path) -> Result<Self> {
        let pepper = Self::generate()?;
        pepper.write_new_file(path)?;
        info!(
            "created pepper file {} (id {})",
            path.display(),
            to_hex(&pepper.id())
        );
        Ok(pepper)
    }

    /// Writes this pepper to `path`, typically after reading it from a
    /// recovery code. An existing pepper file is never overwritten:
    ///
    /// - no file: it is created, as by [`Pepper::create`];
    /// - the same pepper: nothing is written;
    /// - another pepper: fails with [`Error::DifferentPepperExists`], since a
    ///   vault created with it could no longer be opened;
    /// - a file that is not a pepper: fails as [`Pepper::load`] does.
    pub fn install(&self, path: &Path) -> Result<Installed> {
        match Self::load(path) {
            // Comparing the public ids rather than the peppers themselves:
            // equal peppers have equal ids, and two different peppers have
            // the same 128-bit id with a negligible probability.
            Ok(existing) if existing.id() == self.id() => {
                info!("this pepper is already installed at {}", path.display());
                Ok(Installed::AlreadyPresent)
            }
            Ok(existing) => Err(Error::DifferentPepperExists {
                path: path.to_path_buf(),
                existing: existing.id(),
            }),
            Err(Error::PepperMissing(_)) => {
                // `create_new` still refuses a file created in the meantime.
                self.write_new_file(path)?;
                info!(
                    "installed pepper file {} (id {})",
                    path.display(),
                    to_hex(&self.id())
                );
                Ok(Installed::Created)
            }
            Err(error) => Err(error),
        }
    }

    /// Encodes the pepper as a recovery code (see the [module](self)
    /// documentation), in a buffer that is wiped on drop.
    ///
    /// The code **is** the pepper: whoever reads it can rebuild the file.
    pub fn to_recovery_code(&self) -> Zeroizing<String> {
        // Sized exactly: growing would leave unwiped copies of the code.
        let mut code = Zeroizing::new(String::with_capacity(RECOVERY_CODE_LEN));
        let capacity = code.capacity();
        code.push_str(RECOVERY_PREFIX);

        let id = self.id();
        let check = &id[..RECOVERY_CHECK_LEN];
        for (i, &byte) in self.as_bytes().iter().chain(check).enumerate() {
            if i % RECOVERY_GROUP_LEN == 0 {
                code.push('-');
            }
            // Hex by hand: `format!` would build temporary strings that are
            // not wiped.
            hex::push_byte(&mut code, byte);
        }

        debug_assert_eq!(code.len(), RECOVERY_CODE_LEN);
        debug_assert_eq!(code.capacity(), capacity, "buffer was reallocated");
        code
    }

    /// Decodes a recovery code written by [`Pepper::to_recovery_code`].
    ///
    /// Forgiving with the layout: letters can be in any case, and spaces,
    /// tabs, line breaks and `-` are ignored wherever they are. Fails with
    /// [`Error::InvalidRecoveryCode`] if the prefix is not `ARGOS-PEPPER-1`,
    /// if there are not exactly 68 hex digits after it, or if the check group
    /// does not match the pepper (a typo).
    pub fn from_recovery_code(code: &str) -> Result<Self> {
        // The characters that matter, one at a time: the code is never copied
        // into another string.
        let mut chars = code.chars().filter(|&c| is_significant(c));

        for expected in RECOVERY_PREFIX.chars().filter(|&c| is_significant(c)) {
            match chars.next() {
                Some(c) if c.eq_ignore_ascii_case(&expected) => {}
                _ => return Err(Error::InvalidRecoveryCode(BAD_PREFIX)),
            }
        }

        // Each hex digit is a half byte (nibble): two of them make a byte,
        // high half first. The pepper is decoded straight into its heap buffer.
        let mut pepper = Box::new(Zeroizing::new([0u8; PEPPER_LEN]));
        let mut check = [0u8; RECOVERY_CHECK_LEN];
        let mut digits = 0;
        for c in chars {
            let Some(nibble) = hex::nibble(c) else {
                return Err(Error::InvalidRecoveryCode(NOT_HEX));
            };
            let index = digits / 2;
            let byte = if index < PEPPER_LEN {
                &mut pepper[index]
            } else if let Some(byte) = check.get_mut(index - PEPPER_LEN) {
                byte
            } else {
                return Err(Error::InvalidRecoveryCode(BAD_LENGTH));
            };
            *byte = (*byte << 4) | nibble;
            digits += 1;
        }
        if digits != 2 * (PEPPER_LEN + RECOVERY_CHECK_LEN) {
            return Err(Error::InvalidRecoveryCode(BAD_LENGTH));
        }

        let pepper = Self(pepper);
        let id = pepper.id();
        if id[..RECOVERY_CHECK_LEN] != check {
            return Err(Error::InvalidRecoveryCode(CHECK_MISMATCH));
        }
        debug!("recovery code decoded (pepper id {})", to_hex(&id));
        Ok(pepper)
    }

    /// The pepper bytes, for Argon2id only.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &**self.0
    }

    /// Writes the pepper to a new file at `path`, which must not exist.
    /// On Unix, the file gets `600` permissions and a newly created parent
    /// directory `700`.
    fn write_new_file(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            create_private_dir(parent)?;
        }

        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        if let Err(e) = file
            .write_all(self.as_bytes())
            .and_then(|()| file.sync_all())
        {
            // Never leave a truncated pepper behind: it would look valid enough
            // to be backed up. The file is ours (`create_new`), so remove it.
            drop(file);
            let _ = fs::remove_file(path);
            return Err(e.into());
        }
        // A vault may be rewritten right after this: make sure the pepper's
        // directory entry is on disk too, not only its content.
        sync_parent_dir(path)?;
        Ok(())
    }
}

/// Shortens a (public) pepper id for messages: its first 4 bytes in hex.
pub fn short_id(id: &[u8; PEPPER_ID_LEN]) -> String {
    to_hex(&id[..4])
}

/// Tells whether `input` holds as many characters as a whole recovery code,
/// ignoring the layout as [`Pepper::from_recovery_code`] does. Whether these
/// characters form a valid code is not checked.
///
/// For reading a code typed or pasted over several lines: it tells when to
/// stop asking for more.
pub fn recovery_code_is_complete(input: &str) -> bool {
    let prefix_len = RECOVERY_PREFIX
        .chars()
        .filter(|&c| is_significant(c))
        .count();
    let needed = prefix_len + 2 * (PEPPER_LEN + RECOVERY_CHECK_LEN);
    input.chars().filter(|&c| is_significant(c)).count() >= needed
}

/// Tells whether `c` counts in a recovery code: spaces, tabs, line breaks and
/// `-` are only layout.
fn is_significant(c: char) -> bool {
    !c.is_ascii_whitespace() && c != '-'
}

/// Warns if the pepper file can be read by other users (Unix only).
fn warn_if_readable_by_others(path: &Path, metadata: &fs::Metadata) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            log::warn!(
                "pepper file {} is accessible to other users (mode {mode:o}): run `chmod 600` on it",
                path.display()
            );
        }
    }
    #[cfg(not(unix))]
    let _ = (path, metadata);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Returns a path in the system temp directory, unique to each test, with
    /// no file left over by an interrupted run.
    fn temp_pepper_path(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("argospass-unit-pepper-{name}.key"));
        let _ = fs::remove_file(&path);
        path
    }

    #[test]
    fn id_is_stable_and_differs_between_peppers() {
        let a = Pepper::generate().expect("generation");
        let b = Pepper::generate().expect("generation");
        // The id is public: `assert_eq!` may print it.
        assert_eq!(a.id(), a.id());
        assert_ne!(a.id(), b.id());
    }

    #[test]
    fn id_matches_its_definition() {
        // Part of the file format: computed independently with Python's hashlib.
        let pepper = Pepper(Box::new(Zeroizing::new([0x42; PEPPER_LEN])));
        assert_eq!(to_hex(&pepper.id()), "a11261119d5ae3efcc9ed61295224995");
    }

    #[test]
    fn create_then_load_gives_the_same_pepper() {
        let path = temp_pepper_path("round-trip");
        let created = Pepper::create(&path).expect("creation");
        let loaded = Pepper::load(&path).expect("load");
        assert!(created.as_bytes() == loaded.as_bytes());
        fs::remove_file(&path).expect("cleanup");
    }

    #[test]
    fn create_refuses_to_overwrite() {
        let path = temp_pepper_path("no-overwrite");
        let first = Pepper::create(&path).expect("creation");

        assert!(matches!(
            Pepper::create(&path),
            Err(Error::Io(e)) if e.kind() == io::ErrorKind::AlreadyExists
        ));
        let kept = Pepper::load(&path).expect("load");
        assert!(kept.as_bytes() == first.as_bytes());

        fs::remove_file(&path).expect("cleanup");
    }

    #[test]
    fn load_rejects_wrong_sizes() {
        let path = temp_pepper_path("wrong-size");
        for len in [PEPPER_LEN - 1, PEPPER_LEN + 1] {
            fs::write(&path, vec![0u8; len]).expect("write");
            assert!(matches!(
                Pepper::load(&path),
                Err(Error::InvalidPepper { len: found, .. }) if found == len as u64
            ));
        }
        fs::remove_file(&path).expect("cleanup");
    }

    #[test]
    fn missing_file_is_reported_as_such() {
        let path = temp_pepper_path("missing");
        assert!(matches!(
            Pepper::load(&path),
            Err(Error::PepperMissing(missing)) if missing == path
        ));
    }

    /// A fixed pepper, so that its recovery code can be written out in full.
    fn sample_pepper() -> Pepper {
        Pepper(Box::new(Zeroizing::new([0x42; PEPPER_LEN])))
    }

    /// The recovery code of [`sample_pepper`]: the check group `a112` is the
    /// start of its id (see `id_matches_its_definition`).
    fn sample_code() -> String {
        format!("ARGOS-PEPPER-1{}-a112", "-4242".repeat(16))
    }

    /// Checks that `code` is rejected, for the given `reason`.
    fn assert_rejected(code: &str, reason: &str) {
        assert!(matches!(
            Pepper::from_recovery_code(code),
            Err(Error::InvalidRecoveryCode(r)) if r == reason
        ));
    }

    #[test]
    fn recovery_code_has_the_documented_layout() {
        let code = sample_pepper().to_recovery_code();
        // The pepper is a test value: comparing with `assert!` all the same.
        assert!(*code == sample_code());
        assert_eq!(code.len(), 99);
        // Sized exactly, never grown.
        assert_eq!(code.capacity(), code.len());
    }

    #[test]
    fn recovery_code_round_trip() {
        let pepper = Pepper::generate().expect("generation");
        let decoded = Pepper::from_recovery_code(&pepper.to_recovery_code()).expect("valid code");
        assert!(decoded.as_bytes() == pepper.as_bytes());
        assert_eq!(decoded.id(), pepper.id());
    }

    #[test]
    fn recovery_code_tolerates_case_spaces_and_line_breaks() {
        let pepper = sample_pepper();
        let variants = [
            sample_code().to_uppercase(),
            sample_code().replace('-', " "),
            sample_code().replace('-', "--"),
            sample_code().replace('-', ""),
            format!(" \t{}\r\n\n", sample_code()),
            // As copied by hand: 4 groups per line, any line ending.
            "Argos-Pepper-1\n\
             4242 4242 4242 4242\r\n\
             4242 4242 4242 4242\n\
             \t4242 4242 4242 4242\n\
             4242 4242 4242 4242 -\n\
             A112\n"
                .to_string(),
        ];
        for variant in variants {
            let decoded = Pepper::from_recovery_code(&variant).expect("tolerated layout");
            assert!(decoded.as_bytes() == pepper.as_bytes());
        }
    }

    #[test]
    fn a_code_on_several_lines_is_complete_with_its_last_line() {
        let lines = [
            "Argos-Pepper-1",
            "4242 4242 4242 4242",
            "4242 4242 4242 4242",
            "4242 4242 4242 4242",
            "4242 4242 4242 4242 a112",
        ];
        let mut input = String::new();
        for (i, line) in lines.iter().enumerate() {
            input.push_str(line);
            input.push('\n');
            assert_eq!(recovery_code_is_complete(&input), i == lines.len() - 1);
        }
        assert!(recovery_code_is_complete(&sample_code()));
        assert!(!recovery_code_is_complete(&sample_code()[..98]));
    }

    #[test]
    fn recovery_code_needs_its_prefix() {
        let digits = &sample_code()[RECOVERY_PREFIX.len()..];
        for prefix in [
            "",
            "ARGOS-PEPPER-2",
            "ARGOS-PEPPER",
            "ARGOS-PASS-1",
            "PEPPER-1",
        ] {
            assert_rejected(&format!("{prefix}{digits}"), BAD_PREFIX);
        }
        assert_rejected("", BAD_PREFIX);
    }

    #[test]
    fn recovery_code_needs_exactly_68_hex_digits() {
        let code = sample_code();
        assert_rejected(&code[..code.len() - 1], BAD_LENGTH); // one digit missing
        assert_rejected(&format!("{code}0"), BAD_LENGTH); // one digit too many
        assert_rejected(&code[..code.len() - 5], BAD_LENGTH); // no check group
        assert_rejected(RECOVERY_PREFIX, BAD_LENGTH);
    }

    #[test]
    fn recovery_code_rejects_characters_that_are_not_hex_digits() {
        // Index 20 is the first digit of the second group. `O` for `0` and
        // `l` for `1` are classic misreadings.
        for c in ["O", "l", "g", "é", "_", "."] {
            let mut code = sample_code();
            code.replace_range(20..21, c);
            assert_rejected(&code, NOT_HEX);
        }
    }

    #[test]
    fn single_character_typos_are_detected() {
        // A wrong digit gives another well-formed code: only the check group
        // can catch it. With 16 bits of check, about 1 typo in 65,536 gets
        // through in general. For this pepper, every one of them is caught.
        let code = sample_code();
        let positions: Vec<usize> = code
            .char_indices()
            .skip(RECOVERY_PREFIX.len())
            .filter(|&(_, c)| c != '-')
            .map(|(i, _)| i)
            .collect();
        assert_eq!(positions.len(), 68);

        for &i in &positions {
            // Every other digit in this position.
            for &digit in b"0123456789abcdef"
                .iter()
                .filter(|&&d| d != code.as_bytes()[i])
            {
                let mut typo = code.clone().into_bytes();
                typo[i] = digit;
                assert_rejected(&String::from_utf8(typo).expect("ASCII"), CHECK_MISMATCH);
            }
            // Two neighbouring digits swapped.
            if let Some(&next) = positions.iter().find(|&&j| j > i) {
                let mut swapped = code.clone().into_bytes();
                swapped.swap(i, next);
                if swapped != code.as_bytes() {
                    let swapped = String::from_utf8(swapped).expect("ASCII");
                    assert_rejected(&swapped, CHECK_MISMATCH);
                }
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn pepper_file_is_readable_by_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let path = temp_pepper_path("permissions");
        Pepper::create(&path).expect("creation");
        let mode = fs::metadata(&path).expect("metadata").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        fs::remove_file(&path).expect("cleanup");
    }
}
