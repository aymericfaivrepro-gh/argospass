//! Pepper: a random secret stored in a local file, never in the vault.
//!
//! The pepper is passed to Argon2id as its secret parameter K. Someone who
//! only gets the vault file (lost backup, leaked cloud copy) then cannot even
//! start guessing the master password: every guess also needs the pepper.
//!
//! The vault header only stores the pepper **id**, a public fingerprint, so
//! that a wrong pepper file is reported clearly instead of as a wrong password.

use crate::{Error, Result, create_private_dir, to_hex};
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
const ID_DOMAIN: &[u8] = b"ArgosPass pepper id v1";

/// A 256-bit secret, used as Argon2id's secret parameter.
///
/// Boxed so that moving it around only copies a pointer, and wiped on drop.
pub struct Pepper(Box<Zeroizing<[u8; PEPPER_LEN]>>);

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
        if let Some(parent) = path.parent() {
            create_private_dir(parent)?;
        }
        let pepper = Self::generate()?;

        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        if let Err(e) = file
            .write_all(pepper.as_bytes())
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

        info!(
            "created pepper file {} (id {})",
            path.display(),
            to_hex(&pepper.id())
        );
        Ok(pepper)
    }

    /// The pepper bytes, for Argon2id only.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &**self.0
    }
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

/// Flushes the directory entry of `path` to disk (Unix only).
fn sync_parent_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let parent = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        fs::File::open(parent)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
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
