//! Password manager logic.
pub mod crypto;
mod error;
pub mod format;
pub mod generator;
pub mod pepper;

pub use error::{Error, Result};

use crypto::{ENVELOPE_LEN, KdfParams, NONCE_LEN, SALT_LEN, TAG_LEN, VaultKey};
use format::{FORMAT_VERSION, HEADER_LEN, Header, MAGIC};
use log::{debug, info, warn};
use pepper::{PEPPER_ID_LEN, Pepper};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// A vault entry: an account and its password.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Entry {
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: Option<String>,
}

impl Entry {
    /// Creates a new entry.
    pub fn new(title: &str, username: &str, password: &str, url: Option<&str>) -> Self {
        Self {
            title: title.to_string(),
            username: username.to_string(),
            password: password.to_string(),
            url: url.map(|s| s.to_string()),
        }
    }
}

/// The vault: a collection of entries.
#[derive(Default, Serialize, Deserialize)]
pub struct Vault {
    entries: Vec<Entry>,
}

impl Vault {
    /// Creates an empty vault.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an entry to the vault.
    /// Fails with [`Error::EntryAlreadyExists`] if an entry has the same title.
    pub fn add(&mut self, entry: Entry) -> Result<()> {
        if self.entries.iter().any(|e| e.title == entry.title) {
            return Err(Error::EntryAlreadyExists(entry.title.clone()));
        }

        self.entries.push(entry);
        Ok(())
    }

    /// Finds an entry by its title.
    /// Fails with [`Error::EntryNotFound`] if there is none.
    pub fn get(&self, title: &str) -> Result<&Entry> {
        let index = self.index_of(title)?;
        Ok(&self.entries[index])
    }

    /// Returns all entries.
    pub fn list(&self) -> &[Entry] {
        &self.entries
    }

    /// Removes and returns an entry by its title.
    /// Fails with [`Error::EntryNotFound`] if there is none.
    pub fn remove(&mut self, title: &str) -> Result<Entry> {
        let index = self.index_of(title)?;
        Ok(self.entries.remove(index))
    }

    /// Returns the position of the entry titled `title`.
    fn index_of(&self, title: &str) -> Result<usize> {
        self.entries
            .iter()
            .position(|e| e.title == title)
            .ok_or_else(|| Error::EntryNotFound(title.to_string()))
    }

    /// Opens and decrypts a vault file with the master password and the pepper.
    ///
    /// Vaults in an older format (v2, v1, or the legacy format before them)
    /// are opened without the pepper, then upgraded automatically to the
    /// current format, which uses it.
    /// Fails with [`Error::PepperMismatch`] if the vault was created with
    /// another pepper, and with [`Error::DecryptionFailed`] if the master
    /// password is wrong or if the file has been modified.
    pub fn open(path: &Path, password: &str, pepper: &Pepper) -> Result<(Self, VaultKey)> {
        let data = fs::read(path)?;
        info!("opening vault");
        debug!("read {} bytes from {}", data.len(), path.display());

        if !data.starts_with(MAGIC) {
            return Self::open_legacy(path, password, pepper, &data);
        }

        let header = Header::from_bytes(&data)?;
        let (header_bytes, rest) = data.split_at(header.encoded_len());
        debug!("format version {}, {:?}", header.version(), header.params);
        debug!("salt (from file header): {}", to_hex(&header.salt));
        if let Some(pepper_id) = header.pepper_id() {
            debug!("pepper id (from file header): {}", to_hex(&pepper_id));
        }

        match header.version() {
            1 => Self::open_v1(path, password, pepper, &header, header_bytes, rest),
            2 => {
                let (vault, old_key) = Self::open_envelope(password, header, rest, None)?;
                drop(old_key); // wipes the v2 data key: the upgrade generates a new one
                warn!("vault uses format v2 (no pepper): upgrading it to format v{FORMAT_VERSION}");
                vault.upgrade(path, password, pepper)
            }
            FORMAT_VERSION => Self::open_envelope(password, header, rest, Some(pepper)),
            // Already rejected by `Header::from_bytes`.
            other => Err(Error::UnsupportedVersion(other)),
        }
    }

    /// Opens a vault in format v2 or later: `header || envelope || payload`.
    ///
    /// The KEK derived from the master password (and the pepper from format
    /// v3 on) unwraps the data key from the envelope, and the data key
    /// decrypts the payload.
    fn open_envelope(
        password: &str,
        header: Header,
        rest: &[u8],
        pepper: Option<&Pepper>,
    ) -> Result<(Self, VaultKey)> {
        // Checked before running Argon2id: a truncated file must fail fast.
        if rest.len() < ENVELOPE_LEN + NONCE_LEN + TAG_LEN {
            return Err(Error::Truncated);
        }

        let (envelope, payload) = rest.split_at(ENVELOPE_LEN);
        debug!(
            "envelope: {} bytes, payload: {} bytes",
            envelope.len(),
            payload.len()
        );

        let key = VaultKey::unlock(password, header, envelope, pepper)?;
        let plaintext = key.decrypt(payload)?;
        let vault: Vault = serde_json::from_slice(&plaintext)?;
        info!("vault decrypted: {} entries", vault.entries.len());
        Ok((vault, key))
    }

    /// Opens a vault in format v1 (`header || nonce || ciphertext || tag`,
    /// encrypted with the key derived from the master password), then rewrites
    /// it in the current format.
    fn open_v1(
        path: &Path,
        password: &str,
        pepper: &Pepper,
        header: &Header,
        header_bytes: &[u8],
        encrypted: &[u8],
    ) -> Result<(Self, VaultKey)> {
        // The raw header bytes from the file are the associated data: they are
        // exactly what v1 authenticated.
        let vault: Vault = {
            let key = crypto::derive_key(password, &header.salt, &header.params, None)?;
            let plaintext = crypto::decrypt(&key, encrypted, header_bytes)?;
            serde_json::from_slice(&plaintext)?
        }; // the v1 key and the decrypted JSON are wiped here
        info!("vault decrypted: {} entries", vault.entries.len());

        warn!("vault uses format v1: upgrading it to format v{FORMAT_VERSION}");
        vault.upgrade(path, password, pepper)
    }

    /// Opens a vault in the legacy layout (`salt || nonce || ciphertext || tag`,
    /// fixed Argon2id parameters, no associated data), then rewrites it in the
    /// current format.
    fn open_legacy(
        path: &Path,
        password: &str,
        pepper: &Pepper,
        data: &[u8],
    ) -> Result<(Self, VaultKey)> {
        if data.len() < SALT_LEN {
            return Err(Error::Truncated);
        }

        let (salt, encrypted) = data.split_at(SALT_LEN);
        let salt: [u8; SALT_LEN] = salt.try_into().expect("length checked above");
        debug!("legacy vault, salt: {}", to_hex(&salt));

        let vault: Vault = {
            let key = crypto::derive_key(password, &salt, &KdfParams::LEGACY, None)?;
            let plaintext = crypto::decrypt(&key, encrypted, &[])?;
            serde_json::from_slice(&plaintext)?
        }; // the legacy key and the decrypted JSON are wiped here
        info!("vault decrypted: {} entries", vault.entries.len());

        warn!("vault uses the legacy format: upgrading it to format v{FORMAT_VERSION}");
        vault.upgrade(path, password, pepper)
    }

    /// Rewrites a vault opened from an older format in the current format.
    ///
    /// Everything is regenerated: new salt, current Argon2id parameters, the
    /// pepper, and a new random data key. The old key is never reused: an old
    /// copy and the password would otherwise give the data key without the
    /// pepper. The backup is replaced too, so that no copy without the pepper
    /// is left next to the vault.
    fn upgrade(self, path: &Path, password: &str, pepper: &Pepper) -> Result<(Self, VaultKey)> {
        let key = VaultKey::new(password, pepper)?;
        self.save_and_replace_backup(path, &key)?;
        Ok((self, key))
    }

    /// Encrypts and writes the vault to a file.
    ///
    /// File layout: `header (50 bytes) || envelope (72 bytes) || nonce
    /// (24 bytes) || ciphertext || tag (16 bytes)`. The header (see
    /// [`format`](mod@format)) and the envelope are authenticated as
    /// associated data.
    pub fn save(&self, path: &Path, key: &VaultKey) -> Result<()> {
        info!("saving vault ({} entries)", self.entries.len());
        let plaintext = self.to_json()?;
        debug!(
            "serialized vault to {} bytes of JSON (not shown: it contains secrets)",
            plaintext.len()
        );
        let encrypted = key.encrypt(&plaintext)?;

        let mut data = key.prefix();
        data.extend_from_slice(&encrypted);
        write_atomic(path, &data)
    }

    /// Saves the vault, then replaces the backup with the new version, so that
    /// no file encrypted under the previous password is left next to the vault.
    pub fn save_and_replace_backup(&self, path: &Path, key: &VaultKey) -> Result<()> {
        self.save(path, key)?;

        // `fs::copy` also copies the permission bits: the backup stays `600`.
        let backup_path = sibling(path, ".bak");
        fs::copy(path, &backup_path)?;
        debug!(
            "backup {} replaced with the new version",
            backup_path.display()
        );
        Ok(())
    }

    /// Serializes the vault to JSON in a buffer that is wiped on drop.
    fn to_json(&self) -> Result<Zeroizing<Vec<u8>>> {
        // Size the buffer exactly first: if it grew while serializing, each
        // reallocation would leave an unwiped copy of the secrets behind.
        let mut counter = ByteCounter(0);
        serde_json::to_writer(&mut counter, self)?;
        let mut json = Zeroizing::new(Vec::with_capacity(counter.0));
        let capacity = json.capacity();
        serde_json::to_writer(&mut *json, self)?;
        debug_assert_eq!(json.capacity(), capacity, "buffer was reallocated");
        Ok(json)
    }
}

/// Tells whether the vault at `path` can only be opened with an existing
/// pepper (format v3 and later).
///
/// Older formats return `false`: they are upgraded with the pepper when
/// opened, so a missing pepper file may be created for them. The header is
/// validated as by [`vault_pepper_id`]: a vault in a newer format, or with an
/// invalid header, is an error, so that no pepper is created for it. Nothing is
/// authenticated yet.
pub fn requires_existing_pepper(path: &Path) -> Result<bool> {
    Ok(vault_pepper_id(path)?.is_some())
}

/// Returns the id of the pepper the vault at `path` was created with, or
/// `None` for a vault in a format older than v3 (which has no pepper yet).
///
/// Only the header is read and validated, as [`Vault::open`] does before any
/// key derivation: nothing is decrypted, so no password is needed. The id is
/// not authenticated yet: a tampered id is only detected when the vault is
/// opened.
pub fn vault_pepper_id(path: &Path) -> Result<Option<[u8; PEPPER_ID_LEN]>> {
    let start = read_header_bytes(path)?;
    if !start.starts_with(MAGIC) {
        // The legacy layout has no header (and no pepper).
        return Ok(None);
    }
    Ok(Header::from_bytes(&start)?.pepper_id())
}

/// Reads the first bytes of the file at `path`, up to the length of a header
/// in the current format.
fn read_header_bytes(path: &Path) -> Result<Vec<u8>> {
    let mut start = Vec::with_capacity(HEADER_LEN);
    fs::File::open(path)?
        .take(HEADER_LEN as u64)
        .read_to_end(&mut start)?;
    Ok(start)
}

/// Creates `dir` and its parents if needed.
/// On Unix, newly created directories are restricted to the owner (`700`).
pub fn create_private_dir(dir: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)
}

/// A writer that discards its input and only counts the bytes written.
struct ByteCounter(usize);

impl Write for ByteCounter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Formats bytes as a lowercase hexadecimal string.
///
/// Only use it to log PUBLIC values (salt, nonce, tag), never secrets.
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Returns `path` with `suffix` appended to its full file name:
/// `vault.argos` -> `vault.argos.bak`.
fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// Writes `data` to `path` without ever leaving a partially written file.
///
/// The data is written to a temporary file, flushed to disk, then renamed over
/// the destination. The previous version is kept as a `.bak` file.
/// On Unix, the file is created with `600` permissions (owner read/write only).
fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let tmp_path = sibling(path, ".tmp");
    let backup_path = sibling(path, ".bak");

    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    debug!("writing temporary file {}", tmp_path.display());
    {
        let mut file = options.open(&tmp_path)?;
        file.write_all(data)?;
        file.sync_all()?;
    } // the file is closed here
    debug!("data flushed to disk (fsync)");

    if path.exists() {
        fs::copy(path, &backup_path)?;
        debug!("previous version backed up to {}", backup_path.display());
    }
    fs::rename(&tmp_path, path)?;
    debug!(
        "atomically renamed {} -> {}",
        tmp_path.display(),
        path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_an_entry() {
        let entry = Entry::new(
            "Gmail",
            "moi@gmail.com",
            "secret",
            Some("https://gmail.com"),
        );
        assert_eq!(entry.title, "Gmail");
        assert_eq!(entry.username, "moi@gmail.com");
        assert!(entry.password == "secret");
        assert_eq!(entry.url.as_deref(), Some("https://gmail.com"));
    }
    #[test]
    fn adds_then_finds_entry() {
        let mut vault = Vault::new();
        vault
            .add(Entry::new(
                "Gmail",
                "moi@gmail.com",
                "secret",
                Some("https://gmail.com"),
            ))
            .expect("add should succeed");

        let entry = vault.get("Gmail").expect("entry should exist");
        assert_eq!(entry.username, "moi@gmail.com");
    }

    #[test]
    fn rejects_duplicate_title() {
        let mut vault = Vault::new();
        vault
            .add(Entry::new(
                "Gmail",
                "premier",
                "secret",
                Some("https://gmail.com"),
            ))
            .expect("add should succeed");

        assert!(matches!(
            vault.add(Entry::new(
                "Gmail",
                "second",
                "autre-secret",
                Some("https://gmail.com"),
            )),
            Err(Error::EntryAlreadyExists(title)) if title == "Gmail"
        ));
        assert_eq!(vault.list().len(), 1);
        assert_eq!(
            vault.get("Gmail").expect("entry should exist").username,
            "premier"
        );
    }

    #[test]
    fn missing_entry_is_not_found() {
        let vault = Vault::new();
        assert!(matches!(
            vault.get("Inconnu"),
            Err(Error::EntryNotFound(title)) if title == "Inconnu"
        ));
    }

    #[test]
    fn removes_an_entry() {
        let mut vault = Vault::new();
        vault
            .add(Entry::new(
                "Gmail",
                "moi@gmail.com",
                "secret",
                Some("https://gmail.com"),
            ))
            .expect("add should succeed");

        let removed = vault.remove("Gmail").expect("entry should exist");
        assert_eq!(removed.title, "Gmail");
        assert!(vault.list().is_empty());
        assert!(matches!(
            vault.remove("Gmail"),
            Err(Error::EntryNotFound(_))
        ));
    }
    #[test]
    fn zeroize_wipes_entry_password() {
        let mut entry = Entry::new("Gmail", "me@gmail.com", "secret", None);
        entry.zeroize();
        assert!(entry.password.is_empty());
    }

    #[test]
    fn sibling_appends_to_the_full_file_name() {
        let cases = [
            ("dir/vault.argos", "dir/vault.argos.bak"),
            ("dir/secrets.db", "dir/secrets.db.bak"),
            ("secrets", "secrets.bak"),
        ];
        for (path, expected) in cases {
            assert_eq!(sibling(Path::new(path), ".bak"), Path::new(expected));
        }
    }

    #[test]
    fn json_buffer_is_never_reallocated() {
        // Characters that serde_json escapes (quote, backslash, control
        // characters) or that take several bytes in UTF-8 (accents, emoji):
        // the output size differs most from the input size here.
        let tricky = "\"quote\" \\back\\slash\n\t\u{1} éàü 🔐";
        let mut vault = Vault::new();
        for i in 0..50 {
            vault
                .add(Entry::new(
                    &format!("{tricky} {i}"),
                    tricky,
                    &tricky.repeat(i + 1),
                    Some(tricky),
                ))
                .expect("titles are unique");
        }

        let json = vault.to_json().expect("serialization should succeed");
        // Exactly sized and never grown: a reallocation would have at least
        // doubled the capacity.
        assert_eq!(json.len(), json.capacity());

        let parsed: Vault = serde_json::from_slice(&json).expect("valid JSON");
        assert_eq!(parsed.list().len(), 50);
        assert!(
            parsed
                .get(&format!("{tricky} 7"))
                .expect("entry should exist")
                .password
                == tricky.repeat(8)
        );
    }
}
