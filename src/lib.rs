//! Password manager logic.
pub mod crypto;
mod error;
pub mod format;
pub mod generator;

pub use error::{Error, Result};

use crypto::{ENVELOPE_LEN, KdfParams, NONCE_LEN, SALT_LEN, TAG_LEN, VaultKey};
use format::{FORMAT_VERSION, HEADER_LEN, Header, MAGIC};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::io::Write;
use std::path::Path;
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

    /// Opens and decrypts a vault file with the master password.
    ///
    /// Vaults in an older format (v1, or the legacy format before it) are
    /// upgraded automatically to the current format.
    /// Fails with [`Error::DecryptionFailed`] if the master password is wrong
    /// or if the file has been modified.
    pub fn open(path: &Path, password: &str) -> Result<(Self, VaultKey)> {
        let data = fs::read(path)?;
        info!("opening vault");
        debug!("read {} bytes from {}", data.len(), path.display());

        if !data.starts_with(MAGIC) {
            return Self::open_legacy(path, password, &data);
        }

        let header = Header::from_bytes(&data)?;
        let (header_bytes, rest) = data.split_at(HEADER_LEN);
        let version = format::version(header_bytes);
        debug!("format version {version}, {:?}", header.params);
        debug!("salt (from file header): {}", to_hex(&header.salt));

        match version {
            1 => Self::open_v1(path, password, &header, header_bytes, rest),
            FORMAT_VERSION => Self::open_v2(password, header, rest),
            // Already rejected by `Header::from_bytes`.
            other => Err(Error::UnsupportedVersion(other)),
        }
    }

    /// Opens a vault in the current format: `header || envelope || payload`.
    ///
    /// The KEK derived from the master password unwraps the data key from the
    /// envelope, and the data key decrypts the payload.
    fn open_v2(password: &str, header: Header, rest: &[u8]) -> Result<(Self, VaultKey)> {
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

        let key = VaultKey::unlock(password, header, envelope)?;
        let plaintext = key.decrypt(payload)?;
        let vault: Vault = serde_json::from_slice(&plaintext)?;
        info!("vault decrypted: {} entries", vault.entries.len());
        Ok((vault, key))
    }

    /// Opens a vault in format v1 (`header || nonce || ciphertext || tag`,
    /// encrypted with the key derived from the master password), then rewrites
    /// it in the current format. The v1 file is kept as the `.bak` backup.
    fn open_v1(
        path: &Path,
        password: &str,
        header: &Header,
        header_bytes: &[u8],
        encrypted: &[u8],
    ) -> Result<(Self, VaultKey)> {
        // The raw header bytes from the file are the associated data: they are
        // what v1 authenticated (`Header::to_bytes` would write version 2).
        let vault: Vault = {
            let key = crypto::derive_key(password, &header.salt, &header.params)?;
            let plaintext = crypto::decrypt(&key, encrypted, header_bytes)?;
            serde_json::from_slice(&plaintext)?
        }; // the v1 key and the decrypted JSON are wiped here
        info!("vault decrypted: {} entries", vault.entries.len());

        warn!("vault uses format v1: upgrading it to format v{FORMAT_VERSION}");
        vault.upgrade(path, password)
    }

    /// Opens a vault in the legacy layout (`salt || nonce || ciphertext || tag`,
    /// fixed Argon2id parameters, no associated data), then rewrites it in the
    /// current format. The legacy file is kept as the `.bak` backup.
    fn open_legacy(path: &Path, password: &str, data: &[u8]) -> Result<(Self, VaultKey)> {
        if data.len() < SALT_LEN {
            return Err(Error::Truncated);
        }

        let (salt, encrypted) = data.split_at(SALT_LEN);
        let salt: [u8; SALT_LEN] = salt.try_into().expect("length checked above");
        debug!("legacy vault, salt: {}", to_hex(&salt));

        let vault: Vault = {
            let key = crypto::derive_key(password, &salt, &KdfParams::LEGACY)?;
            let plaintext = crypto::decrypt(&key, encrypted, &[])?;
            serde_json::from_slice(&plaintext)?
        }; // the legacy key and the decrypted JSON are wiped here
        info!("vault decrypted: {} entries", vault.entries.len());

        warn!("vault uses the legacy format: upgrading it to format v{FORMAT_VERSION}");
        vault.upgrade(path, password)
    }

    /// Rewrites a vault opened from an older format in the current format.
    ///
    /// Everything is regenerated: new salt, current Argon2id parameters and a
    /// new random data key. The key derived for the old format is never reused.
    fn upgrade(self, path: &Path, password: &str) -> Result<(Self, VaultKey)> {
        let key = VaultKey::new(password)?;
        self.save(path, &key)?;
        Ok((self, key))
    }

    /// Encrypts and writes the vault to a file.
    ///
    /// File layout: `header || envelope (72 bytes) || nonce (24 bytes) ||
    /// ciphertext || tag (16 bytes)`. The header (see [`format`](mod@format))
    /// and the envelope are authenticated as associated data.
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

/// Writes `data` to `path` without ever leaving a partially written file.
///
/// The data is written to a temporary file, flushed to disk, then renamed over
/// the destination. The previous version is kept as a `.bak` file.
/// On Unix, the file is created with `600` permissions (owner read/write only).
fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let tmp_path = path.with_extension("argos.tmp");
    let backup_path = path.with_extension("argos.bak");

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
        assert_eq!(entry.password, "secret");
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
        assert_eq!(
            parsed.get(&format!("{tricky} 7")).unwrap().password,
            tricky.repeat(8)
        );
    }
}
