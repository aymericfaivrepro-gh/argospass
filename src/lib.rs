//! Password manager logic.
pub mod crypto;
mod error;
pub mod format;
pub mod generator;
mod hex;
pub mod pepper;

pub use error::{Error, Result};

use crypto::{ENVELOPE_LEN, KdfParams, NONCE_LEN, SALT_LEN, TAG_LEN, VaultKey};
use format::{FORMAT_VERSION, HEADER_LEN, Header, MAGIC};
use log::{debug, info, warn};
use pepper::{PEPPER_ID_LEN, Pepper};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::fs;
use std::io;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Size of an entry id: 16 bytes.
pub const ENTRY_ID_LEN: usize = 16;

/// Name of the password field, in the associated data of its encryption.
const PASSWORD_FIELD: &str = "password";

/// Random id of an entry, drawn when the entry is created and never changed.
/// Its protected fields are bound to it. Not secret: written in hex in the
/// JSON content and in the debug logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub struct EntryId([u8; ENTRY_ID_LEN]);

impl EntryId {
    /// Draws a new id from the operating system's CSPRNG.
    fn generate() -> Result<Self> {
        let mut id = [0u8; ENTRY_ID_LEN];
        getrandom::fill(&mut id)?;
        Ok(Self(id))
    }

    /// The id bytes.
    pub fn as_bytes(&self) -> &[u8; ENTRY_ID_LEN] {
        &self.0
    }

    /// An id chosen by a test.
    #[cfg(test)]
    pub(crate) fn from_bytes(bytes: [u8; ENTRY_ID_LEN]) -> Self {
        Self(bytes)
    }
}

/// Lowercase hex, as in the JSON content.
impl fmt::Display for EntryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(&self.0))
    }
}

// Written by hand, as hex strings: serde would write a list of 16 numbers.
impl Serialize for EntryId {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for EntryId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        hex::decode(&text)
            .and_then(|bytes| bytes.try_into().ok())
            .map(Self)
            .ok_or_else(|| D::Error::custom("an entry id must be 32 hex digits"))
    }
}

/// An encrypted field of an entry (level 2): `nonce (24 bytes) || ciphertext
/// || tag (16 bytes)`, written in hex in the JSON content.
///
/// It never holds plaintext: it is made by [`VaultKey::seal_field`], and only
/// [`VaultKey::open_field`] gives the text back.
#[derive(Zeroize)]
pub struct ProtectedField(Vec<u8>);

impl ProtectedField {
    /// Wraps the output of the encryption.
    pub(crate) fn from_sealed(sealed: Vec<u8>) -> Self {
        Self(sealed)
    }

    /// The encrypted bytes: `nonce || ciphertext || tag`. Not secret.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Serialize for ProtectedField {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for ProtectedField {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        hex::decode(&text)
            .filter(|bytes| bytes.len() >= NONCE_LEN + TAG_LEN)
            .map(Self)
            .ok_or_else(|| D::Error::custom("a protected field must be at least 80 hex digits"))
    }
}

/// A vault entry: an account, and its password encrypted separately (see
/// [`ProtectedField`]).
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Entry {
    id: EntryId,
    pub title: String,
    pub username: String,
    password: ProtectedField,
    pub url: Option<String>,
}

impl Entry {
    /// The id of the entry. It never changes.
    pub fn id(&self) -> EntryId {
        self.id
    }

    /// Decrypts the password of this entry, into a buffer that is wiped on
    /// drop. Only call it for the entry whose password is needed: the other
    /// passwords stay encrypted in memory.
    pub fn open_password(&self, key: &VaultKey) -> Result<Zeroizing<String>> {
        key.open_field(self.id, PASSWORD_FIELD, &self.password)
    }
}

/// An entry as stored before format v4, with its password in clear in the
/// JSON content. Only read, to upgrade an old vault.
#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct LegacyEntry {
    title: String,
    username: String,
    password: String,
    url: Option<String>,
}

/// The JSON content of a vault before format v4.
#[derive(Deserialize)]
struct LegacyVault {
    entries: Vec<LegacyEntry>,
}

impl LegacyVault {
    /// Rewrites a vault opened from an older format in the current format.
    ///
    /// Everything is regenerated: new salt, current Argon2id parameters, the
    /// pepper, a new random data key and a new vault id. The old key is never
    /// reused: an old copy and the password would otherwise give the data key
    /// without the pepper. Each entry gets an id, and its password is sealed
    /// with the field key. The backup is replaced too, so that no copy in the
    /// old format is left next to the vault.
    ///
    /// Entries are kept as they are, even two with the same title (possible in
    /// a file edited by hand): the upgrade must not lock the owner out.
    fn upgrade(self, path: &Path, password: &str, pepper: &Pepper) -> Result<(Vault, VaultKey)> {
        let key = VaultKey::new(password, pepper)?;
        let mut vault = Vault::new();
        for entry in &self.entries {
            vault.push_entry(
                &key,
                &entry.title,
                &entry.username,
                &entry.password,
                entry.url.as_deref(),
            )?;
        }
        vault.save_and_replace_backup(path, &key)?;
        Ok((vault, key))
    } // the old entries, with their passwords in clear, are wiped here
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

    /// Adds an entry to the vault, with a new random id. Its password is
    /// sealed with `key` right away.
    ///
    /// Fails with [`Error::EntryAlreadyExists`] if an entry has the same
    /// title.
    pub fn add(
        &mut self,
        key: &VaultKey,
        title: &str,
        username: &str,
        password: &str,
        url: Option<&str>,
    ) -> Result<()> {
        if self.entries.iter().any(|e| e.title == title) {
            return Err(Error::EntryAlreadyExists(title.to_string()));
        }
        self.push_entry(key, title, username, password, url)
    }

    /// Adds an entry with a new random id and its password sealed with `key`,
    /// without checking its title.
    fn push_entry(
        &mut self,
        key: &VaultKey,
        title: &str,
        username: &str,
        password: &str,
        url: Option<&str>,
    ) -> Result<()> {
        let id = EntryId::generate()?;
        let password = key.seal_field(id, PASSWORD_FIELD, password)?;
        self.entries.push(Entry {
            id,
            title: title.to_string(),
            username: username.to_string(),
            password,
            url: url.map(str::to_string),
        });
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

    /// Replaces the data key, for `passwd --rotate-key`: returns new key
    /// material under `new_password` (same vault id, new data key, so new
    /// subkeys), and encrypts every protected field again with it.
    ///
    /// All or nothing: if any field fails to open, the entries are unchanged.
    /// `key` is consumed, so it cannot be used by mistake to seal a field that
    /// the new key could not open. Nothing is written: save the vault with the
    /// returned key.
    pub fn rotate_key(
        &mut self,
        key: VaultKey,
        new_password: &str,
        pepper: &Pepper,
    ) -> Result<VaultKey> {
        let new_key = key.rotate(new_password, pepper)?;
        self.reseal(&key, &new_key)?;
        Ok(new_key)
    } // the old data key and its subkeys are wiped here

    /// Encrypts every protected field again: opened with `old`, sealed with
    /// `new`.
    ///
    /// All or nothing: if any field fails to open, nothing is changed.
    fn reseal(&mut self, old: &VaultKey, new: &VaultKey) -> Result<()> {
        // Every new field first, before replacing any of them.
        let resealed = self
            .entries
            .iter()
            .map(|entry| {
                let password = entry.open_password(old)?;
                new.seal_field(entry.id, PASSWORD_FIELD, &password)
            }) // each password in clear is wiped here, right after sealing
            .collect::<Result<Vec<_>>>()?;

        for (entry, password) in self.entries.iter_mut().zip(resealed) {
            entry.password = password;
        }
        info!(
            "re-encrypted {} passwords with the new field key",
            self.entries.len()
        );
        Ok(())
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
    /// Only the JSON content is decrypted: each password stays encrypted until
    /// [`Entry::open_password`]. Vaults in an older format (v3, v2, v1, or the
    /// legacy format before them) are upgraded automatically to the current
    /// format.
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
        if let Some(vault_id) = header.vault_id() {
            debug!("vault id (from file header): {}", to_hex(&vault_id));
        }

        match header.version() {
            1 => Self::open_v1(path, password, pepper, &header, header_bytes, rest),
            2 | 3 => Self::open_v2_v3(path, password, pepper, &header, rest),
            FORMAT_VERSION => Self::open_envelope(password, header, rest, pepper),
            // Already rejected by `Header::from_bytes`.
            other => Err(Error::UnsupportedVersion(other)),
        }
    }

    /// Opens a vault in the current format: `header || envelope || payload`.
    ///
    /// The KEK derived from the master password and the pepper unwraps the
    /// data key from the envelope, and the payload key derived from the data
    /// key decrypts the payload.
    fn open_envelope(
        password: &str,
        header: Header,
        rest: &[u8],
        pepper: &Pepper,
    ) -> Result<(Self, VaultKey)> {
        let (envelope, payload) = split_envelope(rest)?;
        let key = VaultKey::unlock(password, header, envelope, Some(pepper))?;
        let plaintext = key.decrypt(payload)?;
        let vault: Vault = serde_json::from_slice(&plaintext)?;
        info!(
            "vault decrypted: {} entries (their passwords are still encrypted)",
            vault.entries.len()
        );
        Ok((vault, key))
    }

    /// Opens a vault in format v2 or v3 (same layout as the current one, but
    /// the data key itself encrypted the payload, and the passwords are in
    /// clear inside it), then rewrites it in the current format.
    fn open_v2_v3(
        path: &Path,
        password: &str,
        pepper: &Pepper,
        header: &Header,
        rest: &[u8],
    ) -> Result<(Self, VaultKey)> {
        let (envelope, payload) = split_envelope(rest)?;
        // The pepper is ignored for v2, which was derived without one.
        let old: LegacyVault = {
            let plaintext =
                crypto::open_old_payload(password, header, envelope, payload, Some(pepper))?;
            serde_json::from_slice(&plaintext)?
        }; // the old data key and the decrypted JSON are wiped here
        info!("vault decrypted: {} entries", old.entries.len());

        warn!(
            "vault uses format v{}: upgrading it to format v{FORMAT_VERSION}",
            header.version()
        );
        old.upgrade(path, password, pepper)
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
        let old: LegacyVault = {
            let key = crypto::derive_key(password, &header.salt, &header.params, None)?;
            let plaintext = crypto::decrypt(&key, encrypted, header_bytes)?;
            serde_json::from_slice(&plaintext)?
        }; // the v1 key and the decrypted JSON are wiped here
        info!("vault decrypted: {} entries", old.entries.len());

        warn!("vault uses format v1: upgrading it to format v{FORMAT_VERSION}");
        old.upgrade(path, password, pepper)
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

        let old: LegacyVault = {
            let key = crypto::derive_key(password, &salt, &KdfParams::LEGACY, None)?;
            let plaintext = crypto::decrypt(&key, encrypted, &[])?;
            serde_json::from_slice(&plaintext)?
        }; // the legacy key and the decrypted JSON are wiped here
        info!("vault decrypted: {} entries", old.entries.len());

        warn!("vault uses the legacy format: upgrading it to format v{FORMAT_VERSION}");
        old.upgrade(path, password, pepper)
    }

    /// Encrypts and writes the vault to a file.
    ///
    /// File layout: `header (66 bytes) || envelope (72 bytes) || nonce
    /// (24 bytes) || ciphertext || tag (16 bytes)`. The JSON content is
    /// encrypted with the payload key; the passwords inside it already are,
    /// with the field key. The header (see [`format`](mod@format)) and the
    /// envelope are authenticated as associated data.
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
    hex::encode(bytes)
}

/// Splits `envelope || payload`. The length is checked first: a truncated file
/// must fail before Argon2id runs.
fn split_envelope(rest: &[u8]) -> Result<(&[u8], &[u8])> {
    if rest.len() < ENVELOPE_LEN + NONCE_LEN + TAG_LEN {
        return Err(Error::Truncated);
    }
    let (envelope, payload) = rest.split_at(ENVELOPE_LEN);
    debug!(
        "envelope: {} bytes, payload: {} bytes",
        envelope.len(),
        payload.len()
    );
    Ok((envelope, payload))
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

    /// A vault holding one entry, "Gmail", whose password is `password`.
    fn vault_with_gmail(key: &VaultKey, password: &str) -> Vault {
        let mut vault = Vault::new();
        vault
            .add(
                key,
                "Gmail",
                "moi@gmail.com",
                password,
                Some("https://gmail.com"),
            )
            .expect("add should succeed");
        vault
    }

    #[test]
    fn adds_then_finds_entry() {
        let key = VaultKey::for_tests();
        let vault = vault_with_gmail(&key, "secret");

        let entry = vault.get("Gmail").expect("entry should exist");
        assert_eq!(entry.title, "Gmail");
        assert_eq!(entry.username, "moi@gmail.com");
        assert_eq!(entry.url.as_deref(), Some("https://gmail.com"));
        let password = entry.open_password(&key).expect("open should succeed");
        assert!(*password == "secret");
    }

    #[test]
    fn the_password_is_sealed_as_soon_as_it_is_added() {
        let key = VaultKey::for_tests();
        let vault = vault_with_gmail(&key, "hunter2-secret");

        let entry = vault.get("Gmail").expect("entry should exist");
        assert_eq!(entry.password.as_bytes().len(), NONCE_LEN + 14 + TAG_LEN);
        let json = vault.to_json().expect("serialization should succeed");
        assert!(!json.windows(7).any(|w| w == b"hunter2"));
        // The other fields are only protected by the payload encryption.
        assert!(json.windows(5).any(|w| w == b"Gmail"));
    }

    #[test]
    fn entry_ids_are_random_and_kept_in_the_json() {
        let key = VaultKey::for_tests();
        let mut vault = vault_with_gmail(&key, "one");
        vault
            .add(&key, "GitHub", "me", "two", None)
            .expect("add should succeed");
        let ids: Vec<EntryId> = vault.list().iter().map(Entry::id).collect();
        assert_ne!(ids[0], ids[1]);

        let json = vault.to_json().expect("serialization should succeed");
        let text = std::str::from_utf8(&json).expect("UTF-8");
        assert!(text.contains(&format!(r#""id":"{}""#, ids[0])));

        let parsed: Vault = serde_json::from_slice(&json).expect("valid JSON");
        let entry = parsed.get("GitHub").expect("entry should exist");
        assert_eq!(entry.id(), ids[1]);
        assert!(*entry.open_password(&key).expect("open should succeed") == "two");
    }

    #[test]
    fn malformed_ids_and_protected_fields_are_rejected() {
        let id = "00".repeat(ENTRY_ID_LEN);
        let field = "00".repeat(NONCE_LEN + TAG_LEN);
        let entry = |id: &str, field: &str| {
            format!(
                r#"{{"entries":[{{"id":"{id}","title":"t","username":"u","password":"{field}","url":null}}]}}"#
            )
        };
        assert!(serde_json::from_str::<Vault>(&entry(&id, &field)).is_ok());

        let too_short = "00".repeat(NONCE_LEN + TAG_LEN - 1);
        let short_id = "00".repeat(ENTRY_ID_LEN - 1);
        for (id, field) in [
            (short_id.as_str(), field.as_str()),
            ("not hex", field.as_str()),
            (id.as_str(), too_short.as_str()),
            (id.as_str(), "zz"),
        ] {
            let result = serde_json::from_str::<Vault>(&entry(id, field));
            assert!(matches!(result.map_err(Error::from), Err(Error::Json(_))));
        }
    }

    #[test]
    fn rejects_duplicate_title() {
        let key = VaultKey::for_tests();
        let mut vault = Vault::new();
        vault
            .add(&key, "Gmail", "premier", "secret", None)
            .expect("add should succeed");

        assert!(matches!(
            vault.add(&key, "Gmail", "second", "autre-secret", None),
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
        let key = VaultKey::for_tests();
        let mut vault = vault_with_gmail(&key, "secret");

        let removed = vault.remove("Gmail").expect("entry should exist");
        assert_eq!(removed.title, "Gmail");
        assert!(vault.list().is_empty());
        assert!(matches!(
            vault.remove("Gmail"),
            Err(Error::EntryNotFound(_))
        ));
    }

    #[test]
    fn zeroize_wipes_the_entry() {
        let key = VaultKey::for_tests();
        let mut entry = vault_with_gmail(&key, "secret")
            .remove("Gmail")
            .expect("entry should exist");
        entry.zeroize();
        assert!(entry.title.is_empty());
        assert!(entry.password.as_bytes().is_empty());
    }

    #[test]
    fn reseal_encrypts_every_password_with_the_new_key() {
        let old = VaultKey::for_tests();
        let new = VaultKey::for_tests();
        let mut vault = vault_with_gmail(&old, "one");
        vault
            .add(&old, "GitHub", "me", "two", None)
            .expect("add should succeed");
        let before: Vec<Vec<u8>> = vault
            .list()
            .iter()
            .map(|e| e.password.as_bytes().to_vec())
            .collect();

        vault.reseal(&old, &new).expect("reseal should succeed");

        for (entry, (old_bytes, text)) in vault.list().iter().zip(before.iter().zip(["one", "two"]))
        {
            assert!(entry.password.as_bytes() != old_bytes.as_slice());
            assert!(*entry.open_password(&new).expect("open should succeed") == text);
            assert!(matches!(
                entry.open_password(&old),
                Err(Error::DecryptionFailed)
            ));
        }
    }

    #[test]
    fn reseal_changes_nothing_if_a_field_fails_to_open() {
        let old = VaultKey::for_tests();
        let new = VaultKey::for_tests();
        let mut vault = vault_with_gmail(&old, "one");
        vault
            .add(&old, "GitHub", "me", "two", None)
            .expect("add should succeed");
        // The second entry is damaged: the first one would reseal fine.
        vault.entries[1].password.0[NONCE_LEN] ^= 0x01;
        let before: Vec<Vec<u8>> = vault
            .list()
            .iter()
            .map(|e| e.password.as_bytes().to_vec())
            .collect();

        assert!(matches!(
            vault.reseal(&old, &new),
            Err(Error::DecryptionFailed)
        ));
        let after: Vec<Vec<u8>> = vault
            .list()
            .iter()
            .map(|e| e.password.as_bytes().to_vec())
            .collect();
        assert!(after == before);
        let first = vault.get("Gmail").expect("entry should exist");
        assert!(*first.open_password(&old).expect("still the old key") == "one");
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
        let key = VaultKey::for_tests();
        let mut vault = Vault::new();
        for i in 0..50 {
            vault
                .add(
                    &key,
                    &format!("{tricky} {i}"),
                    tricky,
                    &tricky.repeat(i + 1),
                    Some(tricky),
                )
                .expect("titles are unique");
        }

        let json = vault.to_json().expect("serialization should succeed");
        // Exactly sized and never grown: a reallocation would have at least
        // doubled the capacity.
        assert_eq!(json.len(), json.capacity());

        let parsed: Vault = serde_json::from_slice(&json).expect("valid JSON");
        assert_eq!(parsed.list().len(), 50);
        let entry = parsed
            .get(&format!("{tricky} 7"))
            .expect("entry should exist");
        assert!(*entry.open_password(&key).expect("open should succeed") == tricky.repeat(8));
    }
}
