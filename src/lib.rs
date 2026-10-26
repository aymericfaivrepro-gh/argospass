//! Password manager logic.
pub mod crypto;
mod error;
pub mod format;
pub mod generator;
mod hex;
pub mod pepper;

pub use error::{Error, Result};

use crypto::{ENVELOPE_LEN, NONCE_LEN, TAG_LEN, VaultKey};
use format::{FORMAT_VERSION, HEADER_LEN, Header};
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

/// Largest vault file accepted, in bytes (64 MiB): far more than any real
/// vault needs, and small enough that a crafted file cannot exhaust memory.
pub const MAX_VAULT_LEN: u64 = 64 * 1024 * 1024;

/// Name of the password field, in the associated data of its encryption.
const PASSWORD_FIELD: &str = "password";

/// Suffix of the temporary file a file is written to before it replaces it.
const TMP_SUFFIX: &str = ".tmp";

/// Suffix of the backup of a vault: its previous version.
const BACKUP_SUFFIX: &str = ".bak";

/// Suffix of the lock file of a vault (see [`VaultLock`]).
const LOCK_SUFFIX: &str = ".lock";

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
    /// The KEK derived from the master password and the pepper unwraps the
    /// data key from the envelope, and the payload key derived from the data
    /// key decrypts the payload. Only the JSON content is decrypted: each
    /// password stays encrypted until [`Entry::open_password`].
    ///
    /// Only format v4 is opened: an older format fails with
    /// [`Error::UnsupportedVersion`], or [`Error::BadMagic`] for the legacy
    /// layout (which has no header), before any key derivation. Fails with
    /// [`Error::PepperMismatch`] if the vault was created with another
    /// pepper, and with [`Error::DecryptionFailed`] if the master password is
    /// wrong or if the file has been modified.
    pub fn open(path: &Path, password: &str, pepper: &Pepper) -> Result<(Self, VaultKey)> {
        let data = read_vault_file(path)?;
        info!("opening vault");
        debug!("read {} bytes from {}", data.len(), path.display());

        let header = Header::from_bytes(&data)?;
        debug!("format version {FORMAT_VERSION}, {:?}", header.params);
        debug!("salt (from file header): {}", to_hex(&header.salt));
        debug!(
            "pepper id (from file header): {}",
            to_hex(&header.pepper_id())
        );
        debug!(
            "vault id (from file header): {}",
            to_hex(&header.vault_id())
        );

        // `from_bytes` checked that the whole header is there.
        let rest = data.get(HEADER_LEN..).ok_or(Error::Truncated)?;
        let (envelope, payload) = split_envelope(rest)?;
        let key = VaultKey::unlock(password, header, envelope, pepper)?;
        let plaintext = key.decrypt(payload)?;
        let vault: Vault = serde_json::from_slice(&plaintext)?;
        info!(
            "vault decrypted: {} entries (their passwords are still encrypted)",
            vault.entries.len()
        );
        Ok((vault, key))
    }

    /// Encrypts and writes the vault to a file.
    ///
    /// File layout: `header (66 bytes) || envelope (72 bytes) || nonce
    /// (24 bytes) || ciphertext || tag (16 bytes)`. The JSON content is
    /// encrypted with the payload key; the passwords inside it already are,
    /// with the field key. The header (see [`format`](mod@format)) and the
    /// envelope are authenticated as associated data.
    ///
    /// Fails with [`Error::VaultTooLarge`], before writing anything, if the
    /// file would be larger than [`MAX_VAULT_LEN`]: it could not be opened
    /// again.
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
        check_vault_len(data.len() as u64)?;
        write_atomic(path, &data)
    }

    /// Saves the vault, then replaces the backup with the new version, so that
    /// no file encrypted under the previous password is left next to the vault.
    ///
    /// Fails with [`Error::BackupNotReplaced`] if the vault was saved but its
    /// backup could not be replaced: the backup then still holds the previous
    /// version.
    pub fn save_and_replace_backup(&self, path: &Path, key: &VaultKey) -> Result<()> {
        self.save(path, key)?;

        let backup_path = sibling(path, BACKUP_SUFFIX);
        if let Err(source) = fs::read(path).and_then(|data| replace_file(&backup_path, &data)) {
            return Err(Error::BackupNotReplaced {
                path: backup_path,
                source,
            });
        }
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

/// Returns the id of the pepper the vault at `path` was created with.
///
/// Only the header is read and validated, as [`Vault::open`] does before any
/// key derivation: nothing is decrypted, so no password is needed. A vault in
/// another format fails as it would when opened. The id is not authenticated
/// yet: a tampered id is only detected when the vault is opened.
pub fn vault_pepper_id(path: &Path) -> Result<[u8; PEPPER_ID_LEN]> {
    Ok(Header::from_bytes(&read_header_bytes(path)?)?.pepper_id())
}

/// Reads the first bytes of the file at `path`, up to the length of a header.
fn read_header_bytes(path: &Path) -> Result<Vec<u8>> {
    let mut start = Vec::with_capacity(HEADER_LEN);
    fs::File::open(path)?
        .take(HEADER_LEN as u64)
        .read_to_end(&mut start)?;
    Ok(start)
}

/// Reads the whole vault file at `path`. Fails with [`Error::VaultTooLarge`]
/// if it is larger than [`MAX_VAULT_LEN`], before reading it.
fn read_vault_file(path: &Path) -> Result<Vec<u8>> {
    let file = fs::File::open(path)?;
    check_vault_len(file.metadata()?.len())?;

    // Bounded all the same: the size given by the metadata may change, and
    // means nothing for a pipe or a device.
    let mut data = Vec::new();
    file.take(MAX_VAULT_LEN + 1).read_to_end(&mut data)?;
    check_vault_len(data.len() as u64)?;
    Ok(data)
}

/// Fails with [`Error::VaultTooLarge`] if a vault file of `len` bytes is
/// larger than [`MAX_VAULT_LEN`].
fn check_vault_len(len: u64) -> Result<()> {
    if len > MAX_VAULT_LEN {
        return Err(Error::VaultTooLarge(len));
    }
    Ok(())
}

/// Every file ArgosPass writes for the vault at `path`: the vault, its
/// backup, the temporary files they are written through, and the lock file.
///
/// No other file, such as the pepper, may have one of these paths: saving the
/// vault would overwrite it.
pub fn vault_files(path: &Path) -> [PathBuf; 5] {
    let backup = sibling(path, BACKUP_SUFFIX);
    [
        path.to_path_buf(),
        sibling(path, TMP_SUFFIX),
        sibling(&backup, TMP_SUFFIX),
        backup,
        sibling(path, LOCK_SUFFIX),
    ]
}

/// An exclusive lock on a vault, for a command that changes it: held from
/// reading the vault to saving it, so that two commands cannot each save their
/// own version and lose the other one's changes. Released when dropped.
///
/// The lock is taken on a `.lock` file next to the vault, which stays there:
/// it is never written to, nor removed (two commands could otherwise lock two
/// different files).
pub struct VaultLock {
    // Only kept for the lock: closing the file releases it.
    _file: fs::File,
}

impl VaultLock {
    /// Locks the vault at `path`. Fails with [`Error::VaultBusy`] if another
    /// command holds the lock, rather than waiting for it.
    ///
    /// On a file system without file locks (some network drives), goes on
    /// without one, and logs a warning.
    pub fn acquire(path: &Path) -> Result<Self> {
        let lock_path = sibling(path, LOCK_SUFFIX);
        let mut options = fs::OpenOptions::new();
        // Created if needed, but never truncated: the file stays empty.
        options.write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&lock_path)?;

        match file.try_lock() {
            Ok(()) => debug!("locked {}", lock_path.display()),
            Err(fs::TryLockError::WouldBlock) => return Err(Error::VaultBusy),
            Err(fs::TryLockError::Error(e)) if e.kind() == io::ErrorKind::Unsupported => {
                warn!(
                    "{} cannot be locked (the file system does not support it): \
                     do not run two commands that change the vault at the same time",
                    lock_path.display()
                );
            }
            Err(fs::TryLockError::Error(e)) => return Err(e.into()),
        }
        Ok(Self { _file: file })
    }
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

/// Flushes the directory entry of `path` to disk, so that a file just created
/// or renamed there is still there after a crash (Unix only).
pub(crate) fn sync_parent_dir(path: &Path) -> io::Result<()> {
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

/// Writes `data` to `path` without ever leaving a partially written file (see
/// [`replace_file`]). The previous version, if any, is kept first as the
/// `.bak` backup, replaced the same way.
fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    if path.exists() {
        let backup_path = sibling(path, BACKUP_SUFFIX);
        replace_file(&backup_path, &fs::read(path)?)?;
        debug!("previous version backed up to {}", backup_path.display());
    }
    replace_file(path, data)?;
    Ok(())
}

/// Replaces the content of `path` with `data` atomically: `data` is written to
/// a temporary file, flushed to disk, then renamed over `path`. At any moment,
/// `path` holds either its old content or the new one, never a partially
/// written file.
///
/// The temporary file is always a new file, never one found in its place: a
/// leftover file could keep other permissions, or be a link to another file.
/// On Unix, it is created with `600` permissions (owner read/write only).
fn replace_file(path: &Path, data: &[u8]) -> io::Result<()> {
    let tmp_path = sibling(path, TMP_SUFFIX);
    match fs::remove_file(&tmp_path) {
        Ok(()) => debug!("removed the leftover file {}", tmp_path.display()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }

    let mut options = fs::OpenOptions::new();
    // `create_new` fails if anything (even a link) appeared at this path in
    // the meantime, instead of writing through it.
    options.write(true).create_new(true);
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

    fs::rename(&tmp_path, path)?;
    // The rename itself only survives a crash once the directory is flushed.
    sync_parent_dir(path)?;
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
            assert!(matches!(
                result.map_err(Error::from),
                Err(Error::Json { .. })
            ));
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
    fn vault_files_are_all_the_files_written_next_to_the_vault() {
        let files = vault_files(Path::new("dir/vault.argos"));
        let expected = [
            "dir/vault.argos",
            "dir/vault.argos.tmp",
            "dir/vault.argos.bak.tmp",
            "dir/vault.argos.bak",
            "dir/vault.argos.lock",
        ];
        assert_eq!(files, expected.map(PathBuf::from));
    }

    #[test]
    fn vault_files_up_to_64_mib_are_accepted() {
        assert!(check_vault_len(0).is_ok());
        assert!(check_vault_len(MAX_VAULT_LEN).is_ok());
        assert!(matches!(
            check_vault_len(MAX_VAULT_LEN + 1),
            Err(Error::VaultTooLarge(len)) if len == MAX_VAULT_LEN + 1
        ));
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
