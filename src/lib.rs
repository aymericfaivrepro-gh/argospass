//! Password manager logic.
pub mod crypto;

use crypto::{SALT_LEN, VaultKey};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::Path;
/// A vault entry: an account and its password.
#[derive(Serialize, Deserialize)]
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
    /// Returns `false` if an entry with the same title already exists.
    #[must_use]
    pub fn add(&mut self, entry: Entry) -> bool {
        if self.get(&entry.title).is_some() {
            return false;
        }

        self.entries.push(entry);
        true
    }

    /// Finds an entry by its title.
    pub fn get(&self, title: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.title == title)
    }

    /// Returns all entries.
    pub fn list(&self) -> &[Entry] {
        &self.entries
    }

    /// Removes and returns an entry by its title.
    pub fn remove(&mut self, title: &str) -> Option<Entry> {
        let index = self.entries.iter().position(|e| e.title == title)?;
        Some(self.entries.remove(index))
    }
    /// Opens and decrypts an existing vault file with the master password.
    ///
    /// Returns the vault and the key material needed to save it again.
    /// Fails if the password is wrong or if the file has been modified.
    pub fn open(path: &Path, password: &str) -> io::Result<(Self, VaultKey)> {
        let data = fs::read(path)?;
        if data.len() < SALT_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "vault file is too short",
            ));
        }

        let (salt, encrypted) = data.split_at(SALT_LEN);
        let salt: [u8; SALT_LEN] = salt
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid salt"))?;

        let key = VaultKey::from_salt(password, salt)?;
        let plaintext = crypto::decrypt(&key.key, encrypted)?;
        let vault = serde_json::from_slice(&plaintext)?;
        Ok((vault, key))
    }

    /// Encrypts and writes the vault to a file.
    ///
    /// File layout: `salt (16 bytes) || nonce (24 bytes) || ciphertext || tag (16 bytes)`.
    pub fn save(&self, path: &Path, key: &VaultKey) -> io::Result<()> {
        let plaintext = serde_json::to_vec(self)?;
        let encrypted = crypto::encrypt(&key.key, &plaintext)?;

        let mut data = Vec::with_capacity(SALT_LEN + encrypted.len());
        data.extend_from_slice(&key.salt);
        data.extend_from_slice(&encrypted);
        fs::write(path, data)
    }
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
        assert!(vault.add(Entry::new(
            "Gmail",
            "moi@gmail.com",
            "secret",
            Some("https://gmail.com"),
        )));

        let entry = vault.get("Gmail").expect("entry should exist");
        assert_eq!(entry.username, "moi@gmail.com");
    }

    #[test]
    fn rejects_duplicate_title() {
        let mut vault = Vault::new();
        assert!(vault.add(Entry::new(
            "Gmail",
            "premier",
            "secret",
            Some("https://gmail.com")
        )));

        assert!(!vault.add(Entry::new(
            "Gmail",
            "second",
            "autre-secret",
            Some("https://gmail.com"),
        )));
        assert_eq!(vault.list().len(), 1);
        assert_eq!(
            vault.get("Gmail").expect("entry should exist").username,
            "premier"
        );
    }

    #[test]
    fn returns_none_for_missing_entry() {
        let vault = Vault::new();
        assert!(vault.get("Inconnu").is_none());
    }

    #[test]
    fn removes_an_entry() {
        let mut vault = Vault::new();
        assert!(vault.add(Entry::new(
            "Gmail",
            "moi@gmail.com",
            "secret",
            Some("https://gmail.com"),
        )));

        let removed = vault.remove("Gmail").expect("entry should exist");
        assert_eq!(removed.title, "Gmail");
        assert!(vault.list().is_empty());
    }

    
}
