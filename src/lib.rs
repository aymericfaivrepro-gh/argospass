//! Password manager logic.
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
    /// Loads the vault from a file.
    /// Returns an empty vault if the file does not exist yet.
    pub fn load(path: &Path) -> io::Result<Self> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let content = fs::read_to_string(path)?;
        let vault = serde_json::from_str(&content)?;
        Ok(vault)
    }

    /// Saves the vault to a file.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        fs::write(path, content)
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

    #[test]
    fn saves_then_loads_vault() {
        let path = std::env::temp_dir().join("argospass-test-vault.json");

        let mut vault = Vault::new();
        assert!(vault.add(Entry::new(
            "Gmail",
            "moi@gmail.com",
            "secret",
            Some("https://gmail.com"),
        )));
        vault.save(&path).expect("saving should succeed");

        let loaded = Vault::load(&path).expect("loading should succeed");
        let entry = loaded.get("Gmail").expect("entry should exist");
        assert_eq!(entry.username, "moi@gmail.com");

        std::fs::remove_file(&path).expect("cleanup should succeed");
    }
}
