//! Logique de gestionnaire de mot de passe.
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::Path;
/// Une entrée du coffre : un compte et son mot de passe.
#[derive(Serialize, Deserialize)]
pub struct Entry {
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: Option<String>,
}

impl Entry {
    /// Crée une nouvelle entrée.
    pub fn new(title: &str, username: &str, password: &str, url: Option<&str>) -> Self {
        Self {
            title: title.to_string(),
            username: username.to_string(),
            password: password.to_string(),
            url: url.map(|s| s.to_string()),
        }
    }
}

/// Le coffre : l'ensemble des entrées.
#[derive(Default, Serialize, Deserialize)]
pub struct Vault {
    entries: Vec<Entry>,
}

impl Vault {
    /// Crée un coffre vide.
    pub fn new() -> Self {
        Self::default()
    }

    /// Ajoute une entrée au coffre.
    /// Renvoie `false` si une entrée avec le même titre existe déjà.
    #[must_use]
    pub fn add(&mut self, entry: Entry) -> bool {
        if self.get(&entry.title).is_some() {
            return false;
        }

        self.entries.push(entry);
        true
    }

    /// Cherche une entrée par son titre.
    pub fn get(&self, title: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.title == title)
    }

    /// Renvoie toutes les entrées.
    pub fn list(&self) -> &[Entry] {
        &self.entries
    }

    /// Supprime une entrée par son titre et la renvoie.
    pub fn remove(&mut self, title: &str) -> Option<Entry> {
        let index = self.entries.iter().position(|e| e.title == title)?;
        Some(self.entries.remove(index))
    }
    /// Charge le coffre depuis un fichier.
    /// Si le fichier n'existe pas encore, renvoie un coffre vide.
    pub fn load(path: &Path) -> io::Result<Self> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let content = fs::read_to_string(path)?;
        let vault = serde_json::from_str(&content)?;
        Ok(vault)
    }

    /// Sauvegarde le coffre dans un fichier.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        fs::write(path, content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creation_d_une_entree() {
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
    fn ajout_puis_recherche() {
        let mut vault = Vault::new();
        assert!(vault.add(Entry::new(
            "Gmail",
            "moi@gmail.com",
            "secret",
            Some("https://gmail.com"),
        )));

        let entry = vault.get("Gmail").expect("l'entrée devrait exister");
        assert_eq!(entry.username, "moi@gmail.com");
    }

    #[test]
    fn ajout_refuse_un_titre_deja_present() {
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
            vault
                .get("Gmail")
                .expect("l'entrée devrait exister")
                .username,
            "premier"
        );
    }

    #[test]
    fn recherche_d_une_entree_absente() {
        let vault = Vault::new();
        assert!(vault.get("Inconnu").is_none());
    }

    #[test]
    fn suppression() {
        let mut vault = Vault::new();
        assert!(vault.add(Entry::new(
            "Gmail",
            "moi@gmail.com",
            "secret",
            Some("https://gmail.com"),
        )));

        let removed = vault.remove("Gmail").expect("l'entrée devrait exister");
        assert_eq!(removed.title, "Gmail");
        assert!(vault.list().is_empty());
    }

    #[test]
    fn sauvegarde_puis_chargement() {
        let path = std::env::temp_dir().join("argospass-test-vault.json");

        let mut vault = Vault::new();
        assert!(vault.add(Entry::new(
            "Gmail",
            "moi@gmail.com",
            "secret",
            Some("https://gmail.com"),
        )));
        vault.save(&path).expect("la sauvegarde devrait réussir");

        let loaded = Vault::load(&path).expect("le chargement devrait réussir");
        let entry = loaded.get("Gmail").expect("l'entrée devrait exister");
        assert_eq!(entry.username, "moi@gmail.com");

        std::fs::remove_file(&path).expect("le nettoyage devrait réussir");
    }
}
