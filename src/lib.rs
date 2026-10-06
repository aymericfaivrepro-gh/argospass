//! Logique de gestionnaire de mot de passe.

/// Une entrée du coffre : un compte et son mot de passe.
pub struct Entry {
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
}

impl Entry {
    /// Crée une nouvelle entrée.
    pub fn new(title: &str, username: &str, password: &str, url: &str) -> Self {
        Self {
            title: title.to_string(),
            username: username.to_string(),
            password: password.to_string(),
            url: url.to_string(),
        }
    }
}

/// Le coffre : l'ensemble des entrées.
#[derive(Default)]
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creation_d_une_entree() {
        let entry = Entry::new("Gmail", "moi@gmail.com", "secret", "https://gmail.com");
        assert_eq!(entry.title, "Gmail");
        assert_eq!(entry.username, "moi@gmail.com");
        assert_eq!(entry.password, "secret");
        assert_eq!(entry.url, "https://gmail.com");
    }
}
#[test]
fn ajout_puis_recherche() {
    let mut vault = Vault::new();
    vault.add(Entry::new(
        "Gmail",
        "moi@gmail.com",
        "secret",
        "https://gmail.com",
    ));

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
        "https://gmail.com"
    )));

    assert!(!vault.add(Entry::new(
        "Gmail",
        "second",
        "autre-secret",
        "https://gmail.com",
    )));
    assert_eq!(vault.list().len(), 1);
    assert_eq!(vault.get("Gmail").unwrap().username, "premier");
}

#[test]
fn recherche_d_une_entree_absente() {
    let vault = Vault::new();
    assert!(vault.get("Inconnu").is_none());
}

#[test]
fn suppression() {
    let mut vault = Vault::new();
    vault.add(Entry::new(
        "Gmail",
        "moi@gmail.com",
        "secret",
        "https://gmail.com",
    ));

    let removed = vault.remove("Gmail").expect("l'entrée devrait exister");
    assert_eq!(removed.title, "Gmail");
    assert!(vault.list().is_empty());
}
