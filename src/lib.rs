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
