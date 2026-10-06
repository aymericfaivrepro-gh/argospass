use argospass::{Entry, Vault};
use clap::{Parser, Subcommand};
use std::io;
use std::path::Path;

/// Emplacement du fichier coffre (dans le dossier courant pour l'instant).
const VAULT_PATH: &str = "vault.json";
/// ArgosPass : gestionnaire de mots de passe.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Ajoute une entrée
    Add {
        /// Titre de l'entrée (ex. Gmail)
        title: String,
        /// Nom d'utilisateur ou e-mail
        username: String,
        /// Mot de passe
        password: String,
        ///URL du service (optionnel)
        url: Option<String>,
    },
    /// Liste les entrées
    List,
    /// Affiche une entrée
    Get {
        /// Titre de l'entrée
        title: String,
    },
    /// Supprime une entrée
    Remove {
        /// Titre de l'entrée
        title: String,
    },
}

fn main() -> io::Result<()> {
    let cli = Cli::parse();
    let path = Path::new(VAULT_PATH);
    let mut vault = Vault::load(path)?;

    match cli.command {
        Command::Add {
            title,
            username,
            password,
            url,
        } => {
            if vault.add(Entry::new(&title, &username, &password, url.as_deref())) {
                vault.save(path)?;
                println!("Entrée « {title} » ajoutée");
            } else {
                println!("Une entrée « {title} » existe déjà");
            }
        }
        Command::List => {
            if vault.list().is_empty() {
                println!("Aucune entrée enregistrée.");
            } else {
                println!("Entrées :");
                for entry in vault.list() {
                    println!("- {} ({})", entry.title, entry.username);
                }
            }
        }
        Command::Get { title } => match vault.get(&title) {
            Some(entry) => {
                println!("Titre : {}", entry.title);
                println!("Nom d'utilisateur : {}", entry.username);
                println!("Mot de passe : {}", entry.password);
                if let Some(url) = entry.url.as_deref().filter(|url| !url.is_empty()) {
                    println!("URL : {url}");
                }
            }
            None => println!("Aucune entrée « {title} »"),
        },
        Command::Remove { title } => match vault.remove(&title) {
            Some(_) => {
                vault.save(path)?;
                println!("Entrée « {title} » supprimée");
            }
            None => println!("Aucune entrée « {title} »"),
        },
    }

    Ok(())
}
