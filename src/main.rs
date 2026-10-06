use argospass::{Entry, Vault};
use clap::{Parser, Subcommand};

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

fn main() {
    let cli = Cli::parse();
    let mut vault = Vault::new();

    match cli.command {
        Command::Add {
            title,
            username,
            password,
            url,
        } => {
            if vault.add(Entry::new(
                &title,
                &username,
                &password,
                &url.unwrap_or_default(),
            )) {
                println!("Entrée « {title} » ajoutée");
            } else {
                println!("Une entrée « {title} » existe déjà");
            }
        }
        Command::List => {
            if vault.list().is_empty() {
                println!("Le coffre est vide");
            }
            for entry in vault.list() {
                println!("- {} ({})", entry.title, entry.username);
            }
        }
        Command::Get { title } => match vault.get(&title) {
            Some(entry) => println!("{} : {} / {}", entry.title, entry.username, entry.password),
            None => println!("Aucune entrée « {title} »"),
        },
        Command::Remove { title } => match vault.remove(&title) {
            Some(_) => println!("Entrée « {title} » supprimée"),
            None => println!("Aucune entrée « {title} »"),
        },
    }
}
