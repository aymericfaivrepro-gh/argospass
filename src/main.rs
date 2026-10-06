use argospass::{Entry, Vault};
use clap::{Parser, Subcommand};
use std::io;
use std::path::Path;

/// Vault file location (in the current directory for now).
const VAULT_PATH: &str = "vault.json";
/// ArgosPass: password manager.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Add an entry
    Add {
        /// Entry title (e.g. Gmail)
        title: String,
        /// Username or email address
        username: String,
        /// Service URL (optional)
        url: Option<String>,
    },
    /// List entries
    List,
    /// Show an entry
    Get {
        /// Entry title
        title: String,
    },
    /// Remove an entry
    Remove {
        /// Entry title
        title: String,
    },
}

fn prompt_confirmed_password() -> io::Result<Option<String>> {
    let password = rpassword::prompt_password("Password: ")?;
    let confirmation = rpassword::prompt_password("Confirm password: ")?;

    if password != confirmation {
        eprintln!("Passwords do not match; entry was not added.");
        return Ok(None);
    }

    Ok(Some(password))
}

fn main() -> io::Result<()> {
    let cli = Cli::parse();
    let path = Path::new(VAULT_PATH);
    let mut vault = Vault::load(path)?;

    match cli.command {
        Command::Add {
            title,
            username,
            url,
        } => {
            let Some(password) = prompt_confirmed_password()? else {
                return Ok(());
            };

            if vault.add(Entry::new(&title, &username, &password, url.as_deref())) {
                vault.save(path)?;
                println!("Entry '{title}' added");
            } else {
                println!("An entry titled '{title}' already exists");
            }
        }
        Command::List => {
            if vault.list().is_empty() {
                println!("No entries found.");
            } else {
                println!("Entries:");
                for entry in vault.list() {
                    println!("- {} ({})", entry.title, entry.username);
                }
            }
        }
        Command::Get { title } => match vault.get(&title) {
            Some(entry) => {
                println!("Title: {}", entry.title);
                println!("Username: {}", entry.username);
                println!("Password: {}", entry.password);
                if let Some(url) = entry.url.as_deref().filter(|url| !url.is_empty()) {
                    println!("URL: {url}");
                }
            }
            None => println!("No entry titled '{title}' was found"),
        },
        Command::Remove { title } => match vault.remove(&title) {
            Some(_) => {
                vault.save(path)?;
                println!("Entry '{title}' removed");
            }
            None => println!("No entry titled '{title}' was found"),
        },
    }

    Ok(())
}
