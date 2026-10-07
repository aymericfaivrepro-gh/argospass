use argospass::crypto::VaultKey;
use argospass::{Entry, Vault};
use clap::{Parser, Subcommand};
use std::io;
use std::path::Path;
use std::process::ExitCode;

/// Location of the encrypted vault file (current directory for now).
const VAULT_PATH: &str = "vault.argos";

/// ArgosPass: a command-line password manager.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new encrypted vault
    Init,
    /// Add an entry (the password is prompted with hidden input)
    Add {
        /// Entry title (e.g. Gmail)
        title: String,
        /// Username or e-mail
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

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> io::Result<()> {
    let cli = Cli::parse();
    let path = Path::new(VAULT_PATH);

    match cli.command {
        Command::Init => init(path),
        command => execute(path, command),
    }
}

/// Creates a new vault protected by a new master password.
fn init(path: &Path) -> io::Result<()> {
    if path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "a vault already exists",
        ));
    }

    let Some(password) = ask_new_password("New master password: ")? else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "passwords are empty or do not match",
        ));
    };

    let key = VaultKey::new(&password)?;
    Vault::new().save(path, &key)?;
    println!("Vault created at {}", path.display());
    Ok(())
}

/// Unlocks the vault with the master password, then runs the command.
fn execute(path: &Path, command: Command) -> io::Result<()> {
    if !path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no vault found, run `argospass init` first",
        ));
    }

    let master_password = rpassword::prompt_password("Master password: ")?;
    let (mut vault, key) = Vault::open(path, &master_password)?;

    match command {
        Command::Init => unreachable!("init is handled in run()"),
        Command::Add { title, username, url } => {
            let Some(password) = ask_new_password("Entry password: ")? else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "passwords are empty or do not match",
                ));
            };

            if vault.add(Entry::new(&title, &username, &password, url.as_deref())) {
                vault.save(path, &key)?;
                println!("Entry \"{title}\" added");
            } else {
                println!("An entry named \"{title}\" already exists");
            }
        }
        Command::List => {
            if vault.list().is_empty() {
                println!("The vault is empty.");
            }
            for entry in vault.list() {
                println!("- {} ({})", entry.title, entry.username);
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
            None => println!("No entry named \"{title}\""),
        },
        Command::Remove { title } => match vault.remove(&title) {
            Some(_) => {
                vault.save(path, &key)?;
                println!("Entry \"{title}\" removed");
            }
            None => println!("No entry named \"{title}\""),
        },
    }

    Ok(())
}

/// Prompts twice for a new password with hidden input.
/// Returns `None` if the password is empty or the two inputs differ.
fn ask_new_password(prompt: &str) -> io::Result<Option<String>> {
    let password = rpassword::prompt_password(prompt)?;
    let confirmation = rpassword::prompt_password("Confirm: ")?;

    if password.is_empty() || password != confirmation {
        return Ok(None);
    }
    Ok(Some(password))
}