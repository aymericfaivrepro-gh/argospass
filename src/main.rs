use argospass::crypto::VaultKey;
use argospass::generator::{self, generate_password};
use argospass::{Entry, Vault};
use clap::{Parser, Subcommand};
use log::{LevelFilter, debug, info};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

/// How long a copied password stays in the clipboard, in seconds.
const CLIPBOARD_TIMEOUT_SECS: u64 = 20;

/// ArgosPass: a command-line password manager.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Path to the vault file [default: <user data dir>/argospass/vault.argos]
    #[arg(long, global = true, env = "ARGOSPASS_VAULT")]
    vault: Option<PathBuf>,

    /// Explain what happens on stderr (-v: main steps, -vv: technical details)
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

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
        /// Generate a random password instead of typing one
        #[arg(short, long)]
        generate: bool,
    },
    /// Generate a random password (does not need the vault)
    Generate {
        /// Password length
        #[arg(short, long, default_value_t = generator::DEFAULT_LENGTH)]
        length: usize,
        /// Use only letters and digits
        #[arg(long)]
        no_symbols: bool,
    },
    /// List entries
    List,
    /// Show an entry and copy its password to the clipboard
    Get {
        /// Entry title
        title: String,
        /// Print the password instead of copying it
        #[arg(long)]
        show: bool,
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
    let path = match cli.vault {
        Some(path) => path,
        None => default_vault_path()?,
    };
    init_logging(cli.verbose);
    info!("vault path: {}", path.display());

    match cli.command {
        Command::Init => init(&path),
        Command::Generate { length, no_symbols } => {
            println!("{}", generate_password(length, !no_symbols)?);
            Ok(())
        }
        command => execute(&path, command),
    }
}

/// Returns the default vault location inside the user's data directory.
fn default_vault_path() -> io::Result<PathBuf> {
    let data_dir = dirs::data_dir().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "cannot determine the user data directory",
        )
    })?;
    Ok(data_dir.join("argospass").join("vault.argos"))
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
    if let Some(parent) = path.parent() {
        create_private_dir(parent)?;
    }
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
            format!(
                "no vault found at {}, run `argospass init` first",
                path.display()
            ),
        ));
    }

    let master_password = rpassword::prompt_password("Master password: ")?;
    let (mut vault, key) = Vault::open(path, &master_password)?;

    match command {
        Command::Init | Command::Generate { .. } => unreachable!("handled in run()"),
        Command::Add {
            title,
            username,
            url,
            generate,
        } => {
            let password = if generate {
                generate_password(generator::DEFAULT_LENGTH, true)?
            } else {
                let Some(password) = ask_new_password("Entry password: ")? else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "passwords are empty or do not match",
                    ));
                };
                password
            };

            if vault.add(Entry::new(&title, &username, &password, url.as_deref())) {
                vault.save(path, &key)?;
                println!("Entry \"{title}\" added");
                if generate {
                    copy_temporarily(&password)?;
                }
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
        Command::Get { title, show } => match vault.get(&title) {
            Some(entry) => {
                println!("Title: {}", entry.title);
                println!("Username: {}", entry.username);
                if let Some(url) = entry.url.as_deref().filter(|url| !url.is_empty()) {
                    println!("URL: {url}");
                }
                if show {
                    println!("Password: {}", entry.password);
                } else {
                    copy_temporarily(&entry.password)?;
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
/// Creates `dir` and its parents if needed.
/// On Unix, newly created directories are restricted to the owner (`700`).
fn create_private_dir(dir: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)
}

/// Copies `secret` to the clipboard, waits, then clears it.
///
/// The clipboard is only cleared if it still contains `secret`,
/// so that anything copied by the user in the meantime is preserved.
fn copy_temporarily(secret: &str) -> io::Result<()> {
    let mut clipboard = arboard::Clipboard::new().map_err(clipboard_error)?;
    clipboard.set_text(secret).map_err(clipboard_error)?;

    eprintln!(
        "Warning: if you interrupt this command (Ctrl+C) or a clipboard history is enabled, \
         the password may remain in memory."
    );
    // On Linux, the clipboard content lives in this process: it must stay alive
    // until the user has pasted the password.
    // Pad the number so that "9 s" fully overwrites "10 s" on the same line.
    debug!("waiting {CLIPBOARD_TIMEOUT_SECS} s so the password can be pasted");
    let width = CLIPBOARD_TIMEOUT_SECS.to_string().len();
    for remaining in (1..=CLIPBOARD_TIMEOUT_SECS).rev() {
        print!("\rPassword copied to the clipboard. Clearing in {remaining:>width$} s...");
        io::stdout().flush()?;
        thread::sleep(Duration::from_secs(1));
    }
    println!();

    if clipboard.get_text().is_ok_and(|current| current == secret) {
        debug!("clipboard still contains the password: overwriting it");
        // Overwrite rather than clear: more reliable across clipboard bridges such as WSLg.
        clipboard.set_text("").map_err(clipboard_error)?;
        println!("Clipboard cleared.");
    }
    Ok(())
}

/// Converts a clipboard error into an I/O error.
fn clipboard_error(e: arboard::Error) -> io::Error {
    io::Error::other(format!("clipboard error: {e}"))
}

/// Configures logging on stderr according to the number of `-v` flags.
fn init_logging(verbosity: u8) {
    let level = match verbosity {
        0 => LevelFilter::Warn,
        1 => LevelFilter::Info,
        _ => LevelFilter::Debug,
    };

    env_logger::Builder::new()
        // Dependencies (clipboard, etc.) only show warnings...
        .filter_level(LevelFilter::Warn)
        // ...while our own crate follows the requested level.
        .filter_module("argospass", level)
        .format(|buf, record| writeln!(buf, "[{:<5}] {}", record.level(), record.args()))
        .init();
}
