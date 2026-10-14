use argospass::crypto::VaultKey;
use argospass::generator::{self, generate_password};
use argospass::{Entry, Error, Vault};
use clap::{Parser, Subcommand};
use log::{LevelFilter, debug, info};
use std::fs;
use std::io::{self, Write};
use std::iter;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::thread;
use std::time::Duration;
use zeroize::Zeroizing;

/// Any error: from the library (`argospass::Error`) or from the application.
type AppResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// How long a copied password stays in the clipboard, in seconds.
const CLIPBOARD_TIMEOUT_SECS: u64 = 20;

/// Number of master password attempts before giving up.
const MAX_PASSWORD_ATTEMPTS: u32 = 3;

// Exit codes, so that scripts can tell failures apart.
const EXIT_FAILURE: u8 = 1;
/// Also returned by clap itself for invalid arguments.
const EXIT_USAGE: u8 = 2;
const EXIT_DECRYPTION_FAILED: u8 = 3;
const EXIT_INVALID_VAULT: u8 = 4;
const EXIT_IO: u8 = 5;
const EXIT_ENTRY_NOT_FOUND: u8 = 6;
const EXIT_ENTRY_EXISTS: u8 = 7;

const EXIT_STATUS_HELP: &str = "\
Exit status:
  0  success
  1  other error
  2  invalid command-line usage
  3  wrong master password, or corrupted vault
  4  invalid or unsupported vault file
  5  input/output error
  6  no entry with this title
  7  an entry with this title already exists";

/// ArgosPass: a command-line password manager.
#[derive(Parser)]
#[command(version, about, after_help = EXIT_STATUS_HELP)]
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
    /// Change the master password
    Passwd {
        /// Also generate a new data key (use it if the old password may have leaked)
        #[arg(long)]
        rotate_key: bool,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            report(&*error);
            ExitCode::from(exit_code(&*error))
        }
    }
}

/// Prints `error` on stderr, followed by the errors that caused it.
fn report(error: &dyn std::error::Error) {
    eprint!("Error: {error}");
    for cause in iter::successors(error.source(), |e| e.source()) {
        eprint!(": {cause}");
    }
    eprintln!();
}

/// Chooses the exit code according to what failed.
fn exit_code(error: &(dyn std::error::Error + 'static)) -> u8 {
    if let Some(error) = error.downcast_ref::<Error>() {
        // No `_` arm: a new variant must be given an exit code.
        return match error {
            Error::DecryptionFailed => EXIT_DECRYPTION_FAILED,
            Error::Truncated
            | Error::BadMagic
            | Error::UnsupportedVersion(_)
            | Error::UnsupportedKdfParams(_)
            | Error::Json(_) => EXIT_INVALID_VAULT,
            Error::Io(_) => EXIT_IO,
            Error::PasswordTooShort { .. } => EXIT_USAGE,
            Error::EntryNotFound(_) => EXIT_ENTRY_NOT_FOUND,
            Error::EntryAlreadyExists(_) => EXIT_ENTRY_EXISTS,
            Error::EncryptionFailed | Error::KeyDerivation(_) | Error::Random(_) => EXIT_FAILURE,
        };
    }
    if error.is::<io::Error>() {
        EXIT_IO
    } else {
        EXIT_FAILURE
    }
}

fn run() -> AppResult {
    let cli = Cli::parse();
    let path = match cli.vault {
        Some(path) => path,
        None => default_vault_path()?,
    };
    init_logging(cli.verbose);
    info!("vault path: {}", path.display());

    match cli.command {
        Command::Init => init(&path),
        Command::Passwd { rotate_key } => change_password(&path, rotate_key),
        Command::Generate { length, no_symbols } => {
            println!("{}", *generate_password(length, !no_symbols)?);
            Ok(())
        }
        command => execute(&path, command),
    }
}

/// Returns the default vault location inside the user's data directory.
fn default_vault_path() -> AppResult<PathBuf> {
    let data_dir = dirs::data_dir().ok_or("cannot determine the user data directory")?;
    Ok(data_dir.join("argospass").join("vault.argos"))
}

/// Creates a new vault protected by a new master password.
fn init(path: &Path) -> AppResult {
    if path.exists() {
        return Err("a vault already exists".into());
    }

    let password = ask_new_password("New master password: ")?;
    if let Some(parent) = path.parent() {
        create_private_dir(parent)?;
    }
    let key = VaultKey::new(&password)?;
    Vault::new().save(path, &key)?;
    println!("Vault created at {}", path.display());
    Ok(())
}

/// Changes the master password. With `rotate_key`, also replaces the data key.
fn change_password(path: &Path, rotate_key: bool) -> AppResult {
    require_vault(path)?;
    let (vault, key) = unlock(path)?;

    if rotate_key {
        eprintln!("Choose the new master password (it may be the current one).");
    } else {
        eprintln!("Choose the new master password.");
    }
    let new_password = ask_new_password("New master password: ")?;

    // Without a new data key, keeping the same password would change nothing.
    // The current password is not kept in memory: a new password equal to it
    // is recognized because it opens the current envelope.
    if !rotate_key && key.opens_with(&new_password)? {
        return Err("the new password must be different from the current one".into());
    }

    let new_key = if rotate_key {
        info!("generating a new data key");
        drop(key); // wipes the old data key now
        VaultKey::new(&new_password)?
    } else {
        key.rewrap(&new_password)?
    };
    vault.save_and_replace_backup(path, &new_key)?;

    if rotate_key {
        // The password may be unchanged: do not claim it was changed.
        println!("Master password set and data key replaced.");
    } else {
        println!("Master password changed.");
    }
    eprintln!(
        "Copies of the vault made before this change (cloud history, other backups) \
         still open with the old password."
    );
    if !rotate_key {
        eprintln!("If the old password may have leaked, run `argospass passwd --rotate-key`.");
    }
    Ok(())
}

/// Fails with a helpful message if there is no vault at `path`.
fn require_vault(path: &Path) -> AppResult {
    if !path.exists() {
        let message = format!(
            "no vault found at {}, run `argospass init` first",
            path.display()
        );
        return Err(message.into());
    }
    Ok(())
}

/// Unlocks the vault with the master password, then runs the command.
fn execute(path: &Path, command: Command) -> AppResult {
    require_vault(path)?;
    let (mut vault, key) = unlock(path)?;

    match command {
        Command::Init | Command::Generate { .. } | Command::Passwd { .. } => {
            unreachable!("handled in run()")
        }
        Command::Add {
            title,
            username,
            url,
            generate,
        } => {
            let password = if generate {
                generate_password(generator::DEFAULT_LENGTH, true)?
            } else {
                ask_new_password("Entry password: ")?
            };

            vault.add(Entry::new(&title, &username, &password, url.as_deref()))?;
            vault.save(path, &key)?;
            println!("Entry \"{title}\" added");
            if generate {
                copy_temporarily(&password)?;
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
        Command::Get { title, show } => {
            let entry = vault.get(&title)?;
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
        Command::Remove { title } => {
            vault.remove(&title)?;
            vault.save(path, &key)?;
            println!("Entry \"{title}\" removed");
        }
    }

    Ok(())
}

/// Prompts for the master password and opens the vault.
/// After a wrong password, asks again, up to `MAX_PASSWORD_ATTEMPTS` times.
fn unlock(path: &Path) -> AppResult<(Vault, VaultKey)> {
    let mut attempts_left = MAX_PASSWORD_ATTEMPTS;
    loop {
        let master_password = Zeroizing::new(rpassword::prompt_password("Master password: ")?);
        match Vault::open(path, &master_password) {
            Err(Error::DecryptionFailed) if attempts_left > 1 => {
                attempts_left -= 1;
                let plural = if attempts_left == 1 { "" } else { "s" };
                eprintln!(
                    "Wrong master password (or corrupted vault): \
                     {attempts_left} attempt{plural} left."
                );
            }
            result => return Ok(result?),
        }
    }
}

/// Prompts twice for a new password with hidden input.
/// Fails if the password is empty or the two inputs differ.
fn ask_new_password(prompt: &str) -> AppResult<Zeroizing<String>> {
    let password = Zeroizing::new(rpassword::prompt_password(prompt)?);
    let confirmation = Zeroizing::new(rpassword::prompt_password("Confirm: ")?);

    if password.is_empty() || *password != *confirmation {
        return Err("passwords are empty or do not match".into());
    }
    Ok(password)
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
fn copy_temporarily(secret: &str) -> AppResult {
    let mut clipboard = arboard::Clipboard::new()?;
    clipboard.set_text(secret)?;

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

    // The text read back may be the password: wipe it too.
    let still_ours = clipboard
        .get_text()
        .is_ok_and(|current| *Zeroizing::new(current) == secret);
    if still_ours {
        debug!("clipboard still contains the password: overwriting it");
        // Overwrite rather than clear: more reliable across clipboard bridges such as WSLg.
        clipboard.set_text("")?;
        println!("Clipboard cleared.");
    }
    Ok(())
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
