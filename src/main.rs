use argospass::crypto::VaultKey;
use argospass::format::FORMAT_VERSION;
use argospass::generator::{self, generate_password};
use argospass::pepper::{Installed, PEPPER_ID_LEN, Pepper, recovery_code_is_complete, short_id};
use argospass::{Error, Vault, VaultLock, create_private_dir, vault_files, vault_pepper_id};
use clap::{Parser, Subcommand};
use log::{LevelFilter, debug, info};
use std::fmt::{self, Write as _};
use std::fs;
use std::io::{self, IsTerminal, Read, Write};
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

/// Minimum length of a new master password, in characters. The pepper does not
/// help against someone who gets both files (a backup of the whole directory):
/// the master password is then all that protects the vault.
const MIN_MASTER_PASSWORD_CHARS: usize = 12;

/// Largest input accepted from stdin by `pepper import`: far more than a
/// recovery code (99 characters) needs, whatever spaces or line breaks
/// surround it.
const MAX_RECOVERY_INPUT: usize = 4096;

// Exit codes, so that scripts can tell failures apart.
const EXIT_FAILURE: u8 = 1;
/// Also returned by clap itself for invalid arguments.
const EXIT_USAGE: u8 = 2;
const EXIT_DECRYPTION_FAILED: u8 = 3;
const EXIT_INVALID_VAULT: u8 = 4;
const EXIT_IO: u8 = 5;
const EXIT_ENTRY_NOT_FOUND: u8 = 6;
const EXIT_ENTRY_EXISTS: u8 = 7;
const EXIT_PEPPER: u8 = 8;
const EXIT_RECOVERY_CODE: u8 = 9;

const EXIT_STATUS_HELP: &str = "\
Exit status:
  0  success
  1  other error
  2  invalid command-line usage
  3  wrong master password, or corrupted vault
  4  invalid or unsupported vault file
  5  input/output error
  6  no entry with this title
  7  an entry with this title already exists
  8  pepper file missing, invalid, not the one of this vault, or in the way of an import
  9  invalid pepper recovery code";

/// ArgosPass: a command-line password manager.
#[derive(Parser)]
#[command(version, about, after_help = EXIT_STATUS_HELP)]
struct Cli {
    /// Path to the vault file [default: <user data dir>/argospass/vault.argos]
    #[arg(long, global = true, env = "ARGOSPASS_VAULT")]
    vault: Option<PathBuf>,

    /// Path to the pepper file [default: <user local data dir>/argospass/pepper.key]
    #[arg(long, global = true, env = "ARGOSPASS_PEPPER")]
    pepper: Option<PathBuf>,

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
    /// Check, back up or restore the pepper file (no master password needed)
    ///
    /// Every vault needs the pepper file, in addition to the master password.
    /// `export` prints the pepper as a recovery code to write down, and
    /// `import` rebuilds the pepper file from that code: after losing it, or
    /// on a second computer.
    Pepper {
        #[command(subcommand)]
        command: PepperCommand,
    },
}

#[derive(Subcommand)]
enum PepperCommand {
    /// Show the pepper file, its id, and whether it matches the vault
    Status,
    /// Print the pepper as a recovery code, to write down or move to another computer
    ///
    /// The code is printed on stdout and IS the pepper: keep it on paper or
    /// offline media, apart from the vault, never in a cloud drive, an e-mail,
    /// a chat or a screenshot.
    Export,
    /// Rebuild the pepper file from its recovery code
    ///
    /// The code is read from stdin when it is redirected
    /// (`argospass pepper import < code.txt`), and otherwise typed or pasted
    /// with hidden input: a code on several lines is read until it is complete,
    /// or until an empty line. Spaces, line breaks and letter case do not
    /// matter. An existing pepper file is never overwritten.
    Import,
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

/// Prints `error` on stderr, followed by the errors that caused it and, for
/// some errors, a hint on how to fix it.
fn report(error: &(dyn std::error::Error + 'static)) {
    eprint!("Error: {error}");
    for cause in iter::successors(error.source(), |e| e.source()) {
        eprint!(": {cause}");
    }
    eprintln!();
    if let Some(hint) = hint(error) {
        eprintln!("Hint: {hint}");
    }
}

/// Suggests how to fix some errors.
fn hint(error: &(dyn std::error::Error + 'static)) -> Option<&'static str> {
    match error.downcast_ref::<Error>()? {
        Error::PepperMismatch { .. } => Some(
            "this vault was created with another pepper: point to the right file \
             with --pepper <PATH> (or ARGOSPASS_PEPPER)",
        ),
        Error::PepperMissing(_) => Some(
            "this vault cannot be opened without the pepper file it was created with: \
             restore it from your backup, or point to it with --pepper <PATH> \
             (or ARGOSPASS_PEPPER)",
        ),
        Error::InvalidPepper { .. } => Some(
            "this is not an ArgosPass pepper file, or it is damaged: restore it from your backup",
        ),
        Error::DifferentPepperExists { .. } => Some(
            "it was not overwritten: the vaults created with it could no longer be opened. \
             If you really want to replace it, first move it elsewhere yourself (and keep it \
             until you are sure no vault needs it), or install the new pepper at another \
             path with --pepper <PATH>",
        ),
        Error::InvalidRecoveryCode(_) => Some(
            "check the code against your copy: it is the line printed by \
             `argospass pepper export`; spaces, line breaks and letter case do not matter",
        ),
        Error::UnsupportedVersion(version) if *version < FORMAT_VERSION => Some(
            "this vault is in an older format, which ArgosPass no longer opens \
             (see \"Older formats\" in the README to convert it); it was left as it is",
        ),
        Error::UnsupportedVersion(_) => {
            Some("this vault was written by a newer version of ArgosPass: update ArgosPass")
        }
        Error::BadMagic => Some(
            "the vaults of the first versions of ArgosPass, without a header, are no longer \
             opened: see \"Older formats\" in the README",
        ),
        Error::BackupNotReplaced { .. } => Some(
            "the vault itself was saved (after `passwd`, with the new master password). Its \
             backup still holds the previous version, which opens with the old password: \
             delete it yourself",
        ),
        _ => None,
    }
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
            | Error::VaultTooLarge(_)
            | Error::UnsupportedKdfParams(_)
            | Error::Json { .. } => EXIT_INVALID_VAULT,
            Error::Io(_) | Error::BackupNotReplaced { .. } => EXIT_IO,
            Error::PasswordTooShort { .. } | Error::PasswordTooLong { .. } => EXIT_USAGE,
            Error::EntryNotFound(_) => EXIT_ENTRY_NOT_FOUND,
            Error::EntryAlreadyExists(_) => EXIT_ENTRY_EXISTS,
            Error::PepperMissing(_)
            | Error::InvalidPepper { .. }
            | Error::PepperMismatch { .. }
            | Error::DifferentPepperExists { .. } => EXIT_PEPPER,
            Error::InvalidRecoveryCode(_) => EXIT_RECOVERY_CODE,
            Error::EncryptionFailed
            | Error::KeyDerivation(_)
            | Error::SubkeyDerivation
            | Error::FieldNameTooLong(_)
            | Error::Random(_)
            | Error::VaultBusy => EXIT_FAILURE,
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
    init_logging(cli.verbose);
    // Needs neither the vault nor the pepper.
    if let Command::Generate { length, no_symbols } = cli.command {
        println!("{}", *generate_password(length, !no_symbols)?);
        return Ok(());
    }

    let paths = Paths {
        vault: match cli.vault {
            Some(path) => path,
            None => default_vault_path()?,
        },
        pepper: match cli.pepper {
            Some(path) => path,
            None => default_pepper_path()?,
        },
    };
    info!("vault path: {}", paths.vault.display());
    info!("pepper path: {}", paths.pepper.display());
    check_paths(&paths)?;

    match cli.command {
        Command::Init => init(&paths),
        Command::Passwd { rotate_key } => change_password(&paths, rotate_key),
        Command::Pepper { command } => match command {
            PepperCommand::Status => pepper_status(&paths),
            PepperCommand::Export => export_pepper(&paths),
            PepperCommand::Import => import_pepper(&paths),
        },
        command => execute(&paths, command),
    }
}

/// Files a command works on.
struct Paths {
    vault: PathBuf,
    pepper: PathBuf,
}

/// Returns the default vault location inside the user's data directory.
fn default_vault_path() -> AppResult<PathBuf> {
    let data_dir = dirs::data_dir().ok_or("cannot determine the user data directory")?;
    Ok(data_dir.join("argospass").join("vault.argos"))
}

/// Returns the default pepper location inside the user's *local* data
/// directory: on Windows, `%LOCALAPPDATA%`, which roaming profiles do not sync
/// (unlike `%APPDATA%`, where the vault is).
fn default_pepper_path() -> AppResult<PathBuf> {
    let dir = dirs::data_local_dir().ok_or("cannot determine the user local data directory")?;
    Ok(dir.join("argospass").join("pepper.key"))
}

/// Fails if the pepper file is one of the files written for the vault (the
/// vault itself, its backup, their temporary files, its lock): saving the
/// vault would overwrite the pepper, and the vault could never be opened
/// again. Checked before anything is read or written.
fn check_paths(paths: &Paths) -> AppResult {
    let pepper = comparable(&paths.pepper)?;
    for file in vault_files(&paths.vault) {
        if comparable(&file)? == pepper {
            let message = format!(
                "the pepper path {} is also used for the vault ({}): choose another path \
                 for the pepper",
                paths.pepper.display(),
                file.display()
            );
            return Err(message.into());
        }
    }
    Ok(())
}

/// Returns `path` in a form that can be compared with another path: absolute,
/// with `..` and symbolic links resolved as far as the file exists, or else
/// its directory.
fn comparable(path: &Path) -> io::Result<PathBuf> {
    if let Ok(resolved) = fs::canonicalize(path) {
        return Ok(resolved);
    }
    let path = std::path::absolute(path)?;
    if let (Some(dir), Some(name)) = (path.parent(), path.file_name())
        && let Ok(dir) = fs::canonicalize(dir)
    {
        return Ok(dir.join(name));
    }
    Ok(path)
}

/// Creates a new vault protected by a new master password and the pepper.
fn init(paths: &Paths) -> AppResult {
    let path = paths.vault.as_path();
    if path.exists() {
        return Err("a vault already exists".into());
    }

    let password = ask_new_master_password()?;
    // Created (and on disk) before the vault, which cannot be opened without it.
    let pepper = match Pepper::load(&paths.pepper) {
        Ok(pepper) => {
            info!("reusing the existing pepper {}", paths.pepper.display());
            pepper
        }
        Err(Error::PepperMissing(_)) => create_pepper(&paths.pepper)?,
        Err(error) => return Err(error.into()),
    };
    if let Some(parent) = path.parent() {
        create_private_dir(parent)?;
    }
    let key = VaultKey::new(&password, &pepper)?;

    // Checked again right before writing, under the lock: a vault may have
    // appeared while the password was typed (another command, a synced folder).
    let _lock = VaultLock::acquire(path)?;
    if path.exists() {
        return Err("a vault already exists".into());
    }
    Vault::new().save(path, &key)?;
    println!("Vault created at {}", path.display());
    Ok(())
}

/// Creates a new pepper file and tells the user, very visibly, to back it up.
fn create_pepper(path: &Path) -> AppResult<Pepper> {
    let pepper = Pepper::create(path)?;
    eprintln!(
        "\n\
         ************************************************************************\n\
         * A new PEPPER FILE was created: {}\n\
         *\n\
         * The vault CANNOT BE OPENED WITHOUT IT, even with the right master\n\
         * password. Back it up now, SEPARATELY FROM THE VAULT (for example on a\n\
         * USB key, or in another password manager), and never keep it next to\n\
         * the vault in a synced folder (cloud drive, shared backup).\n\
         *\n\
         * To write it down on paper instead: `argospass pepper export`.\n\
         ************************************************************************\n",
        path.display()
    );
    Ok(pepper)
}

/// Loads the pepper of an existing vault.
///
/// The vault header is read first, so that a vault in another format is
/// reported as such, whatever the state of the pepper file. Then the pepper
/// must be the one the vault was created with: this is checked here, before
/// the master password is asked for, from the header alone. The id read here
/// is not authenticated yet, and the file may change before it is opened:
/// [`Vault::open`] checks it again, and the envelope's tag covers it.
fn pepper_for_vault(paths: &Paths) -> AppResult<Pepper> {
    let expected = vault_pepper_id(&paths.vault)?;
    let pepper = Pepper::load(&paths.pepper)?;
    let found = pepper.id();
    if found != expected {
        return Err(Error::PepperMismatch { expected, found }.into());
    }
    Ok(pepper)
}

/// Changes the master password. With `rotate_key`, also replaces the data key.
fn change_password(paths: &Paths, rotate_key: bool) -> AppResult {
    let path = paths.vault.as_path();
    require_vault(path)?;
    let pepper = pepper_for_vault(paths)?;
    // Held until the new version is saved.
    let _lock = VaultLock::acquire(path)?;
    let (mut vault, key) = unlock(path, &pepper)?;

    if rotate_key {
        eprintln!("Choose the new master password (it may be the current one).");
    } else {
        eprintln!("Choose the new master password.");
    }
    let new_password = ask_new_master_password()?;

    // Without a new data key, keeping the same password would change nothing.
    // The current password is not kept in memory: a new password equal to it
    // is recognized because it opens the current envelope.
    if !rotate_key && key.opens_with(&new_password, &pepper)? {
        return Err("the new password must be different from the current one".into());
    }

    let new_key = if rotate_key {
        // Every password is encrypted again with the new field key, before
        // anything is written: if one fails to open, the vault is unchanged.
        vault.rotate_key(key, &new_password, &pepper)?
    } else {
        // Same data key, so same field key: the passwords stay as they are.
        key.rewrap(&new_password, &pepper)?
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

/// Shows the pepper file, its id, and whether the vault can be opened with it.
/// Only public data is read and shown: never the pepper, and the vault is not
/// decrypted.
fn pepper_status(paths: &Paths) -> AppResult {
    let pepper_id = match Pepper::load(&paths.pepper) {
        Ok(pepper) => Some(pepper.id()),
        Err(Error::PepperMissing(_)) => None,
        Err(error) => return Err(error.into()),
    };

    match &pepper_id {
        Some(id) => {
            println!("Pepper file: {}", paths.pepper.display());
            println!("Pepper id:   {}", short_id(id));
        }
        None => println!("Pepper file: {} (not found)", paths.pepper.display()),
    }
    match vault_status(&paths.vault, pepper_id.as_ref())? {
        Some(status) => {
            println!("Vault file:  {}", paths.vault.display());
            println!("Status:      {status}");
        }
        None => println!("Vault file:  {} (not found)", paths.vault.display()),
    }
    Ok(())
}

/// Tells whether the vault at `path` can be opened with the pepper whose id is
/// `pepper_id` (`None`: there is no pepper file). Returns `None` if there is no
/// vault. Only the vault header is read.
fn vault_status(path: &Path, pepper_id: Option<&[u8; PEPPER_ID_LEN]>) -> AppResult<Option<String>> {
    if !path.exists() {
        return Ok(None);
    }
    let expected = vault_pepper_id(path)?;
    let status = match pepper_id {
        Some(found) if *found == expected => "the pepper matches this vault".to_string(),
        Some(_) => format!(
            "the pepper does NOT match this vault, which needs pepper {}",
            short_id(&expected)
        ),
        None => format!(
            "this vault needs pepper {}, and there is no pepper file",
            short_id(&expected)
        ),
    };
    Ok(Some(status))
}

/// Prints the pepper as a recovery code on stdout, and on stderr what it is
/// and how to keep it.
fn export_pepper(paths: &Paths) -> AppResult {
    let pepper = Pepper::load(&paths.pepper)?;
    let code = pepper.to_recovery_code();

    eprintln!(
        "\n\
         ************************************************************************\n\
         * Recovery code of the pepper {} ({}).\n\
         *\n\
         * This code IS THE PEPPER: with it and a copy of the vault, only the\n\
         * master password protects your entries. Keep it on paper or on\n\
         * offline media (a USB key), SEPARATELY FROM THE VAULT. Never put it in\n\
         * a cloud drive (OneDrive...), an e-mail, a chat or a screenshot.\n\
         ************************************************************************\n",
        short_id(&pepper.id()),
        paths.pepper.display()
    );
    println!("{}", *code);
    if io::stdout().is_terminal() {
        eprintln!(
            "\nOnce it is copied, run `clear`, so that it does not stay on screen \
             or in the terminal's scrollback."
        );
    } else {
        eprintln!(
            "The code was written to a file or a pipe, not to the screen: a file holding it \
             is as sensitive as the pepper. Delete it once the code is stored safely."
        );
        warn_if_stdout_readable_by_others()?;
    }
    Ok(())
}

/// Warns if stdout is a file that other users can access (Unix only): a file
/// created by `> code.txt` gets the shell's default permissions, often `644`.
fn warn_if_stdout_readable_by_others() -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::fd::AsFd;
        use std::os::unix::fs::PermissionsExt;

        // A second handle on stdout, only to read its metadata (`fstat`).
        let stdout = std::fs::File::from(io::stdout().as_fd().try_clone_to_owned()?);
        let metadata = stdout.metadata()?;
        let mode = metadata.permissions().mode() & 0o777;
        if metadata.is_file() && mode & 0o077 != 0 {
            eprintln!(
                "Warning: that file is accessible to other users (mode {mode:o}): \
                 run `chmod 600` on it."
            );
        }
    }
    Ok(())
}

/// Rebuilds the pepper file from a recovery code. An existing pepper file is
/// never overwritten.
fn import_pepper(paths: &Paths) -> AppResult {
    let pepper = read_recovery_code()?;
    let id = pepper.id();
    match pepper.install(&paths.pepper)? {
        Installed::Created => println!(
            "Pepper {} installed at {}",
            short_id(&id),
            paths.pepper.display()
        ),
        Installed::AlreadyPresent => println!(
            "Pepper {} is already installed at {}: nothing was written.",
            short_id(&id),
            paths.pepper.display()
        ),
    }
    // Only informative: the pepper is installed whatever happens here.
    match vault_status(&paths.vault, Some(&id)) {
        Ok(Some(status)) => println!("Vault {}: {status}", paths.vault.display()),
        Ok(None) => {}
        Err(error) => eprintln!(
            "Warning: could not check whether the vault {} matches: {error}",
            paths.vault.display()
        ),
    }
    Ok(())
}

/// Reads a recovery code and decodes it: typed with hidden input on a
/// terminal, or read from stdin when it is redirected. Our copies of the input
/// are wiped once decoded.
fn read_recovery_code() -> AppResult<Pepper> {
    if io::stdin().is_terminal() {
        return read_typed_recovery_code();
    }

    // Sized up front so that it never grows: growing would leave unwiped
    // copies of the code behind. One byte more than accepted tells a longer
    // input apart.
    let mut input = Zeroizing::new(Vec::with_capacity(MAX_RECOVERY_INPUT + 1));
    io::stdin()
        .lock()
        .take(MAX_RECOVERY_INPUT as u64 + 1)
        .read_to_end(&mut input)?;
    if input.len() > MAX_RECOVERY_INPUT {
        return Err(Error::InvalidRecoveryCode("the input is too long").into());
    }
    // Borrowed, not copied: `from_utf8` only checks the bytes.
    let code = std::str::from_utf8(&input)
        .map_err(|_| Error::InvalidRecoveryCode("the input is not valid UTF-8 text"))?;
    Ok(Pepper::from_recovery_code(code)?)
}

/// Reads a recovery code typed or pasted on the terminal, with hidden input.
///
/// Each prompt reads a single line, but a code pasted over several lines
/// arrives all at once: lines are read until the code is complete, or until an
/// empty line. A line left unread would go to the shell once ArgosPass exits,
/// and the shell would show it and save it in its history.
fn read_typed_recovery_code() -> AppResult<Pepper> {
    // Sized up front: growing would leave unwiped copies of the code behind.
    // (rpassword's own buffer for each line still grows: see the README.)
    let mut code = Zeroizing::new(String::with_capacity(MAX_RECOVERY_INPUT));
    let mut prompt = "Recovery code: ";
    loop {
        let line = Zeroizing::new(rpassword::prompt_password(prompt)?);
        if line.trim().is_empty() {
            break;
        }
        if code.len() + line.len() + 1 > code.capacity() {
            return Err(Error::InvalidRecoveryCode("the input is too long").into());
        }
        code.push_str(&line);
        code.push('\n');
        if recovery_code_is_complete(&code) {
            break;
        }
        prompt = "Rest of the code (or an empty line to stop): ";
    }
    Ok(Pepper::from_recovery_code(&code)?)
}

/// Unlocks the vault with the master password, then runs the command.
fn execute(paths: &Paths, command: Command) -> AppResult {
    let path = paths.vault.as_path();
    require_vault(path)?;
    let pepper = pepper_for_vault(paths)?;
    // A command that changes the vault holds its lock from reading it to
    // saving it. Reading alone needs none: a save replaces the file in one go.
    let lock = if matches!(command, Command::Add { .. } | Command::Remove { .. }) {
        Some(VaultLock::acquire(path)?)
    } else {
        None
    };
    let (mut vault, key) = unlock(path, &pepper)?;

    match command {
        Command::Init
        | Command::Generate { .. }
        | Command::Passwd { .. }
        | Command::Pepper { .. } => {
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

            // Sealed right away: only the encrypted password is kept in the vault.
            vault.add(&key, &title, &username, &password, url.as_deref())?;
            vault.save(path, &key)?;
            // Saved: no need to keep other commands waiting while the password
            // sits in the clipboard.
            drop(lock);
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
                println!(
                    "- {} ({})",
                    Printable(&entry.title),
                    Printable(&entry.username)
                );
            }
        }
        Command::Get { title, show } => {
            let entry = vault.get(&title)?;
            println!("Title: {}", Printable(&entry.title));
            println!("Username: {}", Printable(&entry.username));
            if let Some(url) = entry.url.as_deref().filter(|url| !url.is_empty()) {
                println!("URL: {}", Printable(url));
            }
            // Only this entry's password is decrypted, and wiped at the end
            // of this block.
            let password = entry.open_password(&key)?;
            if show {
                println!("Password: {}", Printable(&password));
            } else {
                copy_temporarily(&password)?;
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

/// Prompts for the master password and opens the vault with the pepper.
/// After a wrong password, asks again, up to `MAX_PASSWORD_ATTEMPTS` times.
fn unlock(path: &Path, pepper: &Pepper) -> AppResult<(Vault, VaultKey)> {
    let mut attempts_left = MAX_PASSWORD_ATTEMPTS;
    loop {
        let master_password = Zeroizing::new(rpassword::prompt_password("Master password: ")?);
        match Vault::open(path, &master_password, pepper) {
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

/// Prompts twice for a new master password with hidden input. Fails if the
/// two inputs differ, or if it is shorter than `MIN_MASTER_PASSWORD_CHARS`.
fn ask_new_master_password() -> AppResult<Zeroizing<String>> {
    let password = ask_new_password("New master password: ")?;
    check_master_password(&password)?;
    Ok(password)
}

/// Fails if `password` is too short to be a master password. Its length is not
/// shown: it would tell something about the password.
fn check_master_password(password: &str) -> AppResult {
    // Characters, not bytes: "é" counts as one.
    if password.chars().count() < MIN_MASTER_PASSWORD_CHARS {
        let message = format!(
            "the master password must be at least {MIN_MASTER_PASSWORD_CHARS} characters long"
        );
        return Err(message.into());
    }
    Ok(())
}

/// Shows text from the vault with each control character (escape sequence,
/// line break...) replaced by `�`: an entry cannot drive the terminal, by
/// changing its title, writing to the clipboard or hiding text. Writes
/// straight to the output, one character at a time: no copy of the text is
/// made, which matters for a password.
struct Printable<'a>(&'a str);

impl fmt::Display for Printable<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for c in self.0.chars() {
            f.write_char(if c.is_control() {
                char::REPLACEMENT_CHARACTER
            } else {
                c
            })?;
        }
        Ok(())
    }
}

/// Copies `secret` to the clipboard, waits, then clears it.
///
/// The clipboard is left as it is only if it was read back and holds
/// something else: what the user copied in the meantime is preserved. If it
/// cannot be read back, it is cleared all the same, rather than risk leaving
/// the password in it.
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
    let still_ours = match clipboard.get_text() {
        Ok(current) => *Zeroizing::new(current) == secret,
        Err(error) => {
            debug!("could not read the clipboard back ({error}): clearing it all the same");
            true
        }
    };
    if !still_ours {
        println!("The clipboard changed in the meantime: it was left as it is.");
        return Ok(());
    }
    debug!("clipboard may still contain the password: overwriting it");
    // Overwrite rather than clear: more reliable across clipboard bridges such as WSLg.
    clipboard.set_text("").map_err(|error| {
        format!(
            "could not clear the clipboard, which may still hold the password: \
             clear it yourself ({error})"
        )
    })?;
    println!("Clipboard cleared.");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn master_passwords_need_12_characters() {
        assert!(check_master_password("12345678901").is_err());
        assert!(check_master_password("123456789012").is_ok());
        // Counted in characters: 11 accented letters are 22 bytes, but too short.
        assert!(check_master_password(&"é".repeat(11)).is_err());
        assert!(check_master_password(&"é".repeat(12)).is_ok());
    }

    #[test]
    fn control_characters_are_never_printed() {
        // An escape sequence (clear the screen), a line break, a C1 control
        // character (CSI) and DEL.
        let text = "a\u{1b}[2Jb\nc\u{9b}d\u{7f}e";
        assert_eq!(Printable(text).to_string(), "a�[2Jb�c�d�e");
        // Everything else is kept as it is.
        assert_eq!(Printable("Gmail é 🔐").to_string(), "Gmail é 🔐");
    }
}
