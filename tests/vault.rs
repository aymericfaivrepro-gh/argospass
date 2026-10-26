//! Integration tests: encrypted vault file round-trips.

use argospass::crypto::VaultKey;
use argospass::crypto::{ENVELOPE_LEN, KEY_LEN, KdfParams, SALT_LEN, derive_key, encrypt};
use argospass::format::{HEADER_LEN, HEADER_LEN_V2, MAGIC};
use argospass::pepper::{Installed, PEPPER_ID_LEN, Pepper, short_id};
use argospass::{Entry, Error, Vault, requires_existing_pepper, vault_pepper_id};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// Offset of the pepper id in a v3 header.
const PEPPER_ID_OFFSET: usize = HEADER_LEN - PEPPER_ID_LEN;

/// Returns a path in the system temp directory, unique to each test.
fn temp_vault(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("argospass-test-{name}.argos"))
}

/// Returns the path of a pepper file in the system temp directory, unique to
/// each test, with no file left over by an interrupted run.
fn temp_pepper_path(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("argospass-test-{name}.key"));
    let _ = fs::remove_file(&path);
    path
}

/// Creates a pepper in its own temporary file, unique to each test, and reads
/// it back. The file is deleted right away: the tests only need the pepper.
fn temp_pepper(name: &str) -> Pepper {
    let path = temp_pepper_path(name);
    Pepper::create(&path).expect("pepper creation should succeed");
    let pepper = Pepper::load(&path).expect("pepper should load");
    fs::remove_file(&path).expect("cleanup should succeed");
    pepper
}

#[test]
fn saves_then_opens_encrypted_vault() {
    let path = temp_vault("roundtrip");
    let pepper = temp_pepper("roundtrip");
    let key = VaultKey::new("master", &pepper).expect("key derivation should succeed");

    let mut vault = Vault::new();
    vault
        .add(Entry::new("Gmail", "me@gmail.com", "secret", None))
        .expect("add should succeed");
    vault.save(&path, &key).expect("save should succeed");

    let (opened, _) = Vault::open(&path, "master", &pepper).expect("open should succeed");
    let entry = opened.get("Gmail").expect("entry should exist");
    assert_eq!(entry.password, "secret");

    fs::remove_file(&path).expect("cleanup should succeed");
}

#[test]
fn wrong_master_password_fails_to_open() {
    let path = temp_vault("wrong-password");
    let pepper = temp_pepper("wrong-password");
    let key = VaultKey::new("master", &pepper).expect("key derivation should succeed");
    Vault::new().save(&path, &key).expect("save should succeed");

    // The right pepper with a wrong password: the usual wrong-password error.
    assert!(matches!(
        Vault::open(&path, "not the master", &pepper),
        Err(Error::DecryptionFailed)
    ));

    fs::remove_file(&path).expect("cleanup should succeed");
}

#[test]
fn wrong_pepper_fails_to_open() {
    let path = temp_vault("wrong-pepper");
    let pepper = temp_pepper("wrong-pepper");
    let other = temp_pepper("wrong-pepper-other");
    let key = VaultKey::new("master", &pepper).expect("key derivation should succeed");
    Vault::new().save(&path, &key).expect("save should succeed");

    // Even with the right password, and before any key derivation.
    assert!(matches!(
        Vault::open(&path, "master", &other),
        Err(Error::PepperMismatch { expected, found })
            if expected == pepper.id() && found == other.id()
    ));

    fs::remove_file(&path).expect("cleanup should succeed");
}

#[test]
fn saved_file_does_not_contain_plaintext() {
    let path = temp_vault("no-plaintext");
    let pepper = temp_pepper("no-plaintext");
    let key = VaultKey::new("master", &pepper).expect("key derivation should succeed");

    let mut vault = Vault::new();
    vault
        .add(Entry::new("Gmail", "me@gmail.com", "secret", None))
        .expect("add should succeed");
    vault.save(&path, &key).expect("save should succeed");

    let data = fs::read(&path).expect("read should succeed");
    assert!(!data.windows(6).any(|w| w == b"secret"));
    assert!(!data.windows(5).any(|w| w == b"Gmail"));

    fs::remove_file(&path).expect("cleanup should succeed");
}
#[test]
fn second_save_keeps_previous_version_as_backup() {
    let path = temp_vault("backup");
    let backup = path.with_extension("argos.bak");
    let pepper = temp_pepper("backup");
    let key = VaultKey::new("master", &pepper).expect("key derivation should succeed");

    let mut vault = Vault::new();
    vault
        .add(Entry::new("First", "me", "one", None))
        .expect("add should succeed");
    vault.save(&path, &key).expect("first save should succeed");

    vault
        .add(Entry::new("Second", "me", "two", None))
        .expect("add should succeed");
    vault.save(&path, &key).expect("second save should succeed");

    let (current, _) = Vault::open(&path, "master", &pepper).expect("open should succeed");
    assert_eq!(current.list().len(), 2);

    let (previous, _) = Vault::open(&backup, "master", &pepper).expect("backup should open");
    assert_eq!(previous.list().len(), 1);

    fs::remove_file(&path).expect("cleanup should succeed");
    fs::remove_file(&backup).expect("cleanup should succeed");
}

#[test]
fn save_leaves_no_temporary_file() {
    let path = temp_vault("no-tmp");
    let pepper = temp_pepper("no-tmp");
    let key = VaultKey::new("master", &pepper).expect("key derivation should succeed");
    Vault::new().save(&path, &key).expect("save should succeed");

    assert!(!path.with_extension("argos.tmp").exists());

    fs::remove_file(&path).expect("cleanup should succeed");
}

#[cfg(unix)]
#[test]
fn vault_file_is_readable_by_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let path = temp_vault("permissions");
    let pepper = temp_pepper("permissions");
    let key = VaultKey::new("master", &pepper).expect("key derivation should succeed");
    Vault::new().save(&path, &key).expect("save should succeed");

    let mode = fs::metadata(&path).expect("metadata").permissions().mode();
    assert_eq!(mode & 0o777, 0o600);

    fs::remove_file(&path).expect("cleanup should succeed");
}

#[test]
fn tampered_header_fails_to_open() {
    let path = temp_vault("tampered-header");
    let pepper = temp_pepper("tampered-header");
    let key = VaultKey::new("master", &pepper).expect("key derivation should succeed");
    Vault::new().save(&path, &key).expect("save should succeed");

    let mut data = fs::read(&path).expect("read should succeed");
    data[10] = 4; // iterations: 3 -> 4 (still within the accepted bounds)
    fs::write(&path, &data).expect("write should succeed");

    // The header is authenticated: changing it is detected like a wrong password.
    assert!(matches!(
        Vault::open(&path, "master", &pepper),
        Err(Error::DecryptionFailed)
    ));

    fs::remove_file(&path).expect("cleanup should succeed");
}

#[test]
fn tampered_pepper_id_fails_to_open() {
    let path = temp_vault("tampered-pepper-id");
    let pepper = temp_pepper("tampered-pepper-id");
    let key = VaultKey::new("master", &pepper).expect("key derivation should succeed");
    Vault::new().save(&path, &key).expect("save should succeed");

    let mut data = fs::read(&path).expect("read should succeed");
    data[PEPPER_ID_OFFSET] ^= 0x01;
    fs::write(&path, &data).expect("write should succeed");

    // The id no longer matches the pepper: rejected before any derivation.
    assert!(matches!(
        Vault::open(&path, "master", &pepper),
        Err(Error::PepperMismatch { found, .. }) if found == pepper.id()
    ));

    fs::remove_file(&path).expect("cleanup should succeed");
}

#[test]
fn excessive_kdf_params_are_rejected_before_key_derivation() {
    let path = temp_vault("excessive-params");
    let pepper = temp_pepper("excessive-params");
    let key = VaultKey::new("master", &pepper).expect("key derivation should succeed");
    Vault::new().save(&path, &key).expect("save should succeed");

    let mut data = fs::read(&path).expect("read should succeed");
    data[6..10].copy_from_slice(&u32::MAX.to_le_bytes()); // memory cost: 4 TiB
    fs::write(&path, &data).expect("write should succeed");

    // Rejected from the header alone: Argon2id never tries to allocate 4 TiB.
    assert!(matches!(
        Vault::open(&path, "master", &pepper),
        Err(Error::UnsupportedKdfParams(params)) if params.memory_kib == u32::MAX
    ));

    fs::remove_file(&path).expect("cleanup should succeed");
}

#[test]
fn truncated_vault_fails_to_open() {
    let path = temp_vault("truncated");
    let pepper = temp_pepper("truncated");
    let key = VaultKey::new("master", &pepper).expect("key derivation should succeed");
    Vault::new().save(&path, &key).expect("save should succeed");
    let data = fs::read(&path).expect("read should succeed");

    // Cut in the middle of the header, before or inside the pepper id...
    for len in [10, HEADER_LEN_V2, HEADER_LEN - 1] {
        fs::write(&path, &data[..len]).expect("write should succeed");
        assert!(matches!(
            Vault::open(&path, "master", &pepper),
            Err(Error::Truncated)
        ));
    }

    // ...or right after it, leaving no room for the envelope and the payload.
    fs::write(&path, &data[..HEADER_LEN]).expect("write should succeed");
    assert!(matches!(
        Vault::open(&path, "master", &pepper),
        Err(Error::Truncated)
    ));

    fs::remove_file(&path).expect("cleanup should succeed");
}

#[test]
fn missing_vault_is_an_io_error() {
    let path = temp_vault("missing");
    let pepper = temp_pepper("missing");
    assert!(!path.exists());

    assert!(matches!(
        Vault::open(&path, "master", &pepper),
        Err(Error::Io(e)) if e.kind() == io::ErrorKind::NotFound
    ));
}

#[test]
fn legacy_vault_is_upgraded() {
    let path = temp_vault("legacy");
    let backup = path.with_extension("argos.bak");
    let pepper = temp_pepper("legacy");

    // Build a vault in the pre-v1 layout: salt || nonce || ciphertext || tag.
    let salt = [9u8; SALT_LEN];
    let key = derive_key("master", &salt, &KdfParams::LEGACY, None).expect("derivation");
    let encrypted = encrypt(&key, br#"{"entries":[]}"#, &[]).expect("encryption");
    let mut legacy = salt.to_vec();
    legacy.extend_from_slice(&encrypted);
    fs::write(&path, &legacy).expect("write should succeed");
    assert!(!requires_existing_pepper(&path).expect("read should succeed"));

    let (vault, _) = Vault::open(&path, "master", &pepper).expect("legacy vault should open");
    assert!(vault.list().is_empty());

    let upgraded = fs::read(&path).expect("read should succeed");
    assert!(upgraded.starts_with(MAGIC));
    assert!(Vault::open(&path, "master", &pepper).is_ok());

    fs::remove_file(&path).expect("cleanup should succeed");
    fs::remove_file(&backup).expect("cleanup should succeed");
}

#[test]
fn new_vault_uses_format_v3() {
    let path = temp_vault("format-v3");
    let pepper = temp_pepper("format-v3");
    let key = VaultKey::new("master", &pepper).expect("key derivation should succeed");
    Vault::new().save(&path, &key).expect("save should succeed");

    let data = fs::read(&path).expect("read should succeed");
    assert_eq!(data[5], 3);
    // header 50 + envelope 72 + nonce 24 + `{"entries":[]}` 14 + tag 16
    assert_eq!(data.len(), 176);
    assert_eq!(&data[PEPPER_ID_OFFSET..HEADER_LEN], &pepper.id());
    assert!(requires_existing_pepper(&path).expect("read should succeed"));

    fs::remove_file(&path).expect("cleanup should succeed");
}

#[test]
fn tampered_envelope_is_rejected() {
    let path = temp_vault("tampered-envelope");
    let pepper = temp_pepper("tampered-envelope");
    let key = VaultKey::new("master", &pepper).expect("key derivation should succeed");
    Vault::new().save(&path, &key).expect("save should succeed");

    let mut data = fs::read(&path).expect("read should succeed");
    data[HEADER_LEN + 30] ^= 0x01; // flip one bit of the encrypted data key
    fs::write(&path, &data).expect("write should succeed");

    assert!(matches!(
        Vault::open(&path, "master", &pepper),
        Err(Error::DecryptionFailed)
    ));

    fs::remove_file(&path).expect("cleanup should succeed");
}

/// Builds the header of a format v1 or v2 vault with the weakest accepted
/// parameters, so that the tests stay fast.
fn old_header(version: u8, salt: &[u8; SALT_LEN]) -> Vec<u8> {
    let mut header = MAGIC.to_vec();
    header.push(version);
    header.extend_from_slice(&(64 * 1024u32).to_le_bytes());
    header.extend_from_slice(&3u32.to_le_bytes());
    header.extend_from_slice(&1u32.to_le_bytes());
    header.extend_from_slice(salt);
    assert_eq!(header.len(), HEADER_LEN_V2);
    header
}

/// Checks that an upgraded vault and its backup are in format v3, with the
/// id of `pepper`, and only open with it.
fn assert_upgraded_to_v3(path: &Path, backup: &Path, pepper: &Pepper, other: &Pepper) {
    for file in [path, backup] {
        let data = fs::read(file).expect("read should succeed");
        assert_eq!(data[5], 3);
        assert_eq!(&data[PEPPER_ID_OFFSET..HEADER_LEN], &pepper.id());
        assert!(requires_existing_pepper(file).expect("read should succeed"));

        assert!(Vault::open(file, "master", pepper).is_ok());
        assert!(matches!(
            Vault::open(file, "master", other),
            Err(Error::PepperMismatch { .. })
        ));
    }
}

#[test]
fn v1_vault_is_upgraded_to_v3() {
    let path = temp_vault("v1-upgrade");
    let backup = path.with_extension("argos.bak");
    let pepper = temp_pepper("v1-upgrade");
    let other = temp_pepper("v1-upgrade-other");

    // Build a vault in format v1: header || nonce || ciphertext || tag,
    // encrypted with the Argon2id key itself and the header as AAD.
    let salt = [7u8; SALT_LEN];
    let mut v1 = old_header(1, &salt);
    let key = derive_key("master", &salt, &KdfParams::MINIMUM, None).expect("derivation");
    let encrypted = encrypt(&key, br#"{"entries":[]}"#, &v1).expect("encryption");
    v1.extend_from_slice(&encrypted);
    fs::write(&path, &v1).expect("write should succeed");

    // A wrong password must not upgrade (nor touch) the file.
    assert!(matches!(
        Vault::open(&path, "not the master", &pepper),
        Err(Error::DecryptionFailed)
    ));
    assert_eq!(fs::read(&path).expect("read should succeed"), v1);

    let (vault, _) = Vault::open(&path, "master", &pepper).expect("v1 vault should open");
    assert!(vault.list().is_empty());
    assert_upgraded_to_v3(&path, &backup, &pepper, &other);

    fs::remove_file(&path).expect("cleanup should succeed");
    fs::remove_file(&backup).expect("cleanup should succeed");
}

#[test]
fn v2_vault_is_upgraded_to_v3() {
    let path = temp_vault("v2-upgrade");
    let backup = path.with_extension("argos.bak");
    let pepper = temp_pepper("v2-upgrade");
    let other = temp_pepper("v2-upgrade-other");

    // Build a vault in format v2 (no pepper): header || envelope || payload.
    // The KEK wraps the data key with the header as AAD, and the data key
    // encrypts the JSON with `header || envelope` as AAD.
    let salt = [7u8; SALT_LEN];
    let mut v2 = old_header(2, &salt);
    let kek = derive_key("master", &salt, &KdfParams::MINIMUM, None).expect("derivation");
    let data_key = [5u8; KEY_LEN];
    let envelope = encrypt(&kek, &data_key, &v2).expect("encryption");
    assert_eq!(envelope.len(), ENVELOPE_LEN);
    v2.extend_from_slice(&envelope);
    let json = br#"{"entries":[{"title":"Gmail","username":"me","password":"secret","url":null}]}"#;
    let payload = encrypt(&data_key, json, &v2).expect("encryption");
    v2.extend_from_slice(&payload);
    fs::write(&path, &v2).expect("write should succeed");
    assert!(!requires_existing_pepper(&path).expect("read should succeed"));

    // A wrong password must not upgrade (nor touch) the file.
    assert!(matches!(
        Vault::open(&path, "not the master", &pepper),
        Err(Error::DecryptionFailed)
    ));
    assert_eq!(fs::read(&path).expect("read should succeed"), v2);

    let (vault, _) = Vault::open(&path, "master", &pepper).expect("v2 vault should open");
    let entry = vault.get("Gmail").expect("entry should exist");
    assert_eq!(entry.password, "secret");

    // No copy without the pepper is left: the backup was replaced too.
    assert_upgraded_to_v3(&path, &backup, &pepper, &other);

    fs::remove_file(&path).expect("cleanup should succeed");
    fs::remove_file(&backup).expect("cleanup should succeed");
}

/// Creates a vault protected by "old password" and `pepper` with one entry,
/// and returns the paths of the vault and of its backup.
fn vault_with_old_password(name: &str, pepper: &Pepper) -> (PathBuf, PathBuf) {
    let path = temp_vault(name);
    let backup = path.with_extension("argos.bak");
    let key = VaultKey::new("old password", pepper).expect("key derivation should succeed");

    let mut vault = Vault::new();
    vault
        .add(Entry::new("Gmail", "me@gmail.com", "secret", None))
        .expect("add should succeed");
    vault.save(&path, &key).expect("save should succeed");
    (path, backup)
}

#[test]
fn password_change() {
    let pepper = temp_pepper("passwd");
    let (path, backup) = vault_with_old_password("passwd", &pepper);

    let (vault, key) = Vault::open(&path, "old password", &pepper).expect("open should succeed");
    let new_key = key
        .rewrap("new password", &pepper)
        .expect("rewrap should succeed");
    vault
        .save_and_replace_backup(&path, &new_key)
        .expect("save should succeed");

    let (opened, _) =
        Vault::open(&path, "new password", &pepper).expect("new password should open");
    let entry = opened.get("Gmail").expect("entry should exist");
    assert_eq!(entry.password, "secret");
    assert!(matches!(
        Vault::open(&path, "old password", &pepper),
        Err(Error::DecryptionFailed)
    ));

    // The backup no longer holds the vault under the old password.
    assert!(matches!(
        Vault::open(&backup, "old password", &pepper),
        Err(Error::DecryptionFailed)
    ));
    assert!(Vault::open(&backup, "new password", &pepper).is_ok());

    // The vault still uses the same pepper.
    let data = fs::read(&path).expect("read should succeed");
    assert_eq!(&data[PEPPER_ID_OFFSET..HEADER_LEN], &pepper.id());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&backup)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    fs::remove_file(&path).expect("cleanup should succeed");
    fs::remove_file(&backup).expect("cleanup should succeed");
}

#[test]
fn password_change_with_key_rotation() {
    let pepper = temp_pepper("passwd-rotate");
    let (path, backup) = vault_with_old_password("passwd-rotate", &pepper);

    let (vault, _) = Vault::open(&path, "old password", &pepper).expect("open should succeed");
    let new_key = VaultKey::new("new password", &pepper).expect("key derivation should succeed");
    vault
        .save_and_replace_backup(&path, &new_key)
        .expect("save should succeed");

    for file in [&path, &backup] {
        let (opened, _) =
            Vault::open(file, "new password", &pepper).expect("new password should open");
        let entry = opened.get("Gmail").expect("entry should exist");
        assert_eq!(entry.password, "secret");
        assert!(matches!(
            Vault::open(file, "old password", &pepper),
            Err(Error::DecryptionFailed)
        ));
    }

    fs::remove_file(&path).expect("cleanup should succeed");
    fs::remove_file(&backup).expect("cleanup should succeed");
}

/// The recovery code of the pepper made of 32 bytes `0x42`. Its check group
/// catches every single-digit typo (see the unit tests of `pepper.rs`), so
/// the typo tests below cannot pass by chance.
fn sample_code() -> String {
    format!("ARGOS-PEPPER-1{}-a112", "-4242".repeat(16))
}

#[test]
fn lost_pepper_is_restored_from_its_recovery_code() {
    let path = temp_vault("recovery");
    let pepper_path = temp_pepper_path("recovery");

    // As `init` does: the pepper file first, then a vault created with it.
    let pepper = Pepper::create(&pepper_path).expect("pepper creation should succeed");
    let key = VaultKey::new("master", &pepper).expect("key derivation should succeed");
    let mut vault = Vault::new();
    vault
        .add(Entry::new("Gmail", "me@gmail.com", "secret", None))
        .expect("add should succeed");
    vault.save(&path, &key).expect("save should succeed");
    let code = pepper.to_recovery_code(); // `pepper export`
    drop(pepper);

    // The pepper file is lost: the vault cannot be opened any more.
    fs::remove_file(&pepper_path).expect("delete should succeed");
    assert!(matches!(
        Pepper::load(&pepper_path),
        Err(Error::PepperMissing(_))
    ));

    // `pepper import`
    let imported = Pepper::from_recovery_code(&code).expect("the code should decode");
    assert_eq!(
        imported
            .install(&pepper_path)
            .expect("install should succeed"),
        Installed::Created
    );

    let restored = Pepper::load(&pepper_path).expect("the restored pepper should load");
    let (opened, _) = Vault::open(&path, "master", &restored).expect("the vault should open");
    let entry = opened.get("Gmail").expect("entry should exist");
    assert!(entry.password == "secret");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&pepper_path)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    fs::remove_file(&path).expect("cleanup should succeed");
    fs::remove_file(&pepper_path).expect("cleanup should succeed");
}

#[test]
fn import_never_overwrites_another_pepper() {
    let pepper_path = temp_pepper_path("import-other");
    let installed = Pepper::create(&pepper_path).expect("pepper creation should succeed");
    let before = fs::read(&pepper_path).expect("read should succeed");

    let other = Pepper::from_recovery_code(&sample_code()).expect("the code should decode");
    assert!(matches!(
        other.install(&pepper_path),
        Err(Error::DifferentPepperExists { path, existing })
            if path == pepper_path && existing == installed.id()
    ));
    // Byte for byte the same file (compared with `assert!`: it is the pepper).
    assert!(fs::read(&pepper_path).expect("read should succeed") == before);

    // A file that is not a pepper is not replaced either.
    fs::write(&pepper_path, b"not a pepper").expect("write should succeed");
    assert!(matches!(
        other.install(&pepper_path),
        Err(Error::InvalidPepper { .. })
    ));
    assert_eq!(
        fs::read(&pepper_path).expect("read should succeed"),
        b"not a pepper"
    );

    fs::remove_file(&pepper_path).expect("cleanup should succeed");
}

#[test]
fn importing_the_installed_pepper_writes_nothing() {
    let pepper_path = temp_pepper_path("import-same");
    let pepper = Pepper::create(&pepper_path).expect("pepper creation should succeed");
    let before = fs::read(&pepper_path).expect("read should succeed");
    let modified = fs::metadata(&pepper_path)
        .and_then(|m| m.modified())
        .expect("modification time");

    let imported =
        Pepper::from_recovery_code(&pepper.to_recovery_code()).expect("the code should decode");
    assert_eq!(
        imported
            .install(&pepper_path)
            .expect("the same pepper is a success"),
        Installed::AlreadyPresent
    );

    assert!(fs::read(&pepper_path).expect("read should succeed") == before);
    let after = fs::metadata(&pepper_path)
        .and_then(|m| m.modified())
        .expect("modification time");
    assert_eq!(after, modified);

    fs::remove_file(&pepper_path).expect("cleanup should succeed");
}

#[test]
fn vault_pepper_id_reads_only_the_header() {
    // Format v3: the id of the pepper, read without any password.
    let v3_path = temp_vault("pepper-id-v3");
    let pepper = temp_pepper("pepper-id-v3");
    let key = VaultKey::new("master", &pepper).expect("key derivation should succeed");
    Vault::new()
        .save(&v3_path, &key)
        .expect("save should succeed");
    assert_eq!(
        vault_pepper_id(&v3_path).expect("read should succeed"),
        Some(pepper.id())
    );

    // Format v2 has no pepper. Nothing is decrypted: random bytes after the
    // header are enough.
    let v2_path = temp_vault("pepper-id-v2");
    let mut v2 = old_header(2, &[7u8; SALT_LEN]);
    v2.extend_from_slice(&[0xaa; ENVELOPE_LEN + 24 + 16]);
    fs::write(&v2_path, &v2).expect("write should succeed");
    assert_eq!(
        vault_pepper_id(&v2_path).expect("read should succeed"),
        None
    );

    // The legacy layout has no header at all.
    let legacy_path = temp_vault("pepper-id-legacy");
    fs::write(&legacy_path, [0x55; 70]).expect("write should succeed");
    assert_eq!(
        vault_pepper_id(&legacy_path).expect("read should succeed"),
        None
    );

    // The header is validated as when opening.
    let mut data = fs::read(&v3_path).expect("read should succeed");
    data[6..10].copy_from_slice(&u32::MAX.to_le_bytes()); // memory cost: 4 TiB
    fs::write(&v3_path, &data).expect("write should succeed");
    assert!(matches!(
        vault_pepper_id(&v3_path),
        Err(Error::UnsupportedKdfParams(_))
    ));

    for path in [v3_path, v2_path, legacy_path] {
        fs::remove_file(&path).expect("cleanup should succeed");
    }
}

/// The `argospass` binary, on a test vault and pepper. Both paths are always
/// given, so that the real vault and pepper are never used.
fn cli(vault: &Path, pepper: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_argospass"));
    command
        .arg("--vault")
        .arg(vault)
        .arg("--pepper")
        .arg(pepper)
        .args(args)
        .env_remove("ARGOSPASS_VAULT")
        .env_remove("ARGOSPASS_PEPPER");
    command
}

/// Runs the binary (see [`cli`]) with `stdin` as its standard input.
fn run_cli(vault: &Path, pepper: &Path, args: &[&str], stdin: &[u8]) -> Output {
    let mut child = cli(vault, pepper, args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary should start");
    // Dropping stdin right after writing closes it: the binary sees the end.
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(stdin)
        .expect("write to stdin should succeed");
    child.wait_with_output().expect("the binary should finish")
}

#[test]
fn cli_exports_then_imports_the_pepper() {
    let path = temp_vault("cli-recovery");
    let pepper_path = temp_pepper_path("cli-recovery");
    let pepper = Pepper::create(&pepper_path).expect("pepper creation should succeed");
    let key = VaultKey::new("master", &pepper).expect("key derivation should succeed");
    Vault::new().save(&path, &key).expect("save should succeed");
    let id = short_id(&pepper.id());

    let status = run_cli(&path, &pepper_path, &["pepper", "status"], b"");
    assert!(status.status.success());
    let stdout = String::from_utf8(status.stdout).expect("UTF-8 output");
    assert!(stdout.contains(&id));
    assert!(stdout.contains("the pepper matches this vault"));

    // The code on stdout and nothing else; stderr never shows it.
    let export = run_cli(&path, &pepper_path, &["pepper", "export"], b"");
    assert!(export.status.success());
    let code = pepper.to_recovery_code();
    assert!(export.stdout == format!("{}\n", *code).into_bytes());
    let stderr = String::from_utf8(export.stderr).expect("UTF-8 output");
    assert!(!stderr.contains(code.as_str()));
    assert!(stderr.contains(&id));

    fs::remove_file(&pepper_path).expect("delete should succeed");
    let status = run_cli(&path, &pepper_path, &["pepper", "status"], b"");
    assert!(status.status.success());
    let stdout = String::from_utf8(status.stdout).expect("UTF-8 output");
    assert!(stdout.contains("there is no pepper file"));

    // The code goes through stdin, as with `pepper import < code.txt`.
    let import = run_cli(&path, &pepper_path, &["pepper", "import"], &export.stdout);
    assert!(import.status.success());
    let stdout = String::from_utf8(import.stdout).expect("UTF-8 output");
    assert!(stdout.contains("installed"));
    assert!(stdout.contains("the pepper matches this vault"));
    let restored = Pepper::load(&pepper_path).expect("the restored pepper should load");
    assert!(Vault::open(&path, "master", &restored).is_ok());

    // Importing it again is a success that writes nothing.
    let again = run_cli(&path, &pepper_path, &["pepper", "import"], &export.stdout);
    assert!(again.status.success());
    let stdout = String::from_utf8(again.stdout).expect("UTF-8 output");
    assert!(stdout.contains("already installed"));

    fs::remove_file(&path).expect("cleanup should succeed");
    fs::remove_file(&pepper_path).expect("cleanup should succeed");
}

#[test]
fn cli_rejects_a_recovery_code_with_a_typo() {
    let path = temp_vault("cli-typo");
    let pepper_path = temp_pepper_path("cli-typo");

    // The first digit of the first group: 4 -> 5.
    let typo = sample_code().replacen("-4242", "-5242", 1);
    let import = run_cli(&path, &pepper_path, &["pepper", "import"], typo.as_bytes());
    assert_eq!(import.status.code(), Some(9));
    assert!(!pepper_path.exists());
    let stderr = String::from_utf8(import.stderr).expect("UTF-8 output");
    assert!(stderr.contains("check group"));
    assert!(!stderr.contains("5242"));

    // The same code without the typo is accepted.
    let import = run_cli(
        &path,
        &pepper_path,
        &["pepper", "import"],
        sample_code().as_bytes(),
    );
    assert!(import.status.success());
    assert!(pepper_path.exists());

    // But never over another pepper.
    fs::remove_file(&pepper_path).expect("delete should succeed");
    Pepper::create(&pepper_path).expect("pepper creation should succeed");
    let before = fs::read(&pepper_path).expect("read should succeed");
    let import = run_cli(
        &path,
        &pepper_path,
        &["pepper", "import"],
        sample_code().as_bytes(),
    );
    assert_eq!(import.status.code(), Some(8));
    assert!(fs::read(&pepper_path).expect("read should succeed") == before);

    fs::remove_file(&pepper_path).expect("cleanup should succeed");
}

#[cfg(unix)]
#[test]
fn cli_warns_when_the_code_is_exported_to_a_file_others_can_read() {
    use std::os::unix::fs::PermissionsExt;

    let path = temp_vault("cli-export-file"); // never created: not needed
    let pepper_path = temp_pepper_path("cli-export-file");
    let pepper = Pepper::create(&pepper_path).expect("pepper creation should succeed");
    let code_path = std::env::temp_dir().join("argospass-test-cli-export-file.code");

    // As with `pepper export > code.txt`, under two different umasks.
    for (mode, warned) in [(0o644, true), (0o600, false)] {
        let _ = fs::remove_file(&code_path);
        let file = fs::File::create(&code_path).expect("create should succeed");
        file.set_permissions(fs::Permissions::from_mode(mode))
            .expect("chmod should succeed");

        let export = cli(&path, &pepper_path, &["pepper", "export"])
            .stdin(Stdio::null())
            .stdout(Stdio::from(file))
            .stderr(Stdio::piped())
            .output()
            .expect("the binary should run");
        assert!(export.status.success());
        let stderr = String::from_utf8(export.stderr).expect("UTF-8 output");
        assert_eq!(stderr.contains("accessible to other users"), warned);
        let written = fs::read(&code_path).expect("read should succeed");
        assert!(written == format!("{}\n", *pepper.to_recovery_code()).into_bytes());
    }

    fs::remove_file(&code_path).expect("cleanup should succeed");
    fs::remove_file(&pepper_path).expect("cleanup should succeed");
}
