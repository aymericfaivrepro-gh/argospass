//! Integration tests: encrypted vault file round-trips.

use argospass::crypto::VaultKey;
use argospass::crypto::{KdfParams, SALT_LEN, derive_key, encrypt};
use argospass::format::{HEADER_LEN, MAGIC};
use argospass::{Entry, Error, Vault};
use std::fs;
use std::io;
use std::path::PathBuf;

/// Returns a path in the system temp directory, unique to each test.
fn temp_vault(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("argospass-test-{name}.argos"))
}

#[test]
fn saves_then_opens_encrypted_vault() {
    let path = temp_vault("roundtrip");
    let key = VaultKey::new("master").expect("key derivation should succeed");

    let mut vault = Vault::new();
    vault
        .add(Entry::new("Gmail", "me@gmail.com", "secret", None))
        .expect("add should succeed");
    vault.save(&path, &key).expect("save should succeed");

    let (opened, _) = Vault::open(&path, "master").expect("open should succeed");
    let entry = opened.get("Gmail").expect("entry should exist");
    assert_eq!(entry.password, "secret");

    fs::remove_file(&path).expect("cleanup should succeed");
}

#[test]
fn wrong_master_password_fails_to_open() {
    let path = temp_vault("wrong-password");
    let key = VaultKey::new("master").expect("key derivation should succeed");
    Vault::new().save(&path, &key).expect("save should succeed");

    assert!(matches!(
        Vault::open(&path, "not the master"),
        Err(Error::DecryptionFailed)
    ));

    fs::remove_file(&path).expect("cleanup should succeed");
}

#[test]
fn saved_file_does_not_contain_plaintext() {
    let path = temp_vault("no-plaintext");
    let key = VaultKey::new("master").expect("key derivation should succeed");

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
    let key = VaultKey::new("master").expect("key derivation should succeed");

    let mut vault = Vault::new();
    vault
        .add(Entry::new("First", "me", "one", None))
        .expect("add should succeed");
    vault.save(&path, &key).expect("first save should succeed");

    vault
        .add(Entry::new("Second", "me", "two", None))
        .expect("add should succeed");
    vault.save(&path, &key).expect("second save should succeed");

    let (current, _) = Vault::open(&path, "master").expect("open should succeed");
    assert_eq!(current.list().len(), 2);

    let (previous, _) = Vault::open(&backup, "master").expect("backup should open");
    assert_eq!(previous.list().len(), 1);

    fs::remove_file(&path).expect("cleanup should succeed");
    fs::remove_file(&backup).expect("cleanup should succeed");
}

#[test]
fn save_leaves_no_temporary_file() {
    let path = temp_vault("no-tmp");
    let key = VaultKey::new("master").expect("key derivation should succeed");
    Vault::new().save(&path, &key).expect("save should succeed");

    assert!(!path.with_extension("argos.tmp").exists());

    fs::remove_file(&path).expect("cleanup should succeed");
}

#[cfg(unix)]
#[test]
fn vault_file_is_readable_by_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let path = temp_vault("permissions");
    let key = VaultKey::new("master").expect("key derivation should succeed");
    Vault::new().save(&path, &key).expect("save should succeed");

    let mode = fs::metadata(&path).expect("metadata").permissions().mode();
    assert_eq!(mode & 0o777, 0o600);

    fs::remove_file(&path).expect("cleanup should succeed");
}

#[test]
fn tampered_header_fails_to_open() {
    let path = temp_vault("tampered-header");
    let key = VaultKey::new("master").expect("key derivation should succeed");
    Vault::new().save(&path, &key).expect("save should succeed");

    let mut data = fs::read(&path).expect("read should succeed");
    data[10] = 4; // iterations: 3 -> 4 (still within the accepted bounds)
    fs::write(&path, &data).expect("write should succeed");

    // The header is authenticated: changing it is detected like a wrong password.
    assert!(matches!(
        Vault::open(&path, "master"),
        Err(Error::DecryptionFailed)
    ));

    fs::remove_file(&path).expect("cleanup should succeed");
}

#[test]
fn excessive_kdf_params_are_rejected_before_key_derivation() {
    let path = temp_vault("excessive-params");
    let key = VaultKey::new("master").expect("key derivation should succeed");
    Vault::new().save(&path, &key).expect("save should succeed");

    let mut data = fs::read(&path).expect("read should succeed");
    data[6..10].copy_from_slice(&u32::MAX.to_le_bytes()); // memory cost: 4 TiB
    fs::write(&path, &data).expect("write should succeed");

    // Rejected from the header alone: Argon2id never tries to allocate 4 TiB.
    assert!(matches!(
        Vault::open(&path, "master"),
        Err(Error::UnsupportedKdfParams(params)) if params.memory_kib == u32::MAX
    ));

    fs::remove_file(&path).expect("cleanup should succeed");
}

#[test]
fn truncated_vault_fails_to_open() {
    let path = temp_vault("truncated");
    let key = VaultKey::new("master").expect("key derivation should succeed");
    Vault::new().save(&path, &key).expect("save should succeed");
    let data = fs::read(&path).expect("read should succeed");

    // Cut in the middle of the header...
    fs::write(&path, &data[..10]).expect("write should succeed");
    assert!(matches!(
        Vault::open(&path, "master"),
        Err(Error::Truncated)
    ));

    // ...or right after it, leaving no room for the nonce and the tag.
    fs::write(&path, &data[..HEADER_LEN]).expect("write should succeed");
    assert!(matches!(
        Vault::open(&path, "master"),
        Err(Error::Truncated)
    ));

    fs::remove_file(&path).expect("cleanup should succeed");
}

#[test]
fn missing_vault_is_an_io_error() {
    let path = temp_vault("missing");
    assert!(!path.exists());

    assert!(matches!(
        Vault::open(&path, "master"),
        Err(Error::Io(e)) if e.kind() == io::ErrorKind::NotFound
    ));
}

#[test]
fn legacy_vault_is_upgraded() {
    let path = temp_vault("legacy");
    let backup = path.with_extension("argos.bak");

    // Build a vault in the pre-v1 layout: salt || nonce || ciphertext || tag.
    let salt = [9u8; SALT_LEN];
    let key = derive_key("master", &salt, &KdfParams::LEGACY).expect("derivation");
    let encrypted = encrypt(&key, br#"{"entries":[]}"#, &[]).expect("encryption");
    let mut legacy = salt.to_vec();
    legacy.extend_from_slice(&encrypted);
    fs::write(&path, &legacy).expect("write should succeed");

    let (vault, _) = Vault::open(&path, "master").expect("legacy vault should open");
    assert!(vault.list().is_empty());

    let upgraded = fs::read(&path).expect("read should succeed");
    assert!(upgraded.starts_with(MAGIC));
    assert!(Vault::open(&path, "master").is_ok());

    fs::remove_file(&path).expect("cleanup should succeed");
    fs::remove_file(&backup).expect("cleanup should succeed");
}

#[test]
fn new_vault_uses_format_v2() {
    let path = temp_vault("format-v2");
    let key = VaultKey::new("master").expect("key derivation should succeed");
    Vault::new().save(&path, &key).expect("save should succeed");

    let data = fs::read(&path).expect("read should succeed");
    assert_eq!(data[5], 2);
    // header 34 + envelope 72 + nonce 24 + `{"entries":[]}` 14 + tag 16
    assert_eq!(data.len(), 160);

    fs::remove_file(&path).expect("cleanup should succeed");
}

#[test]
fn tampered_envelope_is_rejected() {
    let path = temp_vault("tampered-envelope");
    let key = VaultKey::new("master").expect("key derivation should succeed");
    Vault::new().save(&path, &key).expect("save should succeed");

    let mut data = fs::read(&path).expect("read should succeed");
    data[HEADER_LEN + 30] ^= 0x01; // flip one bit of the encrypted data key
    fs::write(&path, &data).expect("write should succeed");

    assert!(matches!(
        Vault::open(&path, "master"),
        Err(Error::DecryptionFailed)
    ));

    fs::remove_file(&path).expect("cleanup should succeed");
}

#[test]
fn v1_vault_is_upgraded_to_v2() {
    let path = temp_vault("v1-upgrade");
    let backup = path.with_extension("argos.bak");

    // Build a vault in format v1: header || nonce || ciphertext || tag,
    // encrypted with the Argon2id key itself and the header as AAD.
    let salt = [7u8; SALT_LEN];
    let mut v1 = MAGIC.to_vec();
    v1.push(1);
    v1.extend_from_slice(&(64 * 1024u32).to_le_bytes());
    v1.extend_from_slice(&3u32.to_le_bytes());
    v1.extend_from_slice(&1u32.to_le_bytes());
    v1.extend_from_slice(&salt);
    assert_eq!(v1.len(), HEADER_LEN);

    let key = derive_key("master", &salt, &KdfParams::MINIMUM).expect("derivation");
    let encrypted = encrypt(&key, br#"{"entries":[]}"#, &v1).expect("encryption");
    v1.extend_from_slice(&encrypted);
    fs::write(&path, &v1).expect("write should succeed");

    // A wrong password must not upgrade (nor touch) the file.
    assert!(matches!(
        Vault::open(&path, "not the master"),
        Err(Error::DecryptionFailed)
    ));
    assert_eq!(fs::read(&path).expect("read should succeed"), v1);

    let (vault, _) = Vault::open(&path, "master").expect("v1 vault should open");
    assert!(vault.list().is_empty());

    let upgraded = fs::read(&path).expect("read should succeed");
    assert!(upgraded.starts_with(MAGIC));
    assert_eq!(upgraded[5], 2);
    assert!(Vault::open(&path, "master").is_ok());

    fs::remove_file(&path).expect("cleanup should succeed");
    fs::remove_file(&backup).expect("cleanup should succeed");
}

/// Creates a vault protected by "old password" with one entry, and returns the
/// paths of the vault and of its backup.
fn vault_with_old_password(name: &str) -> (PathBuf, PathBuf) {
    let path = temp_vault(name);
    let backup = path.with_extension("argos.bak");
    let key = VaultKey::new("old password").expect("key derivation should succeed");

    let mut vault = Vault::new();
    vault
        .add(Entry::new("Gmail", "me@gmail.com", "secret", None))
        .expect("add should succeed");
    vault.save(&path, &key).expect("save should succeed");
    (path, backup)
}

#[test]
fn password_change() {
    let (path, backup) = vault_with_old_password("passwd");

    let (vault, key) = Vault::open(&path, "old password").expect("open should succeed");
    let new_key = key.rewrap("new password").expect("rewrap should succeed");
    vault
        .save_and_replace_backup(&path, &new_key)
        .expect("save should succeed");

    let (opened, _) = Vault::open(&path, "new password").expect("new password should open");
    let entry = opened.get("Gmail").expect("entry should exist");
    assert_eq!(entry.password, "secret");
    assert!(matches!(
        Vault::open(&path, "old password"),
        Err(Error::DecryptionFailed)
    ));

    // The backup no longer holds the vault under the old password.
    assert!(matches!(
        Vault::open(&backup, "old password"),
        Err(Error::DecryptionFailed)
    ));
    assert!(Vault::open(&backup, "new password").is_ok());

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
    let (path, backup) = vault_with_old_password("passwd-rotate");

    let (vault, _) = Vault::open(&path, "old password").expect("open should succeed");
    let new_key = VaultKey::new("new password").expect("key derivation should succeed");
    vault
        .save_and_replace_backup(&path, &new_key)
        .expect("save should succeed");

    for file in [&path, &backup] {
        let (opened, _) = Vault::open(file, "new password").expect("new password should open");
        let entry = opened.get("Gmail").expect("entry should exist");
        assert_eq!(entry.password, "secret");
        assert!(matches!(
            Vault::open(file, "old password"),
            Err(Error::DecryptionFailed)
        ));
    }

    fs::remove_file(&path).expect("cleanup should succeed");
    fs::remove_file(&backup).expect("cleanup should succeed");
}
