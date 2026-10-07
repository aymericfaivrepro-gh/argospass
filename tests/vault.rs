//! Integration tests: encrypted vault file round-trips.

use argospass::crypto::VaultKey;
use argospass::{Entry, Vault};
use std::fs;
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
    assert!(vault.add(Entry::new("Gmail", "me@gmail.com", "secret", None)));
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

    assert!(Vault::open(&path, "not the master").is_err());

    fs::remove_file(&path).expect("cleanup should succeed");
}

#[test]
fn saved_file_does_not_contain_plaintext() {
    let path = temp_vault("no-plaintext");
    let key = VaultKey::new("master").expect("key derivation should succeed");

    let mut vault = Vault::new();
    assert!(vault.add(Entry::new("Gmail", "me@gmail.com", "secret", None)));
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
    assert!(vault.add(Entry::new("First", "me", "one", None)));
    vault.save(&path, &key).expect("first save should succeed");

    assert!(vault.add(Entry::new("Second", "me", "two", None)));
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
