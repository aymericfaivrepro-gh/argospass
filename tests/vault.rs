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