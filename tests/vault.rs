//! Integration tests: encrypted vault file round-trips.

use argospass::crypto::VaultKey;
use argospass::crypto::{ENVELOPE_LEN, KEY_LEN, KdfParams, SALT_LEN, derive_key, encrypt};
use argospass::format::{HEADER_LEN, HEADER_LEN_V2, MAGIC};
use argospass::pepper::{PEPPER_ID_LEN, Pepper};
use argospass::{Entry, Error, Vault, requires_existing_pepper};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Offset of the pepper id in a v3 header.
const PEPPER_ID_OFFSET: usize = HEADER_LEN - PEPPER_ID_LEN;

/// Returns a path in the system temp directory, unique to each test.
fn temp_vault(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("argospass-test-{name}.argos"))
}

/// Creates a pepper in its own temporary file, unique to each test, and reads
/// it back. The file is deleted right away: the tests only need the pepper.
fn temp_pepper(name: &str) -> Pepper {
    let path = std::env::temp_dir().join(format!("argospass-test-{name}.key"));
    let _ = fs::remove_file(&path); // left over by an interrupted run
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
