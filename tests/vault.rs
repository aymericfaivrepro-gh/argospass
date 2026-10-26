//! Integration tests: encrypted vault file round-trips.

use argon2::{Algorithm, Argon2, Params, Version};
use argospass::crypto::{ENVELOPE_LEN, KEY_LEN, NONCE_LEN, SALT_LEN, VaultKey};
use argospass::format::{HEADER_LEN, Header, MAGIC};
use argospass::pepper::{Installed, PEPPER_ID_LEN, Pepper, short_id};
use argospass::{Error, MAX_VAULT_LEN, Vault, VaultLock, vault_pepper_id};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// Offset of the pepper id in the header.
const PEPPER_ID_OFFSET: usize = 34;

/// Offset of the vault id in the header.
const VAULT_ID_OFFSET: usize = 50;

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
    temp_pepper_with_bytes(name).0
}

/// Creates a pepper as [`temp_pepper`] does, and also returns the 32 bytes of
/// its file: Argon2id's secret, for the tests that open a vault without the
/// library.
fn temp_pepper_with_bytes(name: &str) -> (Pepper, Vec<u8>) {
    let path = temp_pepper_path(name);
    Pepper::create(&path).expect("pepper creation should succeed");
    let pepper = Pepper::load(&path).expect("pepper should load");
    let bytes = fs::read(&path).expect("read should succeed");
    fs::remove_file(&path).expect("cleanup should succeed");
    (pepper, bytes)
}

#[test]
fn saves_then_opens_encrypted_vault() {
    let path = temp_vault("roundtrip");
    let pepper = temp_pepper("roundtrip");
    let key = VaultKey::new("master", &pepper).expect("key derivation should succeed");

    let mut vault = Vault::new();
    vault
        .add(&key, "Gmail", "me@gmail.com", "secret", None)
        .expect("add should succeed");
    vault.save(&path, &key).expect("save should succeed");

    let (opened, opened_key) = Vault::open(&path, "master", &pepper).expect("open should succeed");
    let entry = opened.get("Gmail").expect("entry should exist");
    let password = entry
        .open_password(&opened_key)
        .expect("the password should open");
    assert!(*password == "secret");

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
        .add(&key, "Gmail", "me@gmail.com", "secret", None)
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
        .add(&key, "First", "me", "one", None)
        .expect("add should succeed");
    vault.save(&path, &key).expect("first save should succeed");

    vault
        .add(&key, "Second", "me", "two", None)
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
    let backup = path.with_extension("argos.bak");
    let pepper = temp_pepper("no-tmp");
    let key = VaultKey::new("master", &pepper).expect("key derivation should succeed");
    // Twice: the second save also writes the backup, through its own
    // temporary file.
    for _ in 0..2 {
        Vault::new().save(&path, &key).expect("save should succeed");
    }

    assert!(!path.with_extension("argos.tmp").exists());
    assert!(!path.with_extension("argos.bak.tmp").exists());

    fs::remove_file(&path).expect("cleanup should succeed");
    fs::remove_file(&backup).expect("cleanup should succeed");
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

#[cfg(unix)]
#[test]
fn a_leftover_temporary_file_is_replaced_not_written_through() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let path = temp_vault("leftover-tmp");
    let tmp = path.with_extension("argos.tmp");
    let target = temp_vault("leftover-tmp-target");
    let pepper = temp_pepper("leftover-tmp");
    let key = VaultKey::new("master", &pepper).expect("key derivation should succeed");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&tmp);

    // A leftover that everyone can read: the vault must not inherit its
    // permissions.
    fs::write(&tmp, b"leftover").expect("write should succeed");
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o644)).expect("chmod should succeed");
    Vault::new().save(&path, &key).expect("save should succeed");
    let mode = fs::metadata(&path).expect("metadata").permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    assert!(!tmp.exists());

    // A link to another file: that file must not be written to.
    fs::write(&target, b"not the vault").expect("write should succeed");
    symlink(&target, &tmp).expect("symlink should succeed");
    Vault::new().save(&path, &key).expect("save should succeed");
    assert_eq!(
        fs::read(&target).expect("read should succeed"),
        b"not the vault"
    );
    assert!(Vault::open(&path, "master", &pepper).is_ok());

    for file in [path.clone(), path.with_extension("argos.bak"), target] {
        fs::remove_file(file).expect("cleanup should succeed");
    }
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
fn tampered_vault_id_fails_to_open() {
    let path = temp_vault("tampered-vault-id");
    let pepper = temp_pepper("tampered-vault-id");
    let key = VaultKey::new("master", &pepper).expect("key derivation should succeed");
    let mut vault = Vault::new();
    vault
        .add(&key, "Gmail", "me@gmail.com", "secret", None)
        .expect("add should succeed");
    vault.save(&path, &key).expect("save should succeed");
    let original = fs::read(&path).expect("read should succeed");

    // Its first and last byte. The vault id is part of the header, which the
    // envelope and the payload authenticate.
    for offset in [VAULT_ID_OFFSET, HEADER_LEN - 1] {
        let mut data = original.clone();
        data[offset] ^= 0x01;
        fs::write(&path, &data).expect("write should succeed");
        assert!(matches!(
            Vault::open(&path, "master", &pepper),
            Err(Error::DecryptionFailed)
        ));
    }

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

    // Cut in the middle of the header, before or inside the ids...
    for len in [
        10,
        PEPPER_ID_OFFSET,
        VAULT_ID_OFFSET - 1,
        VAULT_ID_OFFSET,
        HEADER_LEN - 1,
    ] {
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
fn too_large_vault_file_is_refused_before_being_read() {
    let path = temp_vault("too-large");
    let pepper = temp_pepper("too-large");

    // A sparse file: that large, without taking the space on disk.
    let file = fs::File::create(&path).expect("create should succeed");
    file.set_len(MAX_VAULT_LEN + 1)
        .expect("set_len should succeed");
    drop(file);

    assert!(matches!(
        Vault::open(&path, "master", &pepper),
        Err(Error::VaultTooLarge(len)) if len == MAX_VAULT_LEN + 1
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

/// Builds the header fields up to the salt, with the weakest accepted
/// parameters: the whole header of a vault in format v1 or v2, which v3
/// extended with the pepper id, and v4 with the vault id.
fn old_header(version: u8, salt: &[u8; SALT_LEN]) -> Vec<u8> {
    let mut header = MAGIC.to_vec();
    header.push(version);
    header.extend_from_slice(&(64 * 1024u32).to_le_bytes());
    header.extend_from_slice(&3u32.to_le_bytes());
    header.extend_from_slice(&1u32.to_le_bytes());
    header.extend_from_slice(salt);
    header
}

/// A vault in format v1, as someone who knows the master password but not
/// the pepper could forge it: `header || nonce || ciphertext || tag`, the JSON
/// encrypted with the key that Argon2id derives from the password alone, with
/// the header as associated data.
fn forged_v1_vault(password: &str, json: &[u8]) -> Vec<u8> {
    let salt = [7u8; SALT_LEN];
    let mut vault = old_header(1, &salt);
    let params = Params::new(64 * 1024, 3, 1, Some(KEY_LEN)).expect("valid parameters");
    let mut key = [0u8; KEY_LEN];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), &salt, &mut key)
        .expect("derivation");

    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).expect("random nonce");
    let ciphertext = XChaCha20Poly1305::new(Key::from_slice(&key))
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: json,
                aad: &vault,
            },
        )
        .expect("encryption");
    vault.extend_from_slice(&nonce);
    vault.extend_from_slice(&ciphertext);
    vault
}

#[test]
fn a_forged_vault_in_an_older_format_is_refused() {
    // Someone who knows the master password, but not the pepper, and can
    // write the vault file (a synced folder) replaces the vault with a v1 one
    // of their own. Earlier builds opened it, then re-encrypted it under the
    // pepper.
    let path = temp_vault("forged-v1");
    let pepper = temp_pepper("forged-v1");
    let key = VaultKey::new("master", &pepper).expect("key derivation should succeed");
    let mut vault = Vault::new();
    vault
        .add(
            &key,
            "Bank",
            "alice",
            "real-secret",
            Some("https://bank.example"),
        )
        .expect("add should succeed");
    vault.save(&path, &key).expect("save should succeed");

    let forged = forged_v1_vault(
        "master",
        br#"{"entries":[{"title":"Bank","username":"alice","password":"chosen","url":"https://evil.example"}]}"#,
    );
    fs::write(&path, &forged).expect("write should succeed");

    // The right password and the right pepper: refused all the same, and left
    // as it is.
    assert!(matches!(
        Vault::open(&path, "master", &pepper),
        Err(Error::UnsupportedVersion(1))
    ));
    assert_eq!(fs::read(&path).expect("read should succeed"), forged);

    fs::remove_file(&path).expect("cleanup should succeed");
}

#[test]
fn older_formats_are_refused_and_left_unchanged() {
    let path = temp_vault("older-formats");
    let backup = path.with_extension("argos.bak");
    let pepper = temp_pepper("older-formats");
    let salt = [7u8; SALT_LEN];
    let _ = fs::remove_file(&backup);

    // Each one followed by plausible content: refused from its header alone,
    // or from its first bytes for the legacy layout, which has no header.
    let mut v3 = old_header(3, &salt);
    v3.extend_from_slice(&pepper.id());
    let cases = [
        (vec![0x55u8; SALT_LEN], None),
        (old_header(1, &salt), Some(1)),
        (old_header(2, &salt), Some(2)),
        (v3, Some(3)),
    ];
    for (mut data, version) in cases {
        data.extend_from_slice(&[0xaa; ENVELOPE_LEN + 24 + 14 + 16]);
        fs::write(&path, &data).expect("write should succeed");

        let result = Vault::open(&path, "master", &pepper);
        match version {
            Some(version) => assert!(matches!(
                result,
                Err(Error::UnsupportedVersion(found)) if found == version
            )),
            None => assert!(matches!(result, Err(Error::BadMagic))),
        }
        // Nothing is written: no upgrade, no backup.
        assert_eq!(fs::read(&path).expect("read should succeed"), data);
        assert!(!backup.exists());
    }

    fs::remove_file(&path).expect("cleanup should succeed");
}

#[test]
fn new_vault_uses_format_v4() {
    let path = temp_vault("format-v4");
    let pepper = temp_pepper("format-v4");
    let key = VaultKey::new("master", &pepper).expect("key derivation should succeed");
    Vault::new().save(&path, &key).expect("save should succeed");

    let data = fs::read(&path).expect("read should succeed");
    assert_eq!(data[5], 4);
    // header 66 + envelope 72 + nonce 24 + `{"entries":[]}` 14 + tag 16
    assert_eq!(data.len(), 192);
    assert_eq!(&data[PEPPER_ID_OFFSET..VAULT_ID_OFFSET], &pepper.id());
    assert_eq!(
        vault_pepper_id(&path).expect("read should succeed"),
        pepper.id()
    );

    // The vault id, at offset 50: random, so another vault has another one.
    let other_path = temp_vault("format-v4-other");
    let other_key = VaultKey::new("master", &pepper).expect("key derivation should succeed");
    Vault::new()
        .save(&other_path, &other_key)
        .expect("save should succeed");
    let other = fs::read(&other_path).expect("read should succeed");
    assert_eq!(HEADER_LEN - VAULT_ID_OFFSET, 16);
    assert_ne!(
        &data[VAULT_ID_OFFSET..HEADER_LEN],
        &other[VAULT_ID_OFFSET..HEADER_LEN]
    );

    fs::remove_file(&path).expect("cleanup should succeed");
    fs::remove_file(&other_path).expect("cleanup should succeed");
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

/// Opens the two outer layers of a vault without the library, from the
/// documented format and the primitives alone: Argon2id, with the pepper as
/// its secret, gives the KEK, which opens the envelope (AAD: header) and gives
/// the data key; HKDF-SHA256 gives the payload key, which decrypts the payload
/// (AAD: header || envelope). Returns the data key and the decrypted JSON:
/// level 1 only.
fn open_layers(path: &Path, password: &str, pepper: &[u8]) -> ([u8; KEY_LEN], Vec<u8>) {
    let data = fs::read(path).expect("read should succeed");
    let header = Header::from_bytes(&data).expect("valid header");
    let (prefix, payload) = data.split_at(HEADER_LEN + ENVELOPE_LEN);
    let (header_bytes, envelope) = prefix.split_at(HEADER_LEN);

    let p = header.params;
    let params = Params::new(p.memory_kib, p.iterations, p.parallelism, Some(KEY_LEN))
        .expect("valid parameters");
    let mut kek = [0u8; KEY_LEN];
    Argon2::new_with_secret(pepper, Algorithm::Argon2id, Version::V0x13, params)
        .expect("valid secret")
        .hash_password_into(password.as_bytes(), &header.salt, &mut kek)
        .expect("derivation");

    let data_key: [u8; KEY_LEN] = aead_open(&kek, envelope, header_bytes)
        .try_into()
        .expect("a 32-byte data key");
    let mut payload_key = [0u8; KEY_LEN];
    Hkdf::<Sha256>::new(None, &data_key)
        .expand(b"ArgosPass payload key v1", &mut payload_key)
        .expect("HKDF");
    let json = aead_open(&payload_key, payload, prefix);
    (data_key, json)
}

/// Decrypts `nonce (24) || ciphertext || tag (16)` with XChaCha20-Poly1305.
fn aead_open(key: &[u8; KEY_LEN], sealed: &[u8], aad: &[u8]) -> Vec<u8> {
    let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
    XChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .expect("the tag should match")
}

/// The protected password of each entry of a decrypted JSON content, as
/// written in it: hex, not secret.
fn protected_passwords(json: &[u8]) -> Vec<String> {
    let content: serde_json::Value = serde_json::from_slice(json).expect("valid JSON");
    content["entries"]
        .as_array()
        .expect("a list of entries")
        .iter()
        .map(|entry| {
            entry["password"]
                .as_str()
                .expect("a hex string")
                .to_string()
        })
        .collect()
}

/// Tells whether `needle` appears anywhere in `haystack`.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn decrypted_json_holds_no_password() {
    let path = temp_vault("level-1");
    let (pepper, pepper_bytes) = temp_pepper_with_bytes("level-1");
    let key = VaultKey::new("master", &pepper).expect("key derivation should succeed");
    let passwords = ["correct-horse-battery", "Tr0ub4dor&3"];
    let mut vault = Vault::new();
    vault
        .add(&key, "Gmail", "me@gmail.com", passwords[0], None)
        .expect("add should succeed");
    vault
        .add(&key, "GitHub", "me", passwords[1], None)
        .expect("add should succeed");
    vault.save(&path, &key).expect("save should succeed");

    // What opening the vault decrypts: the payload, not the passwords.
    let (_, json) = open_layers(&path, "master", &pepper_bytes);
    for password in passwords {
        assert!(!contains(&json, password.as_bytes()));
    }

    // The rest of each entry is there, and its password is a protected field:
    // hex of nonce (24) || ciphertext (as long as the password) || tag (16).
    let content: serde_json::Value = serde_json::from_slice(&json).expect("valid JSON");
    assert_eq!(content["entries"][0]["title"], "Gmail");
    assert_eq!(content["entries"][1]["username"], "me");
    for (i, field) in protected_passwords(&json).iter().enumerate() {
        assert_eq!(field.len(), 2 * (24 + passwords[i].len() + 16));
        assert!(
            field
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        let id = content["entries"][i]["id"].as_str().expect("a hex id");
        assert_eq!(id.len(), 32);
    }

    // Each one still opens, on its own.
    let (opened, opened_key) = Vault::open(&path, "master", &pepper).expect("open should succeed");
    let entry = opened.get("GitHub").expect("entry should exist");
    let password = entry
        .open_password(&opened_key)
        .expect("the password should open");
    assert!(*password == passwords[1]);

    fs::remove_file(&path).expect("cleanup should succeed");
}

/// Creates a vault protected by "old password" and `pepper` with two entries,
/// and returns the paths of the vault and of its backup.
fn vault_with_old_password(name: &str, pepper: &Pepper) -> (PathBuf, PathBuf) {
    let path = temp_vault(name);
    let backup = path.with_extension("argos.bak");
    let key = VaultKey::new("old password", pepper).expect("key derivation should succeed");

    let mut vault = Vault::new();
    vault
        .add(&key, "Gmail", "me@gmail.com", "secret", None)
        .expect("add should succeed");
    vault
        .add(&key, "GitHub", "me", "other-secret", None)
        .expect("add should succeed");
    vault.save(&path, &key).expect("save should succeed");
    (path, backup)
}

#[test]
fn password_change() {
    let (pepper, pepper_bytes) = temp_pepper_with_bytes("passwd");
    let (path, backup) = vault_with_old_password("passwd", &pepper);

    let (vault, key) = Vault::open(&path, "old password", &pepper).expect("open should succeed");
    let vault_id =
        fs::read(&path).expect("read should succeed")[VAULT_ID_OFFSET..HEADER_LEN].to_vec();
    let (_, json_before) = open_layers(&path, "old password", &pepper_bytes);
    let new_key = key
        .rewrap("new password", &pepper)
        .expect("rewrap should succeed");
    vault
        .save_and_replace_backup(&path, &new_key)
        .expect("save should succeed");

    let (opened, opened_key) =
        Vault::open(&path, "new password", &pepper).expect("new password should open");
    let entry = opened.get("Gmail").expect("entry should exist");
    let password = entry
        .open_password(&opened_key)
        .expect("the password should open");
    assert!(*password == "secret");
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

    // The vault still uses the same pepper, and is still the same vault.
    let data = fs::read(&path).expect("read should succeed");
    assert_eq!(&data[PEPPER_ID_OFFSET..VAULT_ID_OFFSET], &pepper.id());
    assert_eq!(&data[VAULT_ID_OFFSET..HEADER_LEN], vault_id);

    // Same data key, so same field key: the protected fields are kept byte for
    // byte, and still open (checked above).
    let (_, json_after) = open_layers(&path, "new password", &pepper_bytes);
    assert_eq!(
        protected_passwords(&json_after),
        protected_passwords(&json_before)
    );

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
    let (pepper, pepper_bytes) = temp_pepper_with_bytes("passwd-rotate");
    let (path, backup) = vault_with_old_password("passwd-rotate", &pepper);

    let (mut vault, key) =
        Vault::open(&path, "old password", &pepper).expect("open should succeed");
    let vault_id =
        fs::read(&path).expect("read should succeed")[VAULT_ID_OFFSET..HEADER_LEN].to_vec();
    let (old_data_key, json_before) = open_layers(&path, "old password", &pepper_bytes);
    let fields_before = protected_passwords(&json_before);

    // As `passwd --rotate-key` does.
    let new_key = vault
        .rotate_key(key, "new password", &pepper)
        .expect("rotation should succeed");
    vault
        .save_and_replace_backup(&path, &new_key)
        .expect("save should succeed");

    for file in [&path, &backup] {
        let (opened, opened_key) =
            Vault::open(file, "new password", &pepper).expect("new password should open");
        for (title, expected) in [("Gmail", "secret"), ("GitHub", "other-secret")] {
            let entry = opened.get(title).expect("entry should exist");
            let password = entry
                .open_password(&opened_key)
                .expect("the password should open");
            assert!(*password == expected);
        }
        assert!(matches!(
            Vault::open(file, "old password", &pepper),
            Err(Error::DecryptionFailed)
        ));

        // The same vault, with a new data key: every protected field was
        // encrypted again.
        let data = fs::read(file).expect("read should succeed");
        assert_eq!(&data[VAULT_ID_OFFSET..HEADER_LEN], vault_id);
        let (new_data_key, json) = open_layers(file, "new password", &pepper_bytes);
        assert!(new_data_key != old_data_key);
        let fields = protected_passwords(&json);
        assert_eq!(fields.len(), fields_before.len());
        assert!(fields.iter().all(|field| !fields_before.contains(field)));
    }

    fs::remove_file(&path).expect("cleanup should succeed");
    fs::remove_file(&backup).expect("cleanup should succeed");
}

#[test]
fn a_backup_that_cannot_be_replaced_is_reported_after_the_save() {
    let path = temp_vault("backup-not-replaced");
    let backup = path.with_extension("argos.bak");
    let pepper = temp_pepper("backup-not-replaced");
    let key = VaultKey::new("master", &pepper).expect("key derivation should succeed");
    let _ = fs::remove_file(&path);
    // A directory where the backup goes: no file can replace it.
    let _ = fs::remove_dir(&backup);
    fs::create_dir(&backup).expect("mkdir should succeed");

    assert!(matches!(
        Vault::new().save_and_replace_backup(&path, &key),
        Err(Error::BackupNotReplaced { path: failed, .. }) if failed == backup
    ));
    // The error says so: the vault itself was saved.
    assert!(Vault::open(&path, "master", &pepper).is_ok());

    fs::remove_dir(&backup).expect("cleanup should succeed");
    fs::remove_file(path.with_extension("argos.bak.tmp")).expect("cleanup should succeed");
    fs::remove_file(&path).expect("cleanup should succeed");
}

#[test]
fn a_locked_vault_cannot_be_locked_again() {
    let path = temp_vault("lock");
    let lock_file = path.with_extension("argos.lock");

    let first = VaultLock::acquire(&path).expect("the vault should be free");
    assert!(matches!(VaultLock::acquire(&path), Err(Error::VaultBusy)));
    drop(first);
    let again = VaultLock::acquire(&path).expect("the lock should be released");
    drop(again);

    // The lock file stays in place, empty.
    assert_eq!(fs::metadata(&lock_file).expect("metadata").len(), 0);
    fs::remove_file(&lock_file).expect("cleanup should succeed");
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
        .add(&key, "Gmail", "me@gmail.com", "secret", None)
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
    let (opened, opened_key) =
        Vault::open(&path, "master", &restored).expect("the vault should open");
    let entry = opened.get("Gmail").expect("entry should exist");
    let password = entry
        .open_password(&opened_key)
        .expect("the password should open");
    assert!(*password == "secret");

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
    // Also `assert!`: after a failed check, the file would hold a pepper.
    assert!(fs::read(&pepper_path).expect("read should succeed") == b"not a pepper");

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
    // The id of the pepper, read without any password.
    let v4_path = temp_vault("pepper-id-v4");
    let pepper = temp_pepper("pepper-id-v4");
    let key = VaultKey::new("master", &pepper).expect("key derivation should succeed");
    Vault::new()
        .save(&v4_path, &key)
        .expect("save should succeed");
    assert_eq!(
        vault_pepper_id(&v4_path).expect("read should succeed"),
        pepper.id()
    );

    // An older format fails as when opening. Nothing is decrypted: random
    // bytes after the header are enough.
    let v2_path = temp_vault("pepper-id-v2");
    let mut v2 = old_header(2, &[7u8; SALT_LEN]);
    v2.extend_from_slice(&[0xaa; ENVELOPE_LEN + 24 + 16]);
    fs::write(&v2_path, &v2).expect("write should succeed");
    assert!(matches!(
        vault_pepper_id(&v2_path),
        Err(Error::UnsupportedVersion(2))
    ));

    // The legacy layout has no header at all.
    let legacy_path = temp_vault("pepper-id-legacy");
    fs::write(&legacy_path, [0x55; 70]).expect("write should succeed");
    assert!(matches!(
        vault_pepper_id(&legacy_path),
        Err(Error::BadMagic)
    ));

    // The header is validated as when opening.
    let mut data = fs::read(&v4_path).expect("read should succeed");
    data[6..10].copy_from_slice(&u32::MAX.to_le_bytes()); // memory cost: 4 TiB
    fs::write(&v4_path, &data).expect("write should succeed");
    assert!(matches!(
        vault_pepper_id(&v4_path),
        Err(Error::UnsupportedKdfParams(_))
    ));

    for path in [v4_path, v2_path, legacy_path] {
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

#[test]
fn cli_rejects_a_wrong_pepper_before_asking_for_the_password() {
    let path = temp_vault("cli-wrong-pepper");
    let pepper = temp_pepper("cli-wrong-pepper");
    let other_path = temp_pepper_path("cli-wrong-pepper-other");
    let other = Pepper::create(&other_path).expect("pepper creation should succeed");
    let key = VaultKey::new("master", &pepper).expect("key derivation should succeed");
    Vault::new().save(&path, &key).expect("save should succeed");
    let before = fs::read(&path).expect("read should succeed");

    // The password is read from the terminal, not from stdin. Without one (as
    // in CI), asking for it would fail with an I/O error (exit code 5) instead.
    // Only such a run catches a check done too late: on a terminal, the binary
    // would wait for the password.
    for args in [&["list"][..], &["passwd"]] {
        let output = run_cli(&path, &other_path, args, b"");
        assert_eq!(output.status.code(), Some(8), "{args:?}");
        let stderr = String::from_utf8(output.stderr).expect("UTF-8 output");
        assert!(stderr.contains("wrong pepper"));
        assert!(stderr.contains(&short_id(&pepper.id())));
        assert!(stderr.contains(&short_id(&other.id())));
    }
    assert!(fs::read(&path).expect("read should succeed") == before);

    fs::remove_file(&path).expect("cleanup should succeed");
    fs::remove_file(&other_path).expect("cleanup should succeed");
}

#[test]
fn other_formats_are_unsupported_even_without_a_pepper() {
    let path = temp_vault("other-formats");
    let pepper_path = temp_pepper_path("other-formats");
    let salt = [7u8; SALT_LEN];

    // The fields of a v4 header (pepper id, vault id), with a version this
    // build does not know.
    let mut v5 = old_header(5, &salt);
    v5.extend_from_slice(&[9u8; PEPPER_ID_LEN]);
    v5.extend_from_slice(&[3u8; 16]);
    assert_eq!(v5.len(), HEADER_LEN);
    let legacy = vec![0x55u8; 70];

    for data in [legacy, old_header(1, &salt), old_header(2, &salt), v5] {
        fs::write(&path, &data).expect("write should succeed");

        // Not reported as a missing pepper, with a hint, no pepper is created
        // for it, and the vault is left as it is.
        let output = run_cli(&path, &pepper_path, &["list"], b"");
        assert_eq!(output.status.code(), Some(4));
        let stderr = String::from_utf8(output.stderr).expect("UTF-8 output");
        assert!(stderr.contains("Hint:"));
        assert!(!pepper_path.exists());
        assert_eq!(fs::read(&path).expect("read should succeed"), data);
    }

    fs::remove_file(&path).expect("cleanup should succeed");
}

#[test]
fn cli_refuses_a_pepper_path_used_by_the_vault() {
    let path = temp_vault("cli-pepper-path");
    let name = path.file_name().expect("a file name").to_owned();
    // The same file as the backup, written another way.
    let mut same_as_backup = std::env::temp_dir().join(".").join(name);
    same_as_backup.as_mut_os_string().push(".bak");

    for pepper_path in [
        path.clone(),
        path.with_extension("argos.tmp"),
        path.with_extension("argos.bak"),
        path.with_extension("argos.lock"),
        same_as_backup,
    ] {
        // Refused before the master password is asked for: nothing is written.
        let output = run_cli(&path, &pepper_path, &["init"], b"");
        assert_eq!(output.status.code(), Some(1), "{}", pepper_path.display());
        let stderr = String::from_utf8(output.stderr).expect("UTF-8 output");
        assert!(stderr.contains("also used for the vault"));
        assert!(!path.exists());
        assert!(!pepper_path.exists());
    }

    // An existing pepper at such a path is refused too, and left untouched.
    let pepper_path = path.with_extension("argos.bak");
    Pepper::create(&pepper_path).expect("pepper creation should succeed");
    let before = fs::read(&pepper_path).expect("read should succeed");
    let output = run_cli(&path, &pepper_path, &["pepper", "status"], b"");
    assert_eq!(output.status.code(), Some(1));
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
