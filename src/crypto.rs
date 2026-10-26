//! Cryptography: deriving a key from the master password, envelope encryption
//! and authenticated encryption of the vault.

use crate::format::Header;
use crate::pepper::Pepper;
use crate::{Error, Result, to_hex};
use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use log::{debug, info};
use std::time::Instant;
use zeroize::Zeroizing;

/// Encryption key size: 32 bytes (256 bits).
pub const KEY_LEN: usize = 32;

/// Salt size: 16 bytes (128 bits), per RFC 9106 recommendation.
pub const SALT_LEN: usize = 16;

/// XChaCha20-Poly1305 nonce length: 24 bytes (192 bits).
pub const NONCE_LEN: usize = 24;

/// Poly1305 authentication tag length: 16 bytes.
pub const TAG_LEN: usize = 16;

/// Length of the envelope (the data key wrapped by the KEK): 72 bytes.
pub const ENVELOPE_LEN: usize = NONCE_LEN + KEY_LEN + TAG_LEN;

/// Argon2id cost parameters, stored in the vault header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost, in KiB.
    pub memory_kib: u32,
    /// Number of passes over memory.
    pub iterations: u32,
    /// Degree of parallelism.
    pub parallelism: u32,
}

impl KdfParams {
    /// Parameters used for new vaults.
    pub const DEFAULT: Self = Self {
        memory_kib: 128 * 1024,
        iterations: 3,
        parallelism: 4,
    };

    /// Parameters hard-coded in vaults written before format v1.
    /// Must never change, even if `DEFAULT` does.
    pub const LEGACY: Self = Self {
        memory_kib: 64 * 1024,
        iterations: 3,
        parallelism: 4,
    };

    /// Weakest parameters accepted when opening a vault.
    pub const MINIMUM: Self = Self {
        memory_kib: 64 * 1024,
        iterations: 3,
        parallelism: 1,
    };

    /// Strongest parameters accepted when opening a vault: a crafted header
    /// must not be able to exhaust memory or CPU before the tag is checked.
    pub const MAXIMUM: Self = Self {
        memory_kib: 4 * 1024 * 1024,
        iterations: 64,
        parallelism: 64,
    };

    /// Checks that the parameters are within the accepted bounds.
    pub fn validate(&self) -> Result<()> {
        let (min, max) = (Self::MINIMUM, Self::MAXIMUM);
        let valid = (min.memory_kib..=max.memory_kib).contains(&self.memory_kib)
            && (min.iterations..=max.iterations).contains(&self.iterations)
            && (min.parallelism..=max.parallelism).contains(&self.parallelism);

        if valid {
            Ok(())
        } else {
            Err(Error::UnsupportedKdfParams(*self))
        }
    }
}

/// A 256-bit secret key. Boxed so that moving it around only copies a pointer,
/// never the key bytes themselves, and wiped on drop.
type SecretKey = Box<Zeroizing<[u8; KEY_LEN]>>;

/// Key-encryption key (KEK): derived from the master password (and, from
/// format v3 on, the pepper) with Argon2id.
///
/// Only used to wrap and unwrap the [`DataKey`], never to encrypt the entries.
struct Kek(SecretKey);

impl Kek {
    /// Derives the KEK from the master password, the salt and parameters of
    /// `header`, and the pepper if any.
    fn derive(password: &str, header: &Header, pepper: Option<&Pepper>) -> Result<Self> {
        derive_key(password, &header.salt, &header.params, pepper).map(Self)
    }

    /// Encrypts `data_key` into an envelope:
    /// `nonce (24 bytes) || encrypted data key (32 bytes) || tag (16 bytes)`.
    fn wrap_key(&self, data_key: &DataKey, aad: &[u8]) -> Result<[u8; ENVELOPE_LEN]> {
        let envelope = encrypt(&self.0, &**data_key.0, aad)?;
        envelope.try_into().map_err(|_| Error::EncryptionFailed)
    }

    /// Decrypts the data key from an envelope produced by [`Kek::wrap_key`].
    ///
    /// Fails with [`Error::DecryptionFailed`] if the KEK is wrong (wrong master
    /// password) or if the envelope or `aad` has been modified.
    fn unwrap_key(&self, envelope: &[u8], aad: &[u8]) -> Result<DataKey> {
        let bytes = decrypt(&self.0, envelope, aad)?;
        if bytes.len() != KEY_LEN {
            return Err(Error::DecryptionFailed);
        }

        // Allocated (zeroed) on the heap first, then filled in place: the key
        // bytes are never copied to the stack.
        let mut key = Box::new(Zeroizing::new([0u8; KEY_LEN]));
        key.copy_from_slice(&bytes);
        Ok(DataKey(key))
    }
}

/// Data key: random, generated once when the vault is created, and used to
/// encrypt the entries. Stored in the file wrapped by the [`Kek`].
pub(crate) struct DataKey(SecretKey);

impl DataKey {
    /// Generates a new random data key using the operating system's CSPRNG.
    fn generate() -> Result<Self> {
        // Filled in place on the heap: the key bytes never touch the stack.
        let mut key = Box::new(Zeroizing::new([0u8; KEY_LEN]));
        getrandom::fill(&mut **key)?;
        debug!("generated a new random data key ({KEY_LEN} bytes)");
        Ok(Self(key))
    }
}

/// Key material of an unlocked vault (envelope encryption).
///
/// The master password and the pepper go through Argon2id to give the `Kek`,
/// which only unwraps the `DataKey` stored in the envelope. The data key
/// encrypts the entries. The KEK is wiped as soon as the envelope is opened.
pub struct VaultKey {
    /// Salt, Argon2id parameters and pepper id of the KEK.
    pub(crate) header: Header,
    /// The data key, wrapped by the KEK. Public: written as is on every save.
    envelope: [u8; ENVELOPE_LEN],
    data_key: DataKey,
}

impl VaultKey {
    /// Creates key material for a new vault: fresh salt, default parameters,
    /// the id of `pepper`, and a new random data key.
    pub fn new(password: &str, pepper: &Pepper) -> Result<Self> {
        Self::seal(
            password,
            fresh_header(pepper)?,
            DataKey::generate()?,
            pepper,
        )
    }

    /// Wraps the same data key under a new password, with a fresh salt, the
    /// current default Argon2 parameters and `pepper`. The content key does
    /// not change.
    pub fn rewrap(self, new_password: &str, pepper: &Pepper) -> Result<Self> {
        info!("wrapping the data key under the new password");
        // Moves the box: the data key bytes are not copied.
        Self::seal(new_password, fresh_header(pepper)?, self.data_key, pepper)
    }

    /// Tells whether `password` (with `pepper`) opens the current envelope,
    /// that is, whether it is the current master password. Costs one Argon2id
    /// derivation.
    ///
    /// Lets the caller compare a new password with the current one without
    /// keeping the current one in memory.
    pub fn opens_with(&self, password: &str, pepper: &Pepper) -> Result<bool> {
        match Self::unlock(password, self.header, &self.envelope, Some(pepper)) {
            Ok(_) => Ok(true), // this second copy of the data key is wiped here
            Err(Error::DecryptionFailed) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Opens the envelope of an existing vault with the master password.
    ///
    /// `pepper` is only used if the header has a pepper id (format v3 and
    /// later): it must then be the pepper with that id.
    ///
    /// Fails with [`Error::PepperRequired`] or [`Error::PepperMismatch`] if the
    /// pepper is missing or is not the vault's, and with
    /// [`Error::DecryptionFailed`] if the password is wrong or if the header or
    /// the envelope has been modified.
    pub(crate) fn unlock(
        password: &str,
        header: Header,
        envelope: &[u8],
        pepper: Option<&Pepper>,
    ) -> Result<Self> {
        // Checked before running Argon2id: a malformed file must fail fast.
        let envelope: [u8; ENVELOPE_LEN] = envelope.try_into().map_err(|_| Error::Truncated)?;

        // Also checked before running Argon2id: the pepper id is public, so a
        // missing or wrong pepper can be reported without a derivation.
        let pepper = match header.pepper_id() {
            None => None, // before format v3: derived without a pepper
            Some(expected) => {
                let pepper = pepper.ok_or(Error::PepperRequired)?;
                let found = pepper.id();
                if found != expected {
                    return Err(Error::PepperMismatch { expected, found });
                }
                Some(pepper)
            }
        };

        let data_key = {
            let kek = Kek::derive(password, &header, pepper)?;
            kek.unwrap_key(&envelope, &header.to_bytes())?
        }; // the KEK is wiped here
        info!("envelope opened");

        Ok(Self {
            header,
            envelope,
            data_key,
        })
    }

    /// Wraps `data_key` with the KEK derived from `password`, `header` and
    /// `pepper`, whose id the header must carry.
    fn seal(password: &str, header: Header, data_key: DataKey, pepper: &Pepper) -> Result<Self> {
        debug_assert_eq!(header.pepper_id(), Some(pepper.id()));
        let envelope = {
            let kek = Kek::derive(password, &header, Some(pepper))?;
            kek.wrap_key(&data_key, &header.to_bytes())?
        }; // the KEK is wiped here

        Ok(Self {
            header,
            envelope,
            data_key,
        })
    }

    /// Everything written before the payload: `header || envelope`.
    pub(crate) fn prefix(&self) -> Vec<u8> {
        let mut prefix = Vec::with_capacity(self.header.encoded_len() + ENVELOPE_LEN);
        prefix.extend_from_slice(&self.header.to_bytes());
        prefix.extend_from_slice(&self.envelope);
        prefix
    }

    /// Encrypts the vault content with the data key.
    /// The header and the envelope are authenticated as associated data.
    pub(crate) fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        encrypt(&self.data_key.0, plaintext, &self.prefix())
    }

    /// Decrypts a payload produced by [`VaultKey::encrypt`].
    pub(crate) fn decrypt(&self, data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        decrypt(&self.data_key.0, data, &self.prefix())
    }
}

/// Header for a new KEK: fresh random salt, the default Argon2id parameters
/// and the id of `pepper`.
fn fresh_header(pepper: &Pepper) -> Result<Header> {
    Ok(Header::new(
        KdfParams::DEFAULT,
        generate_salt()?,
        pepper.id(),
    ))
}

/// Generates a random salt using the operating system's CSPRNG.
pub fn generate_salt() -> Result<[u8; SALT_LEN]> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt)?;
    debug!("generated random salt: {}", to_hex(&salt));
    Ok(salt)
}

/// Encrypts `plaintext` with `key` using XChaCha20-Poly1305.
///
/// A fresh random nonce is generated on every call.
/// Output layout: `nonce (24 bytes) || ciphertext || tag (16 bytes)`.
pub fn encrypt(key: &[u8; KEY_LEN], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));

    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce)?;

    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::EncryptionFailed)?;
    debug!("generated random nonce: {}", to_hex(&nonce));
    debug!(
        "encrypted {} bytes -> {} bytes of ciphertext + tag (tag: {})",
        plaintext.len(),
        ciphertext.len(),
        to_hex(&ciphertext[ciphertext.len() - TAG_LEN..])
    );
    let mut output = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypts data produced by [`encrypt`].
///
/// Fails with [`Error::DecryptionFailed`] if the key is wrong or if the data
/// (or the associated data) has been modified.
pub fn decrypt(key: &[u8; KEY_LEN], data: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if data.len() < NONCE_LEN + TAG_LEN {
        return Err(Error::Truncated);
    }

    let (nonce, ciphertext) = data.split_at(NONCE_LEN);
    debug!("nonce (from file): {}", to_hex(nonce));
    debug!(
        "verifying Poly1305 tag and decrypting {} bytes (tag: {})",
        ciphertext.len(),
        to_hex(&ciphertext[ciphertext.len() - TAG_LEN..])
    );
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));

    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::DecryptionFailed)
}

/// Derives a 256-bit key from the master password and salt.
///
/// With `Some(pepper)`, the pepper is Argon2id's secret parameter K (format v3
/// and later). With `None`, no secret is used, as in older formats.
pub fn derive_key(
    password: &str,
    salt: &[u8; SALT_LEN],
    params: &KdfParams,
    pepper: Option<&Pepper>,
) -> Result<Box<Zeroizing<[u8; KEY_LEN]>>> {
    info!(
        "deriving key with Argon2id ({} MiB, {} iterations, parallelism {}, {})",
        params.memory_kib / 1024,
        params.iterations,
        params.parallelism,
        if pepper.is_some() {
            "with pepper"
        } else {
            "without pepper"
        }
    );
    let start = Instant::now();

    let argon2_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )?;

    // Argon2's working memory is derived from the password and is enough to
    // recompute the key: provide it ourselves so that it is wiped afterwards.
    let mut memory = Zeroizing::new(vec![Block::default(); argon2_params.block_count()]);
    let argon2 = match pepper {
        Some(pepper) => Argon2::new_with_secret(
            pepper.as_bytes(),
            Algorithm::Argon2id,
            Version::V0x13,
            argon2_params,
        )?,
        None => Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params),
    };
    let mut key = Box::new(Zeroizing::new([0u8; KEY_LEN]));
    argon2.hash_password_into_with_memory(password.as_bytes(), salt, &mut **key, &mut *memory)?;

    info!("key derived in {:?}", start.elapsed());
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::HEADER_LEN_V2;

    /// Derives a key with the default parameters (no pepper unless given).
    fn derive(password: &str, salt: [u8; SALT_LEN], pepper: Option<&Pepper>) -> SecretKey {
        derive_key(password, &salt, &KdfParams::DEFAULT, pepper).expect("derivation")
    }

    // Keys are compared with `assert!`, not `assert_eq!`: a failure must not
    // print key bytes.

    #[test]
    fn same_password_and_same_salt_produce_the_same_key() {
        let salt = [7u8; SALT_LEN];
        assert!(derive("correct horse", salt, None) == derive("correct horse", salt, None));
    }

    #[test]
    fn different_salt_produces_a_different_key() {
        let k1 = derive("correct horse", [1u8; SALT_LEN], None);
        let k2 = derive("correct horse", [2u8; SALT_LEN], None);
        assert!(k1 != k2);
    }

    #[test]
    fn different_password_produces_a_different_key() {
        let salt = [7u8; SALT_LEN];
        assert!(derive("correct horse", salt, None) != derive("correct hors3", salt, None));
    }

    #[test]
    fn different_peppers_produce_different_keys() {
        let salt = [7u8; SALT_LEN];
        let (a, b) = (
            Pepper::generate().expect("pepper"),
            Pepper::generate().expect("pepper"),
        );
        let with_a = derive("correct horse", salt, Some(&a));
        assert!(with_a == derive("correct horse", salt, Some(&a)));
        assert!(with_a != derive("correct horse", salt, Some(&b)));
        assert!(with_a != derive("correct horse", salt, None));
    }

    #[test]
    fn two_generated_salts_are_different() {
        let s1 = generate_salt().expect("generation");
        let s2 = generate_salt().expect("generation");
        assert_ne!(s1, s2);
    }
    #[test]
    fn encrypt_then_decrypt_returns_plaintext() {
        let key = [42u8; KEY_LEN];
        let encrypted = encrypt(&key, b"hello vault", &[]).expect("encryption should succeed");
        let decrypted = decrypt(&key, &encrypted, &[]).expect("decryption should succeed");
        assert!(decrypted.as_slice() == b"hello vault");
    }

    #[test]
    fn output_has_expected_length() {
        let key = [42u8; KEY_LEN];
        let plaintext = b"hello vault";
        let encrypted = encrypt(&key, plaintext, &[]).expect("encryption should succeed");
        assert_eq!(encrypted.len(), NONCE_LEN + plaintext.len() + TAG_LEN);
    }

    #[test]
    fn same_plaintext_encrypts_differently_each_time() {
        let key = [42u8; KEY_LEN];
        let a = encrypt(&key, b"hello vault", &[]).expect("encryption should succeed");
        let b = encrypt(&key, b"hello vault", &[]).expect("encryption should succeed");
        assert_ne!(a, b);
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        let encrypted =
            encrypt(&[1u8; KEY_LEN], b"hello vault", &[]).expect("encryption should succeed");
        assert!(matches!(
            decrypt(&[2u8; KEY_LEN], &encrypted, &[]),
            Err(Error::DecryptionFailed)
        ));
    }

    #[test]
    fn tampered_data_fails_to_decrypt() {
        let key = [42u8; KEY_LEN];
        let mut encrypted = encrypt(&key, b"hello vault", &[]).expect("encryption should succeed");
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0x01; // flip one bit
        assert!(matches!(
            decrypt(&key, &encrypted, &[]),
            Err(Error::DecryptionFailed)
        ));
    }

    #[test]
    fn too_short_data_fails_to_decrypt() {
        let key = [42u8; KEY_LEN];
        assert!(matches!(
            decrypt(&key, &[0u8; 10], &[]),
            Err(Error::Truncated)
        ));
    }

    #[test]
    fn show_encryption() {
        let key = [42u8; KEY_LEN];
        for _ in 0..2 {
            let encrypted = encrypt(&key, b"hello vault", &[]).expect("encryption should succeed");
            let hex: String = encrypted.iter().map(|b| format!("{b:02x}")).collect();
            println!("{hex}");
        }
    }
    #[test]
    fn caller_provided_memory_gives_the_standard_argon2_key() {
        // Providing Argon2's memory ourselves must not change the key,
        // otherwise existing vaults could no longer be opened.
        let salt = [7u8; SALT_LEN];
        let p = KdfParams::DEFAULT;
        let params = Params::new(p.memory_kib, p.iterations, p.parallelism, Some(KEY_LEN))
            .expect("valid parameters");
        let mut expected = [0u8; KEY_LEN];
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(b"correct horse", &salt, &mut expected)
            .expect("derivation");

        let key = derive("correct horse", salt, None);
        assert!(**key == expected);
    }

    #[test]
    fn pepper_is_argon2_secret_parameter() {
        // The pepper must reach Argon2id as its standard secret K, also when
        // Argon2's memory is provided by the caller.
        let salt = [7u8; SALT_LEN];
        let pepper = Pepper::generate().expect("pepper");
        let p = KdfParams::DEFAULT;
        let params = Params::new(p.memory_kib, p.iterations, p.parallelism, Some(KEY_LEN))
            .expect("valid parameters");
        let mut expected = Zeroizing::new([0u8; KEY_LEN]);
        Argon2::new_with_secret(
            pepper.as_bytes(),
            Algorithm::Argon2id,
            Version::V0x13,
            params,
        )
        .expect("valid secret")
        .hash_password_into(b"correct horse", &salt, &mut *expected)
        .expect("derivation");

        let key = derive("correct horse", salt, Some(&pepper));
        assert!(**key == *expected);
    }

    #[test]
    fn out_of_bounds_params_are_rejected() {
        assert!(KdfParams::DEFAULT.validate().is_ok());
        assert!(KdfParams::LEGACY.validate().is_ok());

        let too_weak = KdfParams {
            iterations: 1,
            ..KdfParams::DEFAULT
        };
        assert!(matches!(
            too_weak.validate(),
            Err(Error::UnsupportedKdfParams(params)) if params == too_weak
        ));
    }

    #[test]
    fn zeroize_wipes_key_bytes() {
        use zeroize::Zeroize;

        let mut key = Zeroizing::new([42u8; KEY_LEN]);
        key.zeroize();
        assert!(*key == [0u8; KEY_LEN]);
    }

    #[test]
    fn envelope_round_trip_and_aad() {
        let kek = Kek(Box::new(Zeroizing::new([1u8; KEY_LEN])));
        let data_key = DataKey::generate().expect("generation");

        let envelope = kek.wrap_key(&data_key, b"header").expect("wrap");
        assert_eq!(envelope.len(), ENVELOPE_LEN);

        let unwrapped = kek.unwrap_key(&envelope, b"header").expect("unwrap");
        // `assert!` rather than `assert_eq!`: a failure must not print key bytes.
        assert!(**unwrapped.0 == **data_key.0);

        assert!(matches!(
            kek.unwrap_key(&envelope, b"other header"),
            Err(Error::DecryptionFailed)
        ));
    }

    #[test]
    fn two_vaults_get_different_data_keys() {
        let pepper = Pepper::generate().expect("pepper");
        let a = VaultKey::new("correct horse", &pepper).expect("key creation");
        let b = VaultKey::new("correct horse", &pepper).expect("key creation");
        assert!(**a.data_key.0 != **b.data_key.0);
    }

    #[test]
    fn new_keys_use_the_current_format_and_the_pepper_id() {
        let pepper = Pepper::generate().expect("pepper");
        let key = VaultKey::new("correct horse", &pepper).expect("key creation");
        assert_eq!(key.header.version(), crate::format::FORMAT_VERSION);
        assert_eq!(key.header.pepper_id(), Some(pepper.id()));
        assert_eq!(key.prefix().len(), crate::format::HEADER_LEN + ENVELOPE_LEN);
    }

    #[test]
    fn rewrap_keeps_data_key_but_changes_salt_and_envelope() {
        let pepper = Pepper::generate().expect("pepper");
        let key = VaultKey::new("old password", &pepper).expect("key creation");
        let old_salt = key.header.salt;
        let old_envelope = key.envelope;
        let old_data_key = Zeroizing::new(**key.data_key.0);

        let key = key.rewrap("new password", &pepper).expect("rewrap");
        assert_ne!(key.header.salt, old_salt);
        assert_ne!(key.envelope, old_envelope);
        assert_eq!(key.header.pepper_id(), Some(pepper.id()));
        assert!(**key.data_key.0 == *old_data_key);
    }

    #[test]
    fn opens_with_recognizes_the_current_password_only() {
        let pepper = Pepper::generate().expect("pepper");
        let key = VaultKey::new("old password", &pepper).expect("key creation");
        assert!(key.opens_with("old password", &pepper).expect("derivation"));
        assert!(!key.opens_with("new password", &pepper).expect("derivation"));

        let key = key.rewrap("new password", &pepper).expect("rewrap");
        assert!(key.opens_with("new password", &pepper).expect("derivation"));
        assert!(!key.opens_with("old password", &pepper).expect("derivation"));
    }

    /// A v3 header whose Argon2id parameters Argon2 itself rejects: if the key
    /// were derived, unlocking would fail with `KeyDerivation`.
    fn header_that_cannot_be_derived(pepper: &Pepper) -> Header {
        let params = KdfParams {
            memory_kib: 0,
            ..KdfParams::DEFAULT
        };
        Header::new(params, [7u8; SALT_LEN], pepper.id())
    }

    #[test]
    fn wrong_pepper_is_rejected_before_key_derivation() {
        let right = Pepper::generate().expect("pepper");
        let wrong = Pepper::generate().expect("pepper");
        let header = header_that_cannot_be_derived(&right);

        let result = VaultKey::unlock("pw", header, &[0u8; ENVELOPE_LEN], Some(&wrong));
        assert!(matches!(
            result,
            Err(Error::PepperMismatch { expected, found })
                if expected == right.id() && found == wrong.id()
        ));
    }

    #[test]
    fn missing_pepper_is_rejected_before_key_derivation() {
        let pepper = Pepper::generate().expect("pepper");
        let header = header_that_cannot_be_derived(&pepper);
        assert!(matches!(
            VaultKey::unlock("pw", header, &[0u8; ENVELOPE_LEN], None),
            Err(Error::PepperRequired)
        ));
    }

    #[test]
    fn v2_header_is_derived_without_the_pepper() {
        // A v2 vault built by hand: KEK without pepper, header as AAD.
        let mut header_bytes = crate::format::MAGIC.to_vec();
        header_bytes.push(2);
        for value in [64 * 1024u32, 3, 1] {
            header_bytes.extend_from_slice(&value.to_le_bytes());
        }
        header_bytes.extend_from_slice(&[7u8; SALT_LEN]);
        assert_eq!(header_bytes.len(), HEADER_LEN_V2);
        let header = Header::from_bytes(&header_bytes).expect("v2 header");

        let kek = Kek(derive_key("pw", &header.salt, &header.params, None).expect("derivation"));
        let data_key = DataKey::generate().expect("generation");
        let envelope = kek.wrap_key(&data_key, &header_bytes).expect("wrap");

        // A pepper given for a v2 header is ignored.
        let pepper = Pepper::generate().expect("pepper");
        let key = VaultKey::unlock("pw", header, &envelope, Some(&pepper)).expect("unlock");
        assert!(**key.data_key.0 == **data_key.0);
    }

    #[test]
    fn different_aad_fails_to_decrypt() {
        let key = [42u8; KEY_LEN];
        let encrypted = encrypt(&key, b"hello vault", b"header v1").expect("encryption");
        assert!(decrypt(&key, &encrypted, b"header v1").is_ok());
        assert!(matches!(
            decrypt(&key, &encrypted, b"header v2"),
            Err(Error::DecryptionFailed)
        ));
    }
}
