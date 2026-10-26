//! Cryptography: deriving a key from the master password, envelope encryption
//! and the two levels of authenticated encryption of the vault content.

use crate::format::{Header, VAULT_ID_LEN};
use crate::pepper::Pepper;
use crate::{EntryId, Error, ProtectedField, Result, to_hex};
use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use log::{debug, info};
use sha2::Sha256;
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

// Domain-separation labels. Each one has a single purpose, and none is a
// prefix of another (checked by a test, with the pepper id's label).

/// HKDF `info` of the payload key (level 1).
pub(crate) const PAYLOAD_KEY_LABEL: &[u8] = b"ArgosPass payload key v1";

/// HKDF `info` of the field key (level 2).
pub(crate) const FIELD_KEY_LABEL: &[u8] = b"ArgosPass field key v1";

/// Start of the associated data of every protected field (see [`aad::field`]).
pub(crate) const FIELD_AAD_LABEL: &[u8] = b"ArgosPass field v1";

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

/// Data key: random, generated when the vault is created (and again by
/// `passwd --rotate-key`), and stored in the file wrapped by the [`Kek`].
///
/// From format v4 on, it encrypts nothing itself: the [`PayloadKey`] and the
/// [`FieldKey`] are derived from it.
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

    /// Derives the subkey named by `label` with HKDF-SHA256 (RFC 5869).
    ///
    /// No salt: HKDF's salt is meant for input keys that are not uniformly
    /// random, and the data key already is. The label is HKDF's `info`: two
    /// labels give two independent keys.
    fn derive_subkey(&self, label: &[u8]) -> Result<SecretKey> {
        let hkdf = Hkdf::<Sha256>::new(None, &**self.0);
        let mut key = Box::new(Zeroizing::new([0u8; KEY_LEN]));
        // Only fails for outputs longer than 255 hashes (8160 bytes).
        hkdf.expand(label, &mut **key)
            .map_err(|_| Error::SubkeyDerivation)?;
        Ok(key)
    }
}

/// Payload key (level 1): encrypts the whole JSON content of the vault.
/// Derived from the [`DataKey`].
struct PayloadKey(SecretKey);

/// Field key (level 2): encrypts each protected field (the passwords) inside
/// the JSON content, separately. Derived from the [`DataKey`].
struct FieldKey(SecretKey);

/// Key material of an unlocked vault.
///
/// The master password and the pepper go through Argon2id to give the `Kek`,
/// which only unwraps the `DataKey` stored in the envelope. The KEK is wiped as
/// soon as the envelope is opened. Two subkeys are derived from the data key
/// with HKDF: the payload key encrypts the JSON content (level 1), and the
/// field key encrypts each password inside it (level 2), so that opening the
/// vault does not decrypt every password.
pub struct VaultKey {
    /// Salt, Argon2id parameters, pepper id and vault id.
    pub(crate) header: Header,
    /// The vault id of the header: every protected field is bound to it.
    vault_id: [u8; VAULT_ID_LEN],
    /// The data key, wrapped by the KEK. Public: written as is on every save.
    envelope: [u8; ENVELOPE_LEN],
    /// Only kept to be wrapped again by [`VaultKey::rewrap`].
    data_key: DataKey,
    payload_key: PayloadKey,
    field_key: FieldKey,
}

impl VaultKey {
    /// Creates key material for a new vault: fresh salt, default parameters,
    /// the id of `pepper`, a new random vault id and a new random data key.
    pub fn new(password: &str, pepper: &Pepper) -> Result<Self> {
        Self::seal(
            password,
            fresh_header(pepper, generate_vault_id()?)?,
            DataKey::generate()?,
            pepper,
        )
    }

    /// Wraps the same data key under a new password, with a fresh salt, the
    /// current default Argon2 parameters and `pepper`. The data key, its
    /// subkeys and the vault id do not change: the protected fields stay
    /// valid as they are.
    pub fn rewrap(self, new_password: &str, pepper: &Pepper) -> Result<Self> {
        info!("wrapping the data key under the new password");
        // Moves the box: the data key bytes are not copied.
        Self::seal(
            new_password,
            fresh_header(pepper, self.vault_id)?,
            self.data_key,
            pepper,
        )
    }

    /// Creates key material with a new random data key (so new subkeys) under
    /// `new_password`, for the same vault: the vault id does not change.
    ///
    /// `self` is left as it is: every protected field must still be opened
    /// with it, then sealed again with the new key. Only
    /// [`Vault::rotate_key`](crate::Vault::rotate_key) calls it, so that the
    /// second step cannot be forgotten.
    pub(crate) fn rotate(&self, new_password: &str, pepper: &Pepper) -> Result<Self> {
        info!("generating a new data key");
        Self::seal(
            new_password,
            fresh_header(pepper, self.vault_id)?,
            DataKey::generate()?,
            pepper,
        )
    }

    /// Tells whether `password` (with `pepper`) opens the current envelope,
    /// that is, whether it is the current master password. Costs one Argon2id
    /// derivation.
    ///
    /// Lets the caller compare a new password with the current one without
    /// keeping the current one in memory.
    pub fn opens_with(&self, password: &str, pepper: &Pepper) -> Result<bool> {
        match Self::unlock(password, self.header, &self.envelope, Some(pepper)) {
            Ok(_) => Ok(true), // this second copy of the keys is wiped here
            Err(Error::DecryptionFailed) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Opens the envelope of a vault in the current format with the master
    /// password and `pepper`.
    ///
    /// Fails with [`Error::UnsupportedVersion`] for an older header (see
    /// [`open_old_payload`]), with [`Error::PepperRequired`] or
    /// [`Error::PepperMismatch`] if the pepper is missing or is not the
    /// vault's, and with [`Error::DecryptionFailed`] if the password is wrong
    /// or if the header or the envelope has been modified.
    pub(crate) fn unlock(
        password: &str,
        header: Header,
        envelope: &[u8],
        pepper: Option<&Pepper>,
    ) -> Result<Self> {
        // Checked before running Argon2id: a malformed file must fail fast.
        let vault_id = vault_id_of(&header)?;
        let envelope: [u8; ENVELOPE_LEN] = envelope.try_into().map_err(|_| Error::Truncated)?;

        let data_key = unwrap_data_key(password, &header, &envelope, pepper)?;
        Self::from_parts(header, vault_id, envelope, data_key)
    }

    /// Wraps `data_key` with the KEK derived from `password`, `header` and
    /// `pepper`, whose id the header must carry.
    fn seal(password: &str, header: Header, data_key: DataKey, pepper: &Pepper) -> Result<Self> {
        debug_assert_eq!(header.pepper_id(), Some(pepper.id()));
        let vault_id = vault_id_of(&header)?;
        let envelope = {
            let kek = Kek::derive(password, &header, Some(pepper))?;
            kek.wrap_key(&data_key, &header.to_bytes())?
        }; // the KEK is wiped here

        Self::from_parts(header, vault_id, envelope, data_key)
    }

    /// Assembles the key material of a vault, and derives the two subkeys
    /// from the data key.
    fn from_parts(
        header: Header,
        vault_id: [u8; VAULT_ID_LEN],
        envelope: [u8; ENVELOPE_LEN],
        data_key: DataKey,
    ) -> Result<Self> {
        let payload_key = PayloadKey(data_key.derive_subkey(PAYLOAD_KEY_LABEL)?);
        let field_key = FieldKey(data_key.derive_subkey(FIELD_KEY_LABEL)?);
        debug!("derived the payload key and the field key from the data key (HKDF-SHA256)");

        Ok(Self {
            header,
            vault_id,
            envelope,
            data_key,
            payload_key,
            field_key,
        })
    }

    /// Everything written before the payload: `header || envelope`.
    pub(crate) fn prefix(&self) -> Vec<u8> {
        let mut prefix = Vec::with_capacity(self.header.encoded_len() + ENVELOPE_LEN);
        prefix.extend_from_slice(&self.header.to_bytes());
        prefix.extend_from_slice(&self.envelope);
        prefix
    }

    /// Encrypts the vault content (level 1) with the payload key.
    /// The header and the envelope are authenticated as associated data.
    pub(crate) fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        encrypt(&self.payload_key.0, plaintext, &self.prefix())
    }

    /// Decrypts a payload produced by [`VaultKey::encrypt`].
    pub(crate) fn decrypt(&self, data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        decrypt(&self.payload_key.0, data, &self.prefix())
    }

    /// Encrypts one field of an entry (level 2) with the field key.
    ///
    /// The associated data binds it to this vault, to the entry and to the
    /// field name (see [`aad::field`]): it cannot be opened as another field.
    /// Fails with [`Error::FieldNameTooLong`] if `field_name` is longer than
    /// 255 bytes.
    pub fn seal_field(
        &self,
        entry_id: EntryId,
        field_name: &str,
        plaintext: &str,
    ) -> Result<ProtectedField> {
        let aad = aad::field(&self.vault_id, entry_id, field_name)?;
        debug!("sealing field \"{field_name}\" of entry {entry_id}");
        // Quietly: the size of the field would give the length of the secret.
        let sealed = encrypt_quietly(&self.field_key.0, plaintext.as_bytes(), &aad)?;
        Ok(ProtectedField::from_sealed(sealed))
    }

    /// Decrypts a field sealed by [`VaultKey::seal_field`], into a buffer that
    /// is wiped on drop.
    ///
    /// Fails with [`Error::DecryptionFailed`] if the field was modified, or
    /// sealed for another vault, another entry or another field name.
    pub fn open_field(
        &self,
        entry_id: EntryId,
        field_name: &str,
        field: &ProtectedField,
    ) -> Result<Zeroizing<String>> {
        let aad = aad::field(&self.vault_id, entry_id, field_name)?;
        debug!("opening field \"{field_name}\" of entry {entry_id}");
        let mut bytes = decrypt_quietly(&self.field_key.0, field.as_bytes(), &aad)?;

        // Moved out of the wiped buffer, not copied: `String::from_utf8` keeps
        // the same allocation, which the new `Zeroizing` wipes in turn.
        match String::from_utf8(std::mem::take(&mut *bytes)) {
            Ok(text) => Ok(Zeroizing::new(text)),
            Err(error) => {
                // Not text, so not sealed by `seal_field`: wipe it all the same.
                drop(Zeroizing::new(error.into_bytes()));
                Err(Error::DecryptionFailed)
            }
        }
    }
}

/// Associated data (AAD) of the encrypted parts of a vault.
mod aad {
    use super::{EntryId, Error, FIELD_AAD_LABEL, Result, VAULT_ID_LEN};
    use crate::ENTRY_ID_LEN;

    /// AAD of a protected field: `"ArgosPass field v1" || vault id (16) ||
    /// entry id (16) || length of the field name (1 byte) || field name`.
    ///
    /// Everything before the name has a fixed size, so the name alone would
    /// already be unambiguous. The length prefix keeps the encoding
    /// unambiguous if anything is ever added after the name: without it,
    /// `"pass" || "word…"` and `"password" || "…"` could give the same bytes.
    /// Fails with [`Error::FieldNameTooLong`] if the name does not fit in 255
    /// bytes.
    pub(super) fn field(
        vault_id: &[u8; VAULT_ID_LEN],
        entry_id: EntryId,
        field_name: &str,
    ) -> Result<Vec<u8>> {
        let name = field_name.as_bytes();
        let name_len = u8::try_from(name.len()).map_err(|_| Error::FieldNameTooLong(name.len()))?;

        let mut aad = Vec::with_capacity(
            FIELD_AAD_LABEL.len() + VAULT_ID_LEN + ENTRY_ID_LEN + 1 + name.len(),
        );
        aad.extend_from_slice(FIELD_AAD_LABEL);
        aad.extend_from_slice(vault_id);
        aad.extend_from_slice(entry_id.as_bytes());
        aad.push(name_len);
        aad.extend_from_slice(name);
        Ok(aad)
    }
}

/// Returns the vault id of `header`, or fails with
/// [`Error::UnsupportedVersion`] if its format has none (before v4).
fn vault_id_of(header: &Header) -> Result<[u8; VAULT_ID_LEN]> {
    header
        .vault_id()
        .ok_or(Error::UnsupportedVersion(header.version()))
}

/// Unwraps the data key from the envelope of a vault in format v2 or later.
///
/// `pepper` is only used if the header has a pepper id (format v3 and
/// later): it must then be the pepper with that id. Both are checked before
/// Argon2id runs.
fn unwrap_data_key(
    password: &str,
    header: &Header,
    envelope: &[u8; ENVELOPE_LEN],
    pepper: Option<&Pepper>,
) -> Result<DataKey> {
    // Checked before running Argon2id: the pepper id is public, so a missing
    // or wrong pepper can be reported without a derivation.
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
        let kek = Kek::derive(password, header, pepper)?;
        kek.unwrap_key(envelope, &header.to_bytes())?
    }; // the KEK is wiped here
    info!("envelope opened");
    Ok(data_key)
}

/// Decrypts the payload of a vault in format v2 or v3, where the data key
/// itself encrypted the JSON content, with `header || envelope` as associated
/// data.
///
/// Only for upgrading such a vault: the old data key is wiped before this
/// returns, and never becomes a [`VaultKey`], so nothing can be encrypted
/// with it any more. Fails as [`VaultKey::unlock`] does.
pub(crate) fn open_old_payload(
    password: &str,
    header: &Header,
    envelope: &[u8],
    payload: &[u8],
    pepper: Option<&Pepper>,
) -> Result<Zeroizing<Vec<u8>>> {
    let envelope: [u8; ENVELOPE_LEN] = envelope.try_into().map_err(|_| Error::Truncated)?;
    let data_key = unwrap_data_key(password, header, &envelope, pepper)?;

    let mut aad = header.to_bytes();
    aad.extend_from_slice(&envelope);
    decrypt(&data_key.0, payload, &aad)
}

/// Header for a new KEK: fresh random salt, the default Argon2id parameters,
/// the id of `pepper` and `vault_id`.
fn fresh_header(pepper: &Pepper, vault_id: [u8; VAULT_ID_LEN]) -> Result<Header> {
    Ok(Header::new(
        KdfParams::DEFAULT,
        generate_salt()?,
        pepper.id(),
        vault_id,
    ))
}

/// Generates a random vault id using the operating system's CSPRNG.
fn generate_vault_id() -> Result<[u8; VAULT_ID_LEN]> {
    let mut vault_id = [0u8; VAULT_ID_LEN];
    getrandom::fill(&mut vault_id)?;
    debug!("generated random vault id: {}", to_hex(&vault_id));
    Ok(vault_id)
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
///
/// Logs the nonce, the sizes and the tag at `-vv`: for an envelope or a
/// payload, whose size is visible in the file anyway.
pub fn encrypt(key: &[u8; KEY_LEN], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let output = encrypt_quietly(key, plaintext, aad)?;
    let (nonce, ciphertext) = output.split_at(NONCE_LEN);
    debug!("generated random nonce: {}", to_hex(nonce));
    debug!(
        "encrypted {} bytes -> {} bytes of ciphertext + tag (tag: {})",
        plaintext.len(),
        ciphertext.len(),
        to_hex(&ciphertext[ciphertext.len() - TAG_LEN..])
    );
    Ok(output)
}

/// Decrypts data produced by [`encrypt`].
///
/// Fails with [`Error::DecryptionFailed`] if the key is wrong or if the data
/// (or the associated data) has been modified.
///
/// Logs the nonce, the size and the tag at `-vv`, like [`encrypt`].
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
    decrypt_quietly(key, data, aad)
}

/// [`encrypt`] without any log. For protected fields: the size of one is the
/// length of the secret it holds, so it must not reach the logs.
fn encrypt_quietly(key: &[u8; KEY_LEN], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
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
    let mut output = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// [`decrypt`] without any log, for the same reason as [`encrypt_quietly`].
fn decrypt_quietly(key: &[u8; KEY_LEN], data: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if data.len() < NONCE_LEN + TAG_LEN {
        return Err(Error::Truncated);
    }

    let (nonce, ciphertext) = data.split_at(NONCE_LEN);
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
impl VaultKey {
    /// Key material for unit tests, without Argon2id (too slow to run in every
    /// test): a random data key and vault id, and a dummy envelope.
    pub(crate) fn for_tests() -> Self {
        let vault_id = generate_vault_id().expect("vault id");
        let header = Header::new(
            KdfParams::MINIMUM,
            [7u8; SALT_LEN],
            [9u8; crate::pepper::PEPPER_ID_LEN],
            vault_id,
        );
        let data_key = DataKey::generate().expect("data key");
        Self::from_parts(header, vault_id, [0u8; ENVELOPE_LEN], data_key).expect("subkeys")
    }
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
    fn two_vaults_get_different_data_keys_and_vault_ids() {
        let pepper = Pepper::generate().expect("pepper");
        let a = VaultKey::new("correct horse", &pepper).expect("key creation");
        let b = VaultKey::new("correct horse", &pepper).expect("key creation");
        assert!(**a.data_key.0 != **b.data_key.0);
        assert_ne!(a.vault_id, b.vault_id);
    }

    #[test]
    fn new_keys_use_the_current_format_the_pepper_id_and_a_vault_id() {
        let pepper = Pepper::generate().expect("pepper");
        let key = VaultKey::new("correct horse", &pepper).expect("key creation");
        assert_eq!(key.header.version(), crate::format::FORMAT_VERSION);
        assert_eq!(key.header.pepper_id(), Some(pepper.id()));
        assert_eq!(key.header.vault_id(), Some(key.vault_id));
        assert_eq!(key.prefix().len(), crate::format::HEADER_LEN + ENVELOPE_LEN);
    }

    #[test]
    fn rewrap_keeps_the_keys_and_vault_id_but_changes_salt_and_envelope() {
        let pepper = Pepper::generate().expect("pepper");
        let key = VaultKey::new("old password", &pepper).expect("key creation");
        let old_salt = key.header.salt;
        let old_envelope = key.envelope;
        let old_vault_id = key.vault_id;
        let old_data_key = Zeroizing::new(**key.data_key.0);
        let old_field_key = Zeroizing::new(**key.field_key.0);

        let key = key.rewrap("new password", &pepper).expect("rewrap");
        assert_ne!(key.header.salt, old_salt);
        assert_ne!(key.envelope, old_envelope);
        assert_eq!(key.header.pepper_id(), Some(pepper.id()));
        assert_eq!(key.vault_id, old_vault_id);
        assert_eq!(key.header.vault_id(), Some(old_vault_id));
        assert!(**key.data_key.0 == *old_data_key);
        assert!(**key.field_key.0 == *old_field_key);
    }

    #[test]
    fn rotate_changes_the_keys_but_keeps_the_vault_id() {
        let pepper = Pepper::generate().expect("pepper");
        let old = VaultKey::new("old password", &pepper).expect("key creation");
        let new = old.rotate("new password", &pepper).expect("rotation");

        assert_eq!(new.vault_id, old.vault_id);
        assert_eq!(new.header.vault_id(), Some(old.vault_id));
        assert_ne!(new.header.salt, old.header.salt);
        assert!(**new.data_key.0 != **old.data_key.0);
        assert!(**new.payload_key.0 != **old.payload_key.0);
        assert!(**new.field_key.0 != **old.field_key.0);
        assert!(new.opens_with("new password", &pepper).expect("derivation"));
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
        Header::new(params, [7u8; SALT_LEN], pepper.id(), [5u8; VAULT_ID_LEN])
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

    /// A v2 header built by hand, with the weakest accepted parameters.
    fn v2_header() -> (Header, Vec<u8>) {
        let mut header_bytes = crate::format::MAGIC.to_vec();
        header_bytes.push(2);
        for value in [64 * 1024u32, 3, 1] {
            header_bytes.extend_from_slice(&value.to_le_bytes());
        }
        header_bytes.extend_from_slice(&[7u8; SALT_LEN]);
        assert_eq!(header_bytes.len(), HEADER_LEN_V2);
        let header = Header::from_bytes(&header_bytes).expect("v2 header");
        (header, header_bytes)
    }

    #[test]
    fn v2_header_is_derived_without_the_pepper() {
        // A v2 envelope built by hand: KEK without pepper, header as AAD.
        let (header, header_bytes) = v2_header();
        let kek = Kek(derive_key("pw", &header.salt, &header.params, None).expect("derivation"));
        let data_key = DataKey::generate().expect("generation");
        let envelope = kek.wrap_key(&data_key, &header_bytes).expect("wrap");

        // A pepper given for a v2 header is ignored.
        let pepper = Pepper::generate().expect("pepper");
        let unwrapped = unwrap_data_key("pw", &header, &envelope, Some(&pepper)).expect("unwrap");
        assert!(**unwrapped.0 == **data_key.0);
    }

    #[test]
    fn older_headers_cannot_become_a_vault_key() {
        // Rejected before any derivation: with a derivation, a wrong envelope
        // would give `DecryptionFailed` instead.
        let (header, _) = v2_header();
        assert!(matches!(
            VaultKey::unlock("pw", header, &[0u8; ENVELOPE_LEN], None),
            Err(Error::UnsupportedVersion(2))
        ));
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

    // Two-level encryption (format v4).

    /// An entry id for tests.
    fn entry(byte: u8) -> EntryId {
        EntryId::from_bytes([byte; crate::ENTRY_ID_LEN])
    }

    #[test]
    fn subkeys_match_their_definition() {
        // Part of the file format: computed independently with Python's
        // hmac and hashlib, following RFC 5869 (no salt: 32 zero bytes).
        let data_key = DataKey(Box::new(Zeroizing::new([0x42; KEY_LEN])));
        let payload_key = data_key.derive_subkey(PAYLOAD_KEY_LABEL).expect("HKDF");
        let field_key = data_key.derive_subkey(FIELD_KEY_LABEL).expect("HKDF");
        // Test values: compared as hex with `assert!` all the same.
        assert!(
            to_hex(&**payload_key)
                == "7fee9ae1a306253e3a28f70cf1fed2e5c345bc67ecce4f40d1f5ee6c19da7a6f"
        );
        assert!(
            to_hex(&**field_key)
                == "127d370b3505552370f181dc1bdc7498cc04d91b2ddbbcf9289d49614257e39f"
        );
    }

    #[test]
    fn payload_key_field_key_and_data_key_all_differ() {
        let key = VaultKey::for_tests();
        assert!(**key.payload_key.0 != **key.field_key.0);
        assert!(**key.payload_key.0 != **key.data_key.0);
        assert!(**key.field_key.0 != **key.data_key.0);
    }

    #[test]
    fn labels_are_distinct_and_none_is_a_prefix_of_another() {
        // A label is followed by other data in the hash, HKDF or AAD input:
        // a label that starts another one could give the same bytes.
        let labels = [
            PAYLOAD_KEY_LABEL,
            FIELD_KEY_LABEL,
            FIELD_AAD_LABEL,
            crate::pepper::ID_DOMAIN,
        ];
        for (i, a) in labels.iter().enumerate() {
            for (j, b) in labels.iter().enumerate() {
                if i != j {
                    assert!(!b.starts_with(a), "{a:?} starts {b:?}");
                }
            }
        }
    }

    #[test]
    fn payload_is_encrypted_with_the_payload_key_not_the_data_key() {
        let key = VaultKey::for_tests();
        let payload = key.encrypt(b"{}").expect("encryption");
        assert!(key.decrypt(&payload).is_ok());
        assert!(matches!(
            decrypt(&key.data_key.0, &payload, &key.prefix()),
            Err(Error::DecryptionFailed)
        ));
        assert!(decrypt(&key.payload_key.0, &payload, &key.prefix()).is_ok());
    }

    #[test]
    fn field_round_trip() {
        let key = VaultKey::for_tests();
        let field = key
            .seal_field(entry(1), "password", "correct horse")
            .expect("seal");
        // nonce || ciphertext (as long as the text) || tag
        assert_eq!(field.as_bytes().len(), NONCE_LEN + 13 + TAG_LEN);
        assert!(!field.as_bytes().windows(5).any(|w| w == b"horse"));

        let opened = key.open_field(entry(1), "password", &field).expect("open");
        assert!(*opened == "correct horse");
    }

    #[test]
    fn sealing_the_same_text_twice_gives_different_fields() {
        let key = VaultKey::for_tests();
        let a = key.seal_field(entry(1), "password", "same").expect("seal");
        let b = key.seal_field(entry(1), "password", "same").expect("seal");
        assert!(a.as_bytes() != b.as_bytes());
    }

    #[test]
    fn a_field_only_opens_as_the_field_it_was_sealed_as() {
        let key = VaultKey::for_tests();
        let field = key
            .seal_field(entry(1), "password", "secret")
            .expect("seal");

        // Another entry, or another field name.
        for (entry_id, name) in [(entry(2), "password"), (entry(1), "username")] {
            assert!(matches!(
                key.open_field(entry_id, name, &field),
                Err(Error::DecryptionFailed)
            ));
        }

        // Another vault with the very same keys: only the vault id differs,
        // so only the associated data can make it fail.
        let other_vault_id = [0xee; VAULT_ID_LEN];
        assert_ne!(other_vault_id, key.vault_id);
        let header = Header::new(
            key.header.params,
            key.header.salt,
            key.header.pepper_id().expect("v4 header"),
            other_vault_id,
        );
        let same_data_key = DataKey(Box::new(Zeroizing::new(**key.data_key.0)));
        let other = VaultKey::from_parts(header, other_vault_id, key.envelope, same_data_key)
            .expect("subkeys");
        assert!(**other.field_key.0 == **key.field_key.0);
        assert!(matches!(
            other.open_field(entry(1), "password", &field),
            Err(Error::DecryptionFailed)
        ));

        // A modified byte.
        let mut bytes = field.as_bytes().to_vec();
        bytes[NONCE_LEN] ^= 0x01;
        let tampered = ProtectedField::from_sealed(bytes);
        assert!(matches!(
            key.open_field(entry(1), "password", &tampered),
            Err(Error::DecryptionFailed)
        ));
    }

    #[test]
    fn field_aad_has_the_documented_layout() {
        let aad = aad::field(&[1u8; VAULT_ID_LEN], entry(2), "password").expect("AAD");
        let mut expected = b"ArgosPass field v1".to_vec();
        expected.extend_from_slice(&[1u8; VAULT_ID_LEN]);
        expected.extend_from_slice(&[2u8; crate::ENTRY_ID_LEN]);
        expected.push(8);
        expected.extend_from_slice(b"password");
        assert_eq!(aad, expected);
        assert_eq!(aad.len(), 18 + 16 + 16 + 1 + 8);
    }

    #[test]
    fn field_names_that_start_one_another_give_different_aads() {
        // With the name last, these would differ even without the length
        // prefix (see `aad::field`): the prefix is what keeps them apart if
        // anything is ever added after the name.
        let vault_id = [1u8; VAULT_ID_LEN];
        let pairs = [("pass", "password"), ("", "\0"), ("a", "a\u{1}")];
        for (short, long) in pairs {
            let a = aad::field(&vault_id, entry(2), short).expect("AAD");
            let b = aad::field(&vault_id, entry(2), long).expect("AAD");
            assert_ne!(a, b);
            // The byte right after the ids is the length, not the name.
            let at = FIELD_AAD_LABEL.len() + VAULT_ID_LEN + crate::ENTRY_ID_LEN;
            assert_eq!(usize::from(a[at]), short.len());
            assert_eq!(usize::from(b[at]), long.len());
        }
    }

    #[test]
    fn field_names_longer_than_255_bytes_are_rejected() {
        let key = VaultKey::for_tests();
        assert!(key.seal_field(entry(1), &"a".repeat(255), "x").is_ok());
        assert!(matches!(
            key.seal_field(entry(1), &"a".repeat(256), "x"),
            Err(Error::FieldNameTooLong(256))
        ));
        // In bytes, not characters: 128 two-byte characters are 256 bytes.
        assert!(matches!(
            key.seal_field(entry(1), &"é".repeat(128), "x"),
            Err(Error::FieldNameTooLong(256))
        ));
    }
}
