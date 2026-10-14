# ArgosPass

A command-line password manager written in Rust. Entries live in a single local file, encrypted with a random key that only your master password can unlock.

> ⚠️ **Personal learning project.** ArgosPass is still in development and it has not been audited by a third party. Use it at your own risk and keep backups of your vault.

## Installation

### Requirements

- A recent stable [Rust toolchain](https://rustup.rs) (edition 2024)
- On Linux: a C linker (`sudo apt install build-essential`)
- For clipboard support on Linux: a graphical session (X11 or Wayland; WSLg works under WSL)

### Build and install

```bash
git clone git@github.com:aymericfaivrepro-gh/argospass.git
cd argospass
cargo install --path .
```

This installs the `argospass` binary in `~/.cargo/bin`. Make sure that directory is in your `PATH`.

To update after pulling new commits, run `cargo install --path .` again.

## Usage

### Quick start

```bash
argospass init                                        # create a new vault (asks for a master password twice)
argospass add GitHub aymeric https://github.com       # add an entry; the password is typed with hidden input
argospass add Mail aymeric --generate                 # add an entry with a generated password
argospass list                                        # list entry titles
argospass get GitHub                                  # copy the password to the clipboard for 20 s
argospass get GitHub --show                           # print the password in the terminal instead
argospass remove GitHub                               # remove an entry
argospass generate                                    # print a random password (no vault needed)
argospass passwd                                      # change the master password
argospass --help                                      # full help (also: argospass <command> --help)
```

### Commands

| Command | Description | Needs the master password |
| --- | --- | --- |
| `init` | Create a new, empty vault | Chooses it |
| `add <TITLE> <USERNAME> [URL]` | Add an entry. Asks for the password, or generates one with `-g` / `--generate`. Titles must be unique. | Yes |
| `list` | List all entries (no passwords shown) | Yes |
| `get <TITLE>` | Copy the entry's password to the clipboard and clear it after 20 seconds. `--show` prints it instead. | Yes |
| `remove <TITLE>` | Delete an entry | Yes |
| `generate` | Print a random password: 24 characters by default (minimum 8), symbols included unless `--no-symbols` is given | No |
| `passwd [--rotate-key]` | Change the master password. `--rotate-key` also generates a new data key. Without `--rotate-key`, the new password must differ from the current one. See [Changing the master password](#changing-the-master-password). | Yes, then chooses the new one |

You get **3 attempts** to type the master password.

The clipboard is only cleared if it still contains the password ArgosPass put there, so anything you copied in the meantime is not erased.

### Global options

| Option | Effect |
| --- | --- |
| `--vault <PATH>` | Use another vault file |
| `ARGOSPASS_VAULT=<PATH>` | Same, through an environment variable |
| `-v` | Show the main steps (key derivation time, file read/written…) |
| `-vv` | Show every detail (sizes, salt, nonces, tags, Argon2 parameters, generator statistics…) |

Logs go to **stderr**, so they never mix with a command's output. They only show public values. The master password, keys, decrypted content and entry passwords are never logged.

### Vault location

| System | Default path |
| --- | --- |
| Linux | `~/.local/share/argospass/vault.argos` |
| macOS | `~/Library/Application Support/argospass/vault.argos` |
| Windows | `%APPDATA%\argospass\vault.argos` |

The previous version of the vault is kept next to it, under the vault's file name followed by `.bak` (`vault.argos.bak`). After `passwd`, the backup is replaced by the new version, so that no file encrypted under the old password is left next to the vault.

Earlier versions of ArgosPass named the backup of a vault whose name does not end in `.argos` after the name without its extension (`secrets.argos.bak` for `secrets.db`). ArgosPass no longer writes or replaces that file: delete it yourself, it may still open with an old password.

> ⚠️ ArgosPass is developed and tested on Linux (including WSL). Windows and macOS paths are given for reference; these platforms are not tested yet.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | Other error |
| `2` | Invalid command-line usage |
| `3` | Wrong master password, or corrupted vault |
| `4` | Invalid or unsupported vault file |
| `5` | Input/output error |
| `6` | No entry with this title |
| `7` | An entry with this title already exists |

## Security model

### What ArgosPass protects against

| Threat | Protection |
| --- | --- |
| **Theft of the vault file** (lost laptop, leaked cloud copy, backup) | Content is encrypted. An attacker must guess the master password, and each guess costs a full Argon2id derivation: tens of megabytes of memory and a noticeable delay. |
| **Modification of the vault file** | Every byte is authenticated: the envelope and the content by their Poly1305 tags, the header and the envelope as associated data. Any change makes opening fail. |
| **Downgrade of the key derivation** (an attacker lowers the Argon2 parameters in the header to speed up guessing) | Parameters are authenticated, and values below a security floor are refused before any derivation. |
| **Absurd parameters in a crafted file** (memory exhaustion) | Values above an upper limit are refused. |
| **Crash or power loss during a save** | Atomic write: the old vault stays intact until the new one is fully on disk, and a `.bak` copy is kept. |
| **Other users of the same machine** | On Unix, the vault is created with `600` permissions and its directory with `700`. |
| **Shoulder surfing and shell history** | Passwords are never command-line arguments and are typed with hidden input. By default, `get` copies to the clipboard instead of printing. |
| **Secrets lingering in memory** | Keys, decrypted content and passwords are overwritten when no longer needed (see [Secrets in memory](#secrets-in-memory)). |

### What ArgosPass does not protect against

- **A compromised machine.** Malware, a keylogger or an administrator can read the master password as you type it, or the decrypted vault while ArgosPass runs. No password manager can defend against that.
- **A weak master password.** Argon2id slows down guessing but cannot save a short or common password. Use a long passphrase, for example 5 or more random words.
- **A forgotten master password.** There is no recovery mechanism or back door. A lost password means a lost vault.
- **Rollback.** An attacker who can write the file can replace it with an **older, valid** version of your vault, and ArgosPass will not notice yet.
- **Metadata.** The file size reveals the approximate size of the content, so roughly how many entries you have. The modification date shows when you last changed it.

## Cryptography

Only audited, widely used implementations from the [RustCrypto](https://github.com/RustCrypto) project are used. ArgosPass contains no custom cryptographic primitive.

| Role | Algorithm | Crate |
| --- | --- | --- |
| Key derivation from the master password | **Argon2id** (RFC 9106), version 0x13 | `argon2` |
| Authenticated encryption (of the data key and of the entries) | **XChaCha20-Poly1305** (AEAD) | `chacha20poly1305` |
| Randomness (salt, nonces, data key, generated passwords) | Operating system CSPRNG | `getrandom` |
| Memory wiping | Volatile writes that the compiler cannot optimize away | `zeroize` |

### Two keys: envelope encryption

ArgosPass uses two 256-bit keys:

- the **key-encryption key (KEK)** is derived from the master password with Argon2id. Its only job is to encrypt the data key;
- the **data key** is drawn at random when the vault is created and never changes. It encrypts the entries.

The data key, encrypted with the KEK, is stored in the file: this is the **envelope**.

### How a vault is opened

```
master password ─┐
salt (header) ───┼──► Argon2id ──► KEK
parameters ──────┘                  │
                                    ▼
envelope ────────────────► XChaCha20-Poly1305 ◄── AAD: header
                                    │  verify tag, decrypt
                                    ▼
                                data key
                                    │
                                    ▼
payload ─────────────────► XChaCha20-Poly1305 ◄── AAD: header ‖ envelope
                                    │  verify tag, decrypt
                                    ▼
                              JSON entries
```

1. ArgosPass reads the header and checks the magic bytes, the format version, the Argon2 parameters and the file length, all before any key derivation.
2. The master password and the salt go through Argon2id with the parameters from the header. The output is the KEK.
3. The KEK opens the envelope: XChaCha20-Poly1305 checks the envelope's tag over the encrypted data key **and the header**, then decrypts the data key. The KEK is wiped right away.
4. The data key decrypts the payload. Its tag covers the ciphertext **and everything before it** (header and envelope).
5. If a tag does not match (wrong password, modified file), nothing is decrypted, and the error does not say which of the two happened.

### How a vault is saved

1. The entries are serialized to JSON into a buffer that will be wiped afterwards.
2. A new random 24-byte nonce is generated. **Every save uses a fresh nonce**, so the payload changes completely even when its content does not.
3. The JSON is encrypted with the data key, with the header and the envelope as associated data.
4. The file (`header ‖ envelope ‖ new payload`) is written atomically (see [Atomic writes](#atomic-writes)).

Saving needs neither the master password nor Argon2id: the data key is kept in memory while the command runs, and the header and the envelope are written back unchanged. The salt and the parameters only change with the master password, and the data key only with `passwd --rotate-key`.

### Changing the master password

1. `passwd` unlocks the vault with the current password, then asks for the new one twice.
2. Without `--rotate-key`, a new password identical to the current one is refused: keeping both the password and the data key would bring no security. The current password is not kept in memory for this: ArgosPass tries the new password on the current envelope, which costs one more Argon2id run. With `--rotate-key`, the same password is accepted.
3. A new KEK is derived from the new password, with a **new salt** and the current default Argon2 parameters.
4. The same data key is wrapped with the new KEK. With `--rotate-key`, a new random data key is generated instead.
5. The vault is saved, then the `.bak` backup is replaced by the new version.

**Plain `passwd` or `--rotate-key`?** A plain `passwd` keeps the data key. Someone who already got the data key, from a copy of the vault made before the change and the old password, can still decrypt every later version of the vault, whatever the new password. Only `--rotate-key` revokes them: the entries are then encrypted with a new key, and an old copy only reveals the entries as they were when it was made. Use `--rotate-key` if the old password may have leaked.

`--rotate-key` also accepts the current password as the new one, to replace only the data key, for example if the data key alone may have been exposed. This does not help if the password itself may have leaked: whoever knows it can open the new vault too. Choose a new password in that case.

### Why these choices

- **Argon2id** is memory-hard: each guess needs a large block of memory, which makes GPU and ASIC attacks much more expensive than with PBKDF2 or bcrypt. The `id` variant combines resistance to side channels and to GPU attacks. It won the Password Hashing Competition and is the RFC 9106 recommendation.
- **XChaCha20-Poly1305** is an AEAD: it encrypts **and** authenticates in a single operation, so tampering is always detected. Its 192-bit nonce is large enough to be drawn at random on every save with no realistic risk of collision. ChaCha20 is also fast and constant-time in software, without needing AES hardware instructions.
- **Envelope encryption** keeps the password-derived key away from the data: the KEK only ever encrypts 32 random bytes, and the entries are encrypted with a key that does not depend on the password at all. It also makes master-password changes simple: `passwd` wraps the same data key again with the new KEK. The payload is still re-encrypted, as on every save, since its associated data includes the header and the envelope.
- **256-bit keys** keep a comfortable margin, including against quantum attacks on symmetric cryptography (Grover's algorithm only halves the effective strength).

### Argon2id parameters

|  | Memory | Iterations | Parallelism |
| --- | --- | --- | --- |
| New vaults | 128 MiB | 3 | 4 |
| Minimum accepted | 64 MiB | 3 | 1 |
| Maximum accepted | 4 GiB | 64 | 64 |

Parameters are stored in each vault's header, so the defaults can be raised later without breaking existing vaults.

### Password generator

Characters are drawn from up to 4 sets, using the OS CSPRNG:

| Set | Characters |
| --- | --- |
| Lowercase | `a`–`z` (26) |
| Uppercase | `A`–`Z` (26) |
| Digits | `0`–`9` (10) |
| Symbols | `!#$%&()*+,-./:;<=>?@[]^_{\|}~` (28) |

Each character is chosen with **rejection sampling**: random bytes that would make some characters more likely than others are discarded. Every character is therefore exactly equally likely.

| Settings | Entropy per character | 24 characters |
| --- | --- | --- |
| With symbols (90 characters) | ≈ 6.49 bits | ≈ 155 bits |
| Without symbols (62 characters) | ≈ 5.95 bits | ≈ 142 bits |

## Vault file format

### Version 2 (current)

| Offset | Size | Part | Field |
| --- | --- | --- | --- |
| 0 | 5 | Header | Magic bytes `ARGOS`, to recognize the file |
| 5 | 1 | Header | Format version (`2`) |
| 6 | 4 | Header | Argon2 memory in KiB (little-endian) |
| 10 | 4 | Header | Argon2 iterations (little-endian) |
| 14 | 4 | Header | Argon2 parallelism (little-endian) |
| 18 | 16 | Header | Random salt |
| 34 | 24 | Envelope | Random nonce |
| 58 | 32 | Envelope | Data key, encrypted with the KEK |
| 90 | 16 | Envelope | Poly1305 authentication tag |
| 106 | 24 | Payload | Random nonce |
| 130 | n | Payload | Encrypted JSON |
| 130 + n | 16 | Payload | Poly1305 authentication tag |

The header (34 bytes) and the envelope (72 bytes) are stored **in clear**, since they are needed to unlock the vault, but they are **authenticated**: the header is the associated data of the envelope, and the header and the envelope together are the associated data of the payload. Changing a single bit anywhere makes opening fail. An empty vault takes 160 bytes.

The salt and the nonces are not secret. Their job is to be unique: the salt makes each vault's KEK different even with the same password (and rules out precomputed tables), and the nonces make each encryption different.

### Version 1 (legacy)

Version 1 had the same header (with version `1`), followed directly by `nonce (24) ‖ encrypted JSON ‖ tag (16)`: the entries were encrypted with the key derived from the master password, with the header as associated data. An empty vault took 88 bytes.

These files are still opened, then **automatically re-saved in version 2** with a new salt, the current Argon2 parameters and a new random data key (the old derived key is never reused). A warning is shown when this happens, only after the vault was decrypted successfully. The version 1 file is kept as the `.bak` backup.

### Legacy format (version 0)

The first versions of ArgosPass wrote `salt (16) ‖ nonce (24) ‖ ciphertext ‖ tag (16)`, with no header and no associated data. These files are still recognized (no magic bytes), opened with the default parameters of the time, and **automatically re-saved in the current version**, like version 1 files. A warning is shown when this happens.

### Decrypted content

Once decrypted, the vault is a JSON document:

```json
{
  "entries": [
    {
      "title": "GitHub",
      "username": "User",
      "password": "password",
      "url": "https://github.com"
    }
  ]
}
```

This plaintext only ever exists in memory. It is never written to disk.

### Atomic writes

```
vault.argos.tmp  ← 1. write the new content (permissions 600), then fsync to force it onto the disk
vault.argos.bak  ← 2. copy of the current vault
vault.argos      ← 3. atomic rename of .tmp over the vault
vault.argos.bak  ← 4. passwd only: replaced by a copy of the new vault
```

The rename is atomic: at any moment, `vault.argos` is either the complete old version or the complete new one, never a half-written file.

## Secrets in memory

When freed, memory is not erased: secrets could remain in RAM, then end up in a core dump or in swap. ArgosPass overwrites them with zeros as soon as they are no longer needed:

| Secret | Protection |
| --- | --- |
| Key-encryption key (KEK) | `Box<Zeroizing<[u8; 32]>>`: stored once on the heap (never copied around the stack). Wiped right after opening (or creating) the envelope, so it is never kept while the vault is open |
| Data key | `Box<Zeroizing<[u8; 32]>>`: drawn at random directly into a zeroed heap buffer, or decrypted into a `Zeroizing<Vec<u8>>` and copied into one, so it never touches the stack. Kept while the command runs (saving needs it) and wiped on drop |
| Keys of the old formats (v1, legacy) | Wiped right after decrypting the old file, before the upgrade |
| Key copy inside the cipher | Each XChaCha20-Poly1305 instance keeps its own copy of the key. It only lives for one encryption or decryption, and the `chacha20poly1305` crate wipes it on drop |
| Argon2 working memory (128 MiB by default) | Allocated by ArgosPass in a `Zeroizing` buffer and wiped after the derivation. The `argon2` crate would otherwise free it without wiping it. |
| Decrypted JSON | `Zeroizing<Vec<u8>>` |
| JSON before encryption | Exact size computed first, so the buffer never reallocates and leaves no unwiped copies behind |
| Entries | `Entry` implements `ZeroizeOnDrop`: every field is wiped when the entry is dropped |
| Master passwords (current and new), generated passwords, clipboard read-back | `Zeroizing<String>`. The current password is wiped as soon as the vault is unlocked, even by `passwd` |

## Known limitations

- **Swap:** memory pages are not locked (`mlock`), so the operating system could write a secret to swap before it is wiped.
- **Copies outside ArgosPass:** the terminal (with `--show`), the clipboard, and especially **clipboard history** tools (`Win + V` on Windows, clipboard managers on Linux) may keep a copy that ArgosPass cannot erase.
- **Ctrl+C during `get`:** interrupting the 20-second countdown leaves the password in the clipboard.
- **Whole vault decrypted at once:** every entry is in clear in memory while a command runs, not only the one you asked for.
- **No rollback protection** and **file size not hidden** (see [Security model](#security-model)).
- **Old copies keep the old password:** copies of the vault made before a password change (cloud history, backups, other computers) still open with the old password.

## Development

```bash
cargo build                                         # build
cargo test --locked                                 # unit and integration tests
cargo fmt --all                                     # format
cargo clippy --all-targets --locked -- -D warnings  # lint (warnings are errors)
cargo audit                                         # check dependencies against RustSec (cargo install cargo-audit)
```

The CI (`.github/workflows/ci.yml`) runs the same checks on every push.

### Project layout

```
src/
├── main.rs        command-line interface (clap), prompts, clipboard, exit codes
├── lib.rs         Entry, Vault, open/save, atomic writes
├── crypto.rs      Argon2id derivation, envelope encryption (KEK, data key), XChaCha20-Poly1305, KdfParams, VaultKey
├── format.rs      vault header: serialization, parsing, validation, format versions
├── generator.rs   password generator
└── error.rs       error type
tests/
└── vault.rs       integration tests on real vault files
```

### Tests

Unit tests live next to the code they test. Integration tests in `tests/vault.rs` check, among other things:

- a vault can be saved and reopened;
- a wrong password is rejected;
- no secret appears in clear in the file;
- the backup is kept and no temporary file is left behind;
- the file has `600` permissions (Unix only);
- new vaults use format v2 (160 bytes when empty);
- a modified header or envelope is rejected;
- v1 and legacy vaults are upgraded to the current format;
- after a password change (with or without `--rotate-key`), the vault and its backup open with the new password only, and the backup keeps `600` permissions.

During development, always use a test vault (`--vault /tmp/...`), never your real one. Vault files (`*.argos`, `*.argos.*`) are ignored by Git.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
