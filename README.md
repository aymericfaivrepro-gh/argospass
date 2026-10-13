# ArgosPass

A command-line password manager written in Rust. Entries live in a single local file, encrypted with a key derived from your master password.

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

You get **3 attempts** to type the master password.

The clipboard is only cleared if it still contains the password ArgosPass put there, so anything you copied in the meantime is not erased.

### Global options

| Option | Effect |
| --- | --- |
| `--vault <PATH>` | Use another vault file |
| `ARGOSPASS_VAULT=<PATH>` | Same, through an environment variable |
| `-v` | Show the main steps (key derivation time, file read/written…) |
| `-vv` | Show every detail (sizes, salt, nonce, Argon2 parameters, generator statistics…) |

Logs go to **stderr**, so they never mix with a command's output. They only show public values. The master password, keys, decrypted content and entry passwords are never logged.

### Vault location

| System | Default path |
| --- | --- |
| Linux | `~/.local/share/argospass/vault.argos` |
| macOS | `~/Library/Application Support/argospass/vault.argos` |
| Windows | `%APPDATA%\argospass\vault.argos` |

The previous version of the vault is kept next to it as `vault.argos.bak`.

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
| **Modification of the vault file** | Every byte is authenticated: the content by the Poly1305 tag, the header as associated data. Any change makes opening fail. |
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
| Authenticated encryption | **XChaCha20-Poly1305** (AEAD) | `chacha20poly1305` |
| Randomness (salt, nonce, generated passwords) | Operating system CSPRNG | `getrandom` |
| Memory wiping | Volatile writes that the compiler cannot optimize away | `zeroize` |

### How a vault is opened

```
master password ─┐
salt (header) ───┼──► Argon2id ──► 256-bit key ─┐
parameters ──────┘   (header)                   │
                                                ▼
header (as AAD) ──────────────────►  XChaCha20-Poly1305  ──►  JSON entries
nonce ‖ ciphertext ‖ tag ─────────►  decrypt + verify tag
```

1. ArgosPass reads the header and checks the magic bytes, the format version and the Argon2 parameters.
2. The master password and the salt go through Argon2id with the parameters from the header. The output is a 256-bit key.
3. XChaCha20-Poly1305 checks the authentication tag over the ciphertext **and the header**, then decrypts.
4. If the tag does not match (wrong password, modified file), nothing is decrypted, and the error does not say which of the two happened.

### How a vault is saved

1. The entries are serialized to JSON into a buffer that will be wiped afterwards.
2. A new random 24-byte nonce is generated. **Every save uses a fresh nonce**, so the file changes completely even when its content does not.
3. The JSON is encrypted with the header as associated data.
4. The file is written atomically (see [Atomic writes](#atomic-writes)).

The key is derived once, when the vault is unlocked, and reused for the save. The salt and parameters stay the same for the vault's lifetime.

### Why these choices

- **Argon2id** is memory-hard: each guess needs a large block of memory, which makes GPU and ASIC attacks much more expensive than with PBKDF2 or bcrypt. The `id` variant combines resistance to side channels and to GPU attacks. It won the Password Hashing Competition and is the RFC 9106 recommendation.
- **XChaCha20-Poly1305** is an AEAD: it encrypts **and** authenticates in a single operation, so tampering is always detected. Its 192-bit nonce is large enough to be drawn at random on every save with no realistic risk of collision. ChaCha20 is also fast and constant-time in software, without needing AES hardware instructions.
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

### Version 1 (current)

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 5 | Magic bytes `ARGOS`, to recognize the file |
| 5 | 1 | Format version (`1`) |
| 6 | 4 | Argon2 memory in KiB (little-endian) |
| 10 | 4 | Argon2 iterations (little-endian) |
| 14 | 4 | Argon2 parallelism (little-endian) |
| 18 | 16 | Random salt |
| 34 | 24 | Random nonce |
| 58 | n | Encrypted JSON |
| 58 + n | 16 | Poly1305 authentication tag |

The first 34 bytes form the header. It is stored **in clear**, since it is needed to derive the key, but it is **authenticated**: changing a single bit makes opening fail. An empty vault takes 88 bytes.

The salt and the nonce are not secret. Their job is to be unique: the salt makes each vault's key different even with the same password (and rules out precomputed tables), and the nonce makes each encryption different.

### Legacy format (version 0)

The first versions of ArgosPass wrote `salt (16) ‖ nonce (24) ‖ ciphertext ‖ tag (16)`, with no header and no associated data. These files are still recognized (no magic bytes), opened with the default parameters of the time, and **automatically re-saved in version 1**. A warning is shown when this happens.

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
```

The rename is atomic: at any moment, `vault.argos` is either the complete old version or the complete new one, never a half-written file.

## Secrets in memory

When freed, memory is not erased: secrets could remain in RAM, then end up in a core dump or in swap. ArgosPass overwrites them with zeros as soon as they are no longer needed:

| Secret | Protection |
| --- | --- |
| Derived key | `Box<Zeroizing<[u8; 32]>>`: stored once on the heap (never copied around the stack) and wiped on drop |
| Argon2 working memory (128 MiB by default) | Allocated by ArgosPass in a `Zeroizing` buffer and wiped after the derivation. The `argon2` crate would otherwise free it without wiping it. |
| Decrypted JSON | `Zeroizing<Vec<u8>>` |
| JSON before encryption | Exact size computed first, so the buffer never reallocates and leaves no unwiped copies behind |
| Entries | `Entry` implements `ZeroizeOnDrop`: every field is wiped when the entry is dropped |
| Master password, generated passwords, clipboard read-back | `Zeroizing<String>` |

## Known limitations

- **Swap:** memory pages are not locked (`mlock`), so the operating system could write a secret to swap before it is wiped.
- **Copies outside ArgosPass:** the terminal (with `--show`), the clipboard, and especially **clipboard history** tools (`Win + V` on Windows, clipboard managers on Linux) may keep a copy that ArgosPass cannot erase.
- **Ctrl+C during `get`:** interrupting the 20-second countdown leaves the password in the clipboard.
- **Whole vault decrypted at once:** every entry is in clear in memory while a command runs, not only the one you asked for.
- **No rollback protection** and **file size not hidden** (see [Security model](#security-model)).
- **The master password cannot be changed yet.**

## Development

```bash
cargo build                                   # build
cargo test                                    # unit and integration tests
cargo fmt --all                               # format
cargo clippy --all-targets -- -D warnings     # lint (warnings are errors)
cargo audit                                   # check dependencies against RustSec (cargo install cargo-audit)
```

The CI (`.github/workflows/ci.yml`) runs the same checks on every push.

### Project layout

```
src/
├── main.rs        command-line interface (clap), prompts, clipboard, exit codes
├── lib.rs         Entry, Vault, open/save, atomic writes
├── crypto.rs      Argon2id derivation, XChaCha20-Poly1305 encryption, KdfParams, VaultKey
├── format.rs      vault header: serialization, parsing, validation
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
- a modified header is rejected;
- a legacy vault is upgraded to the current format.

During development, always use a test vault (`--vault /tmp/...`), never your real one. Vault files (`*.argos`, `*.argos.*`) are ignored by Git.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
