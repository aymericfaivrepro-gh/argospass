# ArgosPass

A command-line password manager written in Rust. Entries live in a single local file, encrypted with a random key that only your master password, together with a local pepper file, can unlock. Each password is encrypted a second time on its own, so that opening the vault does not decrypt them all.

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
argospass init                                        # create a new vault (asks for a master password twice) and its pepper file
argospass add GitHub aymeric https://github.com       # add an entry; the password is typed with hidden input
argospass add Mail aymeric --generate                 # add an entry with a generated password
argospass list                                        # list entry titles
argospass get GitHub                                  # copy the password to the clipboard for 20 s
argospass get GitHub --show                           # print the password in the terminal instead
argospass remove GitHub                               # remove an entry
argospass generate                                    # print a random password (no vault needed)
argospass passwd                                      # change the master password
argospass pepper status                               # show the pepper file and whether it matches the vault
argospass pepper export                               # print the pepper's recovery code, to write down
argospass pepper import                               # rebuild the pepper file from its recovery code
argospass --help                                      # full help (also: argospass <command> --help)
```

### Commands

| Command | Description | Needs the master password |
| --- | --- | --- |
| `init` | Create a new, empty vault. Also creates the pepper file if there is none yet (see [Pepper file](#pepper-file)). | Chooses it |
| `add <TITLE> <USERNAME> [URL]` | Add an entry. Asks for the password, or generates one with `-g` / `--generate`. Titles must be unique. | Yes |
| `list` | List all entries (no passwords shown) | Yes |
| `get <TITLE>` | Copy the entry's password to the clipboard and clear it after 20 seconds. `--show` prints it instead. | Yes |
| `remove <TITLE>` | Delete an entry | Yes |
| `generate` | Print a random password: 24 characters by default (from 8 to 1024), symbols included unless `--no-symbols` is given | No |
| `passwd [--rotate-key]` | Change the master password. `--rotate-key` also generates a new data key, and encrypts every password again with it. Without `--rotate-key`, the new password must differ from the current one. See [Changing the master password](#changing-the-master-password). | Yes, then chooses the new one |
| `pepper status` | Show the pepper file, its id, and whether it matches the vault. See [Pepper recovery code](#pepper-recovery-code). | No |
| `pepper export` | Print the pepper as a recovery code, to write down or move to another computer | No |
| `pepper import` | Rebuild the pepper file from its recovery code, read from stdin or typed with hidden input. Never overwrites an existing pepper file. | No |

You get **3 attempts** to type the master password. A new master password (`init`, `passwd`) must be at least **12 characters** long.

The clipboard is only cleared if it still contains the password ArgosPass put there, so anything you copied in the meantime is not erased. If it cannot be read back, it is cleared all the same; if it cannot be cleared, ArgosPass says so.

`list` and `get` show the control characters an entry may hold (line breaks, escape sequences…) as `�`, so that an entry cannot drive the terminal (change its title, write to the clipboard, hide text).

`add`, `remove` and `passwd` hold a lock on the vault from reading it to saving it (and `init` while it writes it). A second command that tries to change the same vault at the same time stops with an error (exit code `1`) instead of overwriting the first one's changes. `list` and `get` need no lock: a save replaces the file in one go.

### Global options

| Option | Effect |
| --- | --- |
| `--vault <PATH>` | Use another vault file |
| `ARGOSPASS_VAULT=<PATH>` | Same, through an environment variable |
| `--pepper <PATH>` | Use another pepper file |
| `ARGOSPASS_PEPPER=<PATH>` | Same, through an environment variable |
| `-v` | Show the main steps (key derivation time, file read/written…) |
| `-vv` | Show every detail (sizes, salt, nonces, tags, Argon2 parameters, generator statistics…) |

Logs go to **stderr**, so they never mix with a command's output. They only show public values. The master password, keys, decrypted content and entry passwords are never logged. Neither is the size of an encrypted password: it would give the length of the password.

The error never tells a wrong master password from a damaged file, and neither do the main steps shown by `-v`. The details shown by `-vv` do: they show how far opening got (for example, that the envelope opened before the content failed), which helps to diagnose a problem.

### Vault and pepper locations

| System | Default vault path | Default pepper path |
| --- | --- | --- |
| Linux | `~/.local/share/argospass/vault.argos` | `~/.local/share/argospass/pepper.key` |
| macOS | `~/Library/Application Support/argospass/vault.argos` | `~/Library/Application Support/argospass/pepper.key` |
| Windows | `%APPDATA%\argospass\vault.argos` | `%LOCALAPPDATA%\argospass\pepper.key` |

On Windows, the pepper is in the *local* application data, which roaming profiles do not sync, unlike the vault. On Linux and macOS, both default to the **same directory**. That is fine only as long as this directory is not synced or backed up as a whole, and backup tools often do back it up by default: Time Machine (macOS) includes `~/Library/Application Support`, and Déjà Dup (many Linux desktops) the whole home directory. A backup that holds both files leaves only the master password to protect the vault. If such a backup is enabled, keep the pepper somewhere else with `--pepper` or `ARGOSPASS_PEPPER`, or exclude it from the backup and back it up separately.

The previous version of the vault is kept next to it, under the vault's file name followed by `.bak` (`vault.argos.bak`). After `passwd`, the backup is replaced by the new version, so that no file encrypted under the old password is left next to the vault. If the backup cannot be replaced, `passwd` says so, and that the new password is already in use: delete the backup yourself.

The lock is an empty file next to the vault, under its file name followed by `.lock` (`vault.argos.lock`). It stays there between commands: delete it only when no ArgosPass command is running.

Earlier versions of ArgosPass named the backup of a vault whose name does not end in `.argos` after the name without its extension (`secrets.argos.bak` for `secrets.db`). ArgosPass no longer writes or replaces that file: delete it yourself, it may still open with an old password.

> ⚠️ ArgosPass is developed and tested on Linux (including WSL). Windows and macOS paths are given for reference; these platforms are not tested yet.

### Pepper file

The pepper is a file of 32 random bytes, kept **outside the vault**. ArgosPass needs it, in addition to the master password, to open a vault. See [What the pepper adds](#what-the-pepper-adds) for what it protects against.

- `init` creates it if it does not exist yet, and otherwise reuses it: several vaults can share one pepper. When it creates one, ArgosPass prints a large warning with its path.
- The pepper file can be neither the vault itself nor one of the files ArgosPass writes next to it (`.tmp`, `.bak`, `.bak.tmp`, `.lock`): saving the vault would overwrite it. Such a `--pepper` path is refused before anything is read or written, even when it names the same file another way (through `..`, `.` or a link).
- **Without the pepper file, the vault cannot be opened, even with the right master password.** Nothing can rebuild it except your own backup. Back it up right after it is created, **separately from the vault** (for example on a USB key, in another password manager, or as a [recovery code](#pepper-recovery-code) written on paper), and never keep it next to the vault in a synced folder.
- An existing pepper file is never overwritten. On Unix, it is created with `600` permissions (and a warning is shown if other users can access it).
- If the pepper file is missing, damaged, or not the one the vault was created with, opening the vault stops before the master password is asked for (and before any key derivation) and exits with code `8`, with a hint. (`init` asks for the new master password first: a damaged pepper file is only reported after it.) Point it to the right file with `--pepper <PATH>`, or rebuild it from its recovery code with `pepper import`.

### Pepper recovery code

`argospass pepper export` prints the pepper as a **recovery code**: one line of 99 characters, short enough to write down by hand.

```
ARGOS-PEPPER-1-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-cccc
```

- `ARGOS-PEPPER-1` is a fixed prefix. The `1` is the version of the code format.
- The 16 `xxxx` groups are the 32 bytes of the pepper, in lowercase hexadecimal.
- `cccc` is a check group: the first 2 bytes of the [pepper id](#what-the-pepper-adds). A typo gives another pepper, whose id almost never starts with these 2 bytes, so `pepper import` refuses the code instead of installing a wrong pepper. About 1 typo in 65,536 still gets through: the pepper installed then does not match the vault, and `pepper import` and `pepper status` say so.

**The recovery code is the pepper.** Whoever reads it can rebuild the pepper file. Keep it like the pepper file:

- on paper in a safe place, or on offline media such as a USB key, **separately from the vault**;
- **never** in a cloud drive (OneDrive, Google Drive, Dropbox…), an e-mail, a chat, a synced notes app, a screenshot or a photo.

The code goes to stdout and the explanations to stderr. Run `clear` once you have copied it, so that it does not stay on screen or in the terminal's scrollback. A file you redirect it to is as sensitive as the pepper. The shell creates it with its default permissions, often readable by every user (`644`), so create it readable by you only, `(umask 077; argospass pepper export > code.txt)`, and delete it once the code is stored safely. On Unix, ArgosPass warns if the file is accessible to other users.

`argospass pepper import` rebuilds the pepper file from the code:

- The code is read from stdin if it is redirected (`argospass pepper import < code.txt`), and is otherwise typed or pasted with hidden input. A code on several lines is read until it is complete, or until an empty line: every pasted line is read by ArgosPass, none is left for the shell (which would show it and keep it in its history).
- Letter case, spaces, tabs, line breaks and extra `-` do not matter. A code with a wrong prefix, a wrong number of digits, a character that is not a hex digit, or a check group that does not match is refused with exit code `9`. The error says which, never what the code contains.
- If there is no pepper file, it is created (`600` on Unix), and its id is printed.
- If the same pepper is already installed, nothing is written and the command succeeds.
- If **another** pepper file is already there (or a file that is not a pepper), the import is refused with exit code `8`, and the file is left untouched: overwriting it could make the vaults created with it unreadable. If you really mean to replace it, move it elsewhere yourself first, and keep it until you are sure no vault needs it.
- If the vault exists, the command then tells whether the pepper matches it. This check is only informative: if the vault cannot be read, a warning is shown, and the import still succeeds.

`argospass pepper status` shows the path of the pepper file, whether it exists, its id (first 4 bytes), and, if the vault exists, whether the pepper matches it. It never shows the pepper, and does not decrypt the vault: it only reads the pepper id from the vault header.

The `pepper` commands do not ask for the master password. It would protect nothing: the pepper file is not encrypted, so anyone who can run ArgosPass under your account can read it anyway.

### Using a second computer

1. On the first computer, run `argospass pepper export`, and copy the code by hand, on paper. Or write it to a USB key: `(umask 077; argospass pepper export > /media/usb/pepper-code.txt)`.
2. On the second computer, run `argospass pepper import` and type the code, or run `argospass pepper import < /media/usb/pepper-code.txt`. Then delete the file from the USB key, unless that key is your offline backup.
3. Put the vault on the second computer, then run `argospass pepper status`. It should say `the pepper matches this vault`.

Never send the code or the pepper file through the cloud, e-mail or a chat, even to yourself. The pepper protects you only as long as it stays out of the places where the vault goes.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | Other error (for example, the vault is in use by another command) |
| `2` | Invalid command-line usage |
| `3` | Wrong master password, or corrupted vault |
| `4` | Invalid or unsupported vault file: damaged header, format other than v4, or larger than 64 MiB |
| `5` | Input/output error |
| `6` | No entry with this title |
| `7` | An entry with this title already exists |
| `8` | Pepper file missing, invalid, or not the one this vault was created with. For `pepper import`: another pepper file is already there |
| `9` | Invalid pepper recovery code (`pepper import`) |

## Security model

### What ArgosPass protects against

| Threat | Protection |
| --- | --- |
| **Theft of the vault file** (lost laptop, leaked cloud copy, backup) | Content is encrypted. Without the pepper file, guessing the master password is hopeless (see [What the pepper adds](#what-the-pepper-adds)). With it, each guess still costs a full Argon2id derivation: tens of megabytes of memory and a noticeable delay. |
| **Modification of the vault file** | Every byte is authenticated: the envelope and the content by their Poly1305 tags, the header and the envelope as associated data. Any change makes opening fail. |
| **Downgrade of the key derivation** (an attacker lowers the Argon2 parameters in the header to speed up guessing) | Parameters are authenticated, and values below a security floor are refused before any derivation. |
| **Downgrade to an older file format** (an attacker who knows the master password, but not the pepper, replaces the vault with one of their own in a format that did not use the pepper) | Only format v4 is opened: older formats are refused before any key derivation, and left as they are (see [Older formats](#older-formats-no-longer-opened)). |
| **Absurd parameters in a crafted file** (memory exhaustion) | Values above an upper limit (1 GiB of memory, 16 passes) are refused, and so is a vault file larger than 64 MiB. |
| **Crash or power loss during a save** | Atomic write: the old vault stays intact until the new one is fully on disk, directory entry included, and a `.bak` copy is kept, written the same way. |
| **Two commands changing the vault at once** | A command that changes the vault holds its lock: the second one stops with an error instead of overwriting the first one's changes. |
| **Other users of the same machine** | On Unix, the vault, its backup and the pepper are created with `600` permissions and new directories with `700`. A leftover temporary file is never reused: it could keep other permissions, or be a link to another file. |
| **Shoulder surfing and shell history** | Passwords are never command-line arguments and are typed with hidden input. By default, `get` copies to the clipboard instead of printing. |
| **Secrets lingering in memory** | Keys, decrypted content and passwords are overwritten when no longer needed (see [Secrets in memory](#secrets-in-memory)). The passwords stay encrypted in memory, and are decrypted one at a time (see [What the two levels of encryption add](#what-the-two-levels-of-encryption-add)). |

### What the pepper adds

The pepper is a 256-bit random secret, stored in its own file and never in the vault. It goes into the key derivation as Argon2id's **secret parameter**, so the KEK depends on the master password **and** the pepper.

- **It protects against the theft or leak of the vault file alone** (cloud copy, backup, a USB key holding only the vault). To test a single password guess, an attacker would also need the 256 random bits of the pepper: guessing becomes hopeless, even for a weak master password.
- **It does not help** if the attacker gets both files: from a synced folder or a backup holding both, or from the machine itself. Then only the master password and Argon2id protect the vault, as before the pepper.
- **It does not protect copies made before the pepper existed** (format v2 and older: old backups, cloud history). Whoever gets one can try passwords on it without the pepper, with their own tools, even though ArgosPass no longer opens it.
- **It also guards the vault's authenticity**, since only format v4 is opened: someone who knows the master password, but not the pepper, cannot make ArgosPass accept a vault of their own in an older format, which needed no pepper.
- **Losing it means losing the vault.** Back it up separately from the vault, for example as a [recovery code](#pepper-recovery-code) on paper (see [Pepper file](#pepper-file)).

The vault header stores a pepper **id**: the first 16 bytes of SHA-256(`"ArgosPass pepper id v1"` ‖ pepper). It is public and reveals nothing usable about the pepper, but it lets ArgosPass tell a wrong pepper file from a wrong password, before any key derivation.

### What the two levels of encryption add

From format v4 on, each password is encrypted a second time, on its own, inside the encrypted content (see [Key hierarchy](#key-hierarchy)).

- **It limits the passwords in clear in memory.** Opening the vault decrypts the content (titles, usernames, URLs), not the passwords. `list` decrypts none, and `get` only the one asked for, wiped right after use. A partial leak of memory (a page written to swap, a bug that prints the content) is much less likely to reveal a password.
- **It does not resist a full memory dump** (a core dump, a debugger, malware) taken while ArgosPass runs: the field key is in memory, next to the encrypted passwords. Nor does it help against anyone who has the master password and the pepper, or against a compromised machine.
- **Each password is bound to its place.** Its associated data holds the vault id, the entry id and the field name: it cannot be opened as the password of another entry, or of another vault. Since the whole content is already authenticated, this mostly guards against bugs today. It will matter once entries from several copies of a vault are merged (sync). It does not tell an older version of the same password from the current one: an old copy of the field, put back in place, still opens. Telling them apart is left to the revisions that sync will add.
- **It adds nothing on disk:** the passwords in the file were already encrypted, by the payload layer.

### What ArgosPass does not protect against

- **A compromised machine.** Malware, a keylogger or an administrator can read the master password as you type it, the pepper file, or the decrypted vault while ArgosPass runs. No password manager can defend against that.
- **A weak master password.** Argon2id slows down guessing but cannot save a short or common password. ArgosPass requires at least 12 characters, but cannot tell a common phrase from a random one. Use a long passphrase, for example 5 or more random words.
- **A forgotten master password.** There is no recovery mechanism or back door. A lost password means a lost vault.
- **Rollback.** An attacker who can write the file can replace it with an **older, valid** version of your vault, and ArgosPass will not notice yet.
- **Metadata.** The file size reveals the approximate size of the content, so roughly how many entries you have. The modification date shows when you last changed it.

## Cryptography

Only audited, widely used implementations from the [RustCrypto](https://github.com/RustCrypto) project are used. ArgosPass contains no custom cryptographic primitive.

| Role | Algorithm | Crate |
| --- | --- | --- |
| Key derivation from the master password and the pepper | **Argon2id** (RFC 9106), version 0x13, with the pepper as secret parameter K | `argon2` |
| Pepper id | **SHA-256**, truncated to 16 bytes | `sha2` |
| Subkeys of the data key (payload key, field key) | **HKDF-SHA256** (RFC 5869), without salt, one label per subkey | `hkdf` |
| Authenticated encryption (of the data key, of the content, and of each password) | **XChaCha20-Poly1305** (AEAD) | `chacha20poly1305` |
| Randomness (salt, nonces, data key, vault id, entry ids, pepper, generated passwords) | Operating system CSPRNG | `getrandom` |
| Memory wiping | Volatile writes that the compiler cannot optimize away | `zeroize` |

### Key hierarchy

ArgosPass uses four 256-bit keys:

- the **key-encryption key (KEK)** is derived from the master password and the pepper with Argon2id. Its only job is to encrypt the data key;
- the **data key** is drawn at random when the vault is created, and only changes with `passwd --rotate-key`. The data key, encrypted with the KEK, is stored in the file: this is the **envelope**. From format v4 on, the data key encrypts nothing itself;
- the **payload key** and the **field key** are derived from the data key with HKDF-SHA256, each with its own label. They are independent: knowing one tells nothing about the other, nor about the data key.

```
master password ─┐
pepper ──────────┼─► Argon2id ─► KEK ─► opens the envelope ─► data key
salt, parameters ┘                                               │
                                                     HKDF-SHA256, no salt
                                   ┌─────────────────────────────┴───────────────────┐
                    "ArgosPass payload key v1"                       "ArgosPass field key v1"
                                   ▼                                                 ▼
                      payload key (level 1)                             field key (level 2)
                  encrypts the JSON content                   encrypts each password inside it
```

| Level | Key | Encrypts | Associated data (authenticated, not encrypted) |
| --- | --- | --- | --- |
| 1 | Payload key | The whole JSON content | `header ‖ envelope` |
| 2 | Field key | Each password, separately, with its own nonce | `"ArgosPass field v1" ‖ vault id (16) ‖ entry id (16) ‖ length of the field name (1 byte) ‖ field name` |

HKDF takes no salt here: its salt is meant for input keys that are not uniformly random, and the data key is. In the associated data of a password, the field name is the only part whose size varies; its length prefix keeps the encoding unambiguous if anything is ever added after it.

### How a vault is opened

```
master password ─┐
pepper (file) ───┤
salt (header) ───┼──► Argon2id ──► KEK
parameters ──────┘                  │
                                    ▼
envelope ────────────────► XChaCha20-Poly1305 ◄── AAD: header
                                    │  verify tag, decrypt
                                    ▼
                                data key
                                    │  HKDF-SHA256 ("ArgosPass payload key v1")
                                    ▼
                               payload key
                                    │
                                    ▼
payload ─────────────────► XChaCha20-Poly1305 ◄── AAD: header ‖ envelope
                                    │  verify tag, decrypt
                                    ▼
                  JSON entries (passwords still encrypted)
```

1. ArgosPass checks the file size (at most 64 MiB), reads the header and checks the magic bytes, the format version (only version 4 is opened), the Argon2 parameters and the file length, all before any key derivation.
2. It also checks that the pepper id in the header is the id of the pepper file, still before any derivation. Otherwise it stops: wrong or missing pepper (exit code `8`). The command line already does this check from the header alone before asking for the master password; it is done again here because the id is only authenticated by the envelope's tag, and the file may have changed in between.
3. The master password, the pepper and the salt go through Argon2id with the parameters from the header. The output is the KEK.
4. The KEK opens the envelope: XChaCha20-Poly1305 checks the envelope's tag over the encrypted data key **and the header**, then decrypts the data key. The KEK is wiped right away.
5. The payload key, derived from the data key, decrypts the payload. Its tag covers the ciphertext **and everything before it** (header and envelope).
6. If a tag does not match (wrong password, modified file), nothing is decrypted, and the error does not say which of the two happened.
7. The passwords stay encrypted. `get` decrypts only the one asked for, with the field key: its tag also covers the vault id, the entry id and the field name.

### How a vault is saved

1. The entries are serialized to JSON into a buffer that will be wiped afterwards. Their passwords are already encrypted: each one was sealed with the field key, with its own fresh nonce, as soon as it was added.
2. A new random 24-byte nonce is generated. **Every save uses a fresh nonce**, so the payload changes completely even when its content does not.
3. The JSON is encrypted with the payload key, with the header and the envelope as associated data.
4. The file (`header ‖ envelope ‖ new payload`) is written atomically (see [Atomic writes](#atomic-writes)).

Saving needs neither the master password nor Argon2id: the keys are kept in memory while the command runs, and the header and the envelope are written back unchanged. The salt and the parameters only change with the master password, the data key only with `passwd --rotate-key`, and the vault id never.

### Changing the master password

1. `passwd` takes the vault's lock, unlocks the vault with the current password, then asks for the new one twice (at least 12 characters).
2. Without `--rotate-key`, a new password identical to the current one is refused: keeping both the password and the data key would bring no security. The current password is not kept in memory for this: ArgosPass tries the new password on the current envelope, which costs one more Argon2id run. With `--rotate-key`, the same password is accepted.
3. A new KEK is derived from the new password, with a **new salt**, the current default Argon2 parameters and the same pepper: `passwd` never changes the pepper, nor the vault id.
4. The same data key is wrapped with the new KEK. Its subkeys do not change, so the encrypted passwords are kept as they are. With `--rotate-key`, a new random data key is generated instead, which gives a new payload key and a new field key: **every password is decrypted with the old field key and encrypted again with the new one**, before anything is written. If one of them fails to open, nothing is written.
5. The vault is saved, then the `.bak` backup is replaced by the new version.

**Plain `passwd` or `--rotate-key`?** A plain `passwd` keeps the data key. Someone who already got the data key, from a copy of the vault made before the change and the old password, can still decrypt every later version of the vault, whatever the new password. Only `--rotate-key` revokes them: the content and every password are then encrypted with new keys, and an old copy only reveals the entries as they were when it was made. Use `--rotate-key` if the old password may have leaked.

`--rotate-key` also accepts the current password as the new one, to replace only the data key, for example if the data key alone may have been exposed. This does not help if the password itself may have leaked: whoever knows it can open the new vault too. Choose a new password in that case.

### Why these choices

- **Argon2id** is memory-hard: each guess needs a large block of memory, which makes GPU and ASIC attacks much more expensive than with PBKDF2 or bcrypt. The `id` variant combines resistance to side channels and to GPU attacks. It won the Password Hashing Competition and is the RFC 9106 recommendation.
- **XChaCha20-Poly1305** is an AEAD: it encrypts **and** authenticates in a single operation, so tampering is always detected. Its 192-bit nonce is large enough to be drawn at random on every save with no realistic risk of collision. ChaCha20 is also fast and constant-time in software, without needing AES hardware instructions.
- **Envelope encryption** keeps the password-derived key away from the data: the KEK only ever encrypts 32 random bytes, and the entries are encrypted with a key that does not depend on the password at all. It also makes master-password changes simple: `passwd` wraps the same data key again with the new KEK. The payload is still re-encrypted, as on every save, since its associated data includes the header and the envelope.
- **The pepper as Argon2id's secret parameter**: Argon2 has a dedicated secret input for this, so no extra construction is needed. Its **id** uses SHA-256 with a domain-separation prefix, so that it can never be mistaken for any other use of the pepper.
- **256-bit keys** keep a comfortable margin, including against quantum attacks on symmetric cryptography (Grover's algorithm only halves the effective strength).

### Argon2id parameters

|  | Memory | Iterations | Parallelism |
| --- | --- | --- | --- |
| New vaults | 128 MiB | 3 | 4 |
| Minimum accepted | 64 MiB | 3 | 1 |
| Maximum accepted | 1 GiB | 16 | 64 |

Parameters are stored in each vault's header, so the defaults can be raised later without breaking existing vaults. The maximum bounds what a crafted header can make ArgosPass spend before any tag is checked: about 40 times the cost of the defaults. The parallelism only splits the same memory into lanes, so it does not add to that cost.

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

### Version 4

| Offset | Size | Part | Field |
| --- | --- | --- | --- |
| 0 | 5 | Header | Magic bytes `ARGOS`, to recognize the file |
| 5 | 1 | Header | Format version (`4`) |
| 6 | 4 | Header | Argon2 memory in KiB (little-endian) |
| 10 | 4 | Header | Argon2 iterations (little-endian) |
| 14 | 4 | Header | Argon2 parallelism (little-endian) |
| 18 | 16 | Header | Random salt |
| 34 | 16 | Header | Pepper id (see [What the pepper adds](#what-the-pepper-adds)) |
| 50 | 16 | Header | Vault id: random, drawn when the vault is created, never changed |
| 66 | 24 | Envelope | Random nonce |
| 90 | 32 | Envelope | Data key, encrypted with the KEK |
| 122 | 16 | Envelope | Poly1305 authentication tag |
| 138 | 24 | Payload | Random nonce |
| 162 | n | Payload | JSON content, encrypted with the payload key (see [Decrypted content](#decrypted-content)) |
| 162 + n | 16 | Payload | Poly1305 authentication tag |

The header (66 bytes) and the envelope (72 bytes) are stored **in clear**, since they are needed to unlock the vault, but they are **authenticated**: the header is the associated data of the envelope, and the header and the envelope together are the associated data of the payload. Changing a single bit anywhere makes opening fail. An empty vault takes 192 bytes.

The salt, the nonces, the pepper id and the vault id are not secret. The salt and the nonces must be unique: the salt makes each vault's KEK different even with the same password and pepper (and rules out precomputed tables), and the nonces make each encryption different. The vault id is kept by `passwd`, with or without `--rotate-key`: every encrypted password is bound to it. The pepper itself is never in the file.

### Older formats (no longer opened)

ArgosPass only opens format v4. A vault in an older format is refused with exit code `4` and a hint, before any key derivation, and left as it is: nothing is written, and no pepper file is created for it. A legacy vault, which has no header, is reported as `not an ArgosPass vault`.

| Version | Layout |
| --- | --- |
| 3 | Header of 50 bytes (no vault id), then the same envelope and payload as version 4, but the data key itself encrypts the JSON, and the passwords are in clear inside it. |
| 2 | Header of 34 bytes (no pepper id), then the same envelope and payload as version 3. The KEK is derived without a pepper. |
| 1 | Same 34-byte header (with version `1`), followed directly by `nonce (24) ‖ encrypted JSON ‖ tag (16)`: the entries are encrypted with the key derived from the master password, with the header as associated data. |
| 0 (legacy) | `salt (16) ‖ nonce (24) ‖ ciphertext ‖ tag (16)`, with no header (no magic bytes) and no associated data. |

Earlier builds opened these formats, then rewrote them in version 4 automatically. That made them a way around the pepper: someone who knows the master password, but not the pepper, and can write the vault file (a synced folder), could replace the vault with a version 1 vault holding entries of their choice. ArgosPass accepted it, and re-encrypted it under the pepper. The silent rewrite also told them whether a password they guessed was the right one.

To convert an old vault that you know is yours, open it once with a build of ArgosPass up to commit `a485011` (for example `git checkout a485011`, then `cargo run -- --vault <PATH> --pepper <PATH> list`). It rewrites the vault in version 4, with a new data key and the pepper (created if needed), and replaces its backup. Copies of the old file kept elsewhere stay in their old format: those older than version 3 are not protected by the pepper.

### Decrypted content

Once the payload is decrypted (level 1), the vault is a JSON document:

```json
{
  "entries": [
    {
      "id": "6f1c0e2a9b5d4c3e8a7f6b5c4d3e2f10",
      "title": "GitHub",
      "username": "User",
      "password": "<hex: nonce (24 bytes) ‖ encrypted password ‖ tag (16 bytes)>",
      "url": "https://github.com"
    }
  ]
}
```

- `id` is the entry id: 16 random bytes in hex, drawn when the entry is added and never changed.
- `password` is a **protected field** (level 2): the password encrypted with the field key, in hex. A password of `m` bytes takes `2 × (24 + m + 16)` hex digits: 128 for a generated password of 24 characters. Its associated data is described in [Key hierarchy](#key-hierarchy).
- The title, the username and the URL are only protected by the payload encryption.

This JSON only ever exists in memory. It is never written to disk.

### Atomic writes

```
vault.argos.bak.tmp ← 1. copy of the current vault (permissions 600), then fsync to force it onto the disk
vault.argos.bak     ← 2. atomic rename of .bak.tmp over the backup
vault.argos.tmp     ← 3. write the new content (permissions 600), then fsync
vault.argos         ← 4. atomic rename of .tmp over the vault, then fsync of the directory
vault.argos.bak     ← 5. passwd only: replaced the same way by a copy of the new vault
```

The rename is atomic: at any moment, `vault.argos` is either the complete old version or the complete new one, never a half-written file, and so is its backup. Flushing the directory makes the rename itself survive a crash. Each temporary file is created new: one left behind by an interrupted save is deleted first, never reused, since it could keep other permissions, or be a link to another file.

## Secrets in memory

When freed, memory is not erased: secrets could remain in RAM, then end up in a core dump or in swap. ArgosPass overwrites them with zeros as soon as they are no longer needed:

| Secret | Protection |
| --- | --- |
| Key-encryption key (KEK) | `Box<Zeroizing<[u8; 32]>>`: stored once on the heap (never copied around the stack). Wiped right after opening (or creating) the envelope, so it is never kept while the vault is open |
| Data key | `Box<Zeroizing<[u8; 32]>>`: drawn at random directly into a zeroed heap buffer, or decrypted into a `Zeroizing<Vec<u8>>` and copied into one, so it never touches the stack. Kept while the command runs (`passwd` wraps it again) and wiped on drop. It encrypts nothing itself |
| Payload key and field key | `Box<Zeroizing<[u8; 32]>>`: HKDF writes them directly into a zeroed heap buffer. Kept while the command runs (saving and `get` need them) and wiped on drop |
| Pepper | `Box<Zeroizing<[u8; 32]>>`: drawn at random, read from its file, or decoded from its recovery code, directly into a zeroed heap buffer. Kept while the command runs (opening and `passwd` need it) and wiped on drop |
| Recovery code | `pepper export` builds it in a `Zeroizing<String>` of exactly its size. `pepper import` reads it into a pre-sized `Zeroizing<Vec<u8>>` (stdin) or `Zeroizing<String>` (typed, but see [Known limitations](#known-limitations)), then decodes it character by character straight into the pepper's buffer, with no copy of its own |
| Key copy inside the cipher | Each XChaCha20-Poly1305 instance keeps its own copy of the key. It only lives for one encryption or decryption, and the `chacha20poly1305` crate wipes it on drop |
| Argon2 working memory (128 MiB by default) | Allocated by ArgosPass in a `Zeroizing` buffer and wiped after the derivation. The `argon2` crate would otherwise free it without wiping it. |
| Decrypted JSON | `Zeroizing<Vec<u8>>`. From format v4 on, it holds no password: they stay encrypted inside it |
| JSON before encryption | Exact size computed first, so the buffer never reallocates and leaves no unwiped copies behind |
| Entries | `Entry` implements `ZeroizeOnDrop`: every field is wiped when the entry is dropped. Its password stays encrypted (`ProtectedField`) |
| Entry passwords in clear | Only `get` decrypts one, for the entry asked for, into a `Zeroizing<String>` that reuses the decryption buffer (no copy). It is wiped right after the copy to the clipboard or the display. `add` encrypts the typed or generated password right away. `passwd --rotate-key` decrypts each password only for the time of encrypting it again. `get --show` prints it straight from that buffer, one character at a time, with no copy of its own |
| Master passwords (current and new), generated passwords, clipboard read-back | `Zeroizing<String>`. The current password is wiped as soon as the vault is unlocked, even by `passwd` |

## Known limitations

- **Swap:** memory pages are not locked (`mlock`), so the operating system could write a secret to swap before it is wiped.
- **Copies outside ArgosPass:** the terminal (with `--show`, and the recovery code printed by `pepper export`), the clipboard, and especially **clipboard history** tools (`Win + V` on Windows, clipboard managers on Linux) may keep a copy that ArgosPass cannot erase.
- **Typed secrets:** `rpassword`, which reads hidden input, grows its buffer one character at a time, and each reallocation leaves the previous, unwiped copy in freed memory. A master password, or a recovery code typed or pasted on the terminal, may therefore leave partial copies behind. A recovery code read from stdin does not.
- **Standard input and output buffers:** the Rust standard library keeps what goes through stdin and stdout in buffers that ArgosPass cannot wipe. A recovery code read from stdin, and a password or recovery code printed by `generate`, `get --show` or `pepper export`, stay there until the command exits.
- **Ctrl+C during `get`:** interrupting the 20-second countdown leaves the password in the clipboard.
- **Content decrypted at once:** the titles, usernames and URLs of every entry are in clear in memory while a command runs. The passwords are not (see [What the two levels of encryption add](#what-the-two-levels-of-encryption-add)), except the one `get` shows, and each one in turn during `passwd --rotate-key`.
- **No rollback protection** and **file size not hidden** (see [Security model](#security-model)).
- **Old copies keep the old password:** copies of the vault made before a password change (cloud history, backups, other computers) still open with the old password, and copies made before the pepper (format v2 and older) are not protected by it.
- **File systems without locks:** on some network drives, the vault cannot be locked. ArgosPass then shows a warning and goes on without the lock: two commands that change the vault at the same time could lose changes.
- **A vault appearing during `init`:** `init` checks again that there is no vault right before writing it, but a file that appears in that instant (from a sync tool) is replaced by the new vault. It is kept as the `.bak` backup, until the next save.
- **Hash states are not wiped:** the `sha2`, `blake2`, `hmac` and `hkdf` crates do not wipe their internal state. Computing the pepper id (SHA-256), Argon2id's first step (Blake2b over the password and the pepper), and deriving the subkeys (HMAC-SHA256 over the data key itself, then keyed with a value derived from it and as secret as it) may leave short-lived copies of these secrets on the stack.

## Development

```bash
cargo build                                         # build
cargo test --locked                                 # unit and integration tests
cargo fmt --all                                     # format
cargo clippy --all-targets --locked -- -D warnings  # lint (warnings are errors)
cargo audit                                         # check dependencies against RustSec (cargo install cargo-audit)
```

The CI (`.github/workflows/ci.yml`) runs the same checks on every push, and Clippy on Windows too, so that the code is known to compile there. Its actions are pinned to a commit, which Dependabot keeps up to date.

### Project layout

```
src/
├── main.rs        command-line interface (clap), prompts, clipboard, exit codes
├── lib.rs         Entry, EntryId, ProtectedField, Vault, open/save, vault lock, atomic writes
├── crypto.rs      Argon2id derivation, envelope encryption (KEK, data key), HKDF subkeys (payload key, field key), XChaCha20-Poly1305, KdfParams, VaultKey
├── format.rs      vault header: serialization, parsing, validation, format versions
├── hex.rs         hexadecimal encoding and decoding, written by hand
├── pepper.rs      pepper file: generation, creation, loading, id, recovery code, import
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
- the backup is kept and no temporary file is left behind, neither the vault's nor the backup's;
- the file has `600` permissions, even over a leftover temporary file readable by everyone, and a leftover temporary file that is a link is replaced, never written through (Unix only);
- new vaults use format v4 (192 bytes when empty), with the pepper id at offset 34 and a random vault id at offset 50;
- the decrypted JSON content (level 1) holds no password: the test decrypts it on its own, with the primitives directly (`argon2`, `chacha20poly1305`, `hkdf`) and the documented format, and finds each password as a protected field in hex, of the expected size;
- a wrong pepper is rejected before any key derivation, and a wrong password with the right pepper as before;
- through the binary, a wrong pepper is rejected (exit code `8`) before the master password is asked for, by `list` and `passwd`;
- a modified header, pepper id, vault id or envelope is rejected;
- vaults in an older format (v3, v2, v1, legacy) are refused and left byte for byte unchanged, with no backup written; among them, a v1 vault forged with the right master password but without the pepper;
- a vault file larger than 64 MiB is refused before being read;
- after a password change (with or without `--rotate-key`), the vault and its backup open with the new password only, the vault id is kept, and the backup keeps `600` permissions; a plain `passwd` keeps every encrypted password byte for byte, and `--rotate-key` encrypts every one of them again, under a new data key;
- a backup that cannot be replaced after a save is reported as such, the vault itself being saved;
- a locked vault cannot be locked again until the lock is released;
- a lost pepper file is rebuilt from its recovery code, and the vault opens again;
- importing a pepper never overwrites another pepper file (left byte for byte identical), and importing the installed pepper writes nothing;
- the pepper id of a vault is read from its header alone; for an older format, it fails as opening does;
- through the binary, a vault in an older or newer format is reported as unsupported (exit code `4`), with a hint, not as missing its pepper, and no pepper file is created for it;
- through the binary, a pepper path that is the vault or one of the files written next to it, even written another way, is refused before anything is written (exit code `1`);
- through the binary: `pepper status`, `pepper export` (the code on stdout only, never on stderr, with a warning if the file it goes to is accessible to other users), and `pepper import` from stdin, which rejects a code with a typo (exit code `9`) and never replaces another pepper (exit code `8`).

The unit tests of `crypto.rs` check the two levels of encryption: the subkeys against values computed independently (Python's `hmac`, following RFC 5869), that the payload key, the field key and the data key all differ, that no label is a prefix of another, that a password only opens for its own vault, entry and field name, the exact layout of its associated data, the 255-byte limit on field names, and that the payload is not encrypted with the data key itself. They also check the bounds of the Argon2 parameters, and that `rewrap` refuses another pepper. Those of `format.rs` check that every format version but 4 is refused, as such even when shorter than a v4 header. Those of `lib.rs` check that re-encrypting the passwords for `--rotate-key` is all or nothing, that malformed ids and protected fields are rejected, the files written next to a vault, and the 64 MiB limit. Those of `error.rs` check that a JSON error shows nothing of the content, not even in its debug form. Those of `main.rs` check the 12-character minimum of a master password, and that control characters are never printed.

The unit tests of `pepper.rs` also check the recovery code: its exact layout, that letter case, spaces and line breaks are tolerated, that a wrong prefix, a wrong length, a character that is not a hex digit, and every single-digit typo or swap of two neighbouring digits (for a fixed pepper) are rejected, and that a code typed over several lines is complete only with its last line.

Each test uses its own temporary pepper file. During development, always use a test vault and a test pepper (`--vault /tmp/... --pepper /tmp/...`), never your real ones. Vault and pepper files (`*.argos`, `*.argos.*`, `*.key`) are ignored by Git.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
