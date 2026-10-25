# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

ArgosPass is a command-line password manager in Rust (edition 2024). Each vault is a single encrypted local file. The README covers the security model, cryptography and file format in detail. Read it before changing anything in `crypto.rs`, `format.rs` or the save/open path.

## Commands

```bash
cargo build
cargo test --locked                                  # all unit + integration tests
cargo test --locked <name_substring>                 # single test, e.g. cargo test --locked rewrap
cargo test --locked --test vault <name>              # only integration tests (tests/vault.rs)
cargo test --locked --lib crypto::tests::<name>      # only one unit test module
cargo fmt --all                                      # CI runs `cargo fmt --all --check`
cargo clippy --all-targets --locked -- -D warnings   # warnings are errors in CI
cargo audit                                          # RustSec check (also run weekly in CI)
```

`Cargo.toml` builds dependencies at `opt-level = 3`, even in dev, because Argon2id at the default 128 MiB would otherwise make tests very slow. Many tests still run a real Argon2id derivation, so a full test run takes a few seconds.

When running the binary by hand, always point it at a throwaway vault, never the real one: `cargo run -- --vault /tmp/test.argos init` (or set `ARGOSPASS_VAULT`). Password prompts use `rpassword`, which reads from `/dev/tty`, not stdin. Commands that need a password cannot be scripted by piping input, so test vault behavior through the library API in `tests/vault.rs` instead.

## Architecture

There is a library/binary split. `main.rs` is only the CLI: clap definitions, prompts, clipboard, and mapping errors to exit codes. All vault logic lives in the `argospass` library (`lib.rs` + modules), which the integration tests call directly.

### File layout and key hierarchy (format v3)

```
header (50 B) ‖ envelope (72 B) ‖ payload (nonce 24 ‖ ciphertext ‖ tag 16)
```

- `format.rs`: the header (`ARGOS` magic, version byte, Argon2id params, salt, and from v3 the 16-byte pepper id). `Header` keeps the version it was read in: `to_bytes` reproduces older headers byte for byte, and `Header::new` always creates a current (v3) one. `version >= 3` ⇔ `pepper_id.is_some()`, enforced by keeping those two fields private.
- `pepper.rs`: the `Pepper`, 32 random bytes in a local file (never in the vault), used as Argon2id's secret parameter K. Its public id is `SHA-256("ArgosPass pepper id v1" ‖ pepper)[..16]`. `Pepper::create` never overwrites an existing file.
- `crypto.rs`: envelope encryption.
  - `Kek` is derived from the master password and the pepper (none before v3) with Argon2id. It only wraps and unwraps the `DataKey`. `VaultKey::unlock` checks the header's pepper id against the pepper **before** deriving (`PepperMismatch` / `PepperRequired`).
  - The random `DataKey` encrypts the JSON entries.
  - `VaultKey` holds the header, the envelope and the data key. With a `VaultKey`, `Vault::save` needs neither the password nor Argon2: it writes the header and envelope back unchanged, with a fresh payload nonce.
- AAD chaining: the header is the AAD of the envelope, and `header ‖ envelope` (`VaultKey::prefix()`) is the AAD of the payload. Changing the header or envelope (for example in `passwd`) therefore requires re-encrypting the payload, which every save already does.
- Password change: `VaultKey::rewrap` keeps the data key and uses a new salt, the default params and the same pepper. `passwd --rotate-key` creates a brand-new `VaultKey` instead. Either way, `save_and_replace_backup` runs afterwards so that the `.bak` doesn't keep the old password.

### Format versions and upgrades

`Vault::open` dispatches on the magic and version:

- no magic → `open_legacy`, which uses fixed `KdfParams::LEGACY` and no AAD;
- v1 → `open_v1`, where the password-derived key encrypts the payload directly;
- v2 → `open_envelope` without a pepper, then upgrade;
- v3 → `open_envelope` with the pepper.

Legacy, v1 and v2 vaults are decrypted without the pepper, then immediately re-saved as v3 by `upgrade()`, with a new salt, the current params, the pepper and a **new** data key (never the old one: an old copy plus the password would reveal it without the pepper). `upgrade()` uses `save_and_replace_backup`, so no pre-pepper `.bak` is left. `open_v1` uses the **raw header bytes from the file** as AAD.

In `main.rs`, a missing pepper file is only created for a vault that `requires_existing_pepper` says predates peppers; a v3 vault without its pepper is an error (exit code 8).

To add a format version: bump `FORMAT_VERSION`, add an `open_vN` path, keep the old readers, and update the README's "Vault file format" section and the integration tests. `KdfParams::LEGACY` must never change.

### Validation before key derivation

Lengths, magic, version and `KdfParams` bounds (`MINIMUM`/`MAXIMUM`) are checked **before** any Argon2id run, so a crafted or truncated file fails fast and cannot exhaust memory. Keep new checks in that order.

### Writes

`write_atomic`:

1. writes `<vault>.tmp` (mode `600` on Unix) and fsyncs it;
2. copies the existing vault to `<vault>.bak`;
3. renames the temp file over the vault.

`sibling()` appends the suffix to the full file name (`secrets.db` → `secrets.db.bak`).

### Errors and exit codes

`error::Error` (thiserror) is the library error. In `main.rs`, `exit_code()` deliberately has no `_` arm, so a new variant won't compile until it gets an exit code. Also update the exit-code tables in `EXIT_STATUS_HELP` and the README. `DecryptionFailed` must never reveal whether the password was wrong or the file was tampered with.

## Secret-handling conventions

These are project invariants. Follow them in any new code.

- **Wipe secrets.** Keys are `Box<Zeroizing<[u8; 32]>>`, allocated zeroed on the heap and filled in place so key bytes never touch the stack. Passwords are `Zeroizing<String>`. Decrypted data is `Zeroizing<Vec<u8>>`. `Entry` is `ZeroizeOnDrop`. Temporary keys live in a scoped block so they drop immediately (see the `// the KEK is wiped here` comments).
- **No reallocation of secret buffers.** Pre-size them so no unwiped copy is left behind: `Vault::to_json` measures the size with `ByteCounter` first, and the generator reserves exact capacity.
- **Logging.** `info!` is `-v` and `debug!` is `-vv`, both on stderr. Log only public values (sizes, salt, nonces, tags, params) via `to_hex`. Never log passwords, keys or decrypted content.
- **No secrets in error messages.** `Error::Json` shows only line and column and is not exposed as `source`, because serde_json's message can quote vault content.
- **Tests compare key bytes with `assert!(a == b)`**, not `assert_eq!`, so a failure doesn't print keys.
- **Passwords are never command-line arguments.** They are always prompted with hidden input.

## Tests

Unit tests sit next to the code (`#[cfg(test)] mod tests`). `tests/vault.rs` works on real files through `temp_vault(name)`, which returns a per-test path in the system temp dir, so give each new test a unique name. The README's "Tests" section lists what the integration tests cover; keep it in sync.

Development happens on Linux/WSL. Clipboard support (`arboard`) needs a graphical session (WSLg under WSL). Windows and macOS are not tested.
