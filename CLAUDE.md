# ArgosPass

Command-line password manager in Rust: one crate, library in `src/lib.rs`, binary in `src/main.rs`.
This is a personal learning project of a cybersecurity student. **Correctness and clarity matter more than speed.** Keep changes small and readable, and explain any new Rust or crypto concept you introduce.

## Commands

```sh
cargo fmt --all
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo audit
```

A task is done only when fmt, clippy (with no warnings) and tests all pass. CI runs the same checks (`.github/workflows/ci.yml`).

## Layout

- `src/main.rs`: CLI (clap), prompts, clipboard, exit codes. No crypto.
- `src/lib.rs`: `Entry`, `Vault`, open/save, format migrations, `write_atomic`.
- `src/crypto.rs`: Argon2id, XChaCha20-Poly1305, `KdfParams`, `Kek`, `DataKey`, `VaultKey`. **The only module that handles keys.**
- `src/format.rs`: header encoding and validation. `FORMAT_VERSION` is the source of truth for the current format.
- `src/pepper.rs`: the local pepper file (step 16).
- `src/generator.rs`: password generator.
- `src/error.rs`: error type.
- `tests/vault.rs`: integration tests on real files.
- `README.md`: user and security documentation (file layout, threat model, exit codes). Update it **in the same change** as the code it describes.

## Security rules (non-negotiable)

- No custom crypto: RustCrypto crates only. **Ask before adding any dependency.**
- Randomness comes only from the OS CSPRNG. Every encryption uses a fresh random 24-byte nonce.
- AAD: the envelope uses the header; the payload uses header ‖ envelope. Everything before a ciphertext is authenticated.
- The KEK only wraps the data key. When key protection gets stronger (format upgrade, pepper, rotation), generate a **new** DataKey. Never rewrap during a migration.
- Validate the KDF parameters of every header you read, against both the floor and the ceiling, before deriving.
- Never log, print, `{:?}` or put in an error: passwords, keys, the pepper, plaintext. Public values are fine: sizes, salt, nonce, tag, params, pepper id.
- Key types use a heap `Box<Zeroizing<[u8; 32]>>`. No `Clone`, `Debug` or `Serialize`. No `Drop` impl on structs that own keys, so moves stay possible.
- In tests, compare secrets with `assert!`, never `assert_eq!`: a failing `assert_eq!` prints the values.
- Decryption errors stay indistinct: wrong password and tampered file give the same error.
- **Never touch the real vault or pepper** (`~/.local/share/argospass/`). Use temporary files: `--vault /tmp/x.argos --pepper /tmp/x.key` and a throwaway password.

## Code conventions

- Code, comments, doc-comments and commit messages in English.
- No `unwrap()` or `expect()` outside tests. Use `?` and `crate::Error`.
- Put every `std::os::unix` use under `#[cfg(unix)]`: the code must compile on Windows.
- Permissions on Unix: files 600, directories 700. Every vault write goes through `write_atomic`.

## Format changes

Any change to the file layout needs a new `FORMAT_VERSION`, a migration from every older version, and tests. Follow the `format-version-bump` skill.

## Git

- **Do not commit or push.** The owner reviews the diff and commits himself. When you finish, summarize the changes per file and list anything you did beyond the request, with the reason.
- Never commit `*.argos`, `*.argos.*`, `*.key` or `vault.json`.

## Roadmap

Done: encrypted vault, generator and clipboard, verbose mode, zeroize, versioned header, CI, envelope encryption (v2), `passwd`.
Current step: 16, the local pepper.
Next: 17 two-level encryption (HKDF subkeys, per-field AAD), then 18 sync (revisions, merge, rollback detection), then 19 OneDrive and second PC.

Work on one step at a time. Do not start the next step.
