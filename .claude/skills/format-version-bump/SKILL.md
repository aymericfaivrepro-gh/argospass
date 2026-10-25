---
name: format-version-bump
description: Procedure for any change to the ArgosPass vault file layout (header fields, envelope, payload). Use whenever FORMAT_VERSION must change or a new field is added to the file.
---

# Changing the vault file format

1. **Design first.** Write the new layout as an offset / size / field table, and give the size of an empty vault. Show it to the owner before coding.
2. **`src/format.rs`**
   - Increment `FORMAT_VERSION`. Keep `OLDEST_SUPPORTED_VERSION` unless the owner says otherwise.
   - `Header::from_bytes` parses every supported version and validates its exact length.
   - `to_bytes` reproduces the exact bytes of the header's own version, because older envelopes were authenticated with those bytes.
   - Add a round-trip test for the new version, and keep the round-trip tests of the older ones byte-identical.
3. **`src/lib.rs`**
   - Add a dispatch arm for the new version. The catch-all arm returns `UnsupportedVersion`.
   - The old-version open paths stay unchanged. After a **successful** decryption only, they `warn!` and upgrade.
   - The upgrade uses a **new DataKey** (`VaultKey::new`, never `rewrap`) and `save_and_replace_backup`, so that no older copy is left next to the vault.
4. **Tests** (`tests/vault.rs`)
   - New vault: version byte and total size.
   - Every older version builds a file by hand, opens it, and checks it is rewritten in the new version, `.bak` included.
   - A wrong password on an old file leaves it byte-for-byte unchanged.
   - Modifying one byte of every new field makes opening fail.
5. **`README.md`**: update the layout table, the empty-vault size, the legacy-format list, and "How a vault is opened / saved".
6. Run fmt, clippy and tests, then the `manual-check` skill.
