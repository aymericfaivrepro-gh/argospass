---
name: manual-check
description: End-to-end manual check of the ArgosPass binary on throwaway files, with an annotated hex dump. Use after any change to the file format, the crypto or the CLI commands.
---

# Manual check on throwaway files

Never use the real vault or pepper. Use only temporary paths and a throwaway password (`test-only-pw`).

```sh
V=/tmp/argos-check.argos
P=/tmp/argos-check.key
cargo run -- --vault $V --pepper $P init
cargo run -- --vault $V --pepper $P add Test user
cargo run -- --vault $V --pepper $P -vv list
xxd $V
ls -l $V $V.bak $P
```

Report to the owner:

1. The exit code of every command.
2. The `xxd` output, annotated as a table with offset range, part (header fields, envelope, payload) and content. Check that the total size matches the expected layout.
3. That the `-vv` log shows **only public values** (sizes, salt, nonces, tags, params, pepper id), and nothing secret.
4. File modes: `600` for the vault, `.bak` and pepper.
5. The negative cases relevant to the change, for example a wrong password, a wrong or missing pepper (`--pepper /tmp/other.key`), or a modified byte.

Then delete the temporary files: `rm -f /tmp/argos-check*`.
