---
paths:
  - "tests/**"
---

# Rules for integration tests

- Give every test its own vault and pepper files through the existing helpers (`temp_vault`…). Tests run in parallel.
- Never use the real paths under `~/.local/share/argospass/`.
- Check error cases with `matches!(result, Err(Error::Variant))`, not by string comparison.
- Compare secrets (keys, pepper, passwords) with `assert!`, never `assert_eq!` / `assert_ne!`.
- Use `expect("what was being done")` with a message, not bare `unwrap()`.
- Gate tests on Unix permissions with `#[cfg(unix)]`.
- When building an old-format file by hand, write each field explicitly (magic, version, little-endian integers) so the test documents the layout.
