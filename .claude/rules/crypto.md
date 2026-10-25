---
paths:
  - "src/crypto.rs"
  - "src/format.rs"
  - "src/pepper.rs"
---

# Rules for cryptographic code

Every change in these files must come with tests covering:

- encrypt → decrypt round trip;
- failure with a wrong password, a wrong pepper, a header modified by one byte, a ciphertext modified by one byte, and a different AAD;
- two encryptions of the same plaintext giving different ciphertexts (fresh nonce);
- KDF parameters below the floor or above the ceiling being rejected **before** any derivation.

Also:

- Check lengths (envelope, payload, header) before running Argon2, so malformed input fails fast.
- `Result`-returning checks such as `opens_with` must only treat the specific decryption error as "no". Any other error (RNG, Argon2) must propagate.
- A new key type is a newtype around `Box<Zeroizing<[u8; 32]>>`, with no public accessor to its bytes outside `crypto.rs`.
- Use domain-separation labels (`b"ArgosPass <purpose> v1"`) for any hash or KDF input, and never reuse one label for two purposes.
- An encoder must reproduce exactly the bytes that were authenticated (for example, `Header::to_bytes` for an older version).
