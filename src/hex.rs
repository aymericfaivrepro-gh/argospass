//! Hexadecimal encoding and decoding, written by hand.
//!
//! [`push_byte`] writes into a caller-provided `String`, with no temporary
//! string: it can fill a [`Zeroizing`](zeroize::Zeroizing) buffer with a
//! secret (the pepper recovery code). [`encode`] and [`decode`] are for
//! public values only (ids, nonces, ciphertexts).

/// Lowercase hex digits, indexed by their value.
const DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Appends the two lowercase hex digits of `byte` to `out`, high half first.
pub(crate) fn push_byte(out: &mut String, byte: u8) {
    out.push(char::from(DIGITS[usize::from(byte >> 4)]));
    out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
}

/// Returns the value of the hex digit `c` (in any case), or `None` if `c` is
/// not a hex digit.
pub(crate) fn nibble(c: char) -> Option<u8> {
    // Always below 16, so the conversion is lossless.
    c.to_digit(16).map(|value| value as u8)
}

/// Encodes `bytes` as lowercase hex. Only for public values: the string is
/// not wiped.
pub(crate) fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 * bytes.len());
    for &byte in bytes {
        push_byte(&mut out, byte);
    }
    out
}

/// Decodes a hex string written by [`encode`]. Returns `None` if its length is
/// odd or if it contains anything but hex digits. Only for public values.
pub(crate) fn decode(hex: &str) -> Option<Vec<u8>> {
    // Pairs of digits, and the digit left over if the length is odd.
    let (pairs, rest) = hex.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    // Byte by byte: a byte of a non-ASCII character is never a hex digit.
    // Collecting `Option`s stops at the first `None`.
    pairs
        .iter()
        .map(|&[high, low]| Some((nibble(char::from(high))? << 4) | nibble(char::from(low))?))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let bytes: Vec<u8> = (0..=255).collect();
        let hex = encode(&bytes);
        assert_eq!(hex.len(), 512);
        assert!(hex.starts_with("000102"));
        assert!(hex.ends_with("fdfeff"));
        assert_eq!(decode(&hex), Some(bytes));
    }

    #[test]
    fn decode_accepts_both_cases() {
        assert_eq!(decode("aBcD"), Some(vec![0xab, 0xcd]));
        assert_eq!(decode(""), Some(vec![]));
    }

    #[test]
    fn decode_rejects_malformed_input() {
        // Odd length, characters that are not hex digits, and non-ASCII
        // characters (2 bytes each in UTF-8: the length alone looks even).
        for hex in ["abc", "zz", "0g", " 0", "é0", "00é", "éé"] {
            assert_eq!(decode(hex), None, "{hex}");
        }
    }
}
