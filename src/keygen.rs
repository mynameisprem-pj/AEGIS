use std::fmt;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{AegisError, AegisResult};

/// Size of an AEGIS Master Key in bytes (256 bits).
pub const MASTER_KEY_LEN: usize = 32;

/// A 256-bit cryptographically secure Master Key.
///
/// # Security Properties
/// - **Zeroize-on-Drop:** Automatically scrubs the internal 32-byte array from memory
///   using volatile writes when dropped.
/// - **No `Copy` Trait:** Prevents implicit bitwise duplication of secret key material on the stack.
/// - **Constant-Time Equality:** Uses `subtle::ConstantTimeEq` to prevent timing side-channels.
/// - **Redacted Debug:** Never prints raw secret bytes in `fmt::Debug`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey {
    bytes: [u8; MASTER_KEY_LEN],
}

impl MasterKey {
    /// Generates a fresh 256-bit `MasterKey` directly from the OS CSPRNG (`getrandom`).
    ///
    /// Performs a defensive sanity check to ensure the OS entropy source did not
    /// return an uninitialized all-zero buffer.
    pub fn generate() -> AegisResult<Self> {
        let mut bytes = [0u8; MASTER_KEY_LEN];
        fill_random_bytes(&mut bytes)?;

        // Defensive check against catastrophic RNG stuck-at-zero failure
        if bool::from(bytes.ct_eq(&[0u8; MASTER_KEY_LEN])) {
            bytes.zeroize();
            return Err(AegisError::EntropyFailure);
        }

        Ok(Self { bytes })
    }

    /// Constructs a `MasterKey` from a raw byte slice, validating exact length
    /// and rejecting degenerate all-zero keys.
    ///
    /// Note: The caller is responsible for zeroizing any source buffer they pass in.
    pub fn from_slice(slice: &[u8]) -> AegisResult<Self> {
        if slice.len() != MASTER_KEY_LEN {
            return Err(AegisError::InvalidKeyLength {
                expected: MASTER_KEY_LEN,
                actual: slice.len(),
            });
        }

        let mut bytes = [0u8; MASTER_KEY_LEN];
        bytes.copy_from_slice(slice);

        if bool::from(bytes.ct_eq(&[0u8; MASTER_KEY_LEN])) {
            bytes.zeroize();
            return Err(AegisError::EntropyFailure);
        }

        Ok(Self { bytes })
    }

    /// Borrows the raw 32-byte key material for cryptographic operations
    /// (such as HKDF input keying material or secret sharing).
    #[inline]
    pub fn as_bytes(&self) -> &[u8; MASTER_KEY_LEN] {
        &self.bytes
    }

    /// Encodes the master key as a lowercase hexadecimal string inside a
    /// `zeroize::Zeroizing<String>` wrapper so the hex string is also wiped on drop.
    pub fn to_hex(&self) -> zeroize::Zeroizing<String> {
        zeroize::Zeroizing::new(hex::encode(self.bytes))
    }

    /// Parses a `MasterKey` from a 64-character hexadecimal string.
    /// Intermediate decoded buffers are scrubbed immediately after construction.
    pub fn from_hex(hex_str: &str) -> AegisResult<Self> {
        let trimmed = hex_str.trim();
        let mut decoded = hex::decode(trimmed).map_err(|_| AegisError::SerializationError {
            reason: "Invalid hexadecimal encoding for master key".to_string(),
        })?;

        let result = Self::from_slice(&decoded);
        decoded.zeroize();
        result
    }
}

impl ConstantTimeEq for MasterKey {
    #[inline]
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.bytes.ct_eq(&other.bytes)
    }
}

impl PartialEq for MasterKey {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for MasterKey {}

impl fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MasterKey([REDACTED; 32 bytes])")
    }
}

/// Fills an arbitrary mutable byte slice with cryptographically secure random bytes
/// directly from the operating system's CSPRNG.
pub fn fill_random_bytes(dest: &mut [u8]) -> AegisResult<()> {
    getrandom::getrandom(dest).map_err(|_| AegisError::EntropyFailure)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_master_key_generation_succeeds_and_is_unique() {
        let key1 = MasterKey::generate().expect("CSPRNG keygen should succeed");
        let key2 = MasterKey::generate().expect("CSPRNG keygen should succeed");

        assert_eq!(key1.as_bytes().len(), MASTER_KEY_LEN);
        assert_eq!(key2.as_bytes().len(), MASTER_KEY_LEN);
        assert_ne!(
            key1, key2,
            "Two consecutive CSPRNG 256-bit keys must never collide"
        );
    }

    #[test]
    fn test_master_key_rejects_invalid_lengths() {
        let short_buf = [0xAAu8; 16];
        let long_buf = [0xAAu8; 64];

        assert_eq!(
            MasterKey::from_slice(&short_buf),
            Err(AegisError::InvalidKeyLength {
                expected: 32,
                actual: 16
            })
        );
        assert_eq!(
            MasterKey::from_slice(&long_buf),
            Err(AegisError::InvalidKeyLength {
                expected: 32,
                actual: 64
            })
        );
    }

    #[test]
    fn test_master_key_rejects_all_zero_degenerate_key() {
        let zero_buf = [0u8; MASTER_KEY_LEN];
        assert_eq!(
            MasterKey::from_slice(&zero_buf),
            Err(AegisError::EntropyFailure)
        );
    }

    #[test]
    fn test_master_key_hex_roundtrip() {
        let original = MasterKey::generate().expect("keygen should succeed");
        let hex_wrapped = original.to_hex();
        assert_eq!(hex_wrapped.len(), 64);

        let recovered = MasterKey::from_hex(&hex_wrapped).expect("hex decode should succeed");
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_master_key_debug_is_redacted() {
        let key = MasterKey::generate().expect("keygen should succeed");
        let debug_str = format!("{:?}", key);
        assert_eq!(debug_str, "MasterKey([REDACTED; 32 bytes])");
        assert!(!debug_str.contains(&hex::encode(&key.as_bytes()[0..4])));
    }

    #[test]
    fn test_explicit_zeroize_clears_buffer() {
        let mut key = MasterKey::generate().expect("keygen should succeed");
        assert_ne!(key.as_bytes(), &[0u8; MASTER_KEY_LEN]);
        key.zeroize();
        assert_eq!(key.as_bytes(), &[0u8; MASTER_KEY_LEN]);
    }
}
