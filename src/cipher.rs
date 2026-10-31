use std::fmt;

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{AegisError, AegisResult};
use crate::keygen::fill_random_bytes;

/// Length of a ChaCha20-Poly1305 key in bytes (256 bits).
pub const ENCRYPTION_KEY_LEN: usize = 32;

/// Length of a standard RFC 8439 ChaCha20-Poly1305 nonce in bytes (96 bits).
pub const NONCE_LEN: usize = 12;

/// Length of a Poly1305 authentication tag in bytes (128 bits).
pub const TAG_LEN: usize = 16;

/// Domain-separated 256-bit symmetric key used exclusively for ChaCha20-Poly1305 AEAD.
///
/// Kept as a distinct type from `MasterKey` so the type system prevents accidental
/// direct encryption with a raw master secret.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EncryptionKey {
    bytes: [u8; ENCRYPTION_KEY_LEN],
}

impl EncryptionKey {
    /// Constructs an `EncryptionKey` from a 32-byte slice, rejecting invalid lengths
    /// or degenerate all-zero buffers.
    pub fn from_slice(slice: &[u8]) -> AegisResult<Self> {
        if slice.len() != ENCRYPTION_KEY_LEN {
            return Err(AegisError::InvalidKeyLength {
                expected: ENCRYPTION_KEY_LEN,
                actual: slice.len(),
            });
        }

        let mut bytes = [0u8; ENCRYPTION_KEY_LEN];
        bytes.copy_from_slice(slice);

        if bool::from(bytes.ct_eq(&[0u8; ENCRYPTION_KEY_LEN])) {
            bytes.zeroize();
            return Err(AegisError::EntropyFailure);
        }

        Ok(Self { bytes })
    }

    /// Borrows the raw 32-byte encryption key slice.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; ENCRYPTION_KEY_LEN] {
        &self.bytes
    }
}

impl ConstantTimeEq for EncryptionKey {
    #[inline]
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.bytes.ct_eq(&other.bytes)
    }
}

impl PartialEq for EncryptionKey {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for EncryptionKey {}

impl fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EncryptionKey([REDACTED; 32 bytes])")
    }
}

/// Structured representation of an AEAD-encrypted message (`Nonce || Ciphertext || Tag`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedPayload {
    /// 96-bit (12-byte) unique nonce used during encryption.
    pub nonce: [u8; NONCE_LEN],
    /// Encrypted payload bytes (same length as original plaintext).
    pub ciphertext: Vec<u8>,
    /// 128-bit (16-byte) Poly1305 MAC authentication tag.
    pub tag: [u8; TAG_LEN],
}

impl EncryptedPayload {
    /// Serializes the payload into a contiguous binary frame:
    /// `[12-byte nonce][ciphertext...][16-byte Poly1305 tag]`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(NONCE_LEN + self.ciphertext.len() + TAG_LEN);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out.extend_from_slice(&self.tag);
        out
    }

    /// Parses a binary frame (`Nonce || Ciphertext || Tag`) into an `EncryptedPayload`.
    pub fn from_bytes(bytes: &[u8]) -> AegisResult<Self> {
        if bytes.len() < NONCE_LEN + TAG_LEN {
            return Err(AegisError::SerializationError {
                reason: format!(
                    "Encrypted frame too short: minimum {} bytes required, got {}",
                    NONCE_LEN + TAG_LEN,
                    bytes.len()
                ),
            });
        }

        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[..NONCE_LEN]);

        let tag_start = bytes.len() - TAG_LEN;
        let ciphertext = bytes[NONCE_LEN..tag_start].to_vec();

        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&bytes[tag_start..]);

        Ok(Self {
            nonce,
            ciphertext,
            tag,
        })
    }

    /// Encodes the serialized frame as a lowercase hexadecimal string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Parses an `EncryptedPayload` from a hexadecimal string.
    pub fn from_hex(hex_str: &str) -> AegisResult<Self> {
        let raw = hex::decode(hex_str.trim()).map_err(|_| AegisError::SerializationError {
            reason: "Invalid hexadecimal encoding in encrypted payload".to_string(),
        })?;
        Self::from_bytes(&raw)
    }
}

/// Generates a fresh 96-bit (12-byte) cryptographically secure nonce via the OS CSPRNG.
pub fn generate_nonce() -> AegisResult<[u8; NONCE_LEN]> {
    let mut nonce = [0u8; NONCE_LEN];
    fill_random_bytes(&mut nonce)?;
    Ok(nonce)
}

/// Encrypts `plaintext` using ChaCha20-Poly1305 with a freshly generated 96-bit OS CSPRNG nonce
/// and binds `aad` (Associated Data) to the Poly1305 authentication tag.
pub fn encrypt(key: &EncryptionKey, plaintext: &[u8], aad: &[u8]) -> AegisResult<EncryptedPayload> {
    let nonce = generate_nonce()?;
    encrypt_with_nonce(key, &nonce, plaintext, aad)
}

/// Deterministic ChaCha20-Poly1305 encryption with an explicit 96-bit nonce.
///
/// Exposed for RFC 8439 Known-Answer Test (KAT) verification and internal engine operations.
/// Never reuse the same `(key, nonce)` pair across distinct messages.
pub fn encrypt_with_nonce(
    key: &EncryptionKey,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> AegisResult<EncryptedPayload> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
    let mut buffer = plaintext.to_vec();

    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(nonce), aad, &mut buffer)
        .map_err(|_| AegisError::AuthenticationFailed)?;

    let mut tag_bytes = [0u8; TAG_LEN];
    tag_bytes.copy_from_slice(tag.as_slice());

    Ok(EncryptedPayload {
        nonce: *nonce,
        ciphertext: buffer,
        tag: tag_bytes,
    })
}

/// Verifies the Poly1305 tag in constant time and decrypts the `EncryptedPayload`.
///
/// Returns the decrypted plaintext wrapped in `zeroize::Zeroizing<Vec<u8>>` so the
/// plaintext buffer is automatically wiped from memory when dropped.
/// If the key, nonce, AAD, ciphertext, or tag has been tampered with, the internal buffer
/// is zeroized and `Err(AegisError::AuthenticationFailed)` is returned.
pub fn decrypt(
    key: &EncryptionKey,
    payload: &EncryptedPayload,
    aad: &[u8],
) -> AegisResult<zeroize::Zeroizing<Vec<u8>>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
    let mut buffer = payload.ciphertext.clone();

    let status = cipher.decrypt_in_place_detached(
        Nonce::from_slice(&payload.nonce),
        aad,
        &mut buffer,
        Tag::from_slice(&payload.tag),
    );

    if status.is_err() {
        buffer.zeroize();
        return Err(AegisError::AuthenticationFailed);
    }

    Ok(zeroize::Zeroizing::new(buffer))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_encryption_key() -> EncryptionKey {
        let mut raw = [0u8; ENCRYPTION_KEY_LEN];
        fill_random_bytes(&mut raw).expect("CSPRNG should succeed");
        EncryptionKey::from_slice(&raw).expect("valid 32-byte key")
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = sample_encryption_key();
        let plaintext = b"AEGIS confidential payload: launch sequence alpha-9";
        let aad = b"aegis-v1-header-context";

        let payload = encrypt(&key, plaintext, aad).expect("encryption should succeed");
        assert_eq!(payload.ciphertext.len(), plaintext.len());
        assert_ne!(payload.ciphertext.as_slice(), plaintext);

        let decrypted = decrypt(&key, &payload, aad).expect("decryption should succeed");
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_rejects_tampered_ciphertext() {
        let key = sample_encryption_key();
        let plaintext = b"Transfer $1,000,000 to vault";
        let aad = b"header-v1";

        let mut payload = encrypt(&key, plaintext, aad).expect("encryption should succeed");
        // Flip a single bit in the ciphertext
        payload.ciphertext[0] ^= 0x01;

        let result = decrypt(&key, &payload, aad);
        assert_eq!(result, Err(AegisError::AuthenticationFailed));
    }

    #[test]
    fn test_rejects_tampered_tag() {
        let key = sample_encryption_key();
        let plaintext = b"Critical cryptographic state";
        let aad = b"header-v1";

        let mut payload = encrypt(&key, plaintext, aad).expect("encryption should succeed");
        // Flip the last bit of the 128-bit Poly1305 tag
        payload.tag[TAG_LEN - 1] ^= 0x01;

        let result = decrypt(&key, &payload, aad);
        assert_eq!(result, Err(AegisError::AuthenticationFailed));
    }

    #[test]
    fn test_rejects_tampered_aad() {
        let key = sample_encryption_key();
        let plaintext = b"Authenticated message";
        let aad = b"original-associated-data";

        let payload = encrypt(&key, plaintext, aad).expect("encryption should succeed");
        let result = decrypt(&key, &payload, b"modified-associated-data");
        assert_eq!(result, Err(AegisError::AuthenticationFailed));
    }

    #[test]
    fn test_rejects_wrong_key() {
        let key1 = sample_encryption_key();
        let key2 = sample_encryption_key();
        let plaintext = b"Secret under key1";
        let aad = b"context";

        let payload = encrypt(&key1, plaintext, aad).expect("encryption should succeed");
        let result = decrypt(&key2, &payload, aad);
        assert_eq!(result, Err(AegisError::AuthenticationFailed));
    }

    #[test]
    fn test_payload_serialization_roundtrip_and_malformed_rejection() {
        let key = sample_encryption_key();
        let payload = encrypt(&key, b"serialize me", b"aad").expect("encrypt");

        let hex_str = payload.to_hex();
        let decoded = EncryptedPayload::from_hex(&hex_str).expect("valid hex frame");
        assert_eq!(payload, decoded);

        // Frame shorter than NONCE_LEN (12) + TAG_LEN (16) = 28 bytes must be rejected
        assert!(matches!(
            EncryptedPayload::from_bytes(&[0u8; 27]),
            Err(AegisError::SerializationError { .. })
        ));
    }

    #[test]
    fn test_rfc8439_known_answer_vector() {
        // Official RFC 8439 Section 2.8.2 Test Vector
        let key_bytes: [u8; 32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let nonce: [u8; 12] = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];
        let aad: [u8; 12] = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        let expected_tag: [u8; 16] = [
            0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60,
            0x06, 0x91,
        ];

        let key = EncryptionKey::from_slice(&key_bytes).expect("valid RFC key");
        let payload =
            encrypt_with_nonce(&key, &nonce, plaintext, &aad).expect("RFC encryption succeeds");

        assert_eq!(payload.tag, expected_tag);
        let recovered = decrypt(&key, &payload, &aad).expect("RFC decryption succeeds");
        assert_eq!(recovered.as_slice(), plaintext);
    }
}
