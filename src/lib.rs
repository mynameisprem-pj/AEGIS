#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

//! # AEGIS Cryptographic Engine
//!
//! Adaptive Encryption and Guarded Integrated Secret-Key System.
//! Provides master-key generation, HKDF-SHA256 domain-separated key derivation,
//! ChaCha20-Poly1305 authenticated encryption, and finite-field Shamir Secret Sharing.

/// ChaCha20-Poly1305 Authenticated Encryption with Associated Data (AEAD).
pub mod cipher;
/// High-level integrated AEGIS workflows combining keygen, HKDF, SSS, and AEAD.
pub mod engine;
/// Centralized error handling for AEGIS operations.
pub mod error;
/// Prime finite field arithmetic over `GF(2^31 - 1)`.
pub mod field;
/// HKDF-SHA256 Key Derivation and Domain Separation hierarchy.
pub mod kdf;
/// Cryptographically secure master-key generation and memory-safe secret buffers.
pub mod keygen;
/// Shamir's Secret Sharing (`(k, n)` threshold recovery) over `GF(2^31 - 1)`.
pub mod sss;

pub use cipher::{
    decrypt, encrypt, encrypt_with_nonce, generate_nonce, EncryptedPayload, EncryptionKey,
    ENCRYPTION_KEY_LEN, NONCE_LEN, TAG_LEN,
};
pub use engine::{
    open, open_with_shares, recover_and_verify, seal, split_and_commit, AegisEnvelope,
    VerifiableShareSet, ENVELOPE_HEADER_V1,
};
pub use error::{AegisError, AegisResult};
pub use field::{evaluate_polynomial, FieldElement, FIELD_PRIME};
pub use kdf::{
    derive_encryption_key, derive_hierarchy, derive_key_commitment, hkdf_derive,
    DerivedKeyHierarchy, KeyCommitment, AEGIS_HKDF_SALT, COMMITMENT_LEN, DOMAIN_ENCRYPTION_KEY,
    DOMAIN_KEY_COMMITMENT,
};
pub use keygen::{fill_random_bytes, MasterKey, MASTER_KEY_LEN};
pub use sss::{
    lagrange_interpolate_at_zero, recover_master_key, split_master_key, Share, CHUNKS_PER_KEY,
    SHARE_BYTE_LEN,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_formatting_does_not_leak_secrets() {
        let auth_err = AegisError::AuthenticationFailed;
        assert_eq!(
            auth_err.to_string(),
            "Cryptographic authentication or integrity verification failed"
        );

        let key_err = AegisError::InvalidKeyLength {
            expected: 32,
            actual: 16,
        };
        assert_eq!(
            key_err.to_string(),
            "Invalid key length: expected 32 bytes, got 16 bytes"
        );
    }

    #[test]
    fn test_threshold_error_representation() {
        let err = AegisError::InvalidThresholdParameters {
            threshold: 5,
            total: 3,
        };
        assert!(err.to_string().contains("k=5"));
        assert!(err.to_string().contains("n=3"));
    }
}
