use thiserror::Error;

/// Unified error type for all AEGIS cryptographic and mathematical operations.
///
/// Security Note: Error variants are intentionally designed to avoid leaking
/// sensitive key material, intermediate field values, or fine-grained decryption
/// failure reasons (preventing oracle side-channels).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AegisError {
    /// Returned when the operating system CSPRNG fails to provide sufficient entropy.
    #[error("OS CSPRNG entropy source failure")]
    EntropyFailure,

    /// Returned when a cryptographic key buffer does not match the required byte length.
    #[error("Invalid key length: expected {expected} bytes, got {actual} bytes")]
    InvalidKeyLength {
        /// The required key size in bytes.
        expected: usize,
        /// The actual key size provided in bytes.
        actual: usize,
    },

    /// Returned when an AEAD nonce buffer does not match the required 96-bit (12-byte) length.
    #[error("Invalid nonce length: expected {expected} bytes, got {actual} bytes")]
    InvalidNonceLength {
        /// The required nonce size in bytes.
        expected: usize,
        /// The actual nonce size provided in bytes.
        actual: usize,
    },

    /// Returned when AEAD tag verification or key commitment verification fails.
    #[error("Cryptographic authentication or integrity verification failed")]
    AuthenticationFailed,

    /// Returned when HKDF-SHA256 expansion fails due to an invalid output length request.
    #[error("Key derivation (HKDF expansion) failed: invalid output length")]
    KeyDerivationFailed,

    /// Returned when attempting to compute a multiplicative inverse of zero in a finite field.
    #[error(
        "Finite field arithmetic error: division by zero (zero has no multiplicative inverse)"
    )]
    DivisionByZero,

    /// Returned when a value exceeds the canonical prime modulus of the finite field.
    #[error("Finite field value out of canonical range")]
    FieldValueOutOfRange,

    /// Returned when Shamir Secret Sharing parameters violate `2 <= k <= n <= 255`.
    #[error("Invalid threshold parameters: threshold k={threshold} and total shares n={total} must satisfy 2 <= k <= n <= 255")]
    InvalidThresholdParameters {
        /// Minimum number of shares required for reconstruction (`k`).
        threshold: u8,
        /// Total number of shares generated (`n`).
        total: u8,
    },

    /// Returned when fewer than `k` shares are provided during secret recovery.
    #[error("Insufficient shares for recovery: required at least {required}, provided {provided}")]
    InsufficientShares {
        /// Minimum required shares (`k`).
        required: usize,
        /// Number of shares actually supplied.
        provided: usize,
    },

    /// Returned when a share uses `x = 0` or duplicates another share's `x`-coordinate.
    #[error("Duplicate or invalid share identifier detected (x = {share_id})")]
    InvalidShareIdentifier {
        /// The offending share identifier (`x`-coordinate).
        share_id: u8,
    },

    /// Returned when a share cannot be parsed or has mismatched byte lengths.
    #[error("Malformed share data: {reason}")]
    MalformedShare {
        /// High-level description of the structural issue.
        reason: String,
    },

    /// Returned when hex decoding or binary frame parsing fails.
    #[error("Malformed input or serialization error: {reason}")]
    SerializationError {
        /// High-level description of the parsing failure.
        reason: String,
    },

    /// Returned when a file or stream I/O operation fails.
    #[error("I/O operation failed: {reason}")]
    IoError {
        /// High-level description of the I/O error.
        reason: String,
    },
}

/// Convenience type alias for Results across the AEGIS crate.
pub type AegisResult<T> = Result<T, AegisError>;
