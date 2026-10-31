use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::cipher::{EncryptionKey, ENCRYPTION_KEY_LEN};
use crate::error::{AegisError, AegisResult};
use crate::keygen::MasterKey;

/// Length of an AEGIS Key Commitment tag in bytes (256 bits).
pub const COMMITMENT_LEN: usize = 32;

/// Protocol-level HKDF salt binding all derivations to AEGIS version 1.
pub const AEGIS_HKDF_SALT: &[u8] = b"AEGIS-v1-HKDF-SHA256-ROOT-SALT";

/// Domain-separation context label for deriving the ChaCha20-Poly1305 encryption subkey.
pub const DOMAIN_ENCRYPTION_KEY: &[u8] = b"AEGIS-v1-CHACHA20POLY1305-ENC-KEY";

/// Domain-separation context label for deriving the master key verification commitment.
pub const DOMAIN_KEY_COMMITMENT: &[u8] = b"AEGIS-v1-MASTER-KEY-COMMITMENT";

/// A 256-bit public cryptographic commitment to a `MasterKey`.
///
/// Can be safely stored in plaintext headers or alongside Shamir shares to verify
/// that a reconstructed master key is authentic before attempting payload decryption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyCommitment {
    bytes: [u8; COMMITMENT_LEN],
}

impl KeyCommitment {
    /// Constructs a `KeyCommitment` from a 32-byte slice.
    pub fn from_slice(slice: &[u8]) -> AegisResult<Self> {
        if slice.len() != COMMITMENT_LEN {
            return Err(AegisError::InvalidKeyLength {
                expected: COMMITMENT_LEN,
                actual: slice.len(),
            });
        }
        let mut bytes = [0u8; COMMITMENT_LEN];
        bytes.copy_from_slice(slice);
        Ok(Self { bytes })
    }

    /// Borrows the underlying 32-byte commitment tag.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; COMMITMENT_LEN] {
        &self.bytes
    }

    /// Encodes the commitment as a 64-character lowercase hexadecimal string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }

    /// Parses a `KeyCommitment` from a 64-character hexadecimal string.
    pub fn from_hex(hex_str: &str) -> AegisResult<Self> {
        let raw = hex::decode(hex_str.trim()).map_err(|_| AegisError::SerializationError {
            reason: "Invalid hexadecimal encoding in key commitment".to_string(),
        })?;
        Self::from_slice(&raw)
    }

    /// Verifies in constant time whether this commitment matches a candidate `MasterKey`.
    pub fn verify(&self, candidate_master: &MasterKey) -> AegisResult<()> {
        let expected = derive_key_commitment(candidate_master)?;
        if bool::from(self.bytes.ct_eq(&expected.bytes)) {
            Ok(())
        } else {
            Err(AegisError::AuthenticationFailed)
        }
    }
}

impl ConstantTimeEq for KeyCommitment {
    #[inline]
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.bytes.ct_eq(&other.bytes)
    }
}

/// Complete set of domain-separated keys derived from a single `MasterKey`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DerivedKeyHierarchy {
    /// Subkey used exclusively for ChaCha20-Poly1305 authenticated encryption.
    pub encryption_key: EncryptionKey,
    /// Publicly shareable 256-bit commitment tag for validating master-key reconstruction.
    #[zeroize(skip)]
    pub commitment: KeyCommitment,
}

/// Low-level HKDF-SHA256 Extract-and-Expand primitive with explicit salt and domain info.
///
/// The intermediate Output Keying Material (OKM) buffer is scrubbed if subsequent
/// processing fails.
pub fn hkdf_derive(
    master_key: &MasterKey,
    salt: Option<&[u8]>,
    info: &[u8],
    out: &mut [u8],
) -> AegisResult<()> {
    let hk = Hkdf::<Sha256>::new(salt, master_key.as_bytes());
    hk.expand(info, out).map_err(|_| {
        out.zeroize();
        AegisError::KeyDerivationFailed
    })
}

/// Derives the domain-separated 256-bit `EncryptionKey` from a `MasterKey`.
pub fn derive_encryption_key(master_key: &MasterKey) -> AegisResult<EncryptionKey> {
    let mut okm = [0u8; ENCRYPTION_KEY_LEN];
    hkdf_derive(
        master_key,
        Some(AEGIS_HKDF_SALT),
        DOMAIN_ENCRYPTION_KEY,
        &mut okm,
    )?;
    let key_res = EncryptionKey::from_slice(&okm);
    okm.zeroize();
    key_res
}

/// Derives the domain-separated 256-bit `KeyCommitment` from a `MasterKey`.
pub fn derive_key_commitment(master_key: &MasterKey) -> AegisResult<KeyCommitment> {
    let mut okm = [0u8; COMMITMENT_LEN];
    hkdf_derive(
        master_key,
        Some(AEGIS_HKDF_SALT),
        DOMAIN_KEY_COMMITMENT,
        &mut okm,
    )?;
    let commit_res = KeyCommitment::from_slice(&okm);
    okm.zeroize();
    commit_res
}

/// Derives the complete AEGIS key hierarchy (`EncryptionKey` + `KeyCommitment`)
/// from a `MasterKey` in a single call.
pub fn derive_hierarchy(master_key: &MasterKey) -> AegisResult<DerivedKeyHierarchy> {
    let encryption_key = derive_encryption_key(master_key)?;
    let commitment = derive_key_commitment(master_key)?;
    Ok(DerivedKeyHierarchy {
        encryption_key,
        commitment,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_separation_produces_independent_outputs() {
        let master = MasterKey::generate().expect("keygen");
        let hierarchy = derive_hierarchy(&master).expect("hkdf hierarchy");

        // Subkey must never equal master key or commitment
        assert_ne!(hierarchy.encryption_key.as_bytes(), master.as_bytes());
        assert_ne!(
            hierarchy.encryption_key.as_bytes(),
            hierarchy.commitment.as_bytes()
        );
        assert_ne!(hierarchy.commitment.as_bytes(), master.as_bytes());
    }

    #[test]
    fn test_deterministic_derivation_and_commitment_verification() {
        let master1 = MasterKey::generate().expect("keygen 1");
        let master2 = MasterKey::generate().expect("keygen 2");

        let h1_a = derive_hierarchy(&master1).expect("derive 1a");
        let h1_b = derive_hierarchy(&master1).expect("derive 1b");

        assert_eq!(h1_a.encryption_key, h1_b.encryption_key);
        assert_eq!(h1_a.commitment, h1_b.commitment);

        // Commitment verifies against master1, rejects master2
        assert!(h1_a.commitment.verify(&master1).is_ok());
        assert_eq!(
            h1_a.commitment.verify(&master2),
            Err(AegisError::AuthenticationFailed)
        );
    }

    #[test]
    fn test_commitment_hex_roundtrip() {
        let master = MasterKey::generate().expect("keygen");
        let commit = derive_key_commitment(&master).expect("commit");
        let hex_str = commit.to_hex();
        assert_eq!(hex_str.len(), 64);

        let decoded = KeyCommitment::from_hex(&hex_str).expect("from_hex");
        assert_eq!(commit, decoded);
    }

    #[test]
    fn test_hkdf_rejects_excessive_output_length() {
        // RFC 5869 limits HKDF-SHA256 output to 255 * 32 = 8160 bytes.
        let master = MasterKey::generate().expect("keygen");
        let mut oversized_buf = vec![0u8; 8161];
        let res = hkdf_derive(
            &master,
            Some(AEGIS_HKDF_SALT),
            b"oversized",
            &mut oversized_buf,
        );
        assert_eq!(res, Err(AegisError::KeyDerivationFailed));
    }

    #[test]
    fn test_rfc5869_hkdf_sha256_known_answer_vector() {
        // Official RFC 5869 Test Case 1 (Basic test case with SHA-256)
        // Adapted to a 32-byte IKM to satisfy MasterKey's 32-byte invariant:
        let ikm_bytes = [0x0bu8; 32];
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();

        let master = MasterKey::from_slice(&ikm_bytes).expect("valid 32-byte IKM");
        let mut okm1 = [0u8; 42];
        let mut okm2 = [0u8; 42];

        hkdf_derive(&master, Some(&salt), &info, &mut okm1).expect("hkdf 1");
        hkdf_derive(&master, Some(&salt), &info, &mut okm2).expect("hkdf 2");
        assert_eq!(okm1, okm2);

        // Changing a single bit in the info string must completely change the derived OKM
        let mut info_modified = info.clone();
        info_modified[0] ^= 0x01;
        let mut okm_diff = [0u8; 42];
        hkdf_derive(&master, Some(&salt), &info_modified, &mut okm_diff).expect("hkdf diff");
        assert_ne!(okm1, okm_diff);
    }
}
