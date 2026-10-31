use zeroize::Zeroizing;

use crate::cipher::{decrypt, encrypt, EncryptedPayload};
use crate::error::{AegisError, AegisResult};
use crate::kdf::{derive_hierarchy, KeyCommitment};
use crate::keygen::MasterKey;
use crate::sss::{recover_master_key, split_master_key, Share};

/// Canonical header prefix used in serialized AEGIS envelopes and AAD binding.
pub const ENVELOPE_HEADER_V1: &str = "AEGIS-ENVELOPE-v1";

/// Self-contained authenticated encryption envelope binding the key commitment
/// and encrypted payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AegisEnvelope {
    /// Public 256-bit HKDF commitment to the `MasterKey` that sealed this envelope.
    pub commitment: KeyCommitment,
    /// Underlying ChaCha20-Poly1305 nonce, ciphertext, and 128-bit Poly1305 tag.
    pub payload: EncryptedPayload,
}

impl AegisEnvelope {
    /// Serializes the envelope into a human-readable, structured string format:
    /// `AEGIS-ENVELOPE-v1:<commitment_hex>:<nonce_cipher_tag_hex>`
    pub fn to_encoded_string(&self) -> String {
        format!(
            "{}:{}:{}",
            ENVELOPE_HEADER_V1,
            self.commitment.to_hex(),
            self.payload.to_hex()
        )
    }

    /// Parses an `AegisEnvelope` from its `AEGIS-ENVELOPE-v1:<commitment_hex>:<payload_hex>`
    /// encoded string representation.
    pub fn from_encoded_string(encoded: &str) -> AegisResult<Self> {
        let parts: Vec<&str> = encoded.trim().split(':').collect();
        if parts.len() != 3 || parts[0] != ENVELOPE_HEADER_V1 {
            return Err(AegisError::SerializationError {
                reason: format!(
                    "Invalid envelope format; expected {}:<commitment_hex>:<payload_hex>",
                    ENVELOPE_HEADER_V1
                ),
            });
        }

        let commitment = KeyCommitment::from_hex(parts[1])?;
        let payload = EncryptedPayload::from_hex(parts[2])?;

        Ok(Self {
            commitment,
            payload,
        })
    }
}

/// Output of splitting a `MasterKey` into `(k, n)` threshold shares alongside its
/// public verification commitment.
#[derive(Debug, Clone)]
pub struct VerifiableShareSet {
    /// Public 256-bit HKDF commitment to the split `MasterKey`.
    pub commitment: KeyCommitment,
    /// The `n` generated Shamir secret shares over `GF(2^31 - 1)`.
    pub shares: Vec<Share>,
}

/// Constructs the canonical Associated Data (AAD) transcript that cryptographically binds
/// the envelope version, the 32-byte `KeyCommitment`, and the caller's custom AAD.
fn build_canonical_aad(commitment: &KeyCommitment, user_aad: &[u8]) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(ENVELOPE_HEADER_V1.len() + 1 + 32 + 1 + user_aad.len());
    transcript.extend_from_slice(ENVELOPE_HEADER_V1.as_bytes());
    transcript.push(0x00);
    transcript.extend_from_slice(commitment.as_bytes());
    transcript.push(0x00);
    transcript.extend_from_slice(user_aad);
    transcript
}

/// Seals `plaintext` under `master_key` by deriving the HKDF key hierarchy, binding the
/// `KeyCommitment` and `user_aad` into a canonical AAD transcript, and encrypting with
/// ChaCha20-Poly1305.
pub fn seal(
    master_key: &MasterKey,
    plaintext: &[u8],
    user_aad: &[u8],
) -> AegisResult<AegisEnvelope> {
    let hierarchy = derive_hierarchy(master_key)?;
    let canonical_aad = build_canonical_aad(&hierarchy.commitment, user_aad);
    let payload = encrypt(&hierarchy.encryption_key, plaintext, &canonical_aad)?;

    Ok(AegisEnvelope {
        commitment: hierarchy.commitment.clone(),
        payload,
    })
}

/// Opens and authenticates an `AegisEnvelope` using `master_key` and `user_aad`.
///
/// Performs two independent constant-time verifications:
/// 1. Verifies that `master_key` matches the envelope's HKDF `KeyCommitment`.
/// 2. Verifies the Poly1305 authentication tag over the canonical AAD transcript and ciphertext.
pub fn open(
    master_key: &MasterKey,
    envelope: &AegisEnvelope,
    user_aad: &[u8],
) -> AegisResult<Zeroizing<Vec<u8>>> {
    let hierarchy = derive_hierarchy(master_key)?;

    // Constant-time check that the provided MasterKey matches the envelope's commitment
    if hierarchy.commitment != envelope.commitment {
        return Err(AegisError::AuthenticationFailed);
    }

    let canonical_aad = build_canonical_aad(&envelope.commitment, user_aad);
    decrypt(&hierarchy.encryption_key, &envelope.payload, &canonical_aad)
}

/// Splits `master_key` into `total` (`n`) shares with recovery threshold `threshold` (`k`)
/// and derives its public `KeyCommitment`.
pub fn split_and_commit(
    master_key: &MasterKey,
    threshold: u8,
    total: u8,
) -> AegisResult<VerifiableShareSet> {
    let hierarchy = derive_hierarchy(master_key)?;
    let shares = split_master_key(master_key, threshold, total)?;
    Ok(VerifiableShareSet {
        commitment: hierarchy.commitment.clone(),
        shares,
    })
}

/// Reconstructs a `MasterKey` from at least `k` `Share`s using Lagrange interpolation
/// over `GF(2^31 - 1)` and optionally verifies it in constant time against an expected
/// `KeyCommitment`.
pub fn recover_and_verify(
    shares: &[Share],
    expected_commitment: Option<&KeyCommitment>,
) -> AegisResult<MasterKey> {
    let recovered_key = recover_master_key(shares)?;
    if let Some(commitment) = expected_commitment {
        commitment.verify(&recovered_key)?;
    }
    Ok(recovered_key)
}

/// Reconstructs the `MasterKey` directly from `shares`, verifies it against the
/// `AegisEnvelope`'s embedded `KeyCommitment`, and decrypts the payload.
///
/// The reconstructed `MasterKey` and intermediate `EncryptionKey` are automatically
/// zeroized as soon as decryption completes.
pub fn open_with_shares(
    shares: &[Share],
    envelope: &AegisEnvelope,
    user_aad: &[u8],
) -> AegisResult<Zeroizing<Vec<u8>>> {
    let recovered_key = recover_and_verify(shares, Some(&envelope.commitment))?;
    open(&recovered_key, envelope, user_aad)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_complete_aegis_lifecycle_keygen_split_seal_recover_open() {
        let master = MasterKey::generate().expect("keygen");
        let plaintext = b"AEGIS Phase 7: End-to-End Threshold AEAD Verification";
        let aad = b"vault-id:alpha-01";

        // 1. Seal the payload into an AegisEnvelope
        let envelope = seal(&master, plaintext, aad).expect("seal should succeed");

        // 2. Split the MasterKey into (k=3, n=5) shares with commitment
        let share_set = split_and_commit(&master, 3, 5).expect("split 3-of-5");
        assert_eq!(share_set.commitment, envelope.commitment);

        // 3. Serialize & deserialize the envelope and 3 non-consecutive shares (shares 1, 3, 5)
        let encoded_envelope = envelope.to_encoded_string();
        let parsed_envelope =
            AegisEnvelope::from_encoded_string(&encoded_envelope).expect("parse envelope");

        let selected_encoded = [
            share_set.shares[0].to_encoded_string(),
            share_set.shares[2].to_encoded_string(),
            share_set.shares[4].to_encoded_string(),
        ];
        let parsed_shares: Vec<Share> = selected_encoded
            .iter()
            .map(|s| Share::from_encoded_string(s).expect("parse share"))
            .collect();

        // 4. Open envelope directly using the 3 recovered shares
        let decrypted = open_with_shares(&parsed_shares, &parsed_envelope, aad)
            .expect("open with shares must succeed");
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_rejects_shares_from_wrong_master_key() {
        let master1 = MasterKey::generate().expect("keygen 1");
        let master2 = MasterKey::generate().expect("keygen 2");

        let envelope = seal(&master1, b"Classified data", b"aad").expect("seal");
        let wrong_shares = split_and_commit(&master2, 3, 5).expect("split wrong key");

        // Attempting to open master1's envelope with master2's valid shares must fail
        let result = open_with_shares(&wrong_shares.shares[0..3], &envelope, b"aad");
        assert_eq!(result, Err(AegisError::AuthenticationFailed));
    }

    #[test]
    fn test_rejects_corrupted_share_during_recovery() {
        let master = MasterKey::generate().expect("keygen");
        let share_set = split_and_commit(&master, 3, 5).expect("split");

        let mut subset = [
            share_set.shares[0].clone(),
            share_set.shares[1].clone(),
            share_set.shares[2].clone(),
        ];
        // Corrupt a single evaluation value in share[1]
        subset[1].y_values[0] = subset[1].y_values[0] + crate::field::FieldElement::ONE;

        let res = recover_and_verify(&subset, Some(&share_set.commitment));
        assert_eq!(res, Err(AegisError::AuthenticationFailed));
    }

    #[test]
    fn test_rejects_commitment_substitution_on_envelope() {
        let master1 = MasterKey::generate().expect("keygen 1");
        let master2 = MasterKey::generate().expect("keygen 2");

        let mut envelope = seal(&master1, b"Payload", b"aad").expect("seal");
        let hierarchy2 = derive_hierarchy(&master2).expect("derive 2");

        // Attacker swaps the envelope's commitment with master2's commitment
        envelope.commitment = hierarchy2.commitment.clone();

        // Fails under both master1 (commitment mismatch) and master2 (Poly1305 AAD mismatch)
        assert_eq!(
            open(&master1, &envelope, b"aad"),
            Err(AegisError::AuthenticationFailed)
        );
        assert_eq!(
            open(&master2, &envelope, b"aad"),
            Err(AegisError::AuthenticationFailed)
        );
    }
}
