use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{AegisError, AegisResult};
use crate::field::{evaluate_polynomial, FieldElement};
use crate::keygen::{MasterKey, MASTER_KEY_LEN};

/// Number of 16-bit (`u16`) chunks in a 256-bit (32-byte) `MasterKey`.
pub const CHUNKS_PER_KEY: usize = MASTER_KEY_LEN / 2;

/// Serialized byte length of a single share:
/// `1 byte (threshold k) + 1 byte (share_id x) + 16 * 4 bytes (u32 field elements) = 66 bytes`.
pub const SHARE_BYTE_LEN: usize = 2 + (CHUNKS_PER_KEY * 4);

/// A single threshold share of a 256-bit `MasterKey` evaluated over `GF(2^31 - 1)`.
///
/// Automatically zeroizes its finite-field evaluations when dropped from memory.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Share {
    /// Minimum number of shares (`k`) required to reconstruct the secret.
    pub threshold: u8,
    /// Non-zero evaluation point `x` in `1..=255`.
    pub id: u8,
    /// Polynomial evaluations `[f_0(x), f_1(x), ..., f_15(x)]` in `GF(2^31 - 1)`.
    pub y_values: [FieldElement; CHUNKS_PER_KEY],
}

impl Share {
    /// Serializes the share into a 66-byte binary buffer:
    /// `[threshold (1B)][id (1B)][y_0 (4B LE)]...[y_15 (4B LE)]`.
    pub fn to_bytes(&self) -> zeroize::Zeroizing<Vec<u8>> {
        let mut out = Vec::with_capacity(SHARE_BYTE_LEN);
        out.push(self.threshold);
        out.push(self.id);
        for elem in &self.y_values {
            out.extend_from_slice(&elem.value().to_le_bytes());
        }
        zeroize::Zeroizing::new(out)
    }

    /// Parses a `Share` from its 66-byte binary representation, validating threshold
    /// bounds, non-zero identifier `x`, and canonical finite-field range `0 <= y_i < p`.
    pub fn from_bytes(bytes: &[u8]) -> AegisResult<Self> {
        if bytes.len() != SHARE_BYTE_LEN {
            return Err(AegisError::MalformedShare {
                reason: format!(
                    "Expected share length of {} bytes, got {}",
                    SHARE_BYTE_LEN,
                    bytes.len()
                ),
            });
        }

        let threshold = bytes[0];
        let id = bytes[1];

        if threshold < 2 {
            return Err(AegisError::InvalidThresholdParameters {
                threshold,
                total: threshold,
            });
        }

        if id == 0 {
            return Err(AegisError::InvalidShareIdentifier { share_id: 0 });
        }

        let mut y_values = [FieldElement::ZERO; CHUNKS_PER_KEY];
        for (idx, chunk) in bytes[2..].as_chunks::<4>().0.iter().enumerate() {
            let raw_u32 = u32::from_le_bytes(*chunk);
            y_values[idx] = FieldElement::from_canonical(raw_u32)?;
        }

        Ok(Self {
            threshold,
            id,
            y_values,
        })
    }

    /// Encodes the share as a compact, human-readable string: `AEGIS-SHARE-v1:<k>:<id>:<hex_y>`.
    pub fn to_encoded_string(&self) -> zeroize::Zeroizing<String> {
        let raw = self.to_bytes();
        let hex_payload = hex::encode(&raw[2..]);
        zeroize::Zeroizing::new(format!(
            "AEGIS-SHARE-v1:{}:{}:{}",
            self.threshold, self.id, hex_payload
        ))
    }

    /// Parses a `Share` from its `AEGIS-SHARE-v1:<k>:<id>:<hex_y>` string representation.
    pub fn from_encoded_string(encoded: &str) -> AegisResult<Self> {
        let parts: Vec<&str> = encoded.trim().split(':').collect();
        if parts.len() != 4 || parts[0] != "AEGIS-SHARE-v1" {
            return Err(AegisError::MalformedShare {
                reason: "Invalid share header format; expected AEGIS-SHARE-v1:<k>:<id>:<hex>"
                    .to_string(),
            });
        }

        let threshold: u8 = parts[1].parse().map_err(|_| AegisError::MalformedShare {
            reason: "Invalid threshold integer in share".to_string(),
        })?;
        let id: u8 = parts[2].parse().map_err(|_| AegisError::MalformedShare {
            reason: "Invalid share identifier integer".to_string(),
        })?;

        let mut decoded_y = hex::decode(parts[3]).map_err(|_| AegisError::MalformedShare {
            reason: "Invalid hexadecimal payload in share".to_string(),
        })?;

        let mut full_bytes = Vec::with_capacity(2 + decoded_y.len());
        full_bytes.push(threshold);
        full_bytes.push(id);
        full_bytes.extend_from_slice(&decoded_y);
        decoded_y.zeroize();

        let res = Self::from_bytes(&full_bytes);
        full_bytes.zeroize();
        res
    }
}

impl fmt::Debug for Share {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Share {{ threshold: {}, id: {}, y_values: [REDACTED; {} elements] }}",
            self.threshold, self.id, CHUNKS_PER_KEY
        )
    }
}

/// Splits a 256-bit `MasterKey` into `total` (`n`) shares with recovery threshold `threshold` (`k`)
/// using Shamir's Secret Sharing over `GF(2^31 - 1)`.
///
/// Requires `2 <= threshold <= total <= 255`.
pub fn split_master_key(
    master_key: &MasterKey,
    threshold: u8,
    total: u8,
) -> AegisResult<Vec<Share>> {
    if threshold < 2 || threshold > total {
        return Err(AegisError::InvalidThresholdParameters { threshold, total });
    }

    let k = threshold as usize;
    let n = total as usize;
    let key_bytes = master_key.as_bytes();

    // Pre-allocate n shares with x = 1..=n
    let mut shares: Vec<Share> = (1..=total)
        .map(|id| Share {
            threshold,
            id,
            y_values: [FieldElement::ZERO; CHUNKS_PER_KEY],
        })
        .collect();

    // Temporary polynomial coefficient vector: coeffs[0] = secret chunk, coeffs[1..k] = random
    let mut coeffs = vec![FieldElement::ZERO; k];

    for (chunk_idx, pair) in key_bytes.as_chunks::<2>().0.iter().enumerate() {
        let secret_u16 = u16::from_le_bytes(*pair);
        coeffs[0] = FieldElement::from_canonical(secret_u16 as u32)?;

        // Sample k - 1 uniform random coefficients in GF(p), with highest-degree coeff != 0
        for (deg, coeff_slot) in coeffs.iter_mut().enumerate().skip(1) {
            *coeff_slot = if deg == k - 1 {
                FieldElement::random_nonzero()?
            } else {
                FieldElement::random()?
            };
        }

        // Evaluate f_chunk(x_i) for each participant x_i in 1..=n
        for share in shares.iter_mut().take(n) {
            let x = FieldElement::from_canonical(share.id as u32)?;
            share.y_values[chunk_idx] = evaluate_polynomial(&coeffs, x);
        }

        // Zeroize each coefficient in-place without truncating the Vec length
        for c in &mut coeffs {
            c.zeroize();
        }
    }

    coeffs.zeroize();
    Ok(shares)
}

/// Computes the Lagrange interpolation value `f(0)` over `GF(2^31 - 1)` given `k` distinct
/// points `(x_i, y_i)`.
pub fn lagrange_interpolate_at_zero(
    points: &[(FieldElement, FieldElement)],
) -> AegisResult<FieldElement> {
    let k = points.len();
    if k < 2 {
        return Err(AegisError::InsufficientShares {
            required: 2,
            provided: k,
        });
    }

    let mut secret = FieldElement::ZERO;

    for j in 0..k {
        let (x_j, y_j) = points[j];
        let mut numerator = FieldElement::ONE;
        let mut denominator = FieldElement::ONE;

        for (i, &(x_i, _)) in points.iter().enumerate() {
            if i == j {
                continue;
            }
            // At x = 0: basis term is (0 - x_i) / (x_j - x_i) = x_i / (x_i - x_j)
            numerator = numerator * x_i;
            let diff = x_i - x_j;
            denominator = denominator * diff;
        }

        let basis_j = (numerator / denominator)?;
        secret = secret + (y_j * basis_j);
    }

    Ok(secret)
}

/// Reconstructs the 256-bit `MasterKey` from a slice of `Share`s using Lagrange interpolation.
///
/// Validates:
/// - Non-empty share slice and consistent `threshold` metadata across shares.
/// - At least `threshold` (`k`) shares are provided.
/// - All share identifiers `x_i` are non-zero and pairwise distinct.
/// - Reconstructed field values fit cleanly within canonical 16-bit chunk bounds (`0..=65535`).
pub fn recover_master_key(shares: &[Share]) -> AegisResult<MasterKey> {
    if shares.is_empty() {
        return Err(AegisError::InsufficientShares {
            required: 2,
            provided: 0,
        });
    }

    let k = shares[0].threshold as usize;
    if k < 2 {
        return Err(AegisError::InvalidThresholdParameters {
            threshold: shares[0].threshold,
            total: shares[0].threshold,
        });
    }

    if shares.len() < k {
        return Err(AegisError::InsufficientShares {
            required: k,
            provided: shares.len(),
        });
    }

    // Validate consistent threshold and pairwise distinct non-zero x-coordinates across all provided shares
    for (idx, share) in shares.iter().enumerate() {
        if share.threshold != shares[0].threshold {
            return Err(AegisError::MalformedShare {
                reason: "Mismatched threshold parameters across provided shares".to_string(),
            });
        }
        if share.id == 0 {
            return Err(AegisError::InvalidShareIdentifier { share_id: 0 });
        }
        for prev in &shares[..idx] {
            if prev.id == share.id {
                return Err(AegisError::InvalidShareIdentifier { share_id: share.id });
            }
        }
    }

    // Use exactly the first k validated shares for degree-(k-1) interpolation
    let active_shares = &shares[..k];
    let mut points = vec![(FieldElement::ZERO, FieldElement::ZERO); k];
    let mut key_bytes = [0u8; MASTER_KEY_LEN];

    for chunk_idx in 0..CHUNKS_PER_KEY {
        for (s_idx, share) in active_shares.iter().enumerate() {
            let x = FieldElement::from_canonical(share.id as u32)?;
            let y = share.y_values[chunk_idx];
            points[s_idx] = (x, y);
        }

        let recovered_elem = lagrange_interpolate_at_zero(&points)?;
        let raw_val = recovered_elem.value();

        // If shares came from incompatible polynomials or were corrupted, f(0) in GF(2^31 - 1)
        // will with high probability (~ (p - 2^16)/p > 99.996%) fall outside 0..=65535!
        if raw_val > (u16::MAX as u32) {
            points.zeroize();
            key_bytes.zeroize();
            return Err(AegisError::AuthenticationFailed);
        }

        let u16_bytes = (raw_val as u16).to_le_bytes();
        key_bytes[chunk_idx * 2] = u16_bytes[0];
        key_bytes[chunk_idx * 2 + 1] = u16_bytes[1];
    }

    points.zeroize();
    let result = MasterKey::from_slice(&key_bytes);
    key_bytes.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_and_recover_across_all_3_of_5_combinations() {
        let master = MasterKey::generate().expect("keygen");
        let shares = split_master_key(&master, 3, 5).expect("split 3-of-5");
        assert_eq!(shares.len(), 5);

        // Test every possible 3-share subset out of 5 shares (C(5,3) = 10 combinations)
        for i in 0..5 {
            for j in (i + 1)..5 {
                for m in (j + 1)..5 {
                    let subset = [shares[i].clone(), shares[j].clone(), shares[m].clone()];
                    let recovered =
                        recover_master_key(&subset).expect("3-of-5 subset recovery must succeed");
                    assert_eq!(recovered, master);
                }
            }
        }
    }

    #[test]
    fn test_rejects_insufficient_shares() {
        let master = MasterKey::generate().expect("keygen");
        let shares = split_master_key(&master, 3, 5).expect("split 3-of-5");

        let two_shares = [shares[0].clone(), shares[1].clone()];
        assert_eq!(
            recover_master_key(&two_shares),
            Err(AegisError::InsufficientShares {
                required: 3,
                provided: 2
            })
        );
    }

    #[test]
    fn test_rejects_duplicate_share_identifiers() {
        let master = MasterKey::generate().expect("keygen");
        let shares = split_master_key(&master, 3, 5).expect("split");

        let dup_subset = [shares[0].clone(), shares[1].clone(), shares[0].clone()];
        assert_eq!(
            recover_master_key(&dup_subset),
            Err(AegisError::InvalidShareIdentifier {
                share_id: shares[0].id
            })
        );
    }

    #[test]
    fn test_rejects_invalid_threshold_parameters() {
        let master = MasterKey::generate().expect("keygen");

        // k < 2 is rejected
        assert_eq!(
            split_master_key(&master, 1, 5),
            Err(AegisError::InvalidThresholdParameters {
                threshold: 1,
                total: 5
            })
        );

        // k > n is rejected
        assert_eq!(
            split_master_key(&master, 6, 5),
            Err(AegisError::InvalidThresholdParameters {
                threshold: 6,
                total: 5
            })
        );
    }

    #[test]
    fn test_share_string_and_binary_serialization_roundtrip() {
        let master = MasterKey::generate().expect("keygen");
        let shares = split_master_key(&master, 3, 5).expect("split");

        let encoded_str = shares[2].to_encoded_string();
        let decoded_share =
            Share::from_encoded_string(&encoded_str).expect("valid encoded share string");
        assert_eq!(shares[2], decoded_share);

        // Tampering with share header must fail cleanly
        assert!(matches!(
            Share::from_encoded_string("INVALID-HEADER:3:1:abcd"),
            Err(AegisError::MalformedShare { .. })
        ));
    }

    #[test]
    fn test_share_debug_redacts_field_evaluations() {
        let master = MasterKey::generate().expect("keygen");
        let shares = split_master_key(&master, 2, 3).expect("split");
        let dbg = format!("{:?}", shares[0]);
        assert!(dbg.contains("REDACTED"));
    }
}
