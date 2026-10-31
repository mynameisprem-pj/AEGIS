use aegis::{
    derive_hierarchy, evaluate_polynomial, lagrange_interpolate_at_zero, open, recover_and_verify,
    recover_master_key, seal, split_and_commit, split_master_key, AegisEnvelope, AegisError,
    EncryptedPayload, FieldElement, KeyCommitment, MasterKey, Share, FIELD_PRIME, MASTER_KEY_LEN,
    SHARE_BYTE_LEN,
};
use proptest::prelude::*;

// ============================================================================
// 1. DETERMINISTIC ADVERSARIAL & BOUNDARY TESTS
// ============================================================================

#[test]
fn test_empty_plaintext_and_large_payload_roundtrip() {
    let master = MasterKey::generate().expect("keygen");
    let aad = b"boundary-test-aad";

    // 0-byte empty plaintext
    let empty_env = seal(&master, b"", aad).expect("seal empty");
    assert!(empty_env.payload.ciphertext.is_empty());
    let opened_empty = open(&master, &empty_env, aad).expect("open empty");
    assert!(opened_empty.is_empty());

    // 64 KB payload
    let large_plain = vec![0x5Au8; 65_536];
    let large_env = seal(&master, &large_plain, aad).expect("seal 64KB");
    let opened_large = open(&master, &large_env, aad).expect("open 64KB");
    assert_eq!(opened_large.as_slice(), large_plain.as_slice());
}

#[test]
fn test_exhaustive_single_bit_tampering_across_entire_envelope() {
    let master = MasterKey::generate().expect("keygen");
    let plaintext = b"Critical financial ledger entry #9941";
    let aad = b"ledger-v1";

    let baseline_env = seal(&master, plaintext, aad).expect("seal");

    // 1. Flip every byte in the 12-byte Nonce
    for i in 0..baseline_env.payload.nonce.len() {
        let mut mutated = baseline_env.clone();
        mutated.payload.nonce[i] ^= 0x80;
        assert_eq!(
            open(&master, &mutated, aad),
            Err(AegisError::AuthenticationFailed),
            "Nonce bit-flip at byte {i} must be rejected"
        );
    }

    // 2. Flip every byte in the Ciphertext
    for i in 0..baseline_env.payload.ciphertext.len() {
        let mut mutated = baseline_env.clone();
        mutated.payload.ciphertext[i] ^= 0x01;
        assert_eq!(
            open(&master, &mutated, aad),
            Err(AegisError::AuthenticationFailed),
            "Ciphertext bit-flip at byte {i} must be rejected"
        );
    }

    // 3. Flip every byte in the 16-byte Poly1305 Tag
    for i in 0..baseline_env.payload.tag.len() {
        let mut mutated = baseline_env.clone();
        mutated.payload.tag[i] ^= 0x40;
        assert_eq!(
            open(&master, &mutated, aad),
            Err(AegisError::AuthenticationFailed),
            "Poly1305 tag bit-flip at byte {i} must be rejected"
        );
    }

    // 4. Flip every byte in the 32-byte HKDF KeyCommitment
    for i in 0..32 {
        let mut commit_bytes = *baseline_env.commitment.as_bytes();
        commit_bytes[i] ^= 0x01;
        let mutated_env = AegisEnvelope {
            commitment: KeyCommitment::from_slice(&commit_bytes).unwrap(),
            payload: baseline_env.payload.clone(),
        };
        assert_eq!(
            open(&master, &mutated_env, aad),
            Err(AegisError::AuthenticationFailed),
            "KeyCommitment bit-flip at byte {i} must be rejected"
        );
    }
}

#[test]
fn test_semantic_security_identical_plaintexts_produce_distinct_envelopes() {
    let master = MasterKey::generate().expect("keygen");
    let msg = b"Identical message encrypted twice";
    let aad = b"same-aad";

    let env1 = seal(&master, msg, aad).expect("seal 1");
    let env2 = seal(&master, msg, aad).expect("seal 2");

    assert_ne!(env1.payload.nonce, env2.payload.nonce);
    assert_ne!(env1.payload.ciphertext, env2.payload.ciphertext);
    assert_ne!(env1.payload.tag, env2.payload.tag);
    assert_eq!(env1.commitment, env2.commitment);
}

#[test]
fn test_share_order_independence_and_over_threshold_recovery() {
    let master = MasterKey::generate().expect("keygen");
    let share_set = split_and_commit(&master, 3, 6).expect("3-of-6 split");

    // Reversed order of 3 shares: [S_5, S_2, S_0]
    let reversed_subset = [
        share_set.shares[5].clone(),
        share_set.shares[2].clone(),
        share_set.shares[0].clone(),
    ];
    let rec1 = recover_and_verify(&reversed_subset, Some(&share_set.commitment))
        .expect("reversed subset recovery");
    assert_eq!(rec1, master);

    // Providing more than k shares (e.g., 5 shares when k=3) must also succeed cleanly
    let five_shares = &share_set.shares[0..5];
    let rec2 = recover_and_verify(five_shares, Some(&share_set.commitment))
        .expect("over-threshold recovery");
    assert_eq!(rec2, master);
}

#[test]
fn test_malformed_share_binary_and_canonical_field_overflow_rejection() {
    // 1. Share with x = 0 must be rejected
    let mut raw = vec![0u8; SHARE_BYTE_LEN];
    raw[0] = 3; // k = 3
    raw[1] = 0; // invalid id = 0
    assert_eq!(
        Share::from_bytes(&raw),
        Err(AegisError::InvalidShareIdentifier { share_id: 0 })
    );

    // 2. Share containing a non-canonical field element (y_0 == FIELD_PRIME) must be rejected
    raw[1] = 1; // valid id = 1
    let non_canonical_bytes = FIELD_PRIME.to_le_bytes();
    raw[2..6].copy_from_slice(&non_canonical_bytes);
    assert_eq!(
        Share::from_bytes(&raw),
        Err(AegisError::FieldValueOutOfRange)
    );
}

#[test]
fn test_malformed_hex_and_truncated_frames_never_panic() {
    assert!(MasterKey::from_hex("not-valid-hex!!").is_err());
    assert!(MasterKey::from_hex("abcd").is_err());
    assert!(KeyCommitment::from_hex("1234").is_err());
    assert!(EncryptedPayload::from_hex("deadbeef").is_err());
    assert!(AegisEnvelope::from_encoded_string("AEGIS-ENVELOPE-v1:only-two-parts").is_err());
    assert!(Share::from_encoded_string("AEGIS-SHARE-v1:3:0:00").is_err());
}

// ============================================================================
// 2. PROPERTY-BASED MATHEMATICAL & CRYPTOGRAPHIC TESTS (PROPTEST)
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn prop_finite_field_ring_axioms_and_fermat_inverse(
        a_raw in 0u32..FIELD_PRIME,
        b_raw in 0u32..FIELD_PRIME,
        c_raw in 0u32..FIELD_PRIME,
        nonzero_raw in 1u32..FIELD_PRIME,
    ) {
        let a = FieldElement::from_canonical(a_raw).unwrap();
        let b = FieldElement::from_canonical(b_raw).unwrap();
        let c = FieldElement::from_canonical(c_raw).unwrap();
        let nz = FieldElement::from_canonical(nonzero_raw).unwrap();

        // Commutativity
        prop_assert_eq!(a + b, b + a);
        prop_assert_eq!(a * b, b * a);

        // Associativity
        prop_assert_eq!((a + b) + c, a + (b + c));
        prop_assert_eq!((a * b) * c, a * (b * c));

        // Distributivity
        prop_assert_eq!(a * (b + c), (a * b) + (a * c));

        // Additive identity and inverse
        prop_assert_eq!(a + FieldElement::ZERO, a);
        prop_assert_eq!((a + b) - b, a);

        // Multiplicative inverse via Fermat's Little Theorem: nz * nz^(-1) == 1 (mod p)
        let inv = nz.inverse().unwrap();
        prop_assert_eq!(nz * inv, FieldElement::ONE);
    }

    #[test]
    fn prop_lagrange_interpolation_recovers_random_polynomial_constant_term(
        secret_raw in 0u32..FIELD_PRIME,
        c1_raw in 0u32..FIELD_PRIME,
        c2_raw in 0u32..FIELD_PRIME,
        c3_raw in 1u32..FIELD_PRIME,
    ) {
        let secret = FieldElement::from_canonical(secret_raw).unwrap();
        let coeffs = [
            secret,
            FieldElement::from_canonical(c1_raw).unwrap(),
            FieldElement::from_canonical(c2_raw).unwrap(),
            FieldElement::from_canonical(c3_raw).unwrap(),
        ];

        // Evaluate degree-3 polynomial (k = 4) at 4 distinct points: x = 2, 5, 9, 14
        let xs = [2u32, 5, 9, 14];
        let points: Vec<(FieldElement, FieldElement)> = xs
            .iter()
            .map(|&x_val| {
                let x = FieldElement::from_canonical(x_val).unwrap();
                let y = evaluate_polynomial(&coeffs, x);
                (x, y)
            })
            .collect();

        let recovered_secret = lagrange_interpolate_at_zero(&points).unwrap();
        prop_assert_eq!(recovered_secret, secret);
    }

    #[test]
    fn prop_aead_seal_and_open_arbitrary_payloads_and_aad(
        key_bytes in prop::array::uniform32(1u8..=255u8),
        plaintext in prop::collection::vec(any::<u8>(), 0..2048),
        aad in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let master = MasterKey::from_slice(&key_bytes).unwrap();
        let envelope = seal(&master, &plaintext, &aad).unwrap();
        let decrypted = open(&master, &envelope, &aad).unwrap();
        prop_assert_eq!(decrypted.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn prop_shamir_threshold_split_and_recover_random_keys(
        key_bytes in prop::array::uniform32(1u8..=255u8),
        k in 2u8..=6u8,
        extra in 0u8..=4u8,
    ) {
        let n = k + extra;
        let master = MasterKey::from_slice(&key_bytes).unwrap();
        let hierarchy = derive_hierarchy(&master).unwrap();

        let shares = split_master_key(&master, k, n).unwrap();
        prop_assert_eq!(shares.len(), n as usize);

        // Take the last k shares in reverse order
        let subset: Vec<Share> = shares.into_iter().rev().take(k as usize).collect();
        let recovered = recover_master_key(&subset).unwrap();

        prop_assert_eq!(&recovered, &master);
        prop_assert_eq!(recovered.as_bytes().len(), MASTER_KEY_LEN);
        prop_assert!(hierarchy.commitment.verify(&recovered).is_ok());
    }
}
