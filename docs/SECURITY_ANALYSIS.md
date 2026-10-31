# AEGIS — Formal Threat Model & Security Analysis

**System:** AEGIS (*Adaptive Encryption and Guarded Integrated Secret-Key System*)  
**Language & Toolchain:** Rust (`#![forbid(unsafe_code)]`, Edition 2021)  
**Primitives:** OS CSPRNG (`getrandom`), HKDF-SHA256 (RFC 5869), ChaCha20-Poly1305 (RFC 8439), Shamir's Secret Sharing over $\mathbb{F}_{2^{31}-1}$

---

## 1. Security Objectives & Trust Assumptions

### 1.1 Core Security Goals
1. **Confidentiality (IND-CCA2):** An adversary observing any number of `AegisEnvelope` ciphertexts cannot distinguish the underlying plaintexts without possessing the 256-bit `MasterKey` ($K_{\text{master}}$) or at least $k$ valid threshold shares.
2. **Ciphertext & Header Integrity (INT-CTXT):** Any modification to the envelope version header, the 256-bit `KeyCommitment`, the caller's Associated Data (AAD), the 96-bit nonce, the ciphertext, or the 128-bit Poly1305 tag is detected with probability $\ge 1 - 2^{-128}$ prior to releasing any plaintext.
3. **Information-Theoretic Threshold Confidentiality:** Any adversary compromising up to $k - 1$ Shamir shares gains zero mutual information ($I(K_{\text{master}}; S_{1..k-1}) = 0$) regarding the master key.
4. **Verifiable Reconstruction (Key Commitment):** Corrupted, mismatched, or forged shares are rejected prior to payload decryption via a dual defense: algebraic range validation in $\mathbb{F}_{2^{31}-1}$ ($1 - 2^{-240}$ detection for random faults) and constant-time HKDF-SHA256 `KeyCommitment` verification ($1 - 2^{-256}$ detection).

### 1.2 Trust Boundary & Explicit Assumptions
* **Trusted OS Kernel CSPRNG:** AEGIS assumes the host operating system's entropy source (`getrandom(2)` on Linux) is uncompromised and properly seeded.
* **Endpoint Compromise Out-of-Scope during Execution:** If an adversary has active root/ptrace access to the host CPU registers or physical RAM at the exact millisecond a secret is being encrypted or reconstructed, software-only protections cannot prevent key extraction.
* **Standard Cryptographic Hardness:** Assumes the PRF security of HMAC-SHA256 and the AEAD security of 20-round ChaCha20-Poly1305.

---

## 2. Threat Matrix & Detailed Analysis of the 10 Attack Vectors

### Threat 1: Exhaustive Brute-Force Attacks
* **1. Attack Concept:** An adversary attempts to guess the `MasterKey` ($K_{\text{master}}$), the derived `EncryptionKey` ($K_{\text{enc}}$), or the unobserved polynomial coefficients in $\mathbb{F}_p$ by exhaustive search.
* **2. Addressed by AEGIS:** **Yes.**
* **3. Implemented Mitigation:**
  * `MasterKey` is sampled directly from the OS CSPRNG as a 256-bit (32-byte) uniform random secret (`src/keygen.rs`), providing $2^{256}$ classical keyspace ($2^{128}$ post-quantum under Grover's algorithm).
  * Degenerate all-zero entropy buffers (`[0u8; 32]`) are rejected in constant time during construction.
  * Below threshold $k$, Shamir Secret Sharing over $\mathbb{F}_{2^{31}-1}$ provides **information-theoretic security**: every candidate 16-bit secret chunk in $[0, 65535]$ is algebraically consistent with a unique degree-$(k-1)$ polynomial passing through the attacker's $k - 1$ points. Thus, even an unbounded computational adversary cannot brute-force shares when holding $\le k - 1$ shares.
* **4. Remaining Limitations:** If a user manually imports an external hex key (`MasterKey::from_hex`) derived from a low-entropy human password without a memory-hard KDF (such as Argon2id), brute-force resistance degrades to the entropy of that external source.
* **5. Verification & Testing:** Verified via `keygen::tests::test_master_key_generation_succeeds_and_is_unique`, `keygen::tests::test_master_key_rejects_all_zero_degenerate_key`, and `sss::tests::test_rejects_insufficient_shares`.

---

### Threat 2: Ciphertext, Nonce, AAD, and Header Tampering
* **1. Attack Concept:** An active Man-in-the-Middle (MitM) or storage attacker flips bits in the ciphertext (malleability attack), modifies the Associated Data (AAD), strips or swaps the `KeyCommitment` header, or alters the Poly1305 tag.
* **2. Addressed by AEGIS:** **Yes.**
* **3. Implemented Mitigation:**
  * AEGIS uses RFC 8439 ChaCha20-Poly1305 (`src/cipher.rs`) and constructs an injective canonical AAD transcript (`src/engine.rs`):
    $$\text{AAD}_{\text{canonical}} = \texttt{"AEGIS-ENVELOPE-v1"} \;\|\; \texttt{0x00} \;\|\; C_{\text{key}} \;\|\; \texttt{0x00} \;\|\; \text{AAD}_{\text{user}}$$
  * In `cipher::decrypt`, the 128-bit Poly1305 tag is verified in constant time before releasing plaintext. On verification failure, the temporary buffer is immediately zeroized (`buffer.zeroize()`) and `Err(AegisError::AuthenticationFailed)` is returned.
* **4. Remaining Limitations:** Poly1305 is a 128-bit MAC; the theoretical forgery probability for a single blind attempt is bounded by $\approx 2^{-127}$.
* **5. Verification & Testing:** Exhaustively tested across every single byte of the nonce, ciphertext, Poly1305 tag, and HKDF commitment in `tests/security_tests.rs::test_exhaustive_single_bit_tampering_across_entire_envelope` and `engine::tests::test_rejects_commitment_substitution_on_envelope`.

---

### Threat 3: Direct Key Exposure & Cross-Protocol Key Reuse
* **1. Attack Concept:** Using the same raw secret key directly across algebraic secret sharing, payload encryption, and key verification can allow mathematical interactions between primitives or leak the master key during CLI usage.
* **2. Addressed by AEGIS:** **Yes.**
* **3. Implemented Mitigation:**
  * **Cryptographic Domain Separation (`src/kdf.rs`):** `MasterKey` is never passed into ChaCha20-Poly1305. Instead, HKDF-SHA256 extracts a pseudorandom key with salt `"AEGIS-v1-HKDF-SHA256-ROOT-SALT"` and expands two orthogonal subkeys using distinct domain labels: `"AEGIS-v1-CHACHA20POLY1305-ENC-KEY"` and `"AEGIS-v1-MASTER-KEY-COMMITMENT"`.
  * **Type-System Separation (`src/cipher.rs`):** `MasterKey` and `EncryptionKey` are distinct Rust types without implicit conversion.
  * **Redacted Formatting & Zero-Exposure CLI (`src/main.rs`):** `Debug` implementations on `MasterKey`, `EncryptionKey`, and `Share` output `[REDACTED]`. The CLI supports `aegis keygen --suppress-key` and `aegis decrypt --share ...` (`open_with_shares`), allowing threshold decryption without ever printing or saving the reconstructed master key.
* **4. Remaining Limitations:** When the user explicitly runs `aegis keygen` (without `--suppress-key`) or `aegis recover`, the hex key is printed to `stdout` as requested by the user.
* **5. Verification & Testing:** Verified in `kdf::tests::test_domain_separation_produces_independent_outputs`, `keygen::tests::test_master_key_debug_is_redacted`, and `sss::tests::test_share_debug_redacts_field_evaluations`.

---

### Threat 4: Residual Memory Disclosure (RAM Scavenging / Dead-Store Elimination)
* **1. Attack Concept:** After cryptographic operations complete, secret keys, intermediate polynomial coefficients, or decrypted plaintexts remain in stack or heap memory because the compiler optimizes away manual zeroing loops ("dead-store elimination"), exposing secrets to core dumps or process memory inspection.
* **2. Addressed by AEGIS:** **Yes (at the Rust source/allocator level).**
* **3. Implemented Mitigation:**
  * `MasterKey`, `EncryptionKey`, `DerivedKeyHierarchy`, and `Share` derive `Zeroize` and `ZeroizeOnDrop` (`zeroize` crate), which uses volatile memory writes and compiler fences guaranteed not to be stripped by LLVM.
  * Neither `MasterKey` nor `EncryptionKey` implements `Copy`, preventing silent bitwise stack copies.
  * Temporary buffers (`coeffs` in `src/sss.rs`, `okm` in `src/kdf.rs`, failed decryption buffers in `src/cipher.rs`, and hex-decoded vectors) are explicitly zeroized before scope exit, and decrypted plaintexts are returned inside `zeroize::Zeroizing<Vec<u8>>`.
* **4. Remaining Limitations:** Rust/LLVM does not guarantee automatic scrubbing of CPU SIMD/general-purpose registers, stack spills created internally by the compiler backend, or pages swapped to disk by the OS kernel if `mlock(2)` is not invoked.
* **5. Verification & Testing:** Verified in `keygen::tests::test_explicit_zeroize_clears_buffer` and enforced structurally across all secret types.

---

### Threat 5: Timing Side-Channel Attacks
* **1. Attack Concept:** An attacker measures nanosecond variations in execution time during tag verification, key commitment checking, or finite-field inverse computation to deduce secret bytes or distinguish failure modes.
* **2. Addressed by AEGIS:** **Partially (Constant-time comparisons and fixed-exponent loops implemented; hardware division noted).**
* **3. Implemented Mitigation:**
  * All equality checks on `MasterKey`, `EncryptionKey`, `KeyCommitment`, and `FieldElement` use `subtle::ConstantTimeEq` (`ct_eq`), executing in constant time regardless of where bytes differ.
  * Poly1305 tag verification inside `chacha20poly1305` executes in constant time.
  * All authentication, commitment, and decryption failures return the identical error variant (`AegisError::AuthenticationFailed`), eliminating timing/error-message oracles.
  * In `FieldElement::inverse` (`src/field.rs`), Fermat's Little Theorem computes $a^{p-2} \pmod p$. Because the exponent $p - 2 = 2,147,483,645$ is a **fixed public constant**, the binary exponentiation loop executes the exact same 31 iterations and branch pattern on every call.
* **4. Remaining Limitations:** In `FieldElement::from_reduced`, modular reduction uses the Rust `%` operator (`val % (FIELD_PRIME as u64)`). On some CPU microarchitectures, 64-bit hardware integer division instructions can exhibit minor operand-dependent latency variations. A hardware-hardened deployment can replace `%` with branchless Mersenne prime bitwise folding (`(x & p) + (x >> 31)`).
* **5. Verification & Testing:** Verified via `error::tests::test_error_formatting_does_not_leak_secrets` and static enforcement of `ConstantTimeEq`.

---

### Threat 6: Cache Side-Channel Attacks
* **1. Attack Concept:** An attacker co-located on the same physical CPU core monitors L1/L2/Last-Level Cache eviction patterns (e.g., Prime+Probe or Flush+Reload) to extract keys from S-box lookup tables.
* **2. Addressed by AEGIS:** **Yes (Algorithmic elimination of secret-dependent table lookups).**
* **3. Implemented Mitigation:**
  * AEGIS deliberately selected **ChaCha20-Poly1305** and **HMAC-SHA256** over table-based AES or GF($2^8$) log/exp lookup tables.
  * ChaCha20, Poly1305, SHA-256, and our arithmetic over $\mathbb{F}_{2^{31}-1}$ rely strictly on register-level arithmetic and bitwise operations (`+`, `-`, `*`, `^`, `<<<`) with **zero secret-dependent array indexing or lookup tables**.
* **4. Remaining Limitations:** AEGIS does not mitigate speculative execution vulnerabilities at the CPU silicon level (e.g., Spectre/Meltdown variants) which require OS microcode patches.
* **5. Verification & Testing:** Verified by code inspection of `src/field.rs`, `src/sss.rs`, and `src/cipher.rs` confirming zero secret-indexed lookup tables.

---

### Threat 7: Nonce Misuse & Collision Risks
* **1. Attack Concept:** Reusing a 96-bit nonce $N$ with the same `EncryptionKey` $K_{\text{enc}}$ in ChaCha20-Poly1305 allows an attacker to XOR two ciphertexts ($C_1 \oplus C_2 = P_1 \oplus P_2$) to cancel out the ChaCha20 keystream and recover the one-time Poly1305 evaluation key $r$, enabling universal tag forgery.
* **2. Addressed by AEGIS:** **Yes (for normal operational volumes via CSPRNG generation).**
* **3. Implemented Mitigation:**
  * The public `seal` and `encrypt` functions never ask the user to supply a nonce; a fresh 96-bit (12-byte) nonce is sampled directly from the OS CSPRNG on every encryption call (`generate_nonce` in `src/cipher.rs`).
* **4. Remaining Limitations:** By the Birthday Paradox, random 96-bit nonces have a collision probability of $\approx \frac{q^2}{2 \cdot 2^{96}}$. After $q = 2^{32}$ ($\approx 4.29 \times 10^9$) encryptions under the *exact same* `MasterKey`, the collision probability reaches $2^{-33}$. Furthermore, if a virtual machine snapshot is restored and re-executed without reseeding the guest OS CSPRNG, nonce reuse could occur.
* **5. Verification & Testing:** Verified in `tests/security_tests.rs::test_semantic_security_identical_plaintexts_produce_distinct_envelopes`.

---

### Threat 8: Supply-Chain & Dependency Vulnerabilities
* **1. Attack Concept:** Compromised, unmaintained, or bloated third-party crates introduce memory safety bugs (`unsafe` blocks) or malicious backdoors into the cryptographic binary.
* **2. Addressed by AEGIS:** **Yes.**
* **3. Implemented Mitigation:**
  * The AEGIS crate enforces `#![forbid(unsafe_code)]` at the crate root (`src/lib.rs` and `src/main.rs`).
  * Finite-field arithmetic (`src/field.rs`) and Shamir Secret Sharing (`src/sss.rs`) are implemented in-house with zero external math dependencies.
  * Symmetric primitives rely strictly on minimal, audited `RustCrypto` crates (`chacha20poly1305`, `hkdf`, `sha2`, `zeroize`, `subtle`) with deterministic versions pinned in `Cargo.lock`.
* **4. Remaining Limitations:** Upstream vulnerabilities in `rustc`, standard library `std`, or the Linux kernel inside the container remain part of the host TCB.
* **5. Verification & Testing:** Enforced at compile time by `#![forbid(unsafe_code)]` and `cargo clippy --all-targets -- -D warnings`.

---

### Threat 9: Malformed Input, Integer Overflow, and Parser Attacks
* **1. Attack Concept:** An attacker feeds truncated ciphertexts, invalid hex strings, non-canonical field elements ($y \ge 2^{31}-1$), zero share identifiers ($x = 0$), or threshold parameters $k > n$ to trigger integer overflows, division-by-zero panics, or buffer over-reads.
* **2. Addressed by AEGIS:** **Yes.**
* **3. Implemented Mitigation:**
  * **Overflow-Free Field Arithmetic (`src/field.rs`):** All canonical elements satisfy $0 \le a < 2^{31}-1$. Addition, subtraction, and multiplication uplift operands to `u64`, where the maximum product $(2^{31}-2)^2 < 2^{62} < \texttt{u64::MAX}$, making integer overflow mathematically impossible.
  * **Strict Deserialization Validation (`src/sss.rs`, `src/cipher.rs`):** `Share::from_bytes` rejects $k < 2$, $x = 0$, and $y_i \ge 2^{31}-1$ (`FieldValueOutOfRange`). `EncryptedPayload::from_bytes` rejects frames shorter than `NONCE_LEN + TAG_LEN` (28 bytes).
  * **Zero Unwraps on Untrusted Input:** All parsing and mathematical operations return `AegisResult<T>`.
* **4. Remaining Limitations:** Extremely large input files exceeding available system RAM will cause standard OS memory allocation failure when read into memory via `fs::read`.
* **5. Verification & Testing:** Verified in `field::tests::test_multiplication_does_not_overflow_at_boundary`, `tests/security_tests.rs::test_malformed_share_binary_and_canonical_field_overflow_rejection`, and `test_malformed_hex_and_truncated_frames_never_panic`.

---

### Threat 10: Unauthorized, Insufficient, or Forged Share Recovery Attempts
* **1. Attack Concept:** A malicious insider or external attacker attempts to reconstruct $K_{\text{master}}$ using fewer than $k$ shares, duplicates a valid share ($x_i = x_j$) to meet the count $k$, or injects a corrupted/forged share to trick the system into decrypting with a wrong key.
* **2. Addressed by AEGIS:** **Yes.**
* **3. Implemented Mitigation:**
  * **Pre-Interpolation Validation (`src/sss.rs`):** `recover_master_key` verifies `shares.len() >= k`, checks that all shares agree on `threshold`, rejects $x_i = 0$, and checks pairwise distinctness ($x_i \neq x_j$ for all $i \neq j$) before any Lagrange division occurs.
  * **Algebraic Range Trapdoor (`src/sss.rs`):** Because each 16-bit secret chunk lies in $[0, 65535]$ while interpolation operates in $\mathbb{F}_{2^{31}-1}$, random or corrupted shares produce a reconstructed value $> 65535$ with probability $\frac{2^{31}-1 - 2^{16}}{2^{31}-1} \approx 99.997\%$ per chunk ($1 - 2^{-240}$ across all 16 chunks), triggering immediate `AegisError::AuthenticationFailed`.
  * **HKDF Key Commitment Verification (`src/engine.rs`):** Even if an attacker crafts shares whose interpolation lands in $[0, 65535]^{16}$, `recover_and_verify` checks the 256-bit HKDF `KeyCommitment` in constant time, rejecting any false reconstruction with probability $1 - 2^{-256}$.
* **4. Remaining Limitations:** If an attacker compromises $\ge k$ genuine shares, they have met the legitimate mathematical threshold by definition and can reconstruct $K_{\text{master}}$.
* **5. Verification & Testing:** Verified in `sss::tests::test_rejects_insufficient_shares`, `sss::tests::test_rejects_duplicate_share_identifiers`, `engine::tests::test_rejects_corrupted_share_during_recovery`, and `engine::tests::test_rejects_shares_from_wrong_master_key`.

---

## 3. Summary Matrix for Hackathon Judges

| # | Threat Category | Addressed? | Primary Defense Mechanism | Empirical Test Coverage |
|---|---|---|---|---|
| 1 | Brute-Force Attacks | **Yes** | 256-bit OS CSPRNG + Info-Theoretic SSS ($\mathbb{F}_{2^{31}-1}$) | `test_master_key_generation_succeeds_and_is_unique` |
| 2 | Ciphertext / AAD Tampering | **Yes** | ChaCha20-Poly1305 + Canonical AAD Transcript | `test_exhaustive_single_bit_tampering_across_entire_envelope` |
| 3 | Key Exposure & Reuse | **Yes** | HKDF-SHA256 Domain Separation + Redacted `Debug` | `test_domain_separation_produces_independent_outputs` |
| 4 | Memory Disclosure | **Yes** | `ZeroizeOnDrop`, No `Copy`, `Zeroizing<Vec<u8>>` | `test_explicit_zeroize_clears_buffer` |
| 5 | Timing Side Channels | **Partial** | `subtle::ConstantTimeEq` + Fixed-Exponent Fermat Inverse | `test_error_formatting_does_not_leak_secrets` |
| 6 | Cache Side Channels | **Yes** | ARX Cipher (ChaCha20) + Register-Only Field Math | Architectural verification (0 lookup tables) |
| 7 | Nonce Misuse | **Yes** | Mandatory 96-bit OS CSPRNG Nonce per Encryption | `test_semantic_security_identical_plaintexts_produce_distinct_envelopes` |
| 8 | Supply-Chain / Unsafe Code | **Yes** | `#![forbid(unsafe_code)]` + Minimal Audited Crates | Compiler & Clippy static enforcement |
| 9 | Malformed Input / Overflow | **Yes** | `u64` Intermediate Field Math + Canonical Bounds | `test_malformed_share_binary_and_canonical_field_overflow_rejection` |
| 10 | Unauthorized / Forged Shares | **Yes** | Pairwise $x_i \neq x_j$ Check + $\mathbb{F}_p$ Trapdoor + HKDF Commitment | `test_rejects_corrupted_share_during_recovery` |