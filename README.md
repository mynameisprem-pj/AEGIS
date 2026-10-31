# AEGIS — Adaptive Encryption and Guarded Integrated Secret-Key System

[![Language: Rust](https://img.shields.io/badge/Language-Rust%202021-orange.svg)](https://www.rust-lang.org/)
[![Memory Safety: #![forbid(unsafe_code)]](https://img.shields.io/badge/unsafe-forbidden-brightgreen.svg)](#security-guarantees)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**AEGIS** is a high-assurance, zero-trust cryptographic command-line application and library engineered in pure safe Rust (`#![forbid(unsafe_code)]`). It eliminates single-point-of-failure symmetric key storage and solves the **unauthenticated reconstruction problem** in threshold cryptography by binding **Prime Finite-Field Threshold Algebra ($\mathbb{F}_{2^{31}-1}$)**, **HKDF-SHA256 Key Commitments**, and **ChaCha20-Poly1305 Authenticated Encryption (AEAD)** into a unified architecture.

---

## 1. Architectural Motivation & Original Engineering vs. Standard Primitives

### What Established Primitives AEGIS Uses (We Do Not Roll Our Own Cipher)
* **OS CSPRNG (`getrandom`):** Direct kernel entropy (`getrandom(2)`) for 256-bit master keys, 96-bit AEAD nonces, and polynomial coefficients.
* **HKDF-SHA256 (RFC 5869):** Cryptographic Extract-and-Expand key derivation.
* **ChaCha20-Poly1305 (RFC 8439):** Constant-time ARX stream cipher and universal polynomial MAC over $\mathbb{F}_{2^{130}-5}$.
* **Memory & Timing Hygiene (`zeroize`, `subtle`):** Compiler-fence volatile memory wiping (`ZeroizeOnDrop`) and constant-time equality (`ConstantTimeEq`).

### Original Cryptographic Engineering & Mathematical Contributions in AEGIS
1. **Custom Overflow-Free Prime Field Engine ($\mathbb{F}_{2^{31}-1}$ in `src/field.rs`):** Hand-engineered modular arithmetic over the eighth Mersenne prime $p = 2^{31} - 1 = 2,147,483,647$ using uplifted `u64` intermediates (where $(p-1)^2 < 2^{62} < \texttt{u64::MAX}$ guarantees zero overflow), binary square-and-multiply exponentiation, Fermat's Little Theorem multiplicative inverses ($a^{p-2} \bmod p$), Horner's polynomial evaluation, and 31-bit unbiased rejection sampling.
2. **Two-Layer Verifiable Shamir Threshold Engine (`src/sss.rs` & `src/engine.rs`):**
   * Standard Shamir Secret Sharing blindly interpolates any $k$ points—if a share is corrupted or forged, it silently outputs a garbage key.
   * **Layer 1 (Algebraic Range Trapdoor):** AEGIS partitions a 256-bit `MasterKey` into 16 `u16` chunks ($[0, 65535]$) embedded in $\mathbb{F}_{2^{31}-1}$. A corrupted share causes Lagrange interpolation at $x=0$ to fall outside $[0, 65535]$ with probability $99.997\%$ per chunk ($1 - 2^{-240}$ across all 16 chunks).
   * **Layer 2 (Constant-Time HKDF Key Commitment):** Even if an attacker solves the linear system to force all 16 chunks into $[0, 65535]$, AEGIS verifies the reconstructed key in constant time against an HKDF-derived `KeyCommitment` ($1 - 2^{-256}$ detection) before attempting payload decryption.
3. **Key-Committed Canonical AAD Binding (`src/engine.rs`):** Binds the protocol version, the 256-bit `KeyCommitment`, and user-supplied Associated Data into an injective transcript (`"AEGIS-ENVELOPE-v1" || 0x00 || C_key || 0x00 || AAD`) authenticated by the Poly1305 tag, preventing header stripping and commitment substitution attacks.
4. **Zero-Exposure Ephemeral CLI Workflows (`src/main.rs`):** Supports `aegis keygen --suppress-key` and `aegis decrypt --share ...` (`open_with_shares`), reconstructing the master key strictly in RAM, decrypting the payload, and immediately wiping the key via `ZeroizeOnDrop` without ever printing it to `stdout` or writing it to disk.

---

## 2. System Architecture Diagram

```text
                       +---------------------------------------+
                       |     OS Kernel CSPRNG (getrandom)      |
                       +-------------------+-------------------+
                                           | 256 bits
                                           v
                       +---------------------------------------+
                       |     MasterKey K_master (Zeroize)      |
                       +---------+-------------------+---------+
                                 |                   |
          +----------------------+                   +----------------------+
          | HKDF-SHA256 (RFC 5869)                                          | Shamir Split over GF(2^31 - 1)
          | Salt: "AEGIS-v1-HKDF-SHA256-ROOT-SALT"                          | 16 x u16 chunks -> deg (k-1) polys
          v                                                                 v
+---------+------------------------------+                        +---------+-----------------------------+
| DerivedKeyHierarchy                    |                        | VerifiableShareSet (k-of-n)           |
|  1. EncryptionKey K_enc (Domain-Sep)   |                        |  Shares S_i = (x_i, [f_0(x_i)..f_15]) |
|  2. KeyCommitment C_key (Public Tag)   |                        |  Lagrange Interpolation at x = 0:     |
+---------+--------------------+---------+                        |   Layer 1: GF(p) u16 Range Trapdoor   |
          |                    |                                  |   Layer 2: Constant-Time C_key Match  |
          v                    v                                  +-------------------+-------------------+
+---------+--------------------+---------+                                            |
| ChaCha20-Poly1305 AEAD Engine          |                                            | Reconstructed
|  Nonce: 96-bit CSPRNG                  |<-------------------------------------------+ K_master (RAM only)
|  AAD  : "AEGIS-ENVELOPE-v1"|C_key|User |
|  Out  : AegisEnvelope (C_key||N||C||T) |
+----------------------------------------+

```

---

## 3. Repository Structure

```text
AEGIS/
├── Cargo.toml                         # Dependencies & release security profile (panic = "abort")
├── Cargo.lock                         # Deterministic dependency lockfile
├── README.md                          # Project overview, architecture & CLI guide
├── scripts/
│   └── demo.sh                        # Automated live terminal demonstration script
├── src/
│   ├── lib.rs                         # Library root (#![forbid(unsafe_code)])
│   ├── main.rs                        # Clap CLI binary (`keygen`, `encrypt`, `decrypt`, `split`, `recover`, `verify`, `selftest`)
│   ├── error.rs                       # Oracle-safe error taxonomy (`AegisError`)
│   ├── keygen.rs                      # CSPRNG `MasterKey`, `ZeroizeOnDrop`, `ConstantTimeEq`
│   ├── field.rs                       # Prime field GF(2^31 - 1), Fermat inverse, Horner evaluation
│   ├── sss.rs                         # (k, n) Shamir Secret Sharing & Lagrange interpolation
│   ├── kdf.rs                         # RFC 5869 HKDF-SHA256 key hierarchy & `KeyCommitment`
│   ├── cipher.rs                      # RFC 8439 ChaCha20-Poly1305 AEAD engine
│   └── engine.rs                      # Integrated `AegisEnvelope` & `open_with_shares` workflows
├── tests/
│   └── security_tests.rs              # Adversarial bit-flip fuzzing & `proptest` mathematical suite
└── docs/
    ├── SECURITY_ANALYSIS.md           # Formal 10-vector threat model & side-channel analysis
    ├── AEGIS_MATHEMATICAL_PAPER.tex   # Academic LaTeX specification & proofs
    └── HACKATHON_SUBMISSION.md        # Devpost writeup & demo video voiceover script

```

---

## 4. Build, Lint & Reproducible Test Commands

### Prerequisites

* Rust `1.75+` (tested on `rustc 1.99.1`) and Cargo.

### Verification Suite

```bash
# 1. Check formatting
cargo fmt --check

# 2. Run static analysis with zero warnings permitted
cargo clippy --all-targets -- -D warnings

# 3. Execute all 46 unit, RFC Known-Answer, adversarial, and property-based tests
cargo test

# 4. Run the built-in cryptographic and mathematical self-test
cargo run -- selftest

# 5. Execute the end-to-end terminal demonstration script
./scripts/demo.sh

```

---

## 5. CLI Usage Guide

### 1. Generate a Master Key & Immediately Split into $(k=3, n=5)$ Shares

```bash
cargo run -- keygen -k 3 -n 5

```

*(Add `--suppress-key` to operate in Zero-Exposure Mode so the raw Master Key is never printed to the screen).*

### 2. Encrypt a Sensitive Message with Associated Data (AAD)

```bash
cargo run -- encrypt \
  --key <64_CHAR_MASTER_KEY_HEX> \
  --message "Classified launch authorization code: OMEGA-7" \
  --aad "vault:sector-9"

```

### 3. Zero-Exposure Threshold Decryption (Directly from Any 3 Shares)

```bash
cargo run -- decrypt \
  --envelope "AEGIS-ENVELOPE-v1:..." \
  --share "AEGIS-SHARE-v1:3:1:..." \
  --share "AEGIS-SHARE-v1:3:3:..." \
  --share "AEGIS-SHARE-v1:3:5:..." \
  --aad "vault:sector-9"

```

### 4. Verify Shares Against a Public Key Commitment (Without Exposing the Key)

```bash
cargo run -- verify \
  --commitment <64_CHAR_COMMITMENT_HEX> \
  --share "AEGIS-SHARE-v1:3:2:..." \
  --share "AEGIS-SHARE-v1:3:4:..." \
  --share "AEGIS-SHARE-v1:3:5:..."

```

---

## 6. Documentation & Formal Proofs

* **[Formal Threat Model & Security Analysis](https://www.google.com/search?q=docs/SECURITY_ANALYSIS.md):** Detailed evaluation of 10 threat categories, mitigations, constant-time properties, and microarchitectural boundaries.
* **[Mathematical Specification (LaTeX)](https://www.google.com/search?q=docs/AEGIS_MATHEMATICAL_PAPER.tex):** Complete proofs of 64-bit overflow freedom in $\mathbb{F}_{2^{31}-1}$, Fermat's Little Theorem inverses, Vandermonde matrix invertibility, Lagrange interpolation at $x=0$, and the $1 - 2^{-240}$ algebraic trapdoor.

```

