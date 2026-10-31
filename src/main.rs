#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

//! # AEGIS CLI
//!
//! Command-line interface for the AEGIS Adaptive Encryption and Guarded
//! Integrated Secret-Key System.

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use zeroize::Zeroize;

use aegis::{
    derive_hierarchy, evaluate_polynomial, lagrange_interpolate_at_zero, open, open_with_shares,
    recover_and_verify, seal, split_and_commit, AegisEnvelope, AegisError, AegisResult,
    FieldElement, KeyCommitment, MasterKey, Share, FIELD_PRIME,
};

/// AEGIS — Adaptive Encryption and Guarded Integrated Secret-Key System.
#[derive(Debug, Parser)]
#[command(
    name = "aegis",
    version,
    about = "AEGIS — Cryptographic Master-Key Protection, HKDF, ChaCha20-Poly1305 & Threshold Recovery over GF(2^31 - 1)",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Generate a cryptographically secure 256-bit MasterKey and its HKDF KeyCommitment.
    Keygen {
        /// Optional: immediately split the generated MasterKey with threshold `k`.
        #[arg(short = 'k', long)]
        threshold: Option<u8>,

        /// Optional: total number of shares `n` to generate when splitting.
        #[arg(short = 'n', long)]
        total: Option<u8>,

        /// Do not print the raw MasterKey hex when splitting into shares (zero-exposure mode).
        #[arg(long, default_value_t = false)]
        suppress_key: bool,
    },

    /// Encrypt plaintext or a file into an authenticated AegisEnvelope (ChaCha20-Poly1305).
    Encrypt {
        /// 64-character hex-encoded MasterKey.
        #[arg(short, long)]
        key: String,

        /// Plaintext string to encrypt (mutually exclusive with --in-file).
        #[arg(short, long)]
        message: Option<String>,

        /// Path to an input file to encrypt.
        #[arg(long)]
        in_file: Option<PathBuf>,

        /// Optional path to write the output AegisEnvelope string.
        #[arg(short, long)]
        out_file: Option<PathBuf>,

        /// Optional Associated Data (AAD) string bound to the Poly1305 authentication tag.
        #[arg(short, long, default_value = "")]
        aad: String,
    },

    /// Authenticate and decrypt an AegisEnvelope using a MasterKey or threshold Shares.
    Decrypt {
        /// Encoded AegisEnvelope string (or use --in-file).
        #[arg(short, long)]
        envelope: Option<String>,

        /// Path to a file containing an encoded AegisEnvelope.
        #[arg(long)]
        in_file: Option<PathBuf>,

        /// 64-character hex-encoded MasterKey (or supply multiple --share flags instead).
        #[arg(short, long)]
        key: Option<String>,

        /// Threshold shares (`AEGIS-SHARE-v1:...`) to reconstruct the key in-memory without exposing it.
        #[arg(short, long = "share")]
        shares: Vec<String>,

        /// Associated Data (AAD) string that was bound during encryption.
        #[arg(short, long, default_value = "")]
        aad: String,

        /// Optional path to write the decrypted output bytes.
        #[arg(short, long)]
        out_file: Option<PathBuf>,
    },

    /// Split an existing 256-bit MasterKey into (k, n) Shamir shares over GF(2^31 - 1).
    Split {
        /// 64-character hex-encoded MasterKey.
        #[arg(short = 'M', long)]
        key: String,

        /// Minimum shares required for reconstruction (`k`, where 2 <= k <= n <= 255).
        #[arg(short = 'k', long)]
        threshold: u8,

        /// Total number of shares to generate (`n`, where 2 <= k <= n <= 255).
        #[arg(short = 'n', long)]
        total: u8,
    },

    /// Recover a 256-bit MasterKey from at least `k` Shamir shares via Lagrange interpolation.
    Recover {
        /// Encoded share strings (`AEGIS-SHARE-v1:<k>:<id>:<hex>`). Pass at least `k` times.
        #[arg(short, long = "share", required = true)]
        shares: Vec<String>,

        /// Optional 64-character hex KeyCommitment to verify the reconstructed key against.
        #[arg(short, long)]
        commitment: Option<String>,
    },

    /// Verify a MasterKey or threshold Share set against an expected HKDF KeyCommitment.
    Verify {
        /// Expected 64-character hex KeyCommitment.
        #[arg(short, long)]
        commitment: String,

        /// Candidate 64-character hex MasterKey to verify.
        #[arg(short, long)]
        key: Option<String>,

        /// Candidate threshold shares (`AEGIS-SHARE-v1:...`) to verify without exposing the key.
        #[arg(short, long = "share")]
        shares: Vec<String>,
    },

    /// Execute deterministic self-tests across Finite Field, HKDF, SSS, and ChaCha20-Poly1305.
    Selftest,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("[AEGIS ERROR] {}", err);
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> AegisResult<()> {
    match cli.command {
        Commands::Keygen {
            threshold,
            total,
            suppress_key,
        } => cmd_keygen(threshold, total, suppress_key),
        Commands::Encrypt {
            key,
            message,
            in_file,
            out_file,
            aad,
        } => cmd_encrypt(&key, message, in_file, out_file, &aad),
        Commands::Decrypt {
            envelope,
            in_file,
            key,
            shares,
            aad,
            out_file,
        } => cmd_decrypt(envelope, in_file, key, &shares, &aad, out_file),
        Commands::Split {
            key,
            threshold,
            total,
        } => cmd_split(&key, threshold, total),
        Commands::Recover { shares, commitment } => cmd_recover(&shares, commitment.as_deref()),
        Commands::Verify {
            commitment,
            key,
            shares,
        } => cmd_verify(&commitment, key.as_deref(), &shares),
        Commands::Selftest => cmd_selftest(),
    }
}

fn cmd_keygen(threshold: Option<u8>, total: Option<u8>, suppress_key: bool) -> AegisResult<()> {
    let master = MasterKey::generate()?;
    let hierarchy = derive_hierarchy(&master)?;

    println!("=== AEGIS KEY GENERATION ===");
    if !suppress_key {
        println!("Master Key (256-bit hex) : {}", *master.to_hex());
    } else {
        println!("Master Key (256-bit hex) : [SUPPRESSED IN ZERO-EXPOSURE MODE]");
    }
    println!(
        "Key Commitment (HKDF)    : {}",
        hierarchy.commitment.to_hex()
    );

    match (threshold, total) {
        (Some(k), Some(n)) => {
            let share_set = split_and_commit(&master, k, n)?;
            println!(
                "\n=== SHAMIR SECRET SHARES (k={}, n={}, Field=GF(2^31 - 1)) ===",
                k, n
            );
            for share in &share_set.shares {
                println!("Share #{:02} : {}", share.id, *share.to_encoded_string());
            }
        }
        (None, None) => {}
        _ => {
            return Err(AegisError::SerializationError {
                reason: "Both --threshold (-k) and --total (-n) must be provided together"
                    .to_string(),
            });
        }
    }

    Ok(())
}

fn cmd_encrypt(
    key_hex: &str,
    message: Option<String>,
    in_file: Option<PathBuf>,
    out_file: Option<PathBuf>,
    aad: &str,
) -> AegisResult<()> {
    let master = MasterKey::from_hex(key_hex)?;

    let mut plaintext_bytes = match (message, in_file) {
        (Some(msg), None) => msg.into_bytes(),
        (None, Some(path)) => fs::read(&path).map_err(|e| AegisError::IoError {
            reason: format!("Failed to read input file '{}': {}", path.display(), e),
        })?,
        _ => {
            return Err(AegisError::SerializationError {
                reason: "Provide exactly one of --message (-m) or --in-file".to_string(),
            });
        }
    };

    let envelope = seal(&master, &plaintext_bytes, aad.as_bytes());
    plaintext_bytes.zeroize();
    let envelope = envelope?;
    let encoded = envelope.to_encoded_string();

    if let Some(path) = out_file {
        fs::write(&path, &encoded).map_err(|e| AegisError::IoError {
            reason: format!("Failed to write output file '{}': {}", path.display(), e),
        })?;
        println!("=== AEGIS ENCRYPTION COMPLETE ===");
        println!("Key Commitment : {}", envelope.commitment.to_hex());
        println!("Output Written : {}", path.display());
    } else {
        println!("=== AEGIS ENCRYPTED ENVELOPE ===");
        println!("Key Commitment : {}", envelope.commitment.to_hex());
        println!("Envelope       : {}", encoded);
    }

    Ok(())
}

fn cmd_decrypt(
    envelope_str: Option<String>,
    in_file: Option<PathBuf>,
    key_hex: Option<String>,
    share_strings: &[String],
    aad: &str,
    out_file: Option<PathBuf>,
) -> AegisResult<()> {
    let raw_envelope = match (envelope_str, in_file) {
        (Some(env_s), None) => env_s,
        (None, Some(path)) => fs::read_to_string(&path).map_err(|e| AegisError::IoError {
            reason: format!("Failed to read envelope file '{}': {}", path.display(), e),
        })?,
        _ => {
            return Err(AegisError::SerializationError {
                reason: "Provide exactly one of --envelope (-e) or --in-file".to_string(),
            });
        }
    };

    let envelope = AegisEnvelope::from_encoded_string(&raw_envelope)?;

    let decrypted = match (key_hex, share_strings.is_empty()) {
        (Some(k_hex), true) => {
            let master = MasterKey::from_hex(&k_hex)?;
            open(&master, &envelope, aad.as_bytes())?
        }
        (None, false) => {
            let parsed_shares = parse_share_list(share_strings)?;
            open_with_shares(&parsed_shares, &envelope, aad.as_bytes())?
        }
        _ => {
            return Err(AegisError::SerializationError {
                reason: "Provide either --key (-k) OR multiple --share (-s) flags".to_string(),
            });
        }
    };

    if let Some(path) = out_file {
        fs::write(&path, decrypted.as_slice()).map_err(|e| AegisError::IoError {
            reason: format!("Failed to write decrypted file '{}': {}", path.display(), e),
        })?;
        println!("=== AEGIS DECRYPTION & AUTHENTICATION VERIFIED ===");
        println!("Output Written : {}", path.display());
    } else {
        println!("=== AEGIS DECRYPTION & AUTHENTICATION VERIFIED ===");
        match std::str::from_utf8(decrypted.as_slice()) {
            Ok(utf8_str) => println!("Plaintext      : {}", utf8_str),
            Err(_) => println!("Plaintext (hex): {}", hex::encode(decrypted.as_slice())),
        }
    }

    Ok(())
}

fn cmd_split(key_hex: &str, threshold: u8, total: u8) -> AegisResult<()> {
    let master = MasterKey::from_hex(key_hex)?;
    let share_set = split_and_commit(&master, threshold, total)?;

    println!(
        "=== AEGIS THRESHOLD SPLIT (k={}, n={}, Field=GF(2^31 - 1)) ===",
        threshold, total
    );
    println!("Key Commitment : {}", share_set.commitment.to_hex());
    for share in &share_set.shares {
        println!(
            "Share #{:02}      : {}",
            share.id,
            *share.to_encoded_string()
        );
    }

    Ok(())
}

fn cmd_recover(share_strings: &[String], commitment_hex: Option<&str>) -> AegisResult<()> {
    let shares = parse_share_list(share_strings)?;
    let expected_commit = match commitment_hex {
        Some(c_hex) => Some(KeyCommitment::from_hex(c_hex)?),
        None => None,
    };

    let recovered = recover_and_verify(&shares, expected_commit.as_ref())?;
    let hierarchy = derive_hierarchy(&recovered)?;

    println!("=== AEGIS THRESHOLD RECOVERY SUCCESSFUL ===");
    println!("Recovered Master Key : {}", *recovered.to_hex());
    println!("Key Commitment       : {}", hierarchy.commitment.to_hex());
    if expected_commit.is_some() {
        println!("Commitment Status    : VERIFIED (Constant-Time HKDF Match)");
    }

    Ok(())
}

fn cmd_verify(
    commitment_hex: &str,
    key_hex: Option<&str>,
    share_strings: &[String],
) -> AegisResult<()> {
    let commitment = KeyCommitment::from_hex(commitment_hex)?;

    match (key_hex, share_strings.is_empty()) {
        (Some(k_hex), true) => {
            let master = MasterKey::from_hex(k_hex)?;
            commitment.verify(&master)?;
            println!("=== AEGIS VERIFICATION PASSED ===");
            println!("Status : MasterKey matches HKDF KeyCommitment in constant time.");
        }
        (None, false) => {
            let shares = parse_share_list(share_strings)?;
            let _recovered = recover_and_verify(&shares, Some(&commitment))?;
            println!("=== AEGIS VERIFICATION PASSED ===");
            println!(
                "Status : {} shares algebraically reconstructed and matched KeyCommitment.",
                shares.len()
            );
        }
        _ => {
            return Err(AegisError::SerializationError {
                reason: "Provide either --key (-k) OR multiple --share (-s) flags to verify"
                    .to_string(),
            });
        }
    }

    Ok(())
}

fn cmd_selftest() -> AegisResult<()> {
    println!("=== AEGIS CRYPTOGRAPHIC & MATHEMATICAL SELF-TEST ===");

    // 1. Finite Field GF(2^31 - 1) Fermat's Little Theorem & Horner Evaluation
    let a = FieldElement::from_canonical(1_234_567_891)?;
    let a_inv = a.inverse()?;
    if a * a_inv != FieldElement::ONE {
        return Err(AegisError::AuthenticationFailed);
    }
    let coeffs = [
        FieldElement::from_canonical(999)?,
        FieldElement::from_canonical(42)?,
    ];
    let eval_at_0 = evaluate_polynomial(&coeffs, FieldElement::ZERO);
    let lagrange_0 = lagrange_interpolate_at_zero(&[
        (
            FieldElement::ONE,
            evaluate_polynomial(&coeffs, FieldElement::ONE),
        ),
        (
            FieldElement::from_canonical(2)?,
            evaluate_polynomial(&coeffs, FieldElement::from_canonical(2)?),
        ),
    ])?;
    if eval_at_0 != lagrange_0 {
        return Err(AegisError::AuthenticationFailed);
    }
    println!(
        "[PASS] 1/4 Finite Field GF({}) Fermat Inverse & Lagrange Interpolation",
        FIELD_PRIME
    );

    // 2. CSPRNG MasterKey & HKDF-SHA256 Domain Separation
    let master = MasterKey::generate()?;
    let hierarchy = derive_hierarchy(&master)?;
    hierarchy.commitment.verify(&master)?;
    println!("[PASS] 2/4 CSPRNG 256-bit MasterKey & HKDF-SHA256 Key Commitment");

    // 3. Shamir Secret Sharing (k=3, n=5) Reconstruction
    let share_set = split_and_commit(&master, 3, 5)?;
    let subset = [
        share_set.shares[0].clone(),
        share_set.shares[2].clone(),
        share_set.shares[4].clone(),
    ];
    let recovered = recover_and_verify(&subset, Some(&share_set.commitment))?;
    if recovered != master {
        return Err(AegisError::AuthenticationFailed);
    }
    println!("[PASS] 3/4 Shamir Secret Sharing (3-of-5) Polynomial Reconstruction");

    // 4. ChaCha20-Poly1305 Envelope Seal & Zero-Exposure Share Opening
    let msg = b"AEGIS self-test verification vector";
    let aad = b"selftest-aad";
    let envelope = seal(&master, msg, aad)?;
    let opened = open_with_shares(&subset, &envelope, aad)?;
    if opened.as_slice() != msg {
        return Err(AegisError::AuthenticationFailed);
    }
    println!("[PASS] 4/4 ChaCha20-Poly1305 AEAD Seal, AAD Binding & Threshold Decryption");
    println!("=== ALL AEGIS SELF-TESTS PASSED ===");

    Ok(())
}

fn parse_share_list(raw_shares: &[String]) -> AegisResult<Vec<Share>> {
    let mut parsed = Vec::with_capacity(raw_shares.len());
    for s in raw_shares {
        parsed.push(Share::from_encoded_string(s)?);
    }
    Ok(parsed)
}
