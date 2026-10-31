#!/usr/bin/env bash
set -euo pipefail

echo "========================================================================"
echo "   PROJECT AEGIS — LIVE CRYPTOGRAPHIC & THRESHOLD RECOVERY DEMO"
echo "========================================================================"
echo ""

echo "[Step 1] Building AEGIS in release mode..."
cargo build --quiet
AEGIS_BIN="./target/debug/aegis"

echo ""
echo "[Step 2] Running built-in mathematical & RFC known-answer self-tests..."
$AEGIS_BIN selftest

echo ""
echo "[Step 3] Generating a 256-bit MasterKey and splitting into (k=3, n=5) shares..."
KEYGEN_OUT=$($AEGIS_BIN keygen -k 3 -n 5)
echo "$KEYGEN_OUT"

MASTER_KEY=$(echo "$KEYGEN_OUT" | awk '/Master Key/ {print $NF}')
COMMITMENT=$(echo "$KEYGEN_OUT" | awk '/Key Commitment/ {print $NF}')
SHARE_1=$(echo "$KEYGEN_OUT" | awk '/Share #01/ {print $NF}')
SHARE_2=$(echo "$KEYGEN_OUT" | awk '/Share #02/ {print $NF}')
SHARE_3=$(echo "$KEYGEN_OUT" | awk '/Share #03/ {print $NF}')
SHARE_4=$(echo "$KEYGEN_OUT" | awk '/Share #04/ {print $NF}')
SHARE_5=$(echo "$KEYGEN_OUT" | awk '/Share #05/ {print $NF}')

echo ""
echo "[Step 4] Encrypting classified payload with ChaCha20-Poly1305 & Canonical AAD..."
ENCRYPT_OUT=$($AEGIS_BIN encrypt \
  --key "$MASTER_KEY" \
  --message "AEGIS-TOP-SECRET: Quantum-Resistant Vault Coordinates [27.7172 N, 85.3240 E]" \
  --aad "clearance:level-5")
echo "$ENCRYPT_OUT"

ENVELOPE=$(echo "$ENCRYPT_OUT" | awk '/Envelope/ {print $NF}')

echo ""
echo "[Step 5] Zero-Exposure Threshold Decryption using Shares #1, #3, and #5 (MasterKey never touches disk)..."
$AEGIS_BIN decrypt \
  --envelope "$ENVELOPE" \
  --share "$SHARE_1" \
  --share "$SHARE_3" \
  --share "$SHARE_5" \
  --aad "clearance:level-5"

echo ""
echo "[Step 6] Verifying Shares #2, #4, and #5 against public HKDF KeyCommitment..."
$AEGIS_BIN verify \
  --commitment "$COMMITMENT" \
  --share "$SHARE_2" \
  --share "$SHARE_4" \
  --share "$SHARE_5"

echo ""
echo "[Step 7] Adversarial Test A — Attempting recovery with insufficient shares (only 2 of 3 required)..."
if $AEGIS_BIN decrypt --envelope "$ENVELOPE" --share "$SHARE_1" --share "$SHARE_2" --aad "clearance:level-5" 2>/dev/null; then
  echo "ERROR: Should have rejected insufficient shares!"
  exit 1
else
  echo "[EXPECTED REJECTION] Insufficient shares (2 < k=3) cleanly blocked."
fi

echo ""
echo "[Step 8] Adversarial Test B — Attempting decryption with tampered Associated Data (AAD)..."
if $AEGIS_BIN decrypt --envelope "$ENVELOPE" --share "$SHARE_1" --share "$SHARE_3" --share "$SHARE_5" --aad "clearance:level-1" 2>/dev/null; then
  echo "ERROR: Should have rejected tampered AAD!"
  exit 1
else
  echo "[EXPECTED REJECTION] Tampered AAD rejected by Poly1305 authentication tag."
fi

echo ""
echo "========================================================================"
echo "   ALL AEGIS DEMONSTRATION STEPS COMPLETED SUCCESSFULLY"
echo "========================================================================"
