#!/usr/bin/env bash
#
# Full SIMD-0460 stack-gaps analysis pipeline.
#
# Runs tiers 1–3 against the program corpus, extracts V0 program IDs,
# then queries RPC for on-chain usage of the flagged V0 programs.
#
# Usage:
#   ./run_analysis.sh <programs_dir>
#
# Output files (all written to ./tmp/):
#   tier1.txt           — Tier 1 offsets scan output
#   tier1_ids.txt       — All flagged program IDs (tier 1)
#   tier1_v0_ids.txt    — V0-only flagged program IDs (tier 1)
#   tier2.txt           — Tier 2/3 trace output
#   tier2_ids.txt       — All flagged program IDs (tier 2/3)
#   rpc_usage.txt       — RPC usage output for flagged V0 programs

set -euo pipefail

PROGRAMS_DIR="${1:?Usage: $0 <programs_dir>}"
OUTDIR="./tmp"

if [ ! -d "$PROGRAMS_DIR" ]; then
    echo "ERROR: Directory not found: $PROGRAMS_DIR"
    exit 1
fi

mkdir -p "$OUTDIR"

echo "=== SIMD-0460 Analysis Pipeline ==="
echo "Programs dir: $PROGRAMS_DIR"
echo "Output dir:   $OUTDIR"
echo ""

# --- Tier 1: offsets scan ---
echo "[Tier 1] Running offsets scan..."
cargo run --release -- stack-gaps offsets \
    --dir "$PROGRAMS_DIR" \
    --ids-out "$OUTDIR/tier1_ids.txt" \
    > "$OUTDIR/tier1.txt" 2>&1
echo "[Tier 1] Done. Output: $OUTDIR/tier1.txt"

# Extract V0-only IDs from tier 1 output.
grep 'SBPF V0' "$OUTDIR/tier1.txt" \
    | sed 's/^ *//' \
    | cut -d' ' -f1 \
    | sort \
    > "$OUTDIR/tier1_v0_ids.txt"
V0_COUNT=$(wc -l < "$OUTDIR/tier1_v0_ids.txt")
echo "[Tier 1] Extracted $V0_COUNT V0 program IDs -> $OUTDIR/tier1_v0_ids.txt"
echo ""

# --- Tier 2/3: trace scan ---
echo "[Tier 2/3] Running trace scan (this may take a while)..."
cargo run --release -- stack-gaps trace \
    --dir "$PROGRAMS_DIR" \
    --ids-out "$OUTDIR/tier2_ids.txt" \
    > "$OUTDIR/tier2.txt" 2>&1
echo "[Tier 2/3] Done. Output: $OUTDIR/tier2.txt"
echo ""

# --- RPC usage for flagged V0 programs ---
echo "[RPC] Querying on-chain usage for $V0_COUNT flagged V0 programs..."
cargo run --release -- rpc usage \
    --file "$OUTDIR/tier1_v0_ids.txt" \
    > "$OUTDIR/rpc_usage.txt" 2>&1
echo "[RPC] Done. Output: $OUTDIR/rpc_usage.txt"
echo ""

echo "=== Pipeline complete ==="
echo "Results:"
ls -lh "$OUTDIR"/tier1.txt "$OUTDIR"/tier2.txt "$OUTDIR"/rpc_usage.txt
