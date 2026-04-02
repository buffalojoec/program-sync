#!/usr/bin/env bash
#
# Find duplicate bytecode among flagged programs.
#
# Takes an IDs file (one program ID per line) and a programs directory,
# checksums each .so file, and reports duplicate pairs.
#
# Usage:
#   ./check_dupes.sh <ids_file> <programs_dir>
#
# Output: one line per duplicate pair, tab-separated IDs.
# Exit code 0 regardless of whether duplicates are found.

set -euo pipefail

IDS_FILE="${1:?Usage: $0 <ids_file> <programs_dir>}"
PROGRAMS_DIR="${2:?Usage: $0 <ids_file> <programs_dir>}"

GREEN='\033[0;32m'
DIM='\033[0;90m'
RESET='\033[0m'

# Checksum each program.
declare -A hash_to_ids
missing=0

while read -r id; do
    so_path="${PROGRAMS_DIR}/${id}.so"
    if [ ! -f "$so_path" ]; then
        missing=$((missing + 1))
        continue
    fi
    hash=$(md5sum "$so_path" | awk '{print $1}')
    if [ -n "${hash_to_ids[$hash]+x}" ]; then
        hash_to_ids[$hash]="${hash_to_ids[$hash]} ${id}"
    else
        hash_to_ids[$hash]="$id"
    fi
done < "$IDS_FILE"

# Report duplicates.
total=$(wc -l < "$IDS_FILE")
dupes=0
unique=0

for hash in "${!hash_to_ids[@]}"; do
    ids=(${hash_to_ids[$hash]})
    unique=$((unique + 1))
    if [ ${#ids[@]} -gt 1 ]; then
        dupes=$((dupes + 1))
        echo -e "${GREEN}DUPE${RESET}  ${ids[*]}"
    fi
done

echo ""
echo -e "${DIM}Programs: ${total}  Unique: ${unique}  Duplicate sets: ${dupes}  Missing: ${missing}${RESET}"
