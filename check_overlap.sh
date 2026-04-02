#!/usr/bin/env bash
#
# Cross-reference Alex's runtime-flagged programs against static analysis.
# Green = found, Red = not found.

set -euo pipefail

IDS_FILE="${1:?Usage: $0 <ids_file>}"

GREEN='\033[0;32m'
RED='\033[0;31m'
RESET='\033[0m'

FAIL_IDS=(
    fat2dUTkypDNDT86LtLGmzJDK11FSJ72gfUW35igk7u
    CroWg74XNDF8UMnAZVbXx49iVj7iJ7b4CsqTCVWF7aK
    BGUMAp9Gq7iTEuizy4pqaxsTyUCBK68MDfK752saRPUY
    TCMPhJdwDryooaGtiocG1u3xcYbRpiJzb283XfCZsDp
    LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo
    J88B7gmadHzTNGiy54c9Ms8BsEXNdB2fntFyhKpk3qoT
    pyti8TM4zRVBjmarcgAPmTNNAXYKJv7WVHrkrm6woLN
)

SUCCEED_IDS=(
    NeonVMyRX5GbCrsAHnUwx1nYYoJAtskU1bWUo6JGNyG
    cTokenmWW8bLPjZEBAUgYy3zKxQZW6VKi7bqNFEVv3m
    ZUPYzr87cgminBywohtbUxnaiFMwXNy8A5pD9cCcvVU
    SySTEM1eSU2p4BGQfQpimFEWWSC1XDFeun3Nqzz3rT7
    DiabLoFN9hCNkEc2HhCtgo1VqeQvyRXQiGh2B14mnwJs
)

echo "=== Programs that FAIL (ProgramFailedToComplete / Custom) ==="
for id in "${FAIL_IDS[@]}"; do
    if grep -q "^${id}$" "$IDS_FILE" 2>/dev/null; then
        echo -e "  ${GREEN}FOUND${RESET}  $id"
    else
        echo -e "  ${RED}MISS ${RESET}  $id"
    fi
done

echo ""
echo "=== Programs that SUCCEED DIFFERENTLY (committing garbage) ==="
for id in "${SUCCEED_IDS[@]}"; do
    if grep -q "^${id}$" "$IDS_FILE" 2>/dev/null; then
        echo -e "  ${GREEN}FOUND${RESET}  $id"
    else
        echo -e "  ${RED}MISS ${RESET}  $id"
    fi
done
