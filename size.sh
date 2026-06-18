#!/usr/bin/env bash
# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# Ensure we are in the script directory
cd "$(dirname "$0")"

echo "Building test_fw for rv32imc..."
(
    cd test_fw
    cargo build
)

# Define target binary path
BINARY="test_fw/target/riscv32imc-unknown-none-elf/debug/test-fw"

if [ ! -f "$BINARY" ]; then
    echo "Error: Binary not found at $BINARY" >&2
    exit 1
fi

# Find the main_impl symbol size
# nm output format with -t d: <decimal_address> <decimal_size> <type> <mangled_name>
SYMBOL_LINE=$(nm -S -t d "$BINARY" | grep 'main_impl' | head -n 1 || true)

if [ -z "$SYMBOL_LINE" ]; then
    echo "Error: Could not find 'main_impl' symbol in $BINARY" >&2
    exit 1
fi

# Parse address, size, and name
read -r ADDRESS SIZE TYPE NAME <<< "$SYMBOL_LINE"

# Convert size and address using base-10 to avoid octal interpretation of leading zeros
SIZE_DEC=$((10#$SIZE))
ADDRESS_DEC=$((10#$ADDRESS))

echo "------------------------------------------------"
echo "Function:  main_impl"
echo "Size:      $SIZE_DEC bytes"
echo "Address:   0x$(printf "%08x" "$ADDRESS_DEC")"
echo "------------------------------------------------"
