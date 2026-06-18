#!/usr/bin/env bash
# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# Ensure we are in the script directory
cd "$(dirname "$0")"

echo "Running CI validation..."

# 1. Validation in no_std mode (without std feature)
echo "Checking in no_std mode (without std feature)..."
cargo check --no-default-features
cargo clippy --no-default-features --all-targets -- -D warnings
cargo test --no-default-features

# 2. Validation in std mode (with std/serde features)
echo "Checking in std mode (with std and serde features)..."
cargo check --all-targets --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features

echo "All checks and tests passed successfully!"
