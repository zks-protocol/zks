#!/bin/bash

# Android build script for zks_uniffi AAR
# This script builds the Rust library for Android targets

set -e

echo "Building zks_uniffi for Android targets..."

# Build for Android targets
cargo build --target aarch64-linux-android --release -p zks_uniffi
cargo build --target armv7-linux-androideabi --release -p zks_uniffi
cargo build --target i686-linux-android --release -p zks_uniffi
cargo build --target x86_64-linux-android --release -p zks_uniffi

echo "Android build completed!"