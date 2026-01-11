#!/bin/bash

# Build script for Android AAR
# This script builds the Rust library for Android and packages it into an AAR

set -e

echo "Building Android AAR for zks_uniffi..."

# Create output directory
mkdir -p build/outputs/aar

# Build the AAR using Gradle
cd android
./gradlew :zks-uniffi:assembleRelease

# Copy the AAR to the build directory
cp zks-uniffi/build/outputs/aar/zks-uniffi-release.aar ../build/outputs/aar/

echo "Android AAR build completed!"
echo "Output: build/outputs/aar/zks-uniffi-release.aar"