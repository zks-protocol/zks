# Android AAR Build Guide for zks_uniffi

This guide explains how to build the Android AAR (Android Archive) for the zks_uniffi library.

## Prerequisites

1. **Android SDK** with NDK
2. **Rust** with Android targets
3. **Gradle** build system
4. **Java** JDK 8 or higher

## Setup Steps

### 1. Install Rust Android Targets

```bash
rustup target add aarch64-linux-android
rustup target add armv7-linux-androideabi
rustup target add i686-linux-android
rustup target add x86_64-linux-android
```

### 2. Install Android NDK

Download and install Android NDK through Android Studio or standalone.

### 3. Set Environment Variables

```bash
export ANDROID_NDK_HOME=/path/to/android-ndk
export ANDROID_SDK_ROOT=/path/to/android-sdk
```

### 4. Build Rust Libraries for Android

```bash
# Build for ARM64 (most common)
cargo build --target aarch64-linux-android --release -p zks_uniffi

# Build for ARMv7
cargo build --target armv7-linux-androideabi --release -p zks_uniffi

# Build for x86
cargo build --target i686-linux-android --release -p zks_uniffi

# Build for x86_64
cargo build --target x86_64-linux-android --release -p zks_uniffi
```

### 5. Copy Libraries to Android Project

Copy the built `.so` files to the appropriate directories:

```bash
# ARM64
cp target/aarch64-linux-android/release/libzks_uniffi.so android/zks-uniffi/src/main/jniLibs/arm64-v8a/

# ARMv7
cp target/armv7-linux-androideabi/release/libzks_uniffi.so android/zks-uniffi/src/main/jniLibs/armeabi-v7a/

# x86
cp target/i686-linux-android/release/libzks_uniffi.so android/zks-uniffi/src/main/jniLibs/x86/

# x86_64
cp target/x86_64-linux-android/release/libzks_uniffi.so android/zks-uniffi/src/main/jniLibs/x86_64/
```

### 6. Build the AAR

```bash
cd android
./gradlew :zks-uniffi:assembleRelease
```

The AAR will be available at:
```
android/zks-uniffi/build/outputs/aar/zks-uniffi-release.aar
```

## Project Structure

```
android/
├── zks-uniffi/
│   ├── build.gradle
│   ├── src/
│   │   ├── main/
│   │   │   ├── AndroidManifest.xml
│   │   │   ├── java/com/zks/uniffi/
│   │   │   │   └── ZksMeetWrapper.kt
│   │   │   ├── kotlin/com/zks/uniffi/
│   │   │   │   └── zks_uniffi.kt (generated)
│   │   │   └── jniLibs/
│   │   │       ├── arm64-v8a/
│   │   │       ├── armeabi-v7a/
│   │   │       ├── x86/
│   │   │       └── x86_64/
├── settings.gradle
├── gradle.properties
└── build.gradle (project level)
```

## Usage in Android App

Add the AAR to your Android project:

1. Copy the AAR to your app's `libs/` directory
2. Add to your app's `build.gradle`:

```gradle
dependencies {
    implementation files('libs/zks-uniffi-release.aar')
}
```

3. Use in your code:

```kotlin
import com.zks.uniffi.ZksMeetWrapper

val zksMeet = ZksMeetWrapper()
val peerId = zksMeet.initialize()
```

## Troubleshooting

### Library not found
- Ensure the `.so` files are in the correct `jniLibs` directories
- Check that the architecture matches your device/emulator

### Build failures
- Verify all prerequisites are installed
- Check environment variables are set correctly
- Ensure Rust Android targets are installed

### Runtime crashes
- Check Android permissions in manifest
- Verify native library loading
- Check for architecture compatibility