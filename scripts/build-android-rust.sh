#!/usr/bin/env bash
set -euo pipefail

# Cross-compile l2tunnel-android-service for Android ABIs and package them as
# W^X-compliant native libraries inside clients/android/app/src/main/jniLibs/.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-$HOME/Android/Sdk}}"
NDK_DIR="${ANDROID_NDK_HOME:-$(ls -d "$SDK_ROOT"/ndk/* 2>/dev/null | sort -V | tail -n 1 || true)}"

if [[ -z "${NDK_DIR}" || ! -d "${NDK_DIR}" ]]; then
    echo "error: Android NDK not found (set ANDROID_NDK_HOME or install under \$ANDROID_SDK_ROOT/ndk/)" >&2
    exit 1
fi

NDK_BIN="$NDK_DIR/toolchains/llvm/prebuilt/linux-x86_64/bin"
API_LEVEL="${ANDROID_API_LEVEL:-26}"
JNI_DIR="$ROOT/clients/android/app/src/main/jniLibs"

build_abi() {
    local rust_target="$1"
    local clang_prefix="$2"
    local abi_dir="$3"
    local target_env="${rust_target//-/_}"
    local target_upper="${target_env^^}"
    local clang="$NDK_BIN/${clang_prefix}${API_LEVEL}-clang"
    local ar="$NDK_BIN/llvm-ar"

    if [[ ! -x "$clang" ]]; then
        echo "error: NDK compiler missing: $clang" >&2
        exit 1
    fi

    echo "==> Building l2tunnel-android-service for $rust_target ($abi_dir)"
    env \
        "CC_${target_env}=$clang" \
        "AR_${target_env}=$ar" \
        "CARGO_TARGET_${target_upper}_LINKER=$clang" \
        cargo build --manifest-path "$ROOT/Cargo.toml" \
            --release --locked --target "$rust_target" \
            -p l2tunnel-android --bin l2tunnel-android-service

    mkdir -p "$JNI_DIR/$abi_dir"
    cp "$ROOT/target/$rust_target/release/l2tunnel-android-service" \
       "$JNI_DIR/$abi_dir/libl2tunnel_android_service.so"
    "$NDK_BIN/llvm-strip" "$JNI_DIR/$abi_dir/libl2tunnel_android_service.so"
    ls -lh "$JNI_DIR/$abi_dir/libl2tunnel_android_service.so"
}

build_abi "aarch64-linux-android" "aarch64-linux-android" "arm64-v8a"
build_abi "x86_64-linux-android"  "x86_64-linux-android"  "x86_64"
echo "Done: packaged Android native binaries under $JNI_DIR"
