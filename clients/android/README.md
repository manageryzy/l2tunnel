# l2tunnel Android Client (`clients/android`)

Core Android `VpnService` + Local API v5 shell for the shared Rust
`l2tunnel-android-service` runtime (`CL-28`, `CL-29`, `CL-30`).

## Architecture

- **Native owner (`apps/l2tunnel-android`):** Cross-compiled for `arm64-v8a` and
  `x86_64` as `libl2tunnel_android_service.so` (`useLegacyPackaging = true` so
  it executes from `applicationInfo.nativeLibraryDir` under Android W^X).
- **FD broker (`FdBrokerServer`):** UID-verified (`SO_PEERCRED`) abstract Unix
  socket implementing:
  - `M` monitor stream (closing it cleanly terminates the Rust owner),
  - `P` socket protection via `SCM_RIGHTS` + `VpnService.protect()` for initial
    sockets, reconnect sockets, and make-before-break UDP carrier-switch standby
    sockets,
  - `T` L3 TUN descriptor handoff via `VpnService.Builder.establish()`,
  - `R` readiness signal.
- **Control plane (`LocalApiV5Client`):** Length-delimited Local API v5 JSON
  over the app-private Unix socket (`filesDir/run/service.sock`, mode `0700`).
- **Network transitions (`NetworkChangeCoordinator`):** Debounced (`1.5 s`),
  battery-aware sliding-window capped (`6` / `5 min`) Local API v5 reconnect on
  default-network changes (`ConnectivityManager.NetworkCallback`).
- **Layer contract:** Standard Android `VpnService` is strictly TUN (L3). TAP
  and VXLAN L2 attachments are refused explicitly (`UnsupportedLayerException`).

## Building

Requires Rust Android targets (`aarch64-linux-android`, `x86_64-linux-android`),
Android SDK 35, Android NDK 27+, and JDK 17–21:

```sh
# 1. Cross-compile & strip native Rust binaries into app/src/main/jniLibs/
./scripts/build-android-rust.sh

# 2. Run JVM unit tests and build the debug APK
cd clients/android
ANDROID_HOME="$HOME/Android/Sdk" gradle testDebugUnitTest assembleDebug
```

## Qualification boundary

Cross-compilation of `arm64-v8a`/`x86_64` native binaries, host Rust broker/
socket-protection tests, JVM unit tests, and debug APK assembly do not
substitute for physical Android device qualification (`CL-35`, `TEST-14`).
