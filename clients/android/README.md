# l2tunnel Android Client (`clients/android`)

Jetpack Compose + Material 3 (Material You) Android `VpnService` client for the
shared Rust `l2tunnel-android-service` runtime (`CL-28`, `CL-29`, `CL-30`, `CL-31`).

## Architecture

- **Adaptive UI (4-tab Material 3 / Material You):**
  - Follows system light/dark with Android 12+ Material You dynamic colors, automatically switching between portrait `TopAppBar` + bottom `NavigationBar` and landscape/wide (`>= 600 dp`) left `NavigationRail` + 2-column dashboards and dialogs.
  - `Overview`: hero Connect/Disconnect/Reconnect card, profile switcher, peer/cover/RTT/TX/RX telemetry tiles, and live TX sparkline.
  - `Connection`: live make-before-break UDP cover switcher (`quic-like` / `media-like` / `tls-like`), live FEC, Internal TUN MTU & Capsule/Path MTU tuning (`tuning_get`/`tuning_switch`, with `"Segmented: Internal > Capsule"` indicator when `internal_mtu > capsule_mtu`), live wire speed budget (`rate_budget_set`), and in-process `TunnelTestV1` ping/speed tests.
  - `Profiles & Keys`: multi-profile store under `noBackupFilesDir`, safe `.zip` bundle importer, `l2tunnel://v1/connect` share URI import/export & Android deep-link handler (public by default; opt-in full provisioning; supports `tune_repair`, `tune_device_mtu`, `tune_path_mtu`), one-tap **New Profile** with automatic native `--keygen` + bundled `default_common_plan.json`, typed L3 TUN editor with `common.json` `path_mtu` validation, 64-hex key paste & copyable client public keys, **Redirect Rules** dialog (GeoIP country/region, ASN, Continent, CIDR, Private/LAN presets + live IP rule tester compiled into `VpnService.Builder` routes via CIDR subtraction with mandatory peer anti-loop bypass), per-app split tunneling (`all` / `exclude` / `include` with mandatory anti-loop self-exclusion), and `KeystoreSecretStore` AES-256-GCM envelope encryption under `AndroidKeyStore` (ephemeral runtime staging is zeroed and deleted immediately on Rust readiness `R` or stop).
  - `Stats & Logs`: rolling 60-sample TX & RTT charts, transport/TUN counters, local CSR meters (`meters_read`), bounded redacted event log, and SAF redacted diagnostics JSON export (`CL-16`).

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
socket-protection tests, JVM unit tests, debug APK assembly, and unprivileged
Android 12 (API 32) / Android 15 (API 35) x86_64 emulator runs do not
substitute for physical Android device qualification (`CL-35`, `TEST-14`).
