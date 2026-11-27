#!/usr/bin/env bash
# Build and package the x86_64 Windows client release bundle:
#   - l2tunnel-windows.exe (multi-profile daemon + Windows Service + DPAPI CLI)
#   - l2tunnel-windows-gui.exe (egui Desktop GUI over named-pipe Local API v5)
#   - l2tunnelctl.exe (CLI + offline GeoIP/ASN policy & plan tune)
#   - wintun.dll (official signed Wintun 0.14.1 amd64, SHA-256 verified)
#   - plans/common-1500.json & plans/common-jumbo-4096-1300.json
#   - Install-L2Tunnel.ps1, Uninstall-L2Tunnel.ps1, Verify-L2TunnelWindows.ps1
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="x86_64-pc-windows-gnu"
OUT_DIR="${1:-$ROOT/dist/l2tunnel-windows-x86_64}"
ZIP_PATH="${OUT_DIR}.zip"

WINTUN_VERSION="0.14.1"
WINTUN_URL="https://www.wintun.net/builds/wintun-${WINTUN_VERSION}.zip"
WINTUN_ZIP_SHA256="07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
WINTUN_DLL_SHA256="e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"

echo "==> Building release Windows binaries ($TARGET)..."
cd "$ROOT"
cargo build --release --locked --target "$TARGET" \
    -p l2tunnel-windows --features gui \
    -p l2tunnelctl

echo "==> Preparing signed Wintun ${WINTUN_VERSION} (amd64)..."
CACHE_DIR="$ROOT/target/wintun-cache"
mkdir -p "$CACHE_DIR"
if [[ -n "${WINTUN_DLL:-}" ]]; then
    WINTUN_SRC="$WINTUN_DLL"
else
    WINTUN_ZIP="$CACHE_DIR/wintun-${WINTUN_VERSION}.zip"
    WINTUN_SRC="$CACHE_DIR/wintun.dll"
    if [[ ! -f "$WINTUN_ZIP" ]]; then
        curl -fsSL "$WINTUN_URL" -o "$WINTUN_ZIP"
    fi
    ACTUAL_ZIP_SHA="$(sha256sum "$WINTUN_ZIP" | awk '{print $1}')"
    if [[ "$ACTUAL_ZIP_SHA" != "$WINTUN_ZIP_SHA256" ]]; then
        echo "ERROR: wintun-${WINTUN_VERSION}.zip SHA-256 mismatch: got $ACTUAL_ZIP_SHA, expected $WINTUN_ZIP_SHA256" >&2
        exit 1
    fi
    python3 - "$WINTUN_ZIP" "$WINTUN_SRC" "$WINTUN_DLL_SHA256" <<'PY'
import hashlib, sys, zipfile
zip_path, out_path, expected_sha = sys.argv[1], sys.argv[2], sys.argv[3]
with zipfile.ZipFile(zip_path) as zf:
    data = zf.read("wintun/bin/amd64/wintun.dll")
actual = hashlib.sha256(data).hexdigest()
if actual != expected_sha:
    raise SystemExit(f"wintun.dll SHA-256 mismatch: got {actual}, expected {expected_sha}")
with open(out_path, "wb") as f:
    f.write(data)
PY
fi

echo "==> Staging bundle in $OUT_DIR..."
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR/plans"

for bin in l2tunnel-windows.exe l2tunnel-windows-gui.exe l2tunnelctl.exe; do
    cp "$ROOT/target/$TARGET/release/$bin" "$OUT_DIR/$bin"
    if command -v x86_64-w64-mingw32-strip >/dev/null 2>&1; then
        x86_64-w64-mingw32-strip --strip-unneeded "$OUT_DIR/$bin" || true
    fi
done

cp "$WINTUN_SRC" "$OUT_DIR/wintun.dll"

cp "$ROOT/scripts/windows/Install-L2Tunnel.ps1" "$OUT_DIR/"
cp "$ROOT/scripts/windows/Uninstall-L2Tunnel.ps1" "$OUT_DIR/"
cp "$ROOT/scripts/windows/Verify-L2TunnelWindows.ps1" "$OUT_DIR/"

# Copy default 1500/1500 plan and generate jumbo 4096>1300 plan if host l2tunnelctl exists
BASE_PLAN="$ROOT/clients/android/app/src/main/res/raw/default_common_plan.json"
cp "$BASE_PLAN" "$OUT_DIR/plans/common-1500.json"
if [[ -x "$ROOT/target/release/l2tunnelctl" ]]; then
    "$ROOT/target/release/l2tunnelctl" plan tune \
        --input "$BASE_PLAN" \
        --output "$OUT_DIR/plans/common-jumbo-4096-1300.json" \
        --device-mtu 4096 --path-mtu 1300 --repair off --force >/dev/null
fi

cat > "$OUT_DIR/README-WINDOWS.txt" <<'EOF'
l2tunnel Windows Client Bundle (x86_64)
=======================================

Contents:
  l2tunnel-windows-gui.exe     Unprivileged Desktop GUI (auto-installs service on first Start)
  l2tunnel-windows.exe         Windows Service & multi-profile Wintun L3 daemon (0 args opens GUI)
  l2tunnelctl.exe              CLI + offline GeoIP/ASN policy & MTU plan tools
  wintun.dll                   Official signed Wintun 0.14.1 (amd64) driver DLL (SHA-256 verified)
  plans/common-1500.json       Default Common Swift plan (1500/1500)
  plans/common-jumbo-4096-1300.json  Jumbo Internal 4096 B > Capsule 1300 B plan
  Install-L2Tunnel.ps1         Optional scripted installer (also registers l2tunnel:// handler)
  Uninstall-L2Tunnel.ps1       Clean uninstaller
  Verify-L2TunnelWindows.ps1   Native Windows E2E qualification harness

Quick Start (Zero Manual Setup — same flow as Linux GUI):
  1. Double-click l2tunnel-windows-gui.exe (runs unprivileged; uses DirectX/Vulkan/WARP
     wgpu with automatic OpenGL glow fallback).
  2. Click "Start service..." (or "Install & restart service..." when updating) and
     approve the Windows UAC prompt:
     - Automatically installs l2tunnel-windows.exe and the bundled wintun.dll into
       C:\Program Files\l2tunnel (with WLS-08 admin-only ACLs and pinned SHA-256),
       starts the l2tunnel LocalSystem service, and attaches the GUI.
  3. On Management, paste a l2tunnel://v1/connect?... Share URI, click Import URI,
     Save, and Connect.

Optional Scripted Install / Native E2E Verification (Administrator PowerShell):
  .\Install-L2Tunnel.ps1
  .\Verify-L2TunnelWindows.ps1 -ShareUri "l2tunnel://v1/connect?..."
EOF

(cd "$OUT_DIR" && sha256sum l2tunnel-windows.exe l2tunnel-windows-gui.exe l2tunnelctl.exe wintun.dll Install-L2Tunnel.ps1 Uninstall-L2Tunnel.ps1 Verify-L2TunnelWindows.ps1 > SHA256SUMS.txt)

rm -f "$ZIP_PATH"
(cd "$(dirname "$OUT_DIR")" && python3 -m zipfile -c "$ZIP_PATH" "$(basename "$OUT_DIR")")

echo "==> Bundle ready:"
ls -lh "$OUT_DIR" "$ZIP_PATH"
