#!/usr/bin/env bash
# Pre-places the AppImage build tools that cargo-packager would otherwise download unverified
# (linuxdeploy from a moving "continuous" tag, no checksum). Each file comes from a fixed release
# and must match its pinned SHA-256; cargo-packager reuses files already in its tools folder.
#
# Usage: scripts/fetch-appimage-tools.sh <x86_64|aarch64>
#
# To update a tool: change its URL, download it, check it, and replace the SHA-256 below.
set -euo pipefail

arch="${1:?usage: $0 <x86_64|aarch64>}"
case "$arch" in
  x86_64)
    apprun_sha=f30140a43a0a59e46db21bdefdf749b9e9f2c6946e92afabbacf98b8ae73fb4f
    linuxdeploy_sha=e762bea85c8eb0d4b3508d46e5c1f037f717d0f9303ae3b4aafc8b04991fa1ef
    plugin_sha=992d502a248e14ab185448ddf6f6e7d25558cb84d4623c354c3af350c25fccb3
    ;;
  aarch64)
    apprun_sha=072f17c0895a85c490282fe5395c5007e5fc75da727e553b3b8fb680feb11578
    linuxdeploy_sha=b12b5cc57bd0921e1f98d73f58aa364503bc1a27f54b7a69fd2870bce7fa2f55
    plugin_sha=83c292149274965a865dcd44c135cfca8ba28c6b7de3eb628d4b8b5f248af17c
    ;;
  *) echo "unsupported architecture: $arch" >&2; exit 2 ;;
esac

# Same folder cargo-packager 0.11.8 uses: dirs::cache_dir()/.cargo-packager/AppImage.
tools="${XDG_CACHE_HOME:-$HOME/.cache}/.cargo-packager/AppImage"
mkdir -p "$tools"
cd "$tools"

fetch() {
  local name="$1" url="$2" sha="$3"
  curl --proto '=https' --tlsv1.2 -sSfL --retry 3 -o "$name.download" "$url"
  echo "$sha  $name.download" | sha256sum -c --quiet -
  mv "$name.download" "$name"
  chmod 764 "$name"
  echo "verified $name"
}

# File names must match what cargo-packager looks for.
fetch "AppRun-$arch" \
  "https://github.com/tauri-apps/binary-releases/releases/download/apprun-old/AppRun-$arch" "$apprun_sha"
fetch "linuxdeploy-$arch.AppImage" \
  "https://github.com/tauri-apps/binary-releases/releases/download/linuxdeploy/linuxdeploy-$arch.AppImage" \
  "$linuxdeploy_sha"
fetch "linuxdeploy-plugin-appimage.AppImage" \
  "https://github.com/linuxdeploy/linuxdeploy-plugin-appimage/releases/download/1-alpha-20250213-1/linuxdeploy-plugin-appimage-$arch.AppImage" \
  "$plugin_sha"
