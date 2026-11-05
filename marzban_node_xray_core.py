"""Pinned and verified Xray bootstrap for fresh Marzban nodes."""
from __future__ import annotations

import os
import re

DEFAULT_XRAY_VERSION = "26.6.1"
VERSION_ENV = "NVL_MARZBAN_NODE_XRAY_VERSION"
CORE_DIR = "/var/lib/marzban-node/xray-core"
INSTALL_SCRIPT_PATH = "/opt/marzban-node/install-xray-core.sh"
_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")

_ARCHIVES = {
    "x86_64": "Xray-linux-64.zip",
    "amd64": "Xray-linux-64.zip",
    "aarch64": "Xray-linux-arm64-v8a.zip",
    "arm64": "Xray-linux-arm64-v8a.zip",
}


def target_version() -> str:
    version = os.environ.get(VERSION_ENV, DEFAULT_XRAY_VERSION)
    if not _VERSION_RE.fullmatch(version):
        raise ValueError("invalid NVL_MARZBAN_NODE_XRAY_VERSION")
    return version


def archive_for_architecture(architecture: str) -> str:
    try:
        return _ARCHIVES[str(architecture).strip().lower()]
    except KeyError as exc:
        raise ValueError("unsupported Xray architecture") from exc


def executable_path(version: str) -> str:
    if not _VERSION_RE.fullmatch(version):
        raise ValueError("invalid Xray version")
    return f"{CORE_DIR}/xray-v{version}"


# Xray publishes ZIP digests as .dgst files. This checks transport integrity
# against the versioned release's SHA256 sidecar. An independently pinned hash
# would offer stronger supply-chain assurance than a sidecar from one origin.
INSTALL_SCRIPT = r"""#!/bin/sh
set -eu
version="${1:?version required}"
archive="${2:?archive required}"
case "$version" in
  *[!0-9.]*|"") echo "invalid version" >&2; exit 2 ;;
esac
case "$archive" in
  Xray-linux-64.zip|Xray-linux-arm64-v8a.zip) ;;
  *) echo "unsupported archive" >&2; exit 2 ;;
esac

core_dir="/var/lib/marzban-node/xray-core"
install -d -m 0755 "$core_dir"
stage="$(mktemp -d "$core_dir/.stage.XXXXXXXX")"
trap 'rm -rf "$stage"' EXIT HUP INT TERM
base="https://github.com/XTLS/Xray-core/releases/download/v${version}/${archive}"

curl --fail --location --retry 3 --connect-timeout 15 --max-time 180 \
  --output "$stage/core.zip" "$base"
curl --fail --location --retry 3 --connect-timeout 15 --max-time 40 \
  --output "$stage/core.dgst" "$base.dgst"

expected="$(awk -F '= ' '/256=/ {print $2; exit}' "$stage/core.dgst")"
printf '%s\n' "$expected" | grep -Eq '^[a-fA-F0-9]{64}$' || {
  echo "invalid upstream SHA256 digest" >&2; exit 1;
}
printf '%s  %s\n' "$expected" "$stage/core.zip" | sha256sum -c - >/dev/null || {
  echo "Xray archive SHA256 verification failed" >&2; exit 1;
}

unzip -p "$stage/core.zip" xray > "$stage/xray" || {
  echo "Xray archive has no valid executable" >&2; exit 1;
}
chmod 0755 "$stage/xray"
actual="$("$stage/xray" version | awk 'NR==1 {print $2}')"
[ "$actual" = "$version" ] || {
  echo "Xray binary version mismatch" >&2; exit 1;
}

target="$core_dir/xray-v$version"
if [ -e "$target" ]; then
  old="$("$target" version | awk 'NR==1 {print $2}')"
  [ "$old" = "$version" ] && cmp -s "$stage/xray" "$target" || {
    echo "existing Xray binary differs from verified release" >&2; exit 1;
  }
else
  install -m 0755 "$stage/xray" "$target"
fi
echo "XRAY_CORE_VERIFIED=$version"
"""
