"""R1 disabled-only systemd installation and guarded rollback on disposable VMs.

Install writes only root-owned manifest + ONE dedicated service unit. It never
calls systemctl, starts/ends sessions, changes wg0, user routes, PAM, NAT or DB.
A separately reviewed root-installed agent/dependency bundle is prerequisite.

There is NO CLI or production mode. All mutation requires an explicit opt-in
Python caller and lab identity check; the caller must never supply real VPSes.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Callable

from edge_egress_r1_systemd import (
    R1BootContract, R1ServiceUnsafe, assert_disposable_identity, render_unit,
    _owned, _read_checked, MANIFEST_ROOT, STAGE_ROOT,
)
from edge_egress_r1_transport import _stage_owned

UNIT_ROOT = Path("/etc/systemd/system")


@dataclass(frozen=True)
class R1InstallBundle:
    contract: R1BootContract
    manifest_bytes: bytes
    unit_bytes: bytes
    manifest_sha256: str
    unit_sha256: str


def prepare_bundle(manifest_bytes: bytes, *, expected_manifest_sha256: str,
                   expected_unit_sha256: str) -> R1InstallBundle:
    """Pure code review gate. Hashes must be supplied independently."""
    if type(manifest_bytes) is not bytes or len(manifest_bytes) > 8192:
        raise R1ServiceUnsafe("INVALID_INSTALL_MANIFEST")
    try:
        value = json.loads(manifest_bytes)
        contract = R1BootContract.parse(value)
    except (ValueError, UnicodeError, TypeError) as exc:
        raise R1ServiceUnsafe("INVALID_INSTALL_CONTRACT") from exc
    manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
    if expected_manifest_sha256 != manifest_hash:
        raise R1ServiceUnsafe("REVIEWED_MANIFEST_SHA_REQUIRED")
    unit = render_unit(contract, manifest_hash).encode("utf-8")
    unit_hash = hashlib.sha256(unit).hexdigest()
    if expected_unit_sha256 != unit_hash:
        raise R1ServiceUnsafe("REVIEWED_UNIT_SHA_REQUIRED")
    return R1InstallBundle(contract, manifest_bytes, unit, manifest_hash,
                           unit_hash)


def _assert_bundle(bundle: R1InstallBundle) -> None:
    if not isinstance(bundle, R1InstallBundle):
        raise R1ServiceUnsafe("INVALID_INSTALL_BUNDLE")
    checked = prepare_bundle(
        bundle.manifest_bytes,
        expected_manifest_sha256=bundle.manifest_sha256,
        expected_unit_sha256=bundle.unit_sha256,
    )
    if checked != bundle:
        raise R1ServiceUnsafe("INSTALL_BUNDLE_IDENTITY_CHANGED")


def _paths(bundle: R1InstallBundle, manifest_root: Path, unit_root: Path):
    contract = bundle.contract
    contract.spec.validate()
    if contract.role not in ("core", "edge") or contract.mode != "DISPOSABLE_ONLY":
        raise R1ServiceUnsafe("NON_DISPOSABLE_INSTALL_FORBIDDEN")
    return (manifest_root / contract.filename(),
            unit_root / f"nvl-egress-{contract.spec.edge_id}-transport.service")


def _check_install_dirs(manifest_root: Path, unit_root: Path) -> None:
    if not _owned(manifest_root, directory=True):
        raise R1ServiceUnsafe("ROOT_ONLY_MANIFEST_DIRECTORY_REQUIRED")
    if unit_root.is_symlink():
        raise R1ServiceUnsafe("UNSAFE_UNIT_DIRECTORY")
    try:
        st = unit_root.stat()
    except OSError as exc:
        raise R1ServiceUnsafe("UNSAFE_UNIT_DIRECTORY") from exc
    if not (stat.S_ISDIR(st.st_mode) and st.st_uid == 0
            and not st.st_mode & 0o022):
        raise R1ServiceUnsafe("UNSAFE_UNIT_DIRECTORY")


def _write_exclusive(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(content)
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(path, 0o600)
    dirfd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(dirfd)
    finally:
        os.close(dirfd)


def install_disabled(bundle: R1InstallBundle, *,
                     explicitly_authorized: bool = False,
                     manifest_root: Path = MANIFEST_ROOT,
                     unit_root: Path = UNIT_ROOT,
                     stage_root: Path = STAGE_ROOT,
                     identity_check: Callable[[R1BootContract], None] = assert_disposable_identity,
                     agent_check: Callable[[], bool] | None = None) -> tuple[str, str]:
    """Only create NEW files; no daemon-reload, enable, or start.

    Failure after the manifest is created deliberately leaves an inspectable
    orphan for an explicit guarded rollback rather than guessing ownership.
    """
    if explicitly_authorized is not True or os.geteuid() != 0:
        raise R1ServiceUnsafe("DISABLED_INSTALL_EXPLICIT_ROOT_GATE_REQUIRED")
    _assert_bundle(bundle)
    if agent_check is None or agent_check() is not True:
        raise R1ServiceUnsafe("REVIEWED_ROOT_AGENT_REQUIRED")
    identity_check(bundle.contract)
    _check_install_dirs(manifest_root, unit_root)
    manifest, unit = _paths(bundle, manifest_root, unit_root)
    if (manifest.exists() or manifest.is_symlink()
            or unit.exists() or unit.is_symlink()):
        raise R1ServiceUnsafe("INSTALL_TARGET_ALREADY_EXISTS")
    if not _stage_owned(bundle.contract.spec, bundle.contract.role,
                        stage_root, bundle.contract.stage_sha256):
        raise R1ServiceUnsafe("STAGED_BYTES_NOT_PINNED")
    # Refuse TOCTOU between initial check and exclusive writes. Root files are
    # created with O_EXCL; no preexisting unit is ever adopted/replaced.
    _write_exclusive(manifest, bundle.manifest_bytes)
    _write_exclusive(unit, bundle.unit_bytes)
    return str(manifest), str(unit)


def _exact_owned_bytes(path: Path, digest: str) -> bool:
    if path.is_symlink() or not _owned(path):
        return False
    try:
        raw = _read_checked(path, 16384)
    except (R1ServiceUnsafe, OSError):
        return False
    return hashlib.sha256(raw).hexdigest() == digest


def rollback_disabled(bundle: R1InstallBundle, *,
                      explicitly_authorized: bool = False,
                      manifest_root: Path = MANIFEST_ROOT,
                      unit_root: Path = UNIT_ROOT,
                      identity_check: Callable[[R1BootContract], None] = assert_disposable_identity,
                      inactive_disabled_check: Callable[[str], bool] | None = None,
                      transport_absent_check: Callable[[R1BootContract], bool] | None = None) -> tuple[str, ...]:
    """Only delete THIS pinned unit/manifest when externally verified inactive.

    A running unit, unverified systemd state, network activity, unexpected
    file bytes or a foreign symlink is HOLD. No network or systemd mutations.
    """
    if explicitly_authorized is not True or os.geteuid() != 0:
        raise R1ServiceUnsafe("ROLLBACK_EXPLICIT_ROOT_GATE_REQUIRED")
    _assert_bundle(bundle)
    identity_check(bundle.contract)
    _check_install_dirs(manifest_root, unit_root)
    manifest, unit = _paths(bundle, manifest_root, unit_root)
    if inactive_disabled_check is None or inactive_disabled_check(unit.name) is not True:
        raise R1ServiceUnsafe("UNIT_STATE_NOT_INACTIVE_DISABLED")
    # An inactive oneshot service does NOT prove its old network is gone.
    if transport_absent_check is None or transport_absent_check(bundle.contract) is not True:
        raise R1ServiceUnsafe("DEDICATED_TRANSPORT_STILL_PRESENT_OR_UNKNOWN")
    if not (manifest.exists() or manifest.is_symlink()
            or unit.exists() or unit.is_symlink()):
        return ()
    # Even if one file is absent (interrupted install), ALL remaining bytes
    # must be pinned. Never delete a symlink or a file with changed content.
    present = (
        (unit, bundle.unit_sha256),
        (manifest, bundle.manifest_sha256)
    )
    for path, digest in present:
        if path.exists() or path.is_symlink():
            if not _exact_owned_bytes(path, digest):
                raise R1ServiceUnsafe("ROLLBACK_OWNERSHIP_OR_BYTES_UNCERTAIN")
    removed = []
    for path, _ in present:
        if path.exists():
            path.unlink()
            removed.append(str(path))
    return tuple(removed)
