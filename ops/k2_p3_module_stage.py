"""K2 P3 reviewed Python dependency bundle for PAM/BootGuard installer.

Separate explicit bootstrap operation: only executable-free Python source
modules, pinned per-file SHA256, closed local import graph. Never reads or
stages .env, keys, SQLite, bot entrypoint, symlinks or executable scripts.
The unprivileged per-UID DoH service MUST be able to read installed modules.
"""
from __future__ import annotations

import ast
from hashlib import sha256
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Callable


MODULE_STAGING_ENABLED = False
SOURCE = Path("/root/nvl-release")
TARGET = Path("/opt/nvl-egress")
NAME = re.compile(r"(?:edge_egress_[a-z0-9_]+\.py|ops/(?:__init__|edge_egress_[a-z0-9_]+)\.py)\Z")
SHA = re.compile(r"[a-f0-9]{64}\Z")
REQUIRED = frozenset({
    "edge_egress_v1_admission.py",
    "edge_egress_uid_admission.py",
    "edge_egress_uid_boot.py",
    "edge_egress_uid_dns.py",
    "edge_egress_uid_systemd.py",
    "edge_egress_uid_policy.py",
    "edge_egress_v1_ingress.py",
    "edge_egress_uid_runtime_store.py",
    "ops/edge_egress_provision.py",
})


class ModuleStageHold(ValueError):
    pass


def _owned_dir(p:Path, *, readable=False):
    s=p.lstat()
    if (not stat.S_ISDIR(s.st_mode) or s.st_uid!=0
            or (s.st_mode & 0o022)
            or (readable and not (s.st_mode & 0o005)==0o005)):
        raise ModuleStageHold("UNSAFE_MODULE_DIRECTORY")


def _deps(tree: ast.AST) -> set[str]:
    names=set()
    for node in ast.walk(tree):
        if isinstance(node,ast.Import):
            names.update(a.name for a in node.names)
        if isinstance(node,ast.ImportFrom) and node.level==0 and node.module:
            names.add(node.module)
    result=set()
    for name in names:
        if name.startswith("edge_egress_"):
            result.add(name.split(".")[0]+".py")
        if name.startswith("ops.edge_egress_"):
            result.add(name.replace(".","/")+".py")
    return result


def validate_module_bundle(
    blobs:dict[str,bytes], reviewed_sha256:dict[str,str],
) -> str:
    if (not isinstance(blobs,dict) or not isinstance(reviewed_sha256,dict)
            or set(blobs)!=set(reviewed_sha256)
            or not REQUIRED<=set(blobs)
            or len(blobs)>180):
        raise ModuleStageHold("INCOMPLETE_REVIEWED_MODULE_SET")
    for name,raw in blobs.items():
        if (not isinstance(name,str) or not NAME.fullmatch(name)
                or not isinstance(raw,bytes)
                or not (0<=len(raw)<=600000 if name=="ops/__init__.py" else 1<=len(raw)<=600000)
                or not isinstance(reviewed_sha256[name],str)
                or not SHA.fullmatch(reviewed_sha256[name])
                or sha256(raw).hexdigest()!=reviewed_sha256[name]):
            raise ModuleStageHold("UNREVIEWED_MODULE_BYTES")
        if name=="ops/__init__.py":
            continue
        try:
            deps=_deps(ast.parse(raw.decode("utf-8"),filename=name))
        except (UnicodeError,SyntaxError) as exc:
            raise ModuleStageHold("INVALID_REVIEWED_PYTHON_SOURCE") from exc
        if not deps<=set(blobs):
            raise ModuleStageHold("MISSING_LOCAL_PYTHON_IMPORT")
    return sha256("\n".join(
        name+" "+reviewed_sha256[name] for name in sorted(blobs)
    ).encode()).hexdigest()


def read_source_bundle(
    source_root:Path, reviewed_sha256:dict[str,str],
) -> dict[str,bytes]:
    """No symlink/path traversal, root-only reviewed checkout.

    No Git fetch or branch lookup: caller MUST supply hashes accepted out
    of band for one exact reviewed Git commit. The hash manifest has to be
    stored off-host or signed independently; this function cannot certify
    its provenance.
    """
    if source_root!=SOURCE:
        raise ModuleStageHold("SOURCE_CHECKOUT_PATH_NOT_PINNED")
    _owned_dir(source_root)
    result={}
    if not isinstance(reviewed_sha256,dict) or len(reviewed_sha256)>180:
        raise ModuleStageHold("INVALID_REVIEWED_SHA_MANIFEST")
    for name in reviewed_sha256:
        if not NAME.fullmatch(name):
            raise ModuleStageHold("UNREVIEWED_MODULE_PATH")
        file=source_root.joinpath(*name.split("/"))
        if len(name.split("/"))==2:
            _owned_dir(file.parent)
        st=file.lstat()
        if (not stat.S_ISREG(st.st_mode) or st.st_uid!=0
                or st.st_mode & 0o022 or st.st_size>600000):
            raise ModuleStageHold("UNSAFE_MODULE_SOURCE")
        raw=file.read_bytes()
        if sha256(raw).hexdigest()!=reviewed_sha256[name]:
            raise ModuleStageHold("MODULE_SOURCE_HASH_DRIFT")
        result[name]=raw
    validate_module_bundle(result,reviewed_sha256)
    return result


def stage_module_bundle(
    *, blobs:dict[str,bytes],reviewed_sha256:dict[str,str],
    approved_bundle_digest:str, port:Callable[[Path,bytes],None] | None = None,
    release_enabled:bool=False,
    geteuid:Callable[[],int]=os.geteuid,
):
    """No overwrite. Must finish before PAM/guard installer preflight."""
    if (release_enabled is not True or geteuid()!=0 or port is None
            or not isinstance(approved_bundle_digest,str)
            or not SHA.fullmatch(approved_bundle_digest)):
        raise ModuleStageHold("EXPLICIT_REVIEWED_ROOT_MODULE_RELEASE_REQUIRED")
    digest=validate_module_bundle(blobs,reviewed_sha256)
    if digest!=approved_bundle_digest:
        raise ModuleStageHold("REVIEWED_MODULE_BUNDLE_DRIFT")
    _owned_dir(Path("/opt"),readable=True)
    if not TARGET.exists() and not TARGET.is_symlink():
        TARGET.mkdir(mode=0o755)
    _owned_dir(TARGET,readable=True)
    ops=TARGET/"ops"
    if not ops.exists() and not ops.is_symlink():
        ops.mkdir(mode=0o755)
    _owned_dir(ops,readable=True)
    for name in sorted(blobs):
        path=TARGET.joinpath(*name.split("/"))
        if path.exists() or path.is_symlink():
            raise ModuleStageHold("EXISTING_MODULE_REQUIRES_EXPLICIT_RECONCILIATION")
    for name in sorted(blobs):
        port(TARGET.joinpath(*name.split("/")),blobs[name])
    return digest


def create_public_root_module(path:Path, raw:bytes) -> None:
    """Owner root, readable by unprivileged per-UID DoH worker, never writable."""
    if (not isinstance(path,Path) or path.parent not in (TARGET,TARGET/"ops")
            or not NAME.fullmatch(path.relative_to(TARGET).as_posix())
            or not isinstance(raw,bytes)):
        raise ModuleStageHold("UNTRUSTED_DESTINATION_MODULE")
    _owned_dir(path.parent,readable=True)
    flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0)
    fd=os.open(path,flags,0o644)
    try:
        with os.fdopen(fd,"wb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        raise
    df=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(df)
    finally:os.close(df)
