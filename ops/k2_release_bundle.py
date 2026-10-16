"""Build/verify a pinned source-only handoff. Never installs or enables K2.

Build reads immutable Git objects, not the working tree or live /root. Verify
is read-only. Deployment and rollback remain manual with the owner over SSH.
"""
from __future__ import annotations

import argparse
import ast
from hashlib import sha256
import io
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile


def _git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args])


def _included(name):
    path = PurePosixPath(name)
    return (not path.is_absolute() and ".." not in path.parts
            and not any(part.startswith(".") for part in path.parts)
            and (path.suffix in (".py", ".sh") or name == "requirements.txt"
                 or name in ("docs/K2_PHASE3_TELEGRAM_UX_2026-10-16.md",
                             "docs/K2_PHASE3_MANUAL_RELEASE_2026-10-16.md")))


def _pins(source):
    tree = ast.parse(source)
    for node in tree.body:
        if (isinstance(node, ast.Assign) and any(isinstance(n, ast.Name)
                and n.id == "PINNED_SOURCE_FILES" for n in node.targets)
                and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Name)
                and node.value.func.id == "frozenset"):
            return frozenset(ast.literal_eval(node.value.args[0]))
    raise ValueError("RELEASE_PIN_SET_MISSING")


def build(repo: Path, commit: str, output: Path):
    if not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise ValueError("EXACT_COMMIT_REQUIRED")
    resolved = _git(repo, "rev-parse", "--verify", commit+"^{commit}").decode().strip()
    if resolved != commit:
        raise ValueError("COMMIT_MISMATCH")
    blobs = {}
    for record in _git(repo, "ls-tree", "-rz", commit).split(b"\0"):
        if not record:
            continue
        meta, raw_name = record.split(b"\t", 1)
        name = raw_name.decode("utf-8")
        if not _included(name):
            continue
        mode, kind, oid = meta.decode().split()
        if kind != "blob" or mode not in ("100644", "100755"):
            raise ValueError("SOURCE_SYMLINK_OR_NONREGULAR")
        blobs[name] = _git(repo, "cat-file", "blob", oid)
    required = _pins(blobs["edge_egress_k2_m4_root_worker.py"])
    if not required <= blobs.keys():
        raise ValueError("RELEASE_SOURCE_INCOMPLETE")
    hashes = {name: sha256(raw).hexdigest() for name, raw in sorted(blobs.items())}
    release = {"git_sha": commit, "files": {name: hashes[name] for name in sorted(required)}}
    blobs["release.json"] = json.dumps(release, sort_keys=True).encode()+b"\n"
    hashes["release.json"] = sha256(blobs["release.json"]).hexdigest()
    blobs["package.json"] = json.dumps({"git_sha": commit, "files": hashes}, sort_keys=True).encode()+b"\n"
    # Exclusive creation prevents silently replacing an earlier reviewed bundle.
    with output.open("xb") as target, tarfile.open(fileobj=target, mode="w") as archive:
        for name, raw in sorted(blobs.items()):
            item = tarfile.TarInfo(name)
            item.size = len(raw)
            item.mode = 0o600
            item.mtime = 0
            archive.addfile(item, io.BytesIO(raw))
    return sha256(output.read_bytes()).hexdigest(), sha256(blobs["package.json"]).hexdigest()


def verify(directory: Path, commit: str, package_sha256: str):
    """Verify an already-extracted private staging directory, no mutations."""
    if (not re.fullmatch(r"[a-f0-9]{40}", commit)
            or not re.fullmatch(r"[a-f0-9]{64}", package_sha256)
            or directory.is_symlink() or not directory.is_dir()):
        raise ValueError("RELEASE_VERIFY_INPUT_INVALID")
    manifest = directory / "package.json"
    if manifest.is_symlink() or sha256(manifest.read_bytes()).hexdigest() != package_sha256:
        raise ValueError("PACKAGE_MANIFEST_HASH_MISMATCH")
    data = json.loads(manifest.read_bytes())
    if (set(data) != {"git_sha", "files"} or data["git_sha"] != commit
            or not isinstance(data["files"], dict)):
        raise ValueError("PACKAGE_SCOPE_MISMATCH")
    for name, expected in data["files"].items():
        if name != "release.json" and not _included(name):
            raise ValueError("PACKAGE_PATH_INVALID")
        path = directory
        for part in PurePosixPath(name).parts:
            path = path / part
            if path.is_symlink():
                raise ValueError("PACKAGE_SYMLINK")
        if not path.is_file() or sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError("PACKAGE_CONTENT_MISMATCH")
    expected_files=set(data['files'])|{'package.json'}
    actual_files=set()
    for item in directory.rglob('*'):
        if item.is_symlink():
            raise ValueError('PACKAGE_SYMLINK')
        if item.is_file():
            actual_files.add(item.relative_to(directory).as_posix())
        elif not item.is_dir():
            raise ValueError('PACKAGE_NONREGULAR')
    if actual_files != expected_files:
        raise ValueError('PACKAGE_UNEXPECTED_FILES')
    release = json.loads((directory / "release.json").read_bytes())
    required = _pins((directory / "edge_egress_k2_m4_root_worker.py").read_bytes())
    if (set(release) != {"git_sha", "files"} or release["git_sha"] != commit
            or set(release["files"]) != required
            or any(data["files"].get(n) != release["files"][n] for n in required)):
        raise ValueError("ROOT_RELEASE_PIN_MISMATCH")
    return len(data["files"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    builder = sub.add_parser("build")
    builder.add_argument("--repo", type=Path, required=True)
    builder.add_argument("--commit", required=True)
    builder.add_argument("--output", type=Path, required=True)
    checker = sub.add_parser("verify")
    checker.add_argument("--directory", type=Path, required=True)
    checker.add_argument("--commit", required=True)
    checker.add_argument("--package-sha256", required=True,
                         help="SHA256 of package.json, pinned before host transfer")
    args = parser.parse_args()
    if args.action == "build":
        digest, manifest_digest = build(args.repo, args.commit, args.output)
        print("BUNDLE_SHA256="+digest)
        print("PACKAGE_MANIFEST_SHA256="+manifest_digest)
    else:
        count = verify(args.directory, args.commit, args.package_sha256)
        print(f"SOURCE_VERIFIED={args.commit} FILES={count}")


if __name__ == "__main__":
    main()
