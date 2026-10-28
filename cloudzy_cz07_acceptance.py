"""Independent post-migration CZ07 witness, read-only and fail-closed.

The NVL bot NEVER creates or signs acceptance evidence. A separate trusted
observer must actually verify SSH CREATE, RENEW and the affected ISP customer
path and deliver one root-readable, MAC-authenticated receipt per job.

A signature authenticates the configured producer, not physical network truth.
Deployers must validate the producer independently before enabling this gate.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import time

JOB_RE = re.compile(r"[0-9a-f]{32}\Z")
REF_RE = re.compile(r"[A-Za-z0-9_.:-]{8,96}\Z")
SOURCE_RE = re.compile(r"[A-Za-z0-9_.:-]{4,64}\Z")
MAX_AGE = 24 * 60 * 60
MAX_BYTES = 8192


@dataclass(frozen=True)
class AcceptanceReview:
    ready: bool
    code: str
    create_ref: str = ""
    renew_ref: str = ""
    client_ref: str = ""
    fingerprint: str = ""

    @property
    def refs(self):
        return self.create_ref, self.renew_ref, self.client_ref


class IndependentCZ07Witness:
    """Read-only authenticated proof adapter, never an operator form."""

    def __init__(self, directory: str, key: bytes, *, now=time.time):
        self.directory = Path(directory)
        self.key = key
        self.now = now

    @classmethod
    def from_environment(cls, *, now=time.time):
        directory = os.environ.get("NVL_CZ07_TRUSTED_EVIDENCE_DIR", "")
        key = os.environ.get("NVL_CZ07_TRUSTED_EVIDENCE_KEY", "")
        if not directory or len(key.encode("utf-8")) < 32:
            return None
        return cls(directory, key.encode("utf-8"), now=now)

    @staticmethod
    def _deny(code):
        return AcceptanceReview(False, code)

    def _read(self, job_id):
        directory = self.directory
        if not directory.is_absolute():
            raise ValueError("EVIDENCE_DIRECTORY_NOT_ABSOLUTE")
        ds = directory.lstat()
        if not stat.S_ISDIR(ds.st_mode) or ds.st_mode & 0o022:
            raise ValueError("EVIDENCE_DIRECTORY_UNSAFE")
        # Job ID is strictly hex; no user-originated path is interpolated.
        path = directory / (job_id + ".json")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(path), flags)
        try:
            fs = os.fstat(fd)
            if (not stat.S_ISREG(fs.st_mode) or fs.st_mode & 0o077
                    or fs.st_size > MAX_BYTES):
                raise ValueError("EVIDENCE_FILE_UNSAFE")
            with os.fdopen(fd, "rb", closefd=False) as f:
                raw = f.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise ValueError("EVIDENCE_FILE_TOO_LARGE")
        finally:
            os.close(fd)
        return raw

    def review(self, job):
        if (not isinstance(job, dict) or not JOB_RE.fullmatch(str(job.get("id", "")))
                or job.get("status") != "VERIFYING"
                or type(job.get("total")) is not int
                or type(job.get("moved")) is not int
                or job["total"] != job["moved"]
                or job["total"] < 0):
            return self._deny("EVIDENCE_JOB_NOT_ELIGIBLE")
        try:
            target = str(ipaddress.IPv4Address(job["target"]))
        except (ValueError, KeyError):
            return self._deny("EVIDENCE_TARGET_INVALID")
        if not isinstance(self.key, bytes) or len(self.key) < 32:
            return self._deny("TRUSTED_WITNESS_NOT_CONFIGURED")
        try:
            raw = self._read(job["id"])
        except FileNotFoundError:
            return self._deny("TRUSTED_WITNESS_NOT_RECEIVED")
        except (OSError, ValueError):
            return self._deny("TRUSTED_WITNESS_FILE_INVALID")
        try:
            envelope = json.loads(raw)
            if not isinstance(envelope, dict):
                raise ValueError
            signature = envelope.get("signature")
            if not isinstance(signature, str) or not re.fullmatch(r"[0-9a-f]{64}", signature):
                raise ValueError
            content = dict(envelope)
            del content["signature"]
            canonical = json.dumps(content, sort_keys=True, separators=(",", ":"),
                                   ensure_ascii=False).encode("utf-8")
            expected = hmac.new(self.key, canonical, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(signature, expected):
                return self._deny("TRUSTED_WITNESS_SIGNATURE_INVALID")
            if (content.get("version") != 1 or content.get("job_id") != job["id"]
                    or content.get("target") != target
                    or content.get("producer") != "independent-customer-observer"
                    or not SOURCE_RE.fullmatch(str(content.get("source_id", "")))):
                return self._deny("TRUSTED_WITNESS_IDENTITY_MISMATCH")
            issued = content.get("issued_at")
            now = int(self.now())
            if (type(issued) is not int or issued < int(job["updated_at"])
                    or issued > now + 60 or now - issued > MAX_AGE):
                return self._deny("TRUSTED_WITNESS_STALE")
            refs = []
            for kind in ("create", "renew", "client"):
                value = content.get(kind)
                if (not isinstance(value, dict) or value.get("verified") is not True
                        or value.get("target") != target
                        or not REF_RE.fullmatch(str(value.get("reference", "")))
                        or type(value.get("observed_at")) is not int
                        or not int(job["updated_at"]) <= value["observed_at"] <= issued):
                    return self._deny("TRUSTED_WITNESS_INCOMPLETE")
                if kind in ("create", "renew"):
                    if value.get("ssh_login_success") is not True:
                        return self._deny("TRUSTED_WITNESS_INCOMPLETE")
                else:
                    if (not isinstance(value.get("isp"), str) or
                            not 3 <= len(value["isp"]) <= 60 or
                            value.get("ssh_handshake") is not True or
                            value.get("ssh_auth") is not True or
                            value.get("traffic_passed") is not True):
                        return self._deny("TRUSTED_WITNESS_INCOMPLETE")
                refs.append(value["reference"])
            if len(set(refs)) != 3:
                return self._deny("TRUSTED_WITNESS_DUPLICATE_REFS")
            return AcceptanceReview(True, "TRUSTED_WITNESS_VERIFIED",
                                    *refs, hashlib.sha256(raw).hexdigest())
        except (ValueError, TypeError, KeyError, UnicodeDecodeError, OverflowError):
            return self._deny("TRUSTED_WITNESS_FORMAT_INVALID")

    def verify(self, job, *, create_ref, renew_ref, client_ref, fingerprint):
        proof = self.review(job)
        return bool(proof.ready and proof.refs ==
                    (create_ref, renew_ref, client_ref)
                    and hmac.compare_digest(proof.fingerprint, fingerprint))
