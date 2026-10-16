"""K2 A3: conservative read-only audit of privileged legacy bot surfaces.

Nothing executes, imports, polls Telegram, opens a database or changes any
unit. Static AST matches are review leads, not an authorization to drop root.
Source additions/indirections/dynamic imports require manual verification.
"""
from __future__ import annotations

from dataclasses import dataclass
import ast
from hashlib import sha256
from pathlib import Path
import re

A3_PRIVILEGE_SPLIT_APPROVED = False

# Explicitly privileged/dynamic execution primitives, not harmless logging.
_ROOT_CALLS = frozenset((
    "os.system","os.chown","os.chmod","os.setuid","os.setgid",
    "os.kill","os.execv","os.execve","os.popen","subprocess.run",
    "subprocess.Popen","subprocess.call","subprocess.check_call",
    "subprocess.check_output","subprocess.getoutput",
    "subprocess.getstatusoutput","pty.spawn","paramiko.SSHClient",
    "asyncio.create_subprocess_exec","asyncio.create_subprocess_shell",
    "eval","exec","__import__",
))
_SUSPECT_TERMS = re.compile(
    r"\b(?:sudo|systemctl|iptables|ip6tables|wg-quick|wg |sshd|"
    r"sshpass|chpasswd|useradd|userdel|usermod|pkill|nft |ip rule|"
    r"ip route|/etc/pam\.d|/etc/shadow|/etc/ssh/)\b"
)


@dataclass(frozen=True)
class PrivilegedCallsite:
    function: str
    line: int
    sink: str
    risk: str


@dataclass(frozen=True)
class PrivilegeAuditReport:
    source_sha256: str
    callsites: tuple[PrivilegedCallsite, ...]
    dynamic_calls: int
    functions_scanned: int
    # An AST inventory never proves full privilege-split coverage.
    ready_for_nonroot: bool = False


class A3AuditHold(ValueError):
    pass


def scan_legacy_bot_source(raw: bytes) -> PrivilegeAuditReport:
    if not isinstance(raw,bytes) or not 0 < len(raw) <= 3_000_000:
        raise A3AuditHold("A3_SOURCE_UNAVAILABLE")
    try:
        source=raw.decode("utf-8",errors="strict")
        tree=ast.parse(source)
    except (UnicodeError,SyntaxError,ValueError) as exc:
        raise A3AuditHold("A3_SOURCE_CANNOT_BE_AUDITED") from exc
    hits=[]
    total=0
    dynamic=0

    def identifier(node):
        if isinstance(node,ast.Name):
            return node.id
        if isinstance(node,ast.Attribute):
            prefix=identifier(node.value)
            return prefix+"."+node.attr if prefix else node.attr
        return ""

    class Visitor(ast.NodeVisitor):
        def __init__(self):
            self.stack=[]
            # Resolve static import aliases before deciding whether a call is
            # privileged. Without this, 'from subprocess import run as r'
            # and 'import os as operating_system' can evade the A3 inventory.
            # This remains flow-insensitive: an alias hit is a review lead,
            # never proof of a safe or authorized non-root cutover.
            self.aliases=[{}]

        def visit_Import(self,node):
            for entry in node.names:
                local=entry.asname or entry.name.split(".")[0]
                original=entry.name if entry.asname else entry.name.split(".")[0]
                self.aliases[-1][local]=original

        def visit_ImportFrom(self,node):
            if node.level != 0 or not node.module:
                return
            for entry in node.names:
                if entry.name=="*":
                    name=".".join(self.stack) if self.stack else "<module>"
                    hits.append(PrivilegedCallsite(
                        name,node.lineno,node.module+".*","manual-review"))
                    continue
                local=entry.asname or entry.name
                self.aliases[-1][local]=node.module+"."+entry.name

        def resolve(self,target):
            first,sep,rest=target.partition(".")
            for aliases in reversed(self.aliases):
                if first in aliases:
                    return aliases[first]+(sep+rest if sep else "")
            return target

        def visit_FunctionDef(self,node):
            nonlocal total
            total+=1
            self.stack.append(node.name)
            self.aliases.append({})
            self.generic_visit(node)
            self.aliases.pop()
            self.stack.pop()

        visit_AsyncFunctionDef=visit_FunctionDef

        def visit_Call(self,node):
            nonlocal dynamic
            target=self.resolve(identifier(node.func))
            name=".".join(self.stack) if self.stack else "<module>"
            if target in _ROOT_CALLS:
                hits.append(PrivilegedCallsite(name,node.lineno,target,"root-or-command"))
            elif (target.endswith(".run") or target.endswith(".execute")
                  or target.endswith(".command") or target.endswith(".connect")
                  or target in ("getattr","setattr","compile")):
                dynamic+=1
                hits.append(PrivilegedCallsite(name,node.lineno,target or "dynamic","manual-review"))
            for child in node.args:
                if isinstance(child,(ast.Constant,ast.JoinedStr)):
                    literal=child.value if isinstance(child,ast.Constant) else ""
                    if isinstance(literal,str) and _SUSPECT_TERMS.search(literal):
                        hits.append(PrivilegedCallsite(name,node.lineno,target or "literal","root-command-literal"))
            self.generic_visit(node)

    Visitor().visit(tree)
    unique={(h.function,h.line,h.sink,h.risk):h for h in hits}
    ordered=tuple(sorted(unique.values(),key=lambda x:(x.line,x.sink)))
    return PrivilegeAuditReport(
        sha256(raw).hexdigest(),ordered,dynamic,total,False,
    )


def audit_legacy_bot_file(path: Path) -> PrivilegeAuditReport:
    # Offline opt-in tool only. A malicious symlink or huge source is HOLD.
    if not isinstance(path,Path) or not path.is_file() or path.is_symlink():
        raise A3AuditHold("A3_SOURCE_PATH_UNTRUSTED")
    return scan_legacy_bot_source(path.read_bytes())
