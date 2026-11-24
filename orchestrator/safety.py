"""Scope guard — the pure, I/O-free safety layer.

Every command the model proposes passes through ``SafetyGuard.allow()`` before it can run.
It enforces four things, in order of precedence:

1. **Step cap** — no more than ``max_steps`` actions per run.
2. **Deny list** — destructive / host-affecting / egress-seeking substrings are refused
   (deny beats everything else).
3. **Scope lock** — any IP or hostname referenced must be inside the lab CIDR (plus loopback
   and known lab hostnames). Anything that looks like it reaches off the lab is refused.
4. **Allow list** — when ``default_deny`` is set, the command's binary must be explicitly
   allowed.

This module has NO side effects and NO imports from the rest of the package, so it can be
exhaustively unit-tested (see tests/test_safety.py).
"""

from __future__ import annotations

import ipaddress
import re
import shlex
from dataclasses import dataclass
from urllib.parse import urlparse

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# A token that looks like a public FQDN (has a dot and an alpha TLD), e.g. example.com
_FQDN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)

_ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

# Shell stage separators — a command is split on these so each pipeline/list stage can be
# attributed to its own binary. `||`/`&&` are listed before `|`/`&` so the longer form wins.
_SEGMENT_SPLIT_RE = re.compile(r"\|\||&&|;|\||&")

# A URL token (scheme://…). Its host is validated on its own; the rest (path, query) must not be
# re-scanned for bare hostnames, or a dotted filename like `/ftp/eastere.gg` looks like a host.
_URL_RE = re.compile(r"\w+://[^\s'\"]+")

# Tools that take a host/URL as an argument — only these trigger the bare-hostname scan,
# so `cat config.yaml` is never mistaken for a network call.
_NETWORK_TOOLS = {
    "nmap", "curl", "wget", "nc", "ncat", "netcat", "ssh", "scp", "sftp", "telnet", "ftp",
    "nslookup", "dig", "host", "ping", "ping6", "hydra", "sqlmap", "nikto", "whatweb",
    "gobuster", "ffuf", "wfuzz", "msfconsole", "msfvenom", "medusa", "enum4linux", "smbclient",
}
# Last labels that look like a TLD but are really file/code extensions — ignored by the
# bare-hostname scan to avoid false positives (e.g. notes.txt, config.yaml, index.html).
_IGNORED_TLDS = {
    "txt", "md", "log", "json", "yaml", "yml", "conf", "cfg", "ini", "py", "sh", "bash",
    "js", "ts", "css", "html", "htm", "xml", "csv", "tsv", "png", "jpg", "jpeg", "gif",
    "svg", "pdf", "zip", "gz", "tar", "db", "sqlite", "bak", "tmp", "out", "err", "pid",
    "sock", "lock", "pem", "key", "crt", "php", "jsp", "asp", "aspx",
}


@dataclass(frozen=True)
class Decision:
    permitted: bool
    reason: str


class SafetyGuard:
    def __init__(
        self,
        lab_cidr: str,
        allow: list[str] | None = None,
        deny: list[str] | None = None,
        max_steps: int = 40,
        default_deny: bool = True,
        known_hosts: set[str] | None = None,
    ) -> None:
        self.lab_network = ipaddress.ip_network(lab_cidr, strict=False)
        self.allow = {a.lower() for a in (allow or [])}
        self.deny = [d.lower() for d in (deny or [])]
        self.max_steps = max_steps
        self.default_deny = default_deny
        # Hostnames that resolve *inside* the lab and are therefore in-scope.
        self.known_hosts = {h.lower() for h in (known_hosts or set())} | {"localhost"}
        self._allowed_networks = [
            self.lab_network,
            ipaddress.ip_network("127.0.0.0/8"),
        ]

    # ----------------------------------------------------------------- public API

    @classmethod
    def from_config(cls, cfg) -> SafetyGuard:  # cfg: orchestrator.config.LabConfig
        known = {
            cfg.attacker.container_name,
            cfg.target.container_name,
            "target",
            "attacker",
        }
        return cls(
            lab_cidr=cfg.deployment.lab_cidr,
            allow=cfg.safety.allow,
            deny=cfg.safety.deny,
            max_steps=cfg.run.max_steps,
            default_deny=cfg.safety.default_deny,
            known_hosts=known,
        )

    def allow_command(self, command: str, step: int | None = None) -> Decision:
        """Return a Decision for *command*. ``step`` (1-based) enables the step-cap check."""
        if step is not None and step > self.max_steps:
            return Decision(False, f"step cap reached ({step} > max_steps={self.max_steps})")

        cmd = (command or "").strip()
        if not cmd:
            return Decision(False, "empty command")

        lowered = cmd.lower()

        # (2) Deny list — highest precedence after the cap.
        for pattern in self.deny:
            if pattern and pattern in lowered:
                return Decision(False, f"denied pattern: {pattern!r}")

        # (3) Scope lock — IPs.
        for raw_ip in _IPV4_RE.findall(cmd):
            try:
                addr = ipaddress.ip_address(raw_ip)
            except ValueError:
                continue  # not actually an address (e.g. a version string octet > 255)
            if not any(addr in net for net in self._allowed_networks):
                return Decision(False, f"out-of-scope address: {raw_ip}")

        # Determine the binary up front — it gates both the host scan and the allow list.
        binary = self._binary_of(cmd)
        if binary is None:
            return Decision(False, "could not determine command binary")

        # (3) Scope lock — hostnames (URLs always; bare FQDNs only for network tools).
        host_violation = self._check_hosts(cmd)
        if host_violation is not None:
            return Decision(False, host_violation)

        # (4) Allow list — binary gating.
        if self.default_deny and binary.lower() not in self.allow:
            return Decision(False, f"binary not in allow list: {binary!r}")

        return Decision(True, "ok")

    # ----------------------------------------------------------------- internals

    def _check_hosts(self, cmd: str) -> str | None:
        # Hosts inside URLs are unambiguous egress intent — always checked, across the whole line.
        for token in self._tokens(cmd):
            if "://" in token:
                host = (urlparse(token).hostname or "").lower()
                if not host:
                    continue
                if not self._host_in_scope(host):
                    return f"out-of-scope host in URL: {host}"
        # Bare FQDNs (e.g. `nslookup evil.example.com`) only matter as *network targets*, so scan
        # only the pipeline segments whose OWN binary is a network tool. This keeps a later stage
        # like `... | python3 -c "d=json.load(sys.stdin)"` from being misread as a call to a host
        # named `json.load` — the previous whole-command scan, gated on the first binary alone,
        # flagged exactly that and wasted the step.
        for segment in self._segments(cmd):
            seg_binary = self._binary_of(segment)
            if seg_binary is None or seg_binary.lower() not in _NETWORK_TOOLS:
                continue
            # Blank out URL tokens (keeping offsets) before the bare-FQDN scan: a URL's host is
            # already validated above, and a dotted *filename* in the URL path (e.g.
            # `/ftp/eastere.gg`) is not a network target — scanning it flagged `eastere.gg` as an
            # out-of-scope host and wasted the step in the live Flash-Next run.
            scan = _URL_RE.sub(lambda m: " " * len(m.group(0)), segment)
            for m in _FQDN_RE.finditer(scan):
                # Skip an email-style domain inside a payload (e.g. -d "email=admin@juiceshop.com"):
                # the preceding '@' means it's a login value, not a network target. Real egress
                # hosts are still caught — the URL scan above handles `://host`, and a bare
                # out-of-scope FQDN (e.g. `nslookup evil.example.com`) has no leading '@'.
                if m.start() > 0 and scan[m.start() - 1] == "@":
                    continue
                host = m.group(0).lower()
                if host.rsplit(".", 1)[-1] in _IGNORED_TLDS:
                    continue
                if not self._host_in_scope(host):
                    return f"out-of-scope host: {host}"
        return None

    def _host_in_scope(self, host: str) -> bool:
        if host in self.known_hosts:
            return True
        # An IP literal host is handled by the IP scope check already.
        try:
            addr = ipaddress.ip_address(host)
            return any(addr in net for net in self._allowed_networks)
        except ValueError:
            pass
        # Unknown DNS name -> treat as potential egress -> out of scope.
        return False

    @staticmethod
    def _segments(cmd: str) -> list[str]:
        """Split a command into shell stages (pipeline / list) so each can be attributed to its
        own binary. Operators inside quotes are rarely stage separators for the web commands this
        lab issues; the IP, deny, and `://` URL checks still scan the whole line regardless."""
        return [s for s in _SEGMENT_SPLIT_RE.split(cmd) if s.strip()]

    @staticmethod
    def _tokens(cmd: str) -> list[str]:
        try:
            return shlex.split(cmd)
        except ValueError:
            return cmd.split()

    def _binary_of(self, cmd: str) -> str | None:
        """First real binary token, skipping ENV=val assignments and a leading sudo."""
        for tok in self._tokens(cmd):
            if _ENV_ASSIGN_RE.match(tok):
                continue
            if tok in ("sudo", "command", "env"):
                continue
            # Strip a path prefix: /usr/bin/nmap -> nmap
            return tok.rsplit("/", 1)[-1]
        return None
