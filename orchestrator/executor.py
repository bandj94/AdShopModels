"""Execution channel — the only way the agent reaches into the lab.

One interface, three implementations, so the agent loop is identical across deployment modes:

- DockerExecExecutor : host runs `docker exec <container> sh -lc "<cmd>"`  (this build's default)
- SSHExecutor        : host runs `ssh -i <key> <user>@<host> "<cmd>"`      (future VM mode)
- LocalExecutor      : runs in the current shell                           (dev/testing only)

Every call is bounded by a timeout and returns a structured Observation that the logger and
the memory compactor consume.
"""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass

from .config import LabConfig

_MAX_OBS_CHARS = 8000


@dataclass
class Observation:
    command: str
    exit_code: int
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool = False

    @property
    def text(self) -> str:
        """Combined, truncated output for the model and the transcript."""
        body = self.stdout
        if self.stderr.strip():
            body += ("\n[stderr]\n" + self.stderr)
        if self.timed_out:
            body += f"\n[timed out after {self.duration_s:.0f}s]"
        if len(body) > _MAX_OBS_CHARS:
            body = body[:_MAX_OBS_CHARS] + f"\n...[truncated {len(body) - _MAX_OBS_CHARS} chars]"
        return body


class Executor:
    """Interface. Implementations build an argv and delegate to _spawn()."""

    def run(self, command: str, timeout: int) -> Observation:  # pragma: no cover - abstract
        raise NotImplementedError

    @staticmethod
    def _spawn(argv: list[str], command: str, timeout: int) -> Observation:
        start = time.monotonic()
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            return Observation(
                command=command,
                exit_code=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                duration_s=time.monotonic() - start,
            )
        except subprocess.TimeoutExpired as e:
            return Observation(
                command=command,
                exit_code=124,
                stdout=(e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or ""),
                stderr=(e.stderr or b"").decode(errors="replace") if isinstance(e.stderr, bytes) else (e.stderr or ""),
                duration_s=time.monotonic() - start,
                timed_out=True,
            )
        except FileNotFoundError as e:
            return Observation(
                command=command,
                exit_code=127,
                stdout="",
                stderr=f"executor could not launch: {e}",
                duration_s=time.monotonic() - start,
            )


class DockerExecExecutor(Executor):
    def __init__(self, container: str) -> None:
        self.container = container

    def run(self, command: str, timeout: int) -> Observation:
        argv = ["docker", "exec", self.container, "sh", "-lc", command]
        return self._spawn(argv, command, timeout)


class SSHExecutor(Executor):
    def __init__(self, host: str, user: str = "kali", key_path: str = "keys/lab", port: int = 22) -> None:
        self.host, self.user, self.key_path, self.port = host, user, key_path, port

    def run(self, command: str, timeout: int) -> Observation:
        argv = [
            "ssh", "-i", self.key_path, "-p", str(self.port),
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=10",
            f"{self.user}@{self.host}", command,
        ]
        return self._spawn(argv, command, timeout)


class LocalExecutor(Executor):
    """Runs on the host shell. Dev/testing only — NOT isolated."""

    def run(self, command: str, timeout: int) -> Observation:
        argv = ["sh", "-lc", command]
        return self._spawn(argv, command, timeout)


def make_executor(cfg: LabConfig) -> Executor:
    """Pick the executor implied by the active profile."""
    if cfg.attacker.kind == "container":
        return DockerExecExecutor(cfg.attacker.container_name)
    if cfg.attacker.kind == "vm":
        return SSHExecutor(cfg.attacker.ip)
    raise ValueError(f"unknown attacker.kind: {cfg.attacker.kind!r}")
