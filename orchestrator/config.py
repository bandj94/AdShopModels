"""Load and validate the active lab profile.

Fails CLOSED: if egress is enabled, scope is malformed, or a lab host sits outside the
lab CIDR, loading raises ``ConfigError`` and the agent never starts.

Environment overrides (handy for quick model swaps without editing YAML):
    LLM_ENDPOINT, LLM_MODEL, LLM_TEMPERATURE, LLM_MAX_TOKENS
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


class ConfigError(ValueError):
    """Raised when a profile is missing, malformed, or unsafe."""


# --------------------------------------------------------------------------- models


@dataclass(frozen=True)
class LLMConfig:
    endpoint: str
    model: str
    temperature: float = 0.4
    max_tokens: int = 2048


@dataclass(frozen=True)
class AttackerConfig:
    kind: str                 # container | vm
    ip: str
    llm: LLMConfig
    container_name: str = "lab-attacker"


@dataclass(frozen=True)
class TargetConfig:
    kind: str                 # juice-shop | dvwa | ...
    provider: str             # docker | vm
    ip: str
    container_name: str = "lab-target"


@dataclass(frozen=True)
class BlueTeamConfig:
    siem: str = "wazuh"
    nids: str = "suricata"
    endpoint_monitoring: str = "auditd"


@dataclass(frozen=True)
class RunConfig:
    goal: str
    max_steps: int = 40
    step_timeout_s: int = 120
    max_wall_clock_s: int = 3600
    stop_on_goal: bool = True


@dataclass(frozen=True)
class SafetyConfig:
    default_deny: bool = True
    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class DeploymentConfig:
    mode: str                 # docker | vm | hybrid
    lab_cidr: str
    egress: bool = False


@dataclass(frozen=True)
class LabConfig:
    deployment: DeploymentConfig
    attacker: AttackerConfig
    target: TargetConfig
    blueteam: BlueTeamConfig
    run: RunConfig
    safety: SafetyConfig

    @property
    def lab_network(self) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
        return ipaddress.ip_network(self.deployment.lab_cidr, strict=False)


# --------------------------------------------------------------------------- loading

VALID_MODES = {"docker", "vm", "hybrid"}


def _require(d: dict[str, Any], key: str, where: str) -> Any:
    if key not in d or d[key] is None:
        raise ConfigError(f"missing required key '{key}' in {where}")
    return d[key]


def _env_float(name: str, default: float) -> float:
    v = os.getenv(name)
    return float(v) if v not in (None, "") else default


def _env_int(name: str, default: int) -> int:
    v = os.getenv(name)
    return int(v) if v not in (None, "") else default


def load_and_validate(path: str | Path) -> LabConfig:
    """Parse the YAML profile at *path*, apply env overrides, validate, return a LabConfig."""
    p = Path(path)
    if not p.exists():
        raise ConfigError(
            f"config not found: {p}\n"
            "Copy a profile first, e.g. "
            "`Copy-Item config\\profiles\\docker-web.yaml config\\config.yaml`"
        )

    raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}

    dep_raw = _require(raw, "deployment", "config")
    att_raw = _require(raw, "attacker", "config")
    tgt_raw = _require(raw, "target", "config")
    run_raw = _require(raw, "run", "config")
    llm_raw = _require(att_raw, "llm", "attacker")

    llm = LLMConfig(
        endpoint=os.getenv("LLM_ENDPOINT") or _require(llm_raw, "endpoint", "attacker.llm"),
        model=os.getenv("LLM_MODEL") or _require(llm_raw, "model", "attacker.llm"),
        temperature=_env_float("LLM_TEMPERATURE", float(llm_raw.get("temperature", 0.4))),
        max_tokens=_env_int("LLM_MAX_TOKENS", int(llm_raw.get("max_tokens", 2048))),
    )

    cfg = LabConfig(
        deployment=DeploymentConfig(
            mode=_require(dep_raw, "mode", "deployment"),
            lab_cidr=_require(dep_raw, "lab_cidr", "deployment"),
            egress=bool(dep_raw.get("egress", False)),
        ),
        attacker=AttackerConfig(
            kind=_require(att_raw, "kind", "attacker"),
            ip=_require(att_raw, "ip", "attacker"),
            container_name=att_raw.get("container_name", "lab-attacker"),
            llm=llm,
        ),
        target=TargetConfig(
            kind=_require(tgt_raw, "kind", "target"),
            provider=tgt_raw.get("provider", "docker"),
            ip=_require(tgt_raw, "ip", "target"),
            container_name=tgt_raw.get("container_name", "lab-target"),
        ),
        blueteam=BlueTeamConfig(**(raw.get("blueteam") or {})),
        run=RunConfig(
            goal=_require(run_raw, "goal", "run"),
            max_steps=int(run_raw.get("max_steps", 40)),
            step_timeout_s=int(run_raw.get("step_timeout_s", 120)),
            max_wall_clock_s=int(run_raw.get("max_wall_clock_s", 3600)),
            stop_on_goal=bool(run_raw.get("stop_on_goal", True)),
        ),
        safety=SafetyConfig(**(raw.get("safety") or {})),
    )

    _validate(cfg)
    return cfg


def _validate(cfg: LabConfig) -> None:
    # 1) Fail closed on egress — this is the single most important invariant.
    if cfg.deployment.egress:
        raise ConfigError(
            "deployment.egress is true — refusing to start. The lab must have NO egress. "
            "Set egress: false (see SAFETY.md)."
        )

    # 2) Deployment mode.
    if cfg.deployment.mode not in VALID_MODES:
        raise ConfigError(
            f"deployment.mode '{cfg.deployment.mode}' invalid; must be one of {sorted(VALID_MODES)}"
        )

    # 3) CIDR parses, and lab hosts fall inside it.
    try:
        net = cfg.lab_network
    except ValueError as e:
        raise ConfigError(f"deployment.lab_cidr invalid: {e}") from e

    for label, ip in (("attacker.ip", cfg.attacker.ip), ("target.ip", cfg.target.ip)):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError as e:
            raise ConfigError(f"{label} is not a valid IP: {ip} ({e})") from e
        if addr not in net:
            raise ConfigError(f"{label} {ip} is outside lab_cidr {cfg.deployment.lab_cidr}")

    # 4) Model endpoint sanity.
    if not cfg.attacker.llm.endpoint.startswith(("http://", "https://")):
        raise ConfigError(
            f"attacker.llm.endpoint must be an http(s) URL, got: {cfg.attacker.llm.endpoint}"
        )

    # 5) Positive run bounds (no unbounded autonomy).
    for label, val in (
        ("run.max_steps", cfg.run.max_steps),
        ("run.step_timeout_s", cfg.run.step_timeout_s),
        ("run.max_wall_clock_s", cfg.run.max_wall_clock_s),
    ):
        if val <= 0:
            raise ConfigError(f"{label} must be > 0, got {val}")
