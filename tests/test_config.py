"""Tests for the fail-closed config loader and the ATT&CK mapper."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

from orchestrator import mitre
from orchestrator.config import ConfigError, load_and_validate

BASE: dict = {
    "deployment": {"mode": "docker", "lab_cidr": "10.13.37.0/24", "egress": False},
    "attacker": {
        "kind": "container",
        "ip": "10.13.37.10",
        "container_name": "lab-attacker",
        "llm": {"endpoint": "http://localhost:11434/v1", "model": "qwen3:8b"},
    },
    "target": {"kind": "juice-shop", "provider": "docker", "ip": "10.13.37.20"},
    "run": {"goal": "read the flag", "max_steps": 40, "step_timeout_s": 120},
    "safety": {"default_deny": True, "allow": ["nmap"], "deny": ["reboot"]},
}


@pytest.fixture(autouse=True)
def _clear_llm_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("LLM_ENDPOINT", "LLM_MODEL", "LLM_TEMPERATURE", "LLM_MAX_TOKENS"):
        monkeypatch.delenv(var, raising=False)


def _write(tmp_path: Path, cfg: dict) -> Path:
    p = tmp_path / "config.yaml"
    p.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    return p


def test_valid_profile_loads(tmp_path: Path) -> None:
    cfg = load_and_validate(_write(tmp_path, BASE))
    assert cfg.deployment.mode == "docker"
    assert cfg.attacker.llm.model == "qwen3:8b"
    assert str(cfg.lab_network) == "10.13.37.0/24"
    assert cfg.run.max_steps == 40


def test_env_override_model(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LLM_MODEL", "llama3.1:8b")
    cfg = load_and_validate(_write(tmp_path, BASE))
    assert cfg.attacker.llm.model == "llama3.1:8b"


@pytest.mark.parametrize(
    "mutate,needle",
    [
        (lambda c: c["deployment"].__setitem__("egress", True), "egress"),
        (lambda c: c["attacker"].__setitem__("ip", "192.168.9.9"), "outside lab_cidr"),
        (lambda c: c["deployment"].__setitem__("lab_cidr", "not-a-cidr"), "lab_cidr"),
        (lambda c: c["deployment"].__setitem__("mode", "banana"), "mode"),
        (lambda c: c["attacker"]["llm"].__setitem__("endpoint", "ftp://x"), "http"),
        (lambda c: c["run"].__setitem__("max_steps", 0), "max_steps"),
        (lambda c: c["attacker"]["llm"].pop("model"), "model"),
    ],
)
def test_invalid_profiles_fail_closed(tmp_path: Path, mutate, needle: str) -> None:
    cfg = copy.deepcopy(BASE)
    mutate(cfg)
    with pytest.raises(ConfigError) as exc:
        load_and_validate(_write(tmp_path, cfg))
    assert needle in str(exc.value)


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError) as exc:
        load_and_validate(tmp_path / "nope.yaml")
    assert "not found" in str(exc.value)


# --- ATT&CK mapper ---------------------------------------------------------------


def test_mitre_classifies_nmap_and_sqli() -> None:
    assert "T1046" in mitre.classify("nmap -sV 10.13.37.20").techniques
    assert "T1190" in mitre.classify("sqlmap -u http://10.13.37.20/x --batch").techniques


def test_navigator_layer_shape() -> None:
    layer = mitre.navigator_layer("run-x", {"T1046", "T1190"})
    ids = {t["techniqueID"] for t in layer["techniques"]}
    assert ids == {"T1046", "T1190"}
    assert layer["domain"] == "enterprise-attack"
