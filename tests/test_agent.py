"""Agent-loop tests with a scripted model + fake executor — no Docker, no real model."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from orchestrator.agent import build_system_prompt, goal_met, parse_action, run_agent
from orchestrator.config import load_and_validate
from orchestrator.executor import Executor, Observation

PROFILE: dict = {
    "deployment": {"mode": "docker", "lab_cidr": "10.13.37.0/24", "egress": False},
    "attacker": {
        "kind": "container",
        "ip": "10.13.37.10",
        "llm": {"endpoint": "http://localhost:11434/v1", "model": "qwen3:8b"},
    },
    "target": {"kind": "juice-shop", "provider": "docker", "ip": "10.13.37.20"},
    "run": {"goal": "read the flag", "max_steps": 10, "step_timeout_s": 30, "stop_on_goal": True},
    "safety": {"default_deny": True, "allow": ["nmap", "cat", "curl"], "deny": ["reboot"]},
}


def _cfg(tmp_path: Path):
    p = tmp_path / "config.yaml"
    p.write_text(yaml.safe_dump(PROFILE), encoding="utf-8")
    return load_and_validate(p)


class ScriptedLLM:
    def __init__(self, replies: list[str]) -> None:
        self.replies = replies
        self.i = 0

    def chat(self, messages, **kw) -> str:  # duck-types LLMClient
        reply = self.replies[min(self.i, len(self.replies) - 1)]
        self.i += 1
        return reply


class FakeExecutor(Executor):
    def run(self, command: str, timeout: int) -> Observation:
        out = "flag{demo-captured}" if "flag" in command else "PORT   STATE  SERVICE\n80/tcp open   http"
        return Observation(command=command, exit_code=0, stdout=out, stderr="", duration_s=0.01)


def test_parse_action_variants() -> None:
    assert parse_action("Thought: x\nCMD: nmap -sV 10.13.37.20") == "nmap -sV 10.13.37.20"
    assert parse_action("```bash\nnmap -sV 10.13.37.20\n```") == "nmap -sV 10.13.37.20"
    assert parse_action("Action: cat /flag") == "cat /flag"
    assert parse_action("$ whoami") == "whoami"


def test_goal_met() -> None:
    assert goal_met("output was flag{abc}")
    assert not goal_met("nothing interesting here")


def test_system_prompt_injects(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path)
    s = build_system_prompt(cfg)
    assert "10.13.37.0/24" in s and cfg.target.ip in s and "read the flag" in s


def test_full_loop_captures_flag(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path)
    llm = ScriptedLLM(
        ["Thought: recon\nCMD: nmap -sV 10.13.37.20", "Thought: grab it\nCMD: cat /flag.txt"]
    )
    res = run_agent(cfg, runs_dir=tmp_path / "runs", executor=FakeExecutor(), llm=llm, verbose=False)

    assert res.goal_met and res.steps == 2
    assert "T1046" in res.techniques
    rd = Path(res.run_dir)
    for artifact in ("transcript.jsonl", "report.md", "attack-layer.json", "run.json"):
        assert (rd / artifact).exists(), artifact
    assert len((rd / "transcript.jsonl").read_text(encoding="utf-8").strip().splitlines()) == 2


def test_loop_blocks_out_of_scope(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path)
    llm = ScriptedLLM(["CMD: nmap -sV 8.8.8.8", "CMD: cat /flag"])
    res = run_agent(cfg, runs_dir=tmp_path / "runs", executor=FakeExecutor(), llm=llm, verbose=False)

    recs = [
        json.loads(ln)
        for ln in (Path(res.run_dir) / "transcript.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert recs[0]["blocked"] is True
    assert "out-of-scope" in recs[0]["reason"]
    assert res.goal_met  # second step still captured the flag
