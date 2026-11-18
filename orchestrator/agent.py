"""The ReAct agent loop — wires every module together.

For each step: build the prompt from the running state, ask the model for ONE command, gate it
through the scope guard, execute it (or record the block), log a JSONL line, update memory, map
to ATT&CK, and check the goal and the kill switch. At the end, emit report.md and the Navigator
layer. A run is fully replayable from transcript.jsonl.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from pathlib import Path

from . import mitre
from .config import LabConfig
from .executor import Executor, make_executor
from .llm_client import LLMClient
from .logging_jsonl import JSONLLogger, new_run_id, utcnow_iso
from .memory import RunState
from .safety import SafetyGuard

PROMPTS_DIR = Path(__file__).parent / "prompts"

_CMD_RE = re.compile(r"^\s*cmd:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
_FENCE_RE = re.compile(r"```(?:[a-zA-Z0-9]*)\s*\n(.*?)```", re.S)


# ------------------------------------------------------------------ pure helpers


def _clean(s: str) -> str:
    s = s.strip().strip("`").strip()
    if s.startswith(("$ ", "> ")):
        s = s[2:]
    return s.strip()


def parse_action(text: str) -> str:
    """Extract the single command from a model reply. Tolerant of common formats."""
    m = _CMD_RE.search(text)
    if m:
        return _clean(m.group(1))
    m = _FENCE_RE.search(text)
    if m:
        first = next((ln for ln in m.group(1).splitlines() if ln.strip()), "")
        if first:
            return _clean(first)
    for line in text.splitlines():
        low = line.strip().lower()
        if low.startswith(("action:", "command:")):
            return _clean(line.split(":", 1)[1])
    for line in text.splitlines():
        if line.strip():
            return _clean(line)
    return ""


def goal_met(observation: str) -> bool:
    low = observation.lower()
    return "flag{" in low or "flag:" in low or "ctf{" in low


def build_system_prompt(cfg: LabConfig) -> str:
    tmpl = (PROMPTS_DIR / "system.md").read_text(encoding="utf-8")
    allow = ", ".join(cfg.safety.allow) or "(standard kali tools)"
    return tmpl.format(
        lab_cidr=cfg.deployment.lab_cidr,
        target_ip=cfg.target.ip,
        goal=cfg.run.goal,
        allow_list=allow,
    )


def stop_requested(run_dir: Path | str) -> bool:
    return (Path(run_dir) / "STOP").exists() or Path("STOP").exists()


# ------------------------------------------------------------------ the loop


@dataclass
class RunResult:
    run_id: str
    steps: int
    goal_met: bool
    run_dir: str
    techniques: list[str]


def run_agent(
    cfg: LabConfig,
    runs_dir: str | Path = "runs",
    *,
    executor: Executor | None = None,
    llm: LLMClient | None = None,
    goal: str | None = None,
    max_steps: int | None = None,
    verbose: bool = True,
) -> RunResult:
    goal = goal or cfg.run.goal
    max_steps = max_steps or cfg.run.max_steps

    guard = SafetyGuard.from_config(cfg)
    llm = llm or LLMClient(cfg.attacker.llm, timeout_s=cfg.run.step_timeout_s)
    executor = executor or make_executor(cfg)

    run_id = new_run_id(cfg.attacker.llm.model, cfg.target.kind)
    logger = JSONLLogger(runs_dir, run_id)
    logger.write_meta(
        {
            "started": utcnow_iso(),
            "model": cfg.attacker.llm.model,
            "target": cfg.target.kind,
            "target_ip": cfg.target.ip,
            "goal": goal,
            "max_steps": max_steps,
            "lab_cidr": cfg.deployment.lab_cidr,
        }
    )

    state = RunState(goal=goal)
    system = build_system_prompt(cfg)
    techniques: set[str] = set()
    met = False
    started = time.monotonic()
    used = 0

    for step in range(1, max_steps + 1):
        used = step
        if stop_requested(logger.run_dir):
            if verbose:
                print(f"[{step}] STOP sentinel present — halting.")
            break
        if time.monotonic() - started > cfg.run.max_wall_clock_s:
            if verbose:
                print(f"[{step}] wall-clock cap reached — halting.")
            break

        user = (
            f"GOAL: {goal}\n\n"
            f"STATE:\n{state.summary()}\n\n"
            f"Latest observation:\n{state.last_observation}\n\n"
            "Issue the next single command (Thought + one CMD: line)."
        )
        action_raw = llm.chat([{"role": "system", "content": system}, {"role": "user", "content": user}])
        command = parse_action(action_raw)

        decision = guard.allow_command(command, step)
        if not decision.permitted:
            observation = f"BLOCKED: {decision.reason}"
            blocked, reason = True, decision.reason
        else:
            obs = executor.run(command, cfg.run.step_timeout_s)
            observation = obs.text
            blocked, reason = False, ""

        mapping = mitre.classify(command, observation)
        techniques.update(mapping.techniques)

        logger.step(
            {
                "step": step,
                "model": cfg.attacker.llm.model,
                "action_raw": action_raw,
                "command": command,
                "blocked": blocked,
                "reason": reason,
                "observation": observation,
                "attack_phase": mapping.phase,
                "mitre": mapping.techniques,
            }
        )
        state.update(command, observation, blocked, reason)
        state.maybe_compact()

        if verbose:
            tag = f"BLOCKED ({reason})" if blocked else "ran"
            print(f"[{step}] {tag}: {command}")

        if not blocked and cfg.run.stop_on_goal and goal_met(observation):
            met = True
            if verbose:
                print(f"[{step}] goal appears met — stopping.")
            break

    logger.write_json("attack-layer.json", mitre.navigator_layer(run_id, techniques))
    logger.write_text("report.md", _render_report(cfg, run_id, state, sorted(techniques), met, used))
    logger.write_meta(
        {
            "finished": utcnow_iso(),
            "model": cfg.attacker.llm.model,
            "target": cfg.target.kind,
            "goal": goal,
            "steps_used": used,
            "goal_met": met,
            "techniques": sorted(techniques),
        }
    )
    return RunResult(run_id=run_id, steps=used, goal_met=met, run_dir=str(logger.run_dir), techniques=sorted(techniques))


def _render_report(cfg: LabConfig, run_id: str, state: RunState, techniques: list[str], met: bool, used: int) -> str:
    names = mitre.technique_names()
    rows = []
    for s in state.steps:
        obs = s.observation.strip().replace("\n", " ")
        if len(obs) > 160:
            obs = obs[:160] + "…"
        status = f"BLOCKED ({s.reason})" if s.blocked else "ran"
        rows.append(f"| {s.index} | {status} | `{s.command}` | {obs} |")
    tech_lines = "\n".join(f"- `{t}` — {names.get(t, '')}" for t in techniques) or "- (none mapped)"
    return f"""# Run report — {run_id}

- **Model:** `{cfg.attacker.llm.model}`
- **Target:** {cfg.target.kind} @ {cfg.target.ip}
- **Goal:** {state.goal}
- **Outcome:** {"✅ goal met" if met else "⬜ goal not confirmed"}
- **Steps used:** {used} / {cfg.run.max_steps}

## ATT&CK techniques observed
{tech_lines}

## Step-by-step

| # | Status | Command | Observation (truncated) |
|---|---|---|---|
{chr(10).join(rows) if rows else "| — | — | — | — |"}

---
*Derived from `transcript.jsonl`. See `attack-layer.json` for the Navigator layer.*
"""
