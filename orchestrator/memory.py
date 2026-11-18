"""Run state + rolling-summary compaction.

Small-context models loop when you feed them the raw transcript. RunState keeps a short
digest of older steps plus the most recent few verbatim, so the prompt stays bounded while
the model still "remembers" what it tried.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class StepRecord:
    index: int
    command: str
    observation: str
    blocked: bool = False
    reason: str = ""


@dataclass
class RunState:
    goal: str
    steps: list[StepRecord] = field(default_factory=list)
    digest: str = ""
    recent_keep: int = 6
    compact_budget_chars: int = 6000

    @property
    def last_observation(self) -> str:
        return self.steps[-1].observation if self.steps else "(no actions yet)"

    def update(self, command: str, observation: str, blocked: bool = False, reason: str = "") -> None:
        self.steps.append(
            StepRecord(
                index=len(self.steps) + 1,
                command=command,
                observation=observation,
                blocked=blocked,
                reason=reason,
            )
        )

    def summary(self) -> str:
        """Digest of compacted history + the most recent steps, for the next prompt."""
        parts: list[str] = []
        if self.digest:
            parts.append(f"Earlier (summarized):\n{self.digest}")
        recent = self.steps[-self.recent_keep :]
        if recent:
            lines = []
            for s in recent:
                status = f"BLOCKED ({s.reason})" if s.blocked else "ran"
                obs = s.observation.strip().replace("\n", " ")
                if len(obs) > 300:
                    obs = obs[:300] + "…"
                lines.append(f"  [{s.index}] {status}: {s.command}\n      -> {obs}")
            parts.append("Recent steps:\n" + "\n".join(lines))
        return "\n\n".join(parts) if parts else "(no history yet)"

    def maybe_compact(self) -> None:
        """Fold older-than-recent steps into the digest when history grows too large."""
        older = self.steps[: -self.recent_keep] if len(self.steps) > self.recent_keep else []
        if not older:
            return
        rough = "\n".join(f"[{s.index}] {s.command}" for s in older)
        if len(rough) < self.compact_budget_chars and self.digest:
            return
        tried = "; ".join(dict.fromkeys(s.command.split()[0] for s in older if s.command))
        self.digest = (
            f"{len(older)} earlier steps. Tools used: {tried}. "
            f"Last summarized command: {older[-1].command!r}."
        )
