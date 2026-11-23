"""Collect blue-team telemetry (Suricata eve.json + Wazuh alerts.json) into a run's bluelogs/.

The docker copy is injectable so the logic is unit-testable without Docker.
"""

from __future__ import annotations

import json
import subprocess
from collections import Counter
from collections.abc import Callable
from pathlib import Path

# (container, path inside container, filename in bluelogs/)
SOURCES: list[tuple[str, str, str]] = [
    ("lab-suricata", "/var/log/suricata/eve.json", "eve.json"),
    ("lab-wazuh-manager", "/var/ossec/logs/alerts/alerts.json", "alerts.json"),
]

Runner = Callable[[list[str]], subprocess.CompletedProcess]


def _default_runner(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)


def collect(dest: Path, runner: Runner = _default_runner) -> dict[str, bool]:
    """`docker cp` each source into `dest`. Returns {filename: copied_ok}."""
    dest.mkdir(parents=True, exist_ok=True)
    results: dict[str, bool] = {}
    for container, src, name in SOURCES:
        proc = runner(["docker", "cp", f"{container}:{src}", str(dest / name)])
        results[name] = proc.returncode == 0
    return results


def _jsonl(path: Path):
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def summarize(dest: Path) -> dict:
    """Count Suricata alerts by signature and Wazuh lab alerts by rule / ATT&CK technique."""
    summary: dict = {"suricata_alerts": {}, "wazuh_alerts": {}, "wazuh_techniques": {}}
    eve = dest / "eve.json"
    if eve.exists():
        c = Counter(
            e["alert"].get("signature", "?")
            for e in _jsonl(eve)
            if e.get("event_type") == "alert" and isinstance(e.get("alert"), dict)
        )
        summary["suricata_alerts"] = dict(c)
    wz = dest / "alerts.json"
    if wz.exists():
        rules: Counter = Counter()
        techs: Counter = Counter()
        for a in _jsonl(wz):
            rule = a.get("rule") or {}
            if str(rule.get("id", "")).startswith("1001"):  # lab custom rules (100100+)
                rules[f"{rule.get('id')} {rule.get('description', '')}"] += 1
                for t in (rule.get("mitre") or {}).get("id", []) or []:
                    techs[t] += 1
        summary["wazuh_alerts"] = dict(rules)
        summary["wazuh_techniques"] = dict(techs)
    return summary


def write_summary(dest: Path) -> dict:
    s = summarize(dest)
    (dest / "summary.json").write_text(json.dumps(s, indent=2), encoding="utf-8")
    return s
