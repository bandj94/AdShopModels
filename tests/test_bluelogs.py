"""Blue-team log collection, summary, and rule-sync checks (no Docker needed)."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from orchestrator import bluelogs


def test_collect_reports_per_file_status(tmp_path: Path) -> None:
    calls: list[list[str]] = []

    def runner(cmd: list[str]) -> subprocess.CompletedProcess:
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0 if "lab-suricata" in cmd[2] else 1)

    res = bluelogs.collect(tmp_path / "bluelogs", runner)
    assert res == {"eve.json": True, "alerts.json": False}
    assert all(c[:2] == ["docker", "cp"] for c in calls)


def test_summarize_counts_alerts_and_techniques(tmp_path: Path) -> None:
    eve = [
        {"event_type": "http"},
        {"event_type": "alert", "alert": {"signature": "LAB T1046 nmap-style SYN scan"}},
        {"event_type": "alert", "alert": {"signature": "LAB T1046 nmap-style SYN scan"}},
    ]
    (tmp_path / "eve.json").write_text("\n".join(json.dumps(e) for e in eve) + "\nnot json\n")
    wz = [
        {"rule": {"id": "100102", "description": "scan", "mitre": {"id": ["T1046"]}}},
        {"rule": {"id": "86601", "description": "stock", "mitre": {"id": ["T9999"]}}},
    ]
    (tmp_path / "alerts.json").write_text("\n".join(json.dumps(e) for e in wz) + "\n")
    s = bluelogs.write_summary(tmp_path)
    assert s["suricata_alerts"] == {"LAB T1046 nmap-style SYN scan": 2}
    assert s["wazuh_alerts"] == {"100102 scan": 1}
    assert s["wazuh_techniques"] == {"T1046": 1}
    assert (tmp_path / "summary.json").exists()


def test_summarize_handles_missing_files(tmp_path: Path) -> None:
    assert bluelogs.summarize(tmp_path)["suricata_alerts"] == {}


def test_suricata_and_wazuh_rules_stay_in_sync() -> None:
    """Every Suricata sid Wazuh keys on exists in local.rules, and every sid is handled."""
    root = Path(__file__).resolve().parent.parent / "blueteam"
    sids = set(re.findall(r"sid:(\d+);", (root / "suricata" / "local.rules").read_text()))
    xml = (root / "wazuh" / "rules" / "local_rules.xml").read_text()
    referenced = set(re.findall(r"\^(90000\d\d)\$", xml))
    assert referenced == sids
    assert len(sids) == len(re.findall(r"sid:\d+;", (root / "suricata" / "local.rules").read_text()))
