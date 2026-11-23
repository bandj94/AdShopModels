"""Map observed commands/outputs to MITRE ATT&CK techniques.

A deliberately small, transparent pattern map — good enough to label a transcript and emit a
Navigator layer, and easy to extend as the blue-team work grows. Not a classifier; just rules.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# (regex over the command, ATT&CK technique id, technique name, kill-chain phase)
_RULES: list[tuple[re.Pattern[str], str, str, str]] = [
    (re.compile(r"\bnmap\b|\bmasscan\b|\bping\b|\bnetcat -z|\bnc -z"), "T1046", "Network Service Discovery", "discovery"),
    (re.compile(r"\bwhatweb\b|\bnikto\b|\bwpscan\b|curl .*-I\b"), "T1595", "Active Scanning", "reconnaissance"),
    (re.compile(r"\bgobuster\b|\bffuf\b|\bwfuzz\b|\bdirb\b"), "T1595.003", "Wordlist Scanning", "reconnaissance"),
    (re.compile(r"\bsqlmap\b|union select|' or '1'='1|%27"), "T1190", "Exploit Public-Facing Application", "initial-access"),
    (re.compile(r"\bhydra\b|\bmedusa\b|\bpatator\b|brute"), "T1110", "Brute Force", "credential-access"),
    (re.compile(r"cat .*/etc/passwd|cat .*shadow|\bid\b|\bwhoami\b|\buname\b"), "T1033", "System Owner/User Discovery", "discovery"),
    (re.compile(r"\bnc\b .*-e|/bin/sh|/bin/bash -i|reverse shell|mkfifo"), "T1059", "Command and Scripting Interpreter", "execution"),
    (re.compile(r"\bcat\b .*flag|find .*flag|grep .*flag"), "T1083", "File and Directory Discovery", "discovery"),
]

_DEFAULT = ("TA0043", "Reconnaissance", "reconnaissance")


@dataclass(frozen=True)
class Mapping:
    phase: str
    techniques: list[str]


def classify(command: str, observation: str = "") -> Mapping:
    # Classify on the COMMAND only (the rules are written over commands). Folding in the
    # observation produced false positives — e.g. a bare `\bid\b` rule matched `id="favicon"`
    # in returned HTML and wrongly tagged T1033 on steps that never ran an id/whoami command.
    # ``observation`` is kept in the signature for callers and possible future output rules.
    hay = command.lower()
    techniques: list[str] = []
    phase = _DEFAULT[2]
    for rx, tech, _name, ph in _RULES:
        if rx.search(hay):
            if tech not in techniques:
                techniques.append(tech)
            phase = ph
    return Mapping(phase=phase, techniques=techniques)


def technique_names() -> dict[str, str]:
    return {tech: name for _rx, tech, name, _ph in _RULES}


def navigator_layer(name: str, techniques: set[str]) -> dict:
    """Minimal MITRE ATT&CK Navigator layer JSON for the covered techniques."""
    names = technique_names()
    return {
        "name": name,
        "versions": {"layer": "4.5", "navigator": "4.9.1"},
        "domain": "enterprise-attack",
        "description": "Techniques observed in this LLM Adversary Lab run.",
        "techniques": [
            {"techniqueID": t, "score": 1, "comment": names.get(t, ""), "color": "#e60d0d"}
            for t in sorted(techniques)
        ],
        "gradient": {"colors": ["#ffffff", "#e60d0d"], "minValue": 0, "maxValue": 1},
    }
