"""Unit tests for the scope guard. Pure logic, no I/O — fast and exhaustive."""

from __future__ import annotations

import pytest

from orchestrator.safety import Decision, SafetyGuard

ALLOW = ["nmap", "curl", "cat", "whoami", "sqlmap"]
DENY = ["shutdown", "reboot", "rm -rf /", ":(){"]


@pytest.fixture()
def guard() -> SafetyGuard:
    return SafetyGuard(
        lab_cidr="10.13.37.0/24",
        allow=ALLOW,
        deny=DENY,
        max_steps=40,
        default_deny=True,
        known_hosts={"target", "lab-target"},
    )


# --------------------------------------------------------------------- allowed cases


@pytest.mark.parametrize(
    "cmd",
    [
        "nmap -sV 10.13.37.20",
        "curl http://10.13.37.20:3000/",
        "curl http://target:3000/#/",
        "curl http://127.0.0.1:3000/",
        "cat /etc/passwd",
        "cat config.yaml",            # must NOT be read as a hostname
        "whoami",
        "FOO=bar nmap 10.13.37.20",   # env assignment prefix
        "sudo nmap 10.13.37.20",      # sudo prefix
        "/usr/bin/nmap 10.13.37.20",  # path prefix stripped
        "sqlmap -u http://10.13.37.20/rest/products/search?q=1 --batch",
    ],
)
def test_permits_in_scope_allowed(guard: SafetyGuard, cmd: str) -> None:
    d = guard.allow_command(cmd, step=1)
    assert d.permitted, f"expected permit, got blocked: {d.reason} ({cmd!r})"


# --------------------------------------------------------------------- blocked cases


@pytest.mark.parametrize(
    "cmd,needle",
    [
        ("nmap -sV 8.8.8.8", "out-of-scope address"),
        ("curl http://evil.example.com/", "out-of-scope host in URL"),
        ("nmap scanme.nmap.org", "out-of-scope host"),       # bare FQDN, network tool
        ("shutdown now", "denied pattern"),
        ("rm -rf / --no-preserve-root", "denied pattern"),
        ("wget http://10.13.37.20/x", "not in allow list"),  # wget not allowed
        ("", "empty command"),
    ],
)
def test_blocks(guard: SafetyGuard, cmd: str, needle: str) -> None:
    d = guard.allow_command(cmd, step=1)
    assert not d.permitted, f"expected block for {cmd!r}"
    assert needle in d.reason, f"reason {d.reason!r} missing {needle!r}"


def test_deny_beats_allow(guard: SafetyGuard) -> None:
    # 'cat' is allowed, but the deny substring still wins.
    d = guard.allow_command("cat x && reboot", step=1)
    assert not d.permitted
    assert "denied pattern" in d.reason


def test_step_cap(guard: SafetyGuard) -> None:
    ok = guard.allow_command("nmap 10.13.37.20", step=40)
    over = guard.allow_command("nmap 10.13.37.20", step=41)
    assert ok.permitted
    assert not over.permitted and "step cap" in over.reason


def test_default_deny_false_allows_unknown_binary() -> None:
    g = SafetyGuard(lab_cidr="10.13.37.0/24", allow=[], deny=DENY, default_deny=False)
    permit = g.allow_command("someobscuretool 10.13.37.20", step=1)
    assert permit.permitted
    # ...but scope + deny still apply even with default_deny off.
    assert not g.allow_command("someobscuretool 1.1.1.1", step=1).permitted
    assert not g.allow_command("reboot", step=1).permitted


def test_bare_filename_not_treated_as_host(guard: SafetyGuard) -> None:
    for cmd in ["cat notes.txt", "cat results.json", "cat index.html"]:
        assert guard.allow_command(cmd, step=1).permitted, cmd


def test_decision_is_frozen() -> None:
    d = Decision(True, "ok")
    with pytest.raises(Exception):
        d.permitted = False  # type: ignore[misc]
