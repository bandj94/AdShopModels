#!/usr/bin/env python3
"""lab.py — the lab control surface.

Cross-platform replacement for the Makefile verbs (Windows has no `make`). Everything an
operator — or an agent on the host — needs to drive the lab:

    python lab.py doctor     # check toolchain, model, scope guard (no containers)
    python lab.py up         # start the lab, verify NO egress (fails closed)
    python lab.py attack     # run the LLM attacker against the current target
    python lab.py compare    # bake-off: run every model in config/models.yaml, score + rank
    python lab.py snapshot    # mark/record a clean baseline
    python lab.py reset      # recreate containers from images (clean baseline)
    python lab.py collect    # gather the latest run's artifacts
    python lab.py down       # stop everything
    python lab.py selftest   # scope-guard self-check only

Design: thin wrapper around `docker compose` + the orchestrator. No bespoke state.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CONFIG_PATH = ROOT / "config" / "config.yaml"
MODELS_PATH = ROOT / "config" / "models.yaml"
COMPOSE_DIR = ROOT / "infra" / "docker"
LABNET = "labnet"  # explicit network name set in compose; isolated, no egress


# --------------------------------------------------------------------- helpers


def _load_dotenv() -> None:
    envf = ROOT / ".env"
    if not envf.exists():
        return
    for line in envf.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        os.environ.setdefault(key.strip(), val.strip())


def _c(text: str, color: str) -> str:
    codes = {"g": "92", "y": "93", "r": "91", "b": "96", "d": "90"}
    if not sys.stdout.isatty():
        return text
    return f"\033[{codes.get(color, '0')}m{text}\033[0m"


def ok(msg: str) -> None:
    print(f"  {_c('PASS', 'g')}  {msg}")


def warn(msg: str) -> None:
    print(f"  {_c('WARN', 'y')}  {msg}")


def fail(msg: str) -> None:
    print(f"  {_c('FAIL', 'r')}  {msg}")


def _load_cfg():
    from orchestrator.config import ConfigError, load_and_validate

    try:
        return load_and_validate(CONFIG_PATH)
    except ConfigError as e:
        fail(str(e))
        return None


def _have_docker() -> bool:
    return shutil.which("docker") is not None


def _compose_files(cfg) -> list[Path]:
    files = [COMPOSE_DIR / "docker-compose.yml"]
    files.append(COMPOSE_DIR / "overrides" / f"target.{cfg.target.kind}.yml")
    if cfg.blueteam.siem:
        files.append(COMPOSE_DIR / "overrides" / f"siem.{cfg.blueteam.siem}.yml")
    if cfg.blueteam.nids and cfg.blueteam.nids != "none":
        files.append(COMPOSE_DIR / "overrides" / f"nids.{cfg.blueteam.nids}.yml")
    return files


def _compose(cfg, *args: str) -> list[str]:
    cmd = ["docker", "compose", "-p", "adversary-lab"]
    for f in _compose_files(cfg):
        if f.exists():
            cmd += ["-f", str(f)]
    envf = ROOT / ".env"
    if envf.exists():
        cmd += ["--env-file", str(envf)]
    return cmd + list(args)


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    print(_c("$ " + " ".join(cmd), "d"))
    return subprocess.run(cmd, **kw)


# --------------------------------------------------------------------- commands


def cmd_selftest(_args) -> int:
    """Scope-guard sanity check — no Docker, no model needed."""
    from orchestrator.safety import SafetyGuard

    g = SafetyGuard(lab_cidr="10.13.37.0/24", allow=["nmap", "cat"], deny=["reboot"], known_hosts={"target"})
    checks = [
        ("in-scope nmap permitted", g.allow_command("nmap -sV 10.13.37.20", 1).permitted is True),
        ("out-of-scope blocked", g.allow_command("nmap 8.8.8.8", 1).permitted is False),
        ("deny pattern blocked", g.allow_command("reboot", 1).permitted is False),
        ("unknown binary blocked", g.allow_command("wget http://10.13.37.20", 1).permitted is False),
    ]
    all_ok = True
    for label, passed in checks:
        (ok if passed else fail)(label)
        all_ok &= passed
    print()
    print(_c("scope guard OK", "g") if all_ok else _c("scope guard FAILED", "r"))
    return 0 if all_ok else 1


def cmd_doctor(_args) -> int:
    print(_c("LLM Adversary Lab — doctor", "b"))
    print(f"\nPython: {sys.version.split()[0]}  ({sys.executable})")

    print("\nToolchain:")
    for dep in ("docker", "ollama", "git"):
        (ok if shutil.which(dep) else warn)(f"{dep} {'found' if shutil.which(dep) else 'NOT found'}")

    print("\nConfig:")
    if not CONFIG_PATH.exists():
        warn(f"{CONFIG_PATH} missing — copy a profile: "
             f"Copy-Item config\\profiles\\docker-web.yaml config\\config.yaml")
        cfg = None
    else:
        cfg = _load_cfg()
        if cfg:
            ok(f"profile loads: mode={cfg.deployment.mode}, target={cfg.target.kind}, "
               f"model={cfg.attacker.llm.model}, egress={cfg.deployment.egress}")

    print("\nModel server:")
    if cfg:
        from orchestrator.llm_client import LLMClient

        client = LLMClient(cfg.attacker.llm, timeout_s=10)
        if client.ping():
            ok(f"server reachable at {cfg.attacker.llm.endpoint}")
            if client.model_available():
                ok(f"model '{cfg.attacker.llm.model}' is available")
            else:
                warn(f"model '{cfg.attacker.llm.model}' not listed — run `ollama pull {cfg.attacker.llm.model}`")
        else:
            warn(f"server not reachable at {cfg.attacker.llm.endpoint} — is Ollama running? "
                 f"(ollama serve / ollama list)")
    else:
        warn("skipped (no config)")

    print("\nScope guard:")
    rc = cmd_selftest(_args)

    print("\nDocker daemon:")
    if _have_docker():
        r = _run(["docker", "version", "--format", "{{.Server.Version}}"], capture_output=True, text=True)
        if r.returncode == 0:
            ok(f"docker engine {r.stdout.strip()}")
        else:
            warn("docker installed but daemon not responding — start Docker Desktop")
    else:
        warn("docker not installed yet (see docs/windows-docker-setup.md)")

    return rc


def egress_check() -> bool:
    """Return True if the lab network is confirmed to have NO egress."""
    probe = (
        "timeout 4 wget -q -O- http://1.1.1.1 >/dev/null 2>&1 && echo EGRESS || echo NOEGRESS"
    )
    r = _run(
        ["docker", "run", "--rm", "--network", LABNET, "alpine:3.20", "sh", "-lc", probe],
        capture_output=True, text=True,
    )
    out = (r.stdout or "") + (r.stderr or "")
    if "EGRESS" in out and "NOEGRESS" not in out:
        return False
    return "NOEGRESS" in out


def cmd_up(args) -> int:
    cfg = _load_cfg()
    if not cfg:
        return 1
    if not _have_docker():
        fail("docker not installed — see docs/windows-docker-setup.md")
        return 1
    r = _run(_compose(cfg, "up", "-d"))
    if r.returncode != 0:
        fail("compose up failed")
        return r.returncode
    print("\nVerifying isolation (no egress)…")
    if egress_check():
        ok("lab network has NO egress")
    else:
        fail("lab network CAN reach the internet — tearing down for safety (see SAFETY.md)")
        _run(_compose(cfg, "down"))
        return 2
    print(_c("\nlab is up.", "g"))
    return 0


def cmd_attack(args) -> int:
    cfg = _load_cfg()
    if not cfg:
        return 1
    from orchestrator.agent import run_agent

    print(_c(f"Attacking {cfg.target.kind}@{cfg.target.ip} with {cfg.attacker.llm.model}", "b"))
    res = run_agent(cfg, runs_dir=str(ROOT / "runs"), goal=args.goal)
    print()
    print(_c(f"run: {res.run_id}", "b"))
    print(f"  steps: {res.steps}  goal_met: {res.goal_met}")
    print(f"  techniques: {', '.join(res.techniques) or '(none)'}")
    print(f"  artifacts: {res.run_dir}")
    return 0


def cmd_compare(args) -> int:
    """Bake-off: run every model in config/models.yaml against the current target, score + rank."""
    cfg = _load_cfg()
    if not cfg:
        return 1
    if not _have_docker():
        fail("docker not installed — see docs/windows-docker-setup.md")
        return 1
    if not MODELS_PATH.exists():
        fail(f"{MODELS_PATH} missing — add a model registry (see config/models.yaml)")
        return 1

    from orchestrator.bench import load_model_specs, run_comparison

    specs = load_model_specs(MODELS_PATH)
    if args.models:
        wanted = {m.strip() for m in args.models.split(",")}
        specs = [s for s in specs if s.alias in wanted]
    if args.skip_slow:
        specs = [s for s in specs if not s.slow]
    if not specs:
        fail("no models selected (check --models / --skip-slow against config/models.yaml)")
        return 1

    manage = not args.manual
    print(_c(f"Bake-off: {len(specs)} model(s) vs {cfg.target.kind}@{cfg.target.ip}", "b"))
    print("  " + ", ".join(s.alias for s in specs))
    if manage:
        print(_c("  server mode: automated (harness starts/stops each llama.cpp server)", "d"))
    else:
        print(_c("  server mode: manual (launch each .bat; harness waits for it)", "d"))

    reset_fn = None if args.no_reset else (lambda: cmd_reset(args))
    out_dir, cards = run_comparison(
        cfg, specs,
        comparisons_root=str(ROOT / "comparisons"),
        reset_fn=reset_fn,
        manage_servers=manage,
        repeat=args.repeat,
        goal=args.goal,
        server_timeout_s=args.server_timeout,
        log=print,
    )

    from orchestrator.bench import leaderboard_md

    print()
    print(leaderboard_md(cards))
    ok(f"artifacts: {out_dir}")
    print(f"  leaderboard: {out_dir / 'leaderboard.md'}")
    return 0


def cmd_reset(args) -> int:
    cfg = _load_cfg()
    if not cfg:
        return 1
    _run(_compose(cfg, "down", "-v"))
    return cmd_up(args)


def cmd_snapshot(_args) -> int:
    print("Docker mode: containers are ephemeral; a clean baseline is `python lab.py reset`.")
    print("(VM mode will snapshot disks here.)")
    return 0


def cmd_collect(_args) -> int:
    runs = ROOT / "runs"
    latest = max((p for p in runs.glob("*/") if p.is_dir() and p.name != "sample-run"),
                 key=lambda p: p.stat().st_mtime, default=None)
    if not latest:
        warn("no runs found yet")
        return 0
    ok(f"latest run: {latest}")
    dest = latest / "bluelogs"
    if not _have_docker():
        dest.mkdir(exist_ok=True)
        warn("docker not installed; no blue-team logs collected")
        return 0
    from orchestrator import bluelogs

    results = bluelogs.collect(dest)
    for name, good in results.items():
        if good:
            ok(f"bluelogs/{name}")
        else:
            warn(f"bluelogs/{name}: container not running or no file yet")
    summary = bluelogs.write_summary(dest)
    techs = ", ".join(sorted(summary["wazuh_techniques"])) or "none"
    print(f"  suricata alerts: {sum(summary['suricata_alerts'].values())} | "
          f"wazuh lab alerts: {sum(summary['wazuh_alerts'].values())} | techniques: {techs}")
    ok(f"blue-team logs -> {dest}")
    return 0


def cmd_down(_args) -> int:
    cfg = _load_cfg()
    if not cfg:
        return 1
    if not _have_docker():
        warn("docker not installed; nothing to stop")
        return 0
    return _run(_compose(cfg, "down")).returncode


def main() -> int:
    _load_dotenv()
    parser = argparse.ArgumentParser(prog="lab.py", description="LLM Adversary Lab control surface")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("doctor", help="check toolchain, model, and scope guard")
    sub.add_parser("selftest", help="scope-guard self-check only")
    sub.add_parser("up", help="start the lab and verify no egress")
    p_attack = sub.add_parser("attack", help="run the LLM attacker")
    p_attack.add_argument("--goal", default=None, help="override the profile goal")
    p_cmp = sub.add_parser("compare", help="bake-off: run every model in config/models.yaml, score + rank")
    p_cmp.add_argument("--models", default=None, help="comma-separated aliases to run (default: all)")
    p_cmp.add_argument("--repeat", type=int, default=1, help="runs per model (default: 1)")
    p_cmp.add_argument("--goal", default=None, help="override the profile goal")
    p_cmp.add_argument("--manual", action="store_true", help="you launch each server; harness waits")
    p_cmp.add_argument("--skip-slow", action="store_true", help="skip models marked slow (the 27B)")
    p_cmp.add_argument("--no-reset", action="store_true", help="don't reset the target between models")
    p_cmp.add_argument("--server-timeout", type=int, default=420, help="seconds to wait for a server to load")
    sub.add_parser("snapshot", help="record a clean baseline")
    sub.add_parser("reset", help="recreate containers from images")
    sub.add_parser("collect", help="gather the latest run's artifacts")
    sub.add_parser("down", help="stop the lab")

    args = parser.parse_args()
    handlers = {
        "doctor": cmd_doctor, "selftest": cmd_selftest, "up": cmd_up, "attack": cmd_attack,
        "compare": cmd_compare, "snapshot": cmd_snapshot, "reset": cmd_reset,
        "collect": cmd_collect, "down": cmd_down,
    }
    try:
        return handlers[args.command](args)
    except KeyboardInterrupt:
        print("\ninterrupted.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
