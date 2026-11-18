# Architecture

Deeper notes on the three planes and the control/isolation boundaries. See the README for the
diagrams; this file explains the *why*.

## Control plane (host)

- **Ollama** serves the model over an OpenAI-compatible API on `localhost:11434`. Model choice is
  a config field; nothing else in the system knows or cares which model it is.
- **Orchestrator** (`orchestrator/`) is a small Python package implementing a ReAct loop. It is
  the only bespoke code. It never runs *inside* the lab network — it reaches in via the executor.
- **`lab.py`** is the lifecycle CLI. It wraps `docker compose` with the active profile's overrides
  and runs pre-flight checks (toolchain, model reachability, no-egress).

## Isolation model (two networks)

Docker Compose defines two networks:

- **`labnet`** — `internal: true`. No gateway, no route to host or internet. Attacker, target(s),
  and the NIDS sensor live here. This is where "attacks" happen.
- **`mgmt`** — a normal bridge, but blue-team UI ports are published to `127.0.0.1` only. The SIEM
  attaches to both `labnet` (to ingest) and `mgmt` (so you can open the dashboard).

```
host ──(docker exec)──► attacker ──labnet──► target
                              │
                           labnet (sniffed by suricata) ──► wazuh ──mgmt──► 127.0.0.1:5601
```

The only paths that cross the isolation boundary are:
1. `docker exec` from host into the attacker container (the logged command channel), and
2. the SIEM dashboard, host-localhost-only, read-only to you.

Neither gives the lab egress.

## Executor abstraction

`executor.py` exposes `Executor.run(cmd, timeout) -> Observation`. Three implementations share
the interface so the agent loop is identical across modes:

- `DockerExecExecutor(container)` → `docker exec <container> sh -lc "<cmd>"` **(default)**
- `SSHExecutor(host, key)` → `ssh -i <key> <host> "<cmd>"` (future VM mode)
- `LocalExecutor()` → runs in the current shell (dev/testing only)

Because the orchestrator talks to an executor, not to Docker directly, moving to VM mode later is
a config/executor swap, not a rewrite.

## Safety is a pure function

`safety.py` is deliberately I/O-free so it can be exhaustively unit-tested:

```
SafetyGuard(lab_cidr, allow, deny, max_steps, default_deny)
  .allow(cmd) -> Decision(permitted: bool, reason: str)
```

The agent calls `guard.allow(cmd)` before every execution. Out-of-scope addresses, denied
patterns, and (when `default_deny`) unknown binaries all return `permitted=False` with a reason
that is logged into the transcript.

## Replayability

Every step is one JSON line (`transcript.jsonl`). Given the transcript you can reconstruct the
exact command sequence, the observations, the blocks, and the ATT&CK mapping — without re-running
the model. Reports are derived artifacts; the JSONL is the source of truth.

## Where the model's non-determinism lives

Only in `llm_client.chat()`. Everything downstream (parsing, gating, executing, logging) is
deterministic given the model's output, which is itself logged verbatim as `action_raw`. So two
runs differ only by model sampling, and you can pin `temperature: 0` for near-deterministic
comparisons.
