# Safety Model & Rules of Engagement

> **Read this before running anything.** This lab orchestrates an autonomous LLM "attacker"
> against deliberately vulnerable targets. It is only safe because it is **isolated, bounded,
> and fails closed**. The guarantees below are load-bearing — the architecture assumes them.

---

## 0. Authorization

This project is for **isolated, authorized security research and education only**.

- The attacker tooling is only ever pointed at **targets you build inside this lab**.
- Do **not** point, adapt, or deploy any component against systems you do not own or do not
  have explicit written authorization to test.
- "Uncensored" (for any model used here) means *the model will emit a command instead of
  refusing* — it does **not** mean the scope rules below are relaxed. They are enforced in
  code, not by the model's goodwill.

---

## 1. Network isolation (no egress)

The lab network is defined with **no gateway and no DNS egress**.

- **Docker mode (this machine):** the lab network is declared `internal: true` in Compose, so
  Docker creates **no gateway** for it — containers on it cannot reach the host network or the
  internet. Blue-team *dashboards* attach to a **separate** `mgmt` network that publishes ports
  to `127.0.0.1` only, so you can view them without giving the lab egress.
- **VM mode (future / Linux host):** libvirt *isolated* network or VirtualBox *internal*
  network — same property, no uplink.

**Verified at boot.** `lab.py up` runs an egress check: it execs a command inside the lab
network trying to reach the internet and **fails the lab if it succeeds**. The lab should fail
closed if egress is ever possible.

---

## 2. Scope lock (enforced in `orchestrator/safety.py`)

- Every command the model proposes is parsed, and **any command referencing an address outside
  `deployment.lab_cidr` is dropped** before execution (returns a `BLOCKED` observation).
- Bare hostnames that aren't known lab hosts are rejected; only in-scope lab IPs/hosts pass.
- This is pure, unit-tested logic with no I/O (`tests/test_safety.py`).

## 3. Allow / deny lists

- The model operates **only within the attacker context** (the Kali container).
- **Denied** patterns include host-affecting / destructive / egress-seeking commands
  (e.g. `rm -rf /` on mounts, `shutdown`, `reboot`, package exfil, `curl`/`wget` to non-lab
  hosts, reverse shells to non-lab IPs). See `config/config.yaml -> safety.deny`.
- Deny takes precedence over allow. Unknown commands fail **closed** when
  `safety.default_deny: true`.

## 4. Step & time caps (no unbounded autonomy)

- `run.max_steps` caps the number of agent actions.
- `run.step_timeout_s` caps each command's wall-clock time.
- `run.max_wall_clock_s` (optional) caps the whole run.
- The loop stops on goal, on cap, or on kill switch — never runs open-ended.

## 5. Kill switch

- `lab.py down` halts the whole lab.
- A sentinel file (`runs/<id>/STOP` or `./STOP`) is checked **between every step**; creating it
  halts the orchestrator gracefully after the current step.
- `Ctrl-C` is caught and flushes the transcript before exit.

## 6. Snapshots over rebuilds

- State is **disposable**. The flow is: `snapshot` (clean baseline) -> `attack` -> `collect`
  -> `reset`. Containers are recreated from images; volumes are reset between runs so runs are
  comparable and nothing persists silently.

## 7. Human-in-the-loop defaults

- v1 runs are **human-reviewed**: you read the transcript as it is produced.
- Autonomous mode (v3) only becomes available once caps, memory compaction, and the scope guard
  are all in place and tested.

## 8. Disclosure

- This file and the README state the authorization limits prominently.
- The repo ships **no** real-world targets, credentials, or exploits against third parties —
  only pointers to standard, intentionally-vulnerable training images (Juice Shop, DVWA, etc.).

---

## Pre-flight checklist (every session)

- [ ] `.env` points `LLM_ENDPOINT` at the **host** Ollama, not into the lab network.
- [ ] `lab.py doctor` passes (Docker up, model reachable, scope guard self-test green).
- [ ] `lab.py up` egress check **passed** (lab cannot reach the internet).
- [ ] You are using a **lab-only** model/profile and in-scope targets only.
- [ ] You have authorization for everything in `deployment.lab_cidr` (you built it).

If any box is unchecked, **do not start a run.**
