# sample-run — first real v1 run

A **live** single-target run, committed as the v1 deliverable (`v1.0-single-target`). Unlike the
earlier offline placeholder, this was produced by `python lab.py attack` against the real lab:
the uncensored local model **`ornith-9b`** (llama.cpp on the host) driving the Kali attacker
container against **OWASP Juice Shop v16**, on a Docker internal network with **no egress**.

- `transcript.jsonl` — one JSON object per step (the source of truth; the rest derive from it).
- `report.md` — human-readable write-up.
- `attack-layer.json` — MITRE ATT&CK Navigator layer.
- `run.json` — run metadata (merged start + finish).

## Outcome

| | |
|---|---|
| Model | `ornith-9b` (uncensored, 8B, fits the 8 GB GPU) |
| Target | Juice Shop v16 @ 10.13.37.20 |
| Steps | 40 / 40 |
| `goal_met` | **False** — *expected*: Juice Shop has no literal `flag{}`/`flag:`/`ctf{` string |
| ATT&CK | `T1046` (Network Service Discovery) |

## What it demonstrates

- The full **ReAct loop**: the model reasons, emits one shell command per step, the **scope
  guard** gates it, the executor runs it in the Kali container, and every step is logged.
- **Isolation held** — no-egress was verified at boot; nothing in the transcript reaches off-lab.
- **Honest negative result** — the run is committed as-is, not cherry-picked to look like a win.

## Known limitations (motivating v3)

- `ornith-9b` **fixated**: ~30 of 40 steps were near-identical `POST /login` attempts against the
  wrong endpoint (it never discovered Juice Shop's real `/rest/user/login`), so only one technique
  surfaced. This is a small-model behavior — it loops without strong state — and is exactly what
  the v3 **memory/compaction + dedup** work targets. The two `blocked` steps are empty model
  completions the guard fail-closes on (not a parser bug).

## Reproduce

```powershell
# start a model server (e.g. start-ornith-9b.bat on :8080), then:
$env:LLM_ENDPOINT="http://localhost:8080/v1"; $env:LLM_MODEL="ornith-9b"
python lab.py up        # brings the lab up, verifies NO egress (fails closed)
python lab.py attack    # writes a fresh run under runs/<run_id>/
```
