# sample-run (illustrative)

This run was **generated offline** with a scripted model reply sequence and a fake executor, so
it is deterministic and safe to commit — no containers or real model were involved. It exists to
show the exact artifact format a real run produces:

- `transcript.jsonl` — one JSON object per step (the source of truth).
- `report.md` — the human-readable write-up derived from the transcript.
- `attack-layer.json` — a MITRE ATT&CK Navigator layer for the techniques observed.
- `run.json` — run metadata (merged start + finish).

The scenario: recon (nmap, whatweb) → an **out-of-scope command that the scope guard blocks**
(step 3) → endpoint discovery (gobuster) → SQLi (sqlmap) → flag read via UNION injection.

> Note: `mitre.py` is a transparent *rule map*, not a classifier — e.g. the `"id"` key in the
> step-6 JSON response trips the T1033 rule. v2 tightens the mapping. Real runs replace this file
> with `python lab.py attack` once the lab is up.
