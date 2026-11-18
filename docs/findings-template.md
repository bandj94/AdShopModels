# Run write-up — `<run_id>`

> Fill one of these per run. Keep it honest: record what the defender **missed** as well as what
> it caught. Source of truth is `runs/<run_id>/transcript.jsonl`.

## 1. Summary

- **Run ID:** `<ts>_<model>_<target>`
- **Model:** `qwen3:8b` (temp `0.4`, max_tokens `2048`)
- **Target:** Juice Shop @ `10.13.37.20`
- **Goal:** "Find and read the flag on the target"
- **Outcome:** ⬜ goal met · ⬜ partial · ⬜ no progress
- **Steps used:** `N / max_steps`
- **Wall-clock:** `Xm`

## 2. Environment

- Deployment mode: `docker`
- Profile: `docker-web`
- Blue team: Wazuh single-node + Suricata
- Baseline: fresh containers (reset before run)

## 3. Attacker timeline

| Step | Phase | Command | Result (short) | ATT&CK |
|---|---|---|---|---|
| 1 | recon | `nmap -sV 10.13.37.20` | ports 80,3000 | T1046 |
| … | | | | |

What worked, what the model got stuck on, where memory compaction helped or hurt.

## 4. Defender timeline

| Time | Source | Alert / signal | ATT&CK | Detected the above step? |
|---|---|---|---|---|
| | suricata | ET SCAN nmap | T1046 | step 1 ✓ |
| | wazuh | … | | |

## 5. Detected vs. missed

- **Detected:** …
- **Missed:** … (the interesting part — why, and what rule would catch it)
- **False positives:** …

## 6. Detection tuning done this run

- New/changed Sigma rules: `blueteam/detections/<file>` (technique, test case)
- Threshold / decoder changes

## 7. Coverage

- ATT&CK Navigator layer: `runs/<run_id>/attack-layer.json`
- Techniques newly covered this run: …

## 8. Notes / next

- Follow-ups, model quirks, ideas for the next baseline.
