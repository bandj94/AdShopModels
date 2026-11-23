# sample-run — v2 both-sides run (red + blue)

A **live** run with the **blue team online**, committed as the v2 deliverable
(`v2.0-blue-team`). The uncensored local model **`ornith-9b`** drives the Kali attacker against
**OWASP Juice Shop v16** on a Docker internal no-egress network, while **Suricata** (NIDS) and
**Wazuh** (SIEM) watch and alert. This directory holds *both* sides of the engagement.

## Files

| Side | File | What |
|---|---|---|
| 🔴 red | `transcript.jsonl` | one JSON object per attacker step (source of truth) |
| 🔴 red | `report.md` | attacker write-up |
| 🔴 red | `attack-layer.json` | MITRE ATT&CK Navigator layer (attacker intent) |
| 🔴 red | `run.json` | run metadata |
| 🔵 blue | `bluelogs/eve.json` | Suricata events (what the wire saw) |
| 🔵 blue | `bluelogs/alerts.json` | Wazuh alerts (correlated + ATT&CK-tagged) |
| 🔵 blue | `bluelogs/summary.json` | alert counts by signature / rule / technique (`lab.py collect`) |

## Both-sides timeline

**🔴 Attacker (`ornith-9b`, 40 steps, `goal_met=False`)** — mapped intent `T1046`, `T1083`,
`T1190`: an `nmap` port scan, then web enumeration and injection-style probing of Juice Shop's
REST API (`/rest/products/search`, `/jwttool`, `/api/...`). It never reached a flag (Juice Shop
has no literal `flag{}`), and — as with the v1 run — a small 8B agent loops rather than pivoting.

**🔵 Defender (Suricata + Wazuh)** — detected the reconnaissance: **2 Suricata alerts** for the
SYN scan → Wazuh rule **`100102` (T1046 Network Service Discovery)**. See `bluelogs/summary.json`.

**The interesting part — a detection *gap*.** The attacker's intent spanned `T1046/T1083/T1190`,
but the blue team only caught `T1046`. The web-layer probing evaded Suricata for a subtle reason:
the model *did* send a SQLi tautology (`?search=' OR '1'='1`, steps 33–34), but with a **raw,
un-encoded space** — which malformed the HTTP request line, so Suricata logged those requests as
HTTP **anomalies** (`REQUEST_LINE_INCOMPLETE`; see `bluelogs/eve.json`) rather than parseable
`http` events, and sig `9000004`'s `http.uri` match never had a clean URI to fire on. A properly
URL-encoded tautology *does* trip `9000004` (verified per-signature in `blueteam/README.md`). That
red-vs-blue delta — *attacker did X, defender saw only Y* — is the whole point of the lab, and an
honest, measurable result rather than a staged "everything caught" demo.

## Reproduce

```powershell
Copy-Item config\profiles\docker-web.yaml config\config.yaml   # blue-team profile
python lab.py up                                               # lab + Suricata + Wazuh, no egress
# start a model server (e.g. start-ornith-9b.bat), then:
$env:LLM_ENDPOINT="http://localhost:8080/v1"; $env:LLM_MODEL="ornith-9b"
python lab.py attack
python lab.py collect                                          # pulls bluelogs/ into the run
```
