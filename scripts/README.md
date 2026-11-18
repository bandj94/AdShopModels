# scripts/

Thin wrappers that `lab.py` and operators share. Keep them small and single-purpose; `lab.py`
is the primary control surface.

| Script | Purpose |
|---|---|
| `egress_check.sh` | Standalone no-egress verification for the lab network (Linux/manual). `lab.py up` runs an equivalent check inline on Windows. |

Future (v1–v2): `collect.sh` (pull Wazuh/Suricata logs), `build_attacker.sh` (build the Kali
image), and VM-mode lifecycle wrappers.
