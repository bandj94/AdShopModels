# Blue team: Suricata -> Wazuh

```
attacker (10.13.37.10) --HTTP/TCP--> target (10.13.37.20)        labnet (internal, no egress)
                                          |  same netns
                                       suricata  --writes--> volume suricata-logs: eve.json
                                                                  |  (read-only mount)
                                       wazuh-manager (mgmt net only) logcollector -> analysisd
                                          -> /var/ossec/logs/alerts/alerts.json
```

- **Suricata** (`lab-suricata`) shares the target's network namespace, so it sees every packet
  to/from the target. It loads ONLY `suricata/local.rules` (no ET download, no egress needed) and
  writes JSON events to `/var/log/suricata/eve.json`.
- **Wazuh manager** (`lab-wazuh-manager`) is on `mgmt` only, so the attacker cannot reach it. It reads
  `eve.json` via `wazuh/config/ossec.conf` (`<localfile>` json) and applies
  `wazuh/rules/local_rules.xml`. Only the API (55000) is published, on host `127.0.0.1`.
- Wazuh rules match on `alert.signature_id` = the Suricata sid, so the two rule files are paired
  (a unit test, `tests/test_bluelogs.py`, fails if they drift).
- **Network posture:** `labnet` is internal with **no egress** (verified at boot). `mgmt` is a
  normal bridge, so `wazuh-manager` *can* reach the internet — but nothing bridges `labnet` and
  `mgmt`, so the attacker (on `labnet`) cannot see the manager, and the no-egress guarantee for
  the attack surface is unaffected. The boot egress-check probes `labnet`.

## Detections

| Technique | Suricata sid | Wazuh rule | Sigma |
|---|---|---|---|
| T1046 port scan | 9000001 | 100102 (lvl 8) | `detections/port_scan.yml` |
| T1190 sqlmap UA | 9000002 | 100101 (lvl 10) | `detections/sqlmap_sqli.yml` |
| T1190 SQLi tautology / UNION (URI, body) | 9000004/5/7 | 100104 (lvl 10) | `detections/sqli_patterns.yml` |
| T1595.003 ffuf/gobuster UA, high req rate | 9000003/9 | 100103 (lvl 7) | `detections/content_discovery.yml` |
| T1110 login brute force / hydra | 9000006/8 | 100105 (lvl 9) | `detections/brute_force_login.yml` |

Base rule 100100 (lvl 6) fires on any Suricata alert. Note: sid 9000001 counts bare SYNs, so a
heavy `nmap -sT` and a tight curl loop opening new connections can also trip it.

## Verify a detection (end to end)

```sh
python lab.py up
# 1. attacker action (a deliberately noisy one)
docker exec lab-attacker sh -lc 'curl -s -A "sqlmap/1.8" "http://target:3000/rest/products/search?q=1" >/dev/null'
# 2. Suricata saw it
docker exec lab-suricata sh -lc 'grep 9000002 /var/log/suricata/eve.json | tail -n 1'
# 3. Wazuh alerted (allow ~5-10s)
docker exec lab-wazuh-manager sh -lc 'grep 100101 /var/ossec/logs/alerts/alerts.json | tail -n 1'
# 4. Offline rule test of the Wazuh logic
# optional: docker exec -it lab-wazuh-manager /var/ossec/bin/wazuh-logtest   (paste an eve.json alert line)
```

More triggers: `nmap -sS -p1-1000 target`, `ffuf`/`gobuster` against `http://target:3000/`,
the `# test:` lines at the bottom of each Sigma file. After a run: `python lab.py collect` copies
`eve.json`, `alerts.json` and a `summary.json` into `runs/<latest>/bluelogs/`.
Alert state is ephemeral; collect before `down`/`reset`.

## Troubleshooting

- No eve.json: `docker logs lab-suricata` (rule syntax errors are fatal; test with
  `docker exec lab-suricata suricata -T -S /lab-rules/local.rules -c /etc/suricata/suricata.yaml`).
- Suricata alert but no Wazuh alert: `docker exec lab-wazuh-manager tail /var/ossec/logs/ossec.log`
  (logcollector must say it is monitoring eve.json; rule load errors show up here).
- Filebeat errors in the manager log are expected in core mode (no indexer).

## Optional: indexer + dashboard (not enabled by default, not validated)

`docker compose ... --profile wazuh-ui` adds `wazuh-indexer` and `wazuh-dashboard` (mgmt network;
dashboard on `127.0.0.1:5601`). Before it works you must generate TLS certs into
`blueteam/wazuh/certs/` with Wazuh's `wazuh-certs-tool` and wire the manager's filebeat/indexer
credentials; see comments in `infra/docker/overrides/siem.wazuh.yml`. The core pipeline does not
need it. `.gitignore` the certs.

## Per-run write-up template

Copy to `runs/<run>/bluelogs/WRITEUP.md`:

```markdown
# Run <id>: <model> vs <target>
Goal: ...   Outcome: success / fail   Steps: N

## Timeline (UTC)
| Time | Attacker (command / intent) | ATT&CK | Suricata (sid, signature) | Wazuh (rule, level) | Detected? |
|---|---|---|---|---|---|
| hh:mm:ss | nmap -sV target | T1046 | 9000001 | 100102 / 8 | yes |

## Detection summary
- Detected techniques: ...   Missed: ...   Time-to-first-alert: ...
- False positives: ...

## Gaps and tuning
- Missed behavior -> proposed rule/sigma:
- Noisy rule -> proposed threshold change:
```
