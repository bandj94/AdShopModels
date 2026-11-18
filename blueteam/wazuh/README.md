# Wazuh (SIEM)

## v0 (now)
- `rules/local_rules.xml` — custom, ATT&CK-tagged rules that escalate the Suricata alerts the
  manager ingests from the shared `suricata-logs` volume.
- `infra/docker/overrides/siem.wazuh.yml` wires the **manager** only, so the compose graph is
  valid and the rules + eve.json are mounted.

## v2 build-out (single node)
1. Add `wazuh.indexer` and `wazuh.dashboard` services (Wazuh's official single-node compose is
   the reference). Keep them on the **mgmt** network; publish the dashboard to
   `127.0.0.1:${WAZUH_DASHBOARD_PORT}` only.
2. Generate certificates:
   ```sh
   docker run --rm -v "$PWD/blueteam/wazuh/certs:/certificates" \
     wazuh/wazuh-certs-tool:latest -A
   ```
3. Point the manager at the indexer, load `local_rules.xml`, and confirm alerts land in the
   dashboard. Add a decoder for Suricata if a newer Wazuh version needs one.
4. Map each custom rule to its ATT&CK technique and capture a screenshot for the run write-up.

## Rule id / level conventions
- Local rule ids: `100000+`. Suricata sids: `9000000+`.
- Levels: 6 = informational IDS hit, 8 = recon, 10 = active exploitation.
