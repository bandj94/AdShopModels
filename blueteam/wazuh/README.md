# Wazuh

See ../README.md for the pipeline, detection table and verification steps.

- `config/ossec.conf` minimal manager config (ingests Suricata eve.json as JSON).
- `rules/local_rules.xml` ATT&CK-tagged rules, ids 100100+, keyed on Suricata sid.
- Rule levels: 6 = IDS hit, 7-9 = recon/credential, 10 = exploitation.
- Optional indexer/dashboard: see ../README.md (profile `wazuh-ui`).
