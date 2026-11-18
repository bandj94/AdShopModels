# Detections (detections-as-code)

Portable **Sigma** rules are the source of truth; the Wazuh-native (`../wazuh/rules`) and
Suricata (`../suricata/local.rules`) forms are the deployed equivalents. Every rule here is
annotated with the ATT&CK technique it covers and carries a one-line **test case** so coverage
is verifiable, not aspirational.

| Rule | Technique | Deployed as |
|---|---|---|
| `sqlmap_sqli.yml` | T1190 Exploit Public-Facing Application | Suricata sid 9000002, Wazuh 100101 |
| `content_discovery.yml` | T1595.003 Wordlist Scanning | Suricata sid 9000003 |
| `port_scan.yml` | T1046 Network Service Discovery | Suricata sid 9000001, Wazuh 100102 |

## Workflow
1. Write/adjust the Sigma rule here (with a `test:` comment).
2. Translate to the deployed form (Suricata/Wazuh).
3. Run the test case against the lab; confirm the alert fires.
4. Record detected-vs-missed in the run write-up (`docs/findings-template.md`).
