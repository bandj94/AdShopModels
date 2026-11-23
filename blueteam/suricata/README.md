# Suricata config

Suricata shares the **target's** network namespace (see `infra/docker/overrides/nids.suricata.yml`)
so it sees every packet to/from the target — i.e. all of the attacker's traffic — and writes
`eve.json` to the `suricata-logs` volume, which the Wazuh manager ingests.

## Files

- `local.rules` — custom, ATT&CK-annotated signatures (sids 9000000+). Mounted read-only at
  `/etc/suricata/lab/local.rules` and loaded exclusively via `-S` (see the nids override).

## Testing a rule (from the attacker container)

```sh
# T1190 — should raise sid 9000002
docker exec lab-attacker sh -lc 'curl -s -A "sqlmap/1.8" http://target:3000/rest/products/search?q=1'
# then check:
docker exec lab-suricata sh -lc 'tail -n 50 /var/log/suricata/eve.json | grep 9000002'
```

HOME_NET is set to the target (10.13.37.20/32) via `--set` in the compose command.
