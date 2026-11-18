# Suricata config

Suricata shares the **target's** network namespace (see `infra/docker/overrides/nids.suricata.yml`)
so it sees every packet to/from the target — i.e. all of the attacker's traffic — and writes
`eve.json` to the `suricata-logs` volume, which the Wazuh manager ingests.

## Files

- `local.rules` — custom, ATT&CK-annotated signatures (sids 9000000+). Mount read-only into the
  container at `/var/lib/suricata/rules/local.rules` and reference it from `suricata.yaml`
  (`rule-files:`). Wiring the mount is a v2 step.

## Testing a rule (from the attacker container)

```sh
# T1190 — should raise sid 9000002
docker exec lab-attacker sh -lc 'curl -s -A "sqlmap/1.8" http://target:3000/rest/products/search?q=1'
# then check:
docker exec lab-suricata sh -lc 'tail -n 50 /var/log/suricata/eve.json | grep 9000002'
```

Set `HOME_NET: "[10.13.37.20/32]"` (the target) in `suricata.yaml` so the directional rules match.
