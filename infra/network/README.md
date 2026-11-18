# Isolated network

The lab's isolation is enforced at the network layer.

## Docker mode (this build)

- **`labnet`** is declared `internal: true` in `infra/docker/docker-compose.yml`. Docker creates
  **no gateway** for an internal network, so containers on it **cannot reach the host network or
  the internet** — only each other. Subnet `10.13.37.0/24`.
  - Docker's embedded DNS (`127.0.0.11`) still resolves *container names within the network*
    (e.g. `http://target:3000`). That is internal name resolution, not egress.
- **`mgmt`** is a normal bridge used only by blue-team UIs, which publish to `127.0.0.1` on the
  host. Target traffic never touches it.

### Verification (fails closed)

`lab.py up` runs an egress probe after bringing the stack up:

```
docker run --rm --network labnet alpine:3.20 sh -lc \
  'timeout 4 wget -q -O- http://1.1.1.1 && echo EGRESS || echo NOEGRESS'
```

If anything but `NOEGRESS` comes back, `lab.py up` tears the lab down and refuses to continue.
`scripts/egress_check.sh` is the standalone equivalent.

## VM mode (future, Linux host)

- **libvirt** *isolated* network (`<forward mode='none'/>`), or
- **VirtualBox** *Internal Network* (`intnet`),

both give the same property: an L2 segment with no uplink. The attacker and host-level targets
attach there; the orchestrator reaches them over SSH with a lab-only key.
