# Windows 11 + Docker setup & machine analysis

This file records **why** the lab runs the way it does on this machine, and **how** to set it up.

## Detected machine

| Component | Value |
|---|---|
| OS | Windows 11 Home (23H2, build 22631) |
| CPU | Intel i7-12700H — 14 cores / 20 threads, VT-x enabled |
| RAM | 32 GB |
| GPU | NVIDIA RTX 3070 Ti Laptop — **8 GB VRAM**, driver 596.08 / CUDA 13.2 |
| Disk | ~450 GB free on C: |
| Pre-installed | Ollama (`qwen3:8b`, `llama3.1:8b`, 16k variants), Python 3.12, git, Node, WSL (no distro), winget |
| Installed for the lab | Docker Desktop, GitHub CLI |

## Why all-Docker (not VMs)

- **Windows 11 Home** has no libvirt/KVM and no supported Hyper-V; VirtualBox conflicts with the
  WSL2 backend Docker needs. A clean VM lab isn't practical here.
- The project's first-class requirement is **agent control of the lab**. `docker compose`,
  `docker exec`, and `docker ps` are directly scriptable from PowerShell; VMs are not.
- Web-app targets (Juice Shop, DVWA) fit containers perfectly and pair naturally with an 8 GB
  GPU + an 8B model.
- **Tradeoff accepted:** containers share the host kernel, so this is weaker than VMs for
  full-host privilege-escalation targets. Those are deferred to a future `vm` mode on a Linux
  box. Network no-egress isolation is still fully enforced via an `internal: true` network.

## Why Docker Desktop (not Rancher/Podman/raw WSL)

- Smoothest on Windows: one installer, `docker` on PATH, Compose + GPU included, manages the
  WSL2 VM for us. Free for personal / education / small-business use.
- **FOSS fallbacks** if ever needed: Rancher Desktop, Podman Desktop, or Docker Engine installed
  directly inside a WSL2 Ubuntu distro (driven via `wsl docker ...`).

## Model reality on 8 GB VRAM

- `qwen3:8b` (~5.2 GB) and `llama3.1:8b` (~4.9 GB) fit on the GPU with context headroom → **fast**.
  These are the daily drivers; the config points at `qwen3:8b` by default.
- A **27B** model needs ~16 GB; on 8 GB it spills to CPU/RAM (32 GB available) and is **slow**.
  Keep it as an optional **overnight** comparison model for v3, not interactive use.
- The orchestrator runs on the **host** and reaches Ollama at `http://localhost:11434/v1`. The
  attacker container does **not** need model access, so no `host.docker.internal` wiring is
  required for the model.

## Install Docker Desktop

```powershell
winget install -e --id Docker.DockerDesktop
```

Then:
1. Docker Desktop enables the **WSL2 / Virtual Machine Platform** Windows features. A **reboot**
   is required the first time.
2. After reboot, launch Docker Desktop once and let it finish initializing (whale icon steady).
3. Verify:
   ```powershell
   docker version
   docker run --rm hello-world
   ```
4. (Optional) Settings → Resources: cap CPUs/Memory if you want to reserve headroom for Ollama.

> If `docker run hello-world` fails right after install, it's almost always the pending reboot or
> Docker Desktop still starting. Reboot, start Docker Desktop, wait for the steady whale, retry.

## Ollama (already installed)

```powershell
ollama list                 # confirm models
ollama pull qwen3:8b        # if not present
# Ollama serves an OpenAI-compatible API at http://localhost:11434/v1
```

## GPU in containers (optional, later)

Attacker/target/blue-team containers here are **CPU** workloads — they don't need the GPU. Only
Ollama (on the host) uses the GPU. If a future container ever needs CUDA, Docker Desktop supports
`--gpus all` via the WSL2 NVIDIA runtime, but it's out of scope for this build.

## GitHub CLI

```powershell
winget install -e --id GitHub.cli
gh auth login               # one-time, browser or token — YOU complete this
gh repo create llm-adversary-lab --private --source . --remote origin --push
```
