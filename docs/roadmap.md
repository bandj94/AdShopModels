# Build roadmap — commit & push checkpoints

This is the per-commit checklist that keeps the GitHub history clean and legible. The rule of
thumb: **one logical change per commit, conventional-commit messages, push at the end of every
session, tag at every milestone.**

Conventional prefixes used here: `feat:` `fix:` `docs:` `test:` `chore:` `refactor:` `ci:`.

---

## v0 — Scaffolding (this repo's initial history)

| # | Commit | Contents |
|---|---|---|
| 1 | `chore: scaffold repo — license, safety model, gitignore` | LICENSE, SAFETY.md, .gitignore/.gitattributes, .env.example, original plan |
| 2 | `docs: adapt plan into README + architecture + roadmap (windows/docker)` | README.md, docs/* |
| 3 | `feat(config): lab profile schema, loader, example profiles` | config/profiles/*, orchestrator/config.py |
| 4 | `feat(safety): scope guard + allow/deny + step caps, with tests` | orchestrator/safety.py, tests/test_safety.py |
| 5 | `feat(orchestrator): llm client, executors, memory, logging, mitre` | orchestrator/{llm_client,executor,memory,logging_jsonl,mitre}.py, tests/test_config.py |
| 6 | `feat(agent): ReAct loop + prompts` | orchestrator/agent.py, orchestrator/prompts/* |
| 7 | `feat(cli): lab.py control surface + scripts + Makefile mirror` | lab.py, scripts/*, Makefile |
| 8 | `feat(infra): docker compose base (internal net) + target/siem overrides` | infra/docker/*, infra/network/* |
| 9 | `feat(blueteam): suricata + wazuh config stubs + sigma detection` | blueteam/* |
| 10 | `ci: lint + pytest workflow; packaging; sample-run skeleton` | .github/workflows/ci.yml, pyproject.toml, requirements*.txt, runs/sample-run/* |

**► Checkpoint:** `git push -u origin main` then
```
git tag -a v0.1-scaffold -m "v0 scaffolding complete"
git push origin v0.1-scaffold
```

---

## v1 — Human-in-the-loop, single target

| # | Commit (suggested) |
|---|---|
| 1 | `feat(infra): build attacker Kali image with core tooling` |
| 2 | `feat(infra): juice-shop target on labnet; publish nothing to host` |
| 3 | `feat(exec): wire DockerExecExecutor to the live attacker container` |
| 4 | `feat(agent): end-to-end single-target run writing transcript.jsonl` |
| 5 | `test: executor integration (mocked) + scope-guard regression` |
| 6 | `docs: commit first runs/ example + annotate transcript` |

**► Checkpoint:** push · tag `v1.0-single-target` · the `runs/` example is the deliverable.

---

## v2 — Blue team online

| # | Commit (suggested) |
|---|---|
| 1 | `feat(blueteam): wazuh single-node compose + indexer on mgmt net` |
| 2 | `feat(blueteam): suricata sniffing labnet; eve.json -> wazuh` |
| 3 | `feat(detections): N sigma rules + wazuh-native form + ATT&CK notes` |
| 4 | `feat(mitre): map transcript actions to ATT&CK + emit navigator layer` |
| 5 | `docs: per-run write-up from findings-template; both-sides timeline` |

**► Checkpoint:** push · tag `v2.0-blue-team`.

---

## v3 — Autonomous + comparative

| # | Commit (suggested) |
|---|---|
| 1 | `feat(agent): bounded autonomy — caps + memory compaction` |
| 2 | `feat(cli): batch runner for model comparison on identical baselines` |
| 3 | `feat(report): comparison table (how far each model got + detections)` |
| 4 | `docs: v3 comparison report + runs/ corpus` |

**► Checkpoint:** push · tag `v3.0-autonomous`.

---

## Session discipline (copy/paste)

Start of a session:
```powershell
git pull --ff-only
git switch -c feat/<topic>        # optional: branch per feature, PR into main
```

End of a session (checkpoint):
```powershell
git add -A
git status                        # review what you're committing
git commit -m "feat(scope): concise what-and-why"
git push
```

Milestone:
```powershell
git tag -a vX.Y-name -m "milestone summary"
git push origin vX.Y-name
```

> Keep secrets out of commits: `.env`, `keys/`, and live `config/config.yaml` are git-ignored on
> purpose. If you ever stage one by accident, `git restore --staged <file>` before committing.
