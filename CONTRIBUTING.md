# Contributing / working notes

Small, single-purpose commits; conventional-commit messages; push at the end of a session; tag
at each milestone. The full checkpoint plan is in [`docs/roadmap.md`](docs/roadmap.md).

## Local dev

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest            # tests (safety, config, agent loop — no Docker/model needed)
python -m ruff check .      # lint
python lab.py doctor        # toolchain + model + scope-guard health
```

## Rules of the road

- **Safety is code.** Anything touching scope/egress/caps needs a test in `tests/`. Never weaken
  the fail-closed checks in `orchestrator/config.py` or the guard in `orchestrator/safety.py`
  without a very good reason and a test proving the new behavior.
- **Never commit secrets.** `.env`, `keys/`, and the live `config/config.yaml` are git-ignored.
- **Detections ship with a test case.** Every rule in `blueteam/` names its ATT&CK technique and
  a one-line way to trigger it.
- **Conventional commits:** `feat:`, `fix:`, `docs:`, `test:`, `chore:`, `refactor:`, `ci:`.
