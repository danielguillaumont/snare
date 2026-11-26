# Working in the Snare repo

Snare is a security product. Correctness and honesty of claims matter more than speed.

## Rules

- **Specs before code.** Every milestone starts from a section in `docs/SPEC.md` or
  `docs/ROADMAP.md`. If a change isn't covered there, update the doc first.
- **Tests first for logic.** Scoring, statistics, decoy selection and alert matching get
  unit tests before or alongside the code. `python -m pytest` must pass before a commit.
- **No live API spend without a ceiling.** Anything that calls a model takes `--max-usd`
  and stops when it is reached. Never raise the default ceiling in code.
- **Measured claims only.** README and docs numbers must come from a results directory
  that is referenced next to the number. Report denominators and confidence intervals.
- **Pre-registration.** Thresholds in `docs/killtest.md` are fixed before a live run.
  Changing them after seeing results must be recorded in that file's changelog.
- **No secrets in the repo.** Honey credentials in fixtures must be obviously fake and
  must not match real provider key formats closely enough to trip secret scanners in
  other people's systems.
- **Defensive scope.** Attack payloads in `experiments/` exist only to test detection in
  our own harness. They target mock tools, never real systems.

## Layout

- `experiments/killtest/` — Python 3.12 harness. Package `killtest`, tests in `tests/`.
- Go module `github.com/danielguillaumont/snare`: CLI in `cmd/snare`, packages in `internal/`
  (`token`, `store`, `alert`, `listener`, `admin`, `server`, `seal`, `egress`, `dashboard`,
  `decoys`, `mcp`, `plant`). Design notes per milestone in `docs/`; overview in `docs/ARCHITECTURE.md`.

## Commands

```powershell
cd experiments/killtest; python -m pytest
cd experiments/killtest; python -m killtest run --dry-run --runs 40
go vet ./...; go test ./...    # Go services; run with -race in CI (needs cgo)
```
