# Contributing to woscap

Thanks for contributing. This project follows a lightweight, issue-driven flow.

## Ground rules

- **Everything is tracked through issues.** Before starting work, make sure an
  issue exists and is assigned to you. Reference it in your branch and PR.
- **Design first for non-trivial work.** Substantial features get a short design
  in `docs/superpowers/specs/` before implementation.
- **Zero endpoint dependencies.** Code that runs on an audited host must use only
  in-box Windows PowerShell 5.1. External modules are allowed only as dev/test
  tooling (e.g. Pester, PSScriptAnalyzer) or in operator-side integrations.

## Workflow

1. Pick or open an issue.
2. Branch from `main`: `git checkout -b <type>/<issue#>-short-slug`
   (`type` = `feat` | `fix` | `docs` | `test` | `chore`).
3. Make changes with tests. Follow existing patterns.
4. Run checks locally (see below).
5. Open a PR that references the issue (`Closes #NN`). Fill in the PR template.
6. CI must pass and review must approve before merge. Merges are **squash-only**.

## Commit conventions

- Use clear, imperative commit subjects (Conventional-Commits style encouraged:
  `feat:`, `fix:`, `docs:`, `test:`, `chore:`).
- **All commits must be GPG-signed.**

## Local checks

```powershell
# Lint (targets Windows PowerShell 5.1 compatibility)
Invoke-ScriptAnalyzer -Path . -Recurse -Settings ./PSScriptAnalyzerSettings.psd1

# Tests
Invoke-Pester -Path ./tests
```

## Testing expectations

- New check helpers and the descriptor evaluator get unit tests (mock the OS).
- Reporters get golden-file tests validated against the target schema.
- The read-only guarantee of the audit path must remain covered.
