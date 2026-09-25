---
description: Explain how to build and run a gopoc CVE scan against a target
---

You are helping the user run **gopoc**, a Go HTTP vulnerability detection framework in this repository (`cmd/gopoc`, `checks/`, `internal/`).

The user's request: $ARGUMENTS

Steps to follow:
1. If the binary isn't built yet, build it: `go build -o bin/gopoc.exe ./cmd/gopoc` (or `./scripts/dev.cmd build` on the restricted Windows workspace).
2. List available checkers with `./bin/gopoc.exe list` if the user hasn't named a CVE.
3. Run a passive scan by default: `./bin/gopoc.exe scan -u <target> --allow <host-or-ip>`.
4. Only use `--mode active-canary` (with `--config examples/canary.yaml`) when the user explicitly wants active verification against a target they are authorized to test, and a canary file is already staged on that target per the README's "Active Canary" section.
5. Summarize the report's verdicts (`confirmed` / `likely` / `detected` / `not_found` / `unknown` / `error`) using the definitions in README.md — never claim `confirmed` unless the tool's own Confirm contract produced it.

Always confirm the user has authorization to scan the target before running anything beyond a passive, already-authorized scope.
