# AGENTS.md — nettools (SOC Tool, Network Inspection module)

Agent instructions for this repository. Read this first, then `MEMORY.md`
(working memory per session) and `README.md` (operator-facing description).

## Skills

This repository uses the [superpowers](https://github.com/obra/superpowers)
skill set, installed under `.agents/skills/`:

`brainstorming`, `writing-plans`, `executing-plans`, `test-driven-development`,
`systematic-debugging`, `verification-before-completion`,
`requesting-code-review`, `receiving-code-review`,
`finishing-a-development-branch`, `using-git-worktrees`,
`dispatching-parallel-agents`, `subagent-driven-development`,
`writing-skills`, `diagnosing-superpowers`, `using-superpowers`.

Rules of use:

1. **Invoke the skill before acting.** New feature or behaviour change →
   `brainstorming` first, then `writing-plans` for anything multi-step.
   Bug or failing test → `systematic-debugging`.
2. **`test-driven-development` for every code change**: write the failing
   test, watch it fail for the expected reason, then write the minimum code
   to pass. No production code without a failing test first.
3. **`verification-before-completion` before any success claim**: run
   `go test -count=1 ./...`, `go vet ./...`, `gofmt -l .`, and exercise the
   real interface (CLI/TUI/web) with the built binary.
4. Do not use or reintroduce `god-mode-skill`; it was removed in favour of
   the set above.

## Toolchain

Go is not on `PATH` by default on this host:

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
```

## Verification commands (required before claiming completion)

```bash
export PATH="$HOME/sdk/go1.25.0/bin:$PATH"
go build ./... && go vet ./... && gofmt -l . && go test -count=1 ./...
```

Rebuild all four release targets after any source change (binaries are
committed deliberately):

```bash
cd cmd/nettools
CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -o ../../build/nettools-linux-amd64 .
CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -o ../../build/nettools-linux-wsl .
CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -o ../../build/nettools-linux-arm64 .
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o ../../build/nettools-windows-amd64.exe .
cd ../.. && cp build/nettools-linux-amd64 ./nettools
```

## Architecture rules

- One shared core (`internal/core/*`), three thin front-ends
  (`cmd/nettools` CLI, `internal/tui`, `internal/webui`). **Any check the CLI
  can run must be reachable from the TUI and the web UI** (FR-S1/S2): every
  new switch needs a CLI flag, a TUI key, and a web form field.
- One results model: `finding.Finding{Kind, Severity, What, Because, Detail,
  Tags}`. Every finding carries a severity and a plain-language `Because`
  (FR-S7); severity is never conveyed by colour alone (FR-S5).
- Operator-supplied targets only (FR-S8). No scanning, no discovery of
  third-party names. Checks that leave the target's own records (DoH, CT
  logs, wordlist, AXFR) are **opt-in** and default to off.
- Offline tests: fixtures are in-process UDP DNS servers and in-process TLS
  servers (`internal/core/*/`... `_test.go`). No test may depend on the
  public network.
- Runtime bounds (NFR-2/3): `--timeout` bounds each DNS query and each TLS
  connect/handshake attempt (default 5s). Never introduce an unbounded dial,
  read, or handshake.
- No CGO anywhere; single static binary per target.

## Documentation to update with any change

| File | Purpose |
|---|---|
| `README.md` | operator-facing: flags, check catalogue, known state, measured runtime |
| `MEMORY.md` | per-session working memory: what changed, decisions, gotchas |
| `progress.md` | long-term completion evidence and next steps |
| `docs/NNN-*.md` | decision records (one per judgement call) |
| `docs/superpowers/specs/` | designs produced by the brainstorming skill |
