# SOC Tool — Network Inspection Module

**Project:** security & network assessment toolkit (internal, defensive)
**Module:** Network Inspection — TLS certificate verification + DNS intelligence
**Version:** 0.1.0-dev
**Generated:** 2026-10-11

## What this project is

One internal, cross-platform security tool (Windows + Linux) that answers
certificate and DNS questions about the organisation's own assets, records the
evidence, and ships as a single dependency-free binary with a headless CLI,
terminal UI, and local web UI.

This README covers the **network inspection module** only. The plan
(`project-plan.md`) and specification (`requirements-spec.md`) are the source
of truth for scope, tiers, and acceptance criteria.

## Build

Pure Go, no CGO in the core. One machine, cross-compile into a static-ish
binary per target:

```bash
cd cmd/nettools
CGO_ENABLED=0 go build -o ../../build/nettools-linux-amd64 .
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o ../../build/nettools-linux-arm64 .
CGO_ENABLED=0 GOOS=linux GOARCH=wasm go build -o ../../build/nettools-linux-wsl . 2>/dev/null || true
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o ../../build/nettools-windows-amd64.exe .
```

Run the headless CLI:

```bash
./nettools-linux-amd64 --version
./nettools-linux-amd64 --help
./nettools-linux-amd64 --headless example.com example.com:8443
```

## What's in the tree

| Path | Purpose |
|---|---|
| `cmd/nettools/main.go` | Headless CLI entry point (`--help`, `--version`, `--headless host1 host2 ...`) |
| `cmd/build/build.go` | Build pipeline note (documented, no Go package) |
| `internal/core/target/` | `Target` parsing/validation (`target.go`, `helpers.go`) |
| `internal/core/finding/` | Severity model + `Finding` results model consumed by TUI/web UI |
| `internal/core/engine/` | Orchestration: `Context` + `Run(ctx, target)` |
| `internal/core/dnscheck/` | DNS checks: A/AAAA/CAA |
| `internal/core/dns/` | Shared Go DNS client (`dns.Lookup`, `dns.LookupA`, `dns.LookupMX`, `dns.LookupTXT`, `dns.LookupNS`, `dns.LookupSOA`, `dns.LookupCAA`, `dns.LookupSRV`, `dns.LookupPTR`, `dns.LookupCNAMERecord`) |
| `internal/core/tlscheck/` | TLS certificate checks: identity, validity, expiry, SAN/CN, chain, hostname, protocol/cipher |
| `internal/core/audit/` | JSONL audit log (`audit.go`) |
| `internal/core/report/` | Report rendering (see `requirements-spec.md` for the tier map) |
| `go.mod` / `go.sum` | Module + dependencies (`github.com/miekg/dns`, `golang.org/x/net`) |

## Requirements

See `requirements-spec.md` and `project-plan.md`. Key points:

- **FR-C1 / FR-C2 / FR-S3:** single target, `host:port`, imported list, and
  headless CLI run end-to-end.
- **FR-C3 through FR-C21 / FR-D1 through FR-D23:** Tier 1/Tier 2 DNS and
  certificate capabilities, split by priority.
- **FR-A1 / FR-A4 / FR-C4 / FR-C5 / FR-C7:** audit log fields, JSONL format,
  expiry thresholds, hostname matching, and protocol/cipher reporting.
- **FR-R1 through FR-R9 / FR-S1 through FR-S9 / FR-S6:** text/structured/JSON
  export, remediation guidance, and shared-core TUI + desktop parity.
- **FR-A6 / FR-A7 / FR-A8 / FR-A9:** secrets never logged, no plaintext
  credentials, local-only, no telemetry, offline operation.

## Environment & dependencies

- Go toolchain (module declares `go 1.25.0`). Core uses only the standard
  library plus `github.com/miekg/dns` for record-level queries.
- Reference tools for verification (optional, not required to build):
  `openssl s_client`, `dig`.

## Verification

```bash
go test ./...   # no tests present in this stub; add fixtures and reference data
CGO_ENABLED=0 go vet ./...
gofmt -l ./...
```

## Known state

- `docs/`, `testdata/`, `web/` are empty stubs; `bin/` holds a scratch build
  of `nettools-test`. `internal/core/report/` now renders the structured
  text report (FR-R4/R5) with tests.
- Unit tests exist for `target`, `finding`, `audit`, `dnscheck`, `tlscheck`
  (hand-built x509 fixtures), and `report`; run with `go test ./...`.
  `engine`, `internal/core/dns`, and `cmd/nettools` are not yet covered.
- This project has no git history committed yet.
- The milestone/approval record in `project-plan.md` is **not** a substitute
  for an explicit operator approval before any non-headless feature is
  implemented.

## License

Project scope is reserved; authorise the license before any distribution.

## Maintenance & ownership

- **`README.md`** — this file: what the project is, how to build, what is in
  the tree, and how to verify it.
- **`MEMORY.md`** — per-task work memory: what each task changed, why, and
  what the next step is.
- **`progress.md`** — long-lived ownership: file/state of the current task
  sequence, completion status, and next step.
