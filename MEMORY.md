# MEMORY — SOC Tool (Network Inspection Module)

> Working memory for the current task sequence only. Read before starting
> similar work; do not carry unrelated facts across tasks.

## Current task sequence

1. Restore build pipeline.
   - **Problem:** `go test ./...` failed; `go vet` reported a dead package
     `github.com/soc-tool/internal/core/dns` while the tree also contained
     `internal/core/dnscheck/dns.go`. The imported `dns` package had been left
     with a broken, incomplete implementation.
   - **Repair:** implemented `internal/core/dns/resolver.go` as the shared Go
     DNS client (`dns.Lookup`, `LookupA/MX/TXT/NS/SOA/CAA/SRV/PTR/CNAME`).
   - **Decision:** `dnscheck` keeps its own `Context + Run` so the engine's
     `engine.Context` struct is not changed. Duplication is intentional, not
     a defect.
   - **Verification:** `go test ./cmd/... ./internal/...` clean;
     `CGO_ENABLED=0 go vet ./...` clean; rebuilds succeed.

2. Fix CLI flag handling.
   - **Problem:** `cmd/nettools/main.go` miswired the headless branch, so
     `--headless` with targets never entered the headless run.
   - **Repair:** single flat `flag.FlagSet` for `nettools`; `--headless`
     routes to `runHeadless(fs.Args())`.
   - **Verification:** `--help` correct; `--headless` no args → exit 2 with
     usage; `--headless google.com` → findings + exit 0.

3. Rebuild multi-arch binaries.
   - **Performed:** `CGO_ENABLED=0` builds: `nettools-linux-amd64`,
     `nettools-linux-arm64`, `nettools-linux-wsl` (wasm-derived), plus the
     existing `nettools-windows-amd64.exe`. `nettools-linux-amd64` run with
     `--version`, `--help`, and a real headless scan.
   - **Verification:** binary file types and run output captured; `gofmt`
     clean afterwards.

## Decisions (record now, not later)

- **No git history.** The repo has one commit (`b215f0f SOC Tool`) and no
  `.git` changes — treat the working tree as the current state; do not invent
  diffs or commits.
- **No tests yet.** `testdata/`, `web/`, `docs/`, and
  `internal/core/report/` are empty. "Verification passed" means compile +
  vet + gofmt + multi-arch build + binary run, not unit tests.
- **Dnscheck stays self-contained.** Do not refactor it into `dns/` in this
  cycle; the engine struct is load-bearing and must not change.
- **No git tooling.** No `git add/commit/status` performed — no `.git`
  present.

## Next step (what I'd do next if asked)

1. Re-run the resolved build/vet/gofmt chain from a clean cache.
2. Add targeted unit tests for: `target.ParseTarget`, severity ordering,
   `audit` JSONL append, and `dnscheck` record lookups against a local DNS
   fixture.
3. Add fixture endpoints for Tier 1 TLS behaviours (expired, self-signed,
   hostname mismatch, weak protocol) and compare with `openssl s_client`.
4. Rebuild `build/nettools-linux-amd64`, verify headless output including
   parsed `--headless example.com:8443` and multi-target runs.

## Conventions

- Single flat flagset; headless runs through `runHeadless(fs.Args())`.
- No CGO in `internal/core/`.
- One results model (`finding.Finding`); TUI and web UI consume it, never a
  different shape.
- Audit log: JSONL, `op`, `act`, `tgt`, `ts`, `res` (+optional `findings`).
