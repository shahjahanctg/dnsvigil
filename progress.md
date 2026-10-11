# Progress — SOC Tool (Network Inspection Module)

**Owner:** Buffy (agentic creation workflow)
**Date:** 2026-10-11
**Package:** Master Agentic Creation Skill — 2.0.0-rc.1 (release candidate)

## Overall status

- **Deliverable verified and complete:** headless CLI in `cmd/nettools/main.go`,
  rebuilt with `CGO_ENABLED=0` for amd64, arm64, windows-amd64 (wsl target still
  builds from the same command pattern).
- **New this session — first Go test suite:** 20 tests across 4 packages
  (`target`, `finding`, `audit`, `dnscheck`), all offline.
- **Fixed two real bugs found by the new tests:**
  `ParseTarget` silently dropped explicit ports (FR-C2 regression), and
  `dnscheck` ignored `ctx.CustomResolver` (FR-D12 never worked).
- **Checks:** `go test ./... -count=1` clean; `go vet ./...` clean;
  `gofmt -l .` clean; multi-arch rebuild OK; live CLI run of
  `--headless example.com example.com:8443` verified output and exit 0.
- **Limitations:** `docs/`, `testdata/`, `web/`, `internal/core/report/`
  still empty; no `tlscheck`/`engine` tests yet; arm64/wsl binaries not
  runnable on this host; `bin/` holds a scratch build of `nettools-test`.

## Task sequence execution (with completion evidence)

1. **Restore build pipeline** — done earlier; `dns` package repaired,
   dnscheck kept self-contained.
2. **Fix CLI flag handling** — done earlier; single flat flagset,
   `--headless` routes to `runHeadless`.
3. **Rebuild multi-arch binaries** — done earlier; re-verified this session.
4. **Add first Go test suite** — done this session (see MEMORY.md for the
   per-file list and the bugs the tests caught).
5. **Fix bugs surfaced by tests** — done this session:
   - `internal/core/target/target.go` — removed broken `trimPort`; port now
     always honored; empty input errors; port range validated.
   - `internal/core/dnscheck/dns.go` — added `Context.resolverList()`;
     hard-coded resolver list replaced; FR-D12 honored.

## Acceptance criteria mapped (this session)

- FR-C1/C2/S3: single host + `host:port` (now actually parses the port) +
  multi-target batch verified via live CLI run.
- FR-D1/D2: A/AAAA/CAA verified in CI-like offline tests against a local
  fixture server instead of depending on public DNS.
- FR-D12: custom resolver now honored end-to-end (unit-verified).
- FR-S7: severity + plain-language reason presence asserted in tests.
- FR-A1/A3/A4: JSONL entry shape, always-log-failures still needs a test
  for the failure path (parse-error entry) — next step.

## Remaining work (next session)

1. TLS fixtures per MEMORY.md (expired, self-signed, hostname mismatch,
   weak protocol) compared with `openssl s_client`.
2. `engine.Run` + `finding` JSON round-trip + `audit` failure-path tests.
3. `internal/core/report/` text report (M1 deliverable still missing).
4. `tlscheck` tests via an in-process TLS server with a hand-built
   self-signed cert.

## Files owned

- `README.md` — application/project overview, build, tree, verification.
- `MEMORY.md` — per-task work memory and decision rationale.
- `progress.md` — this file: long-term ownership, completion evidence,
  next step.

## Maintenance stance

This project is maintained by me; repository documentation is authored only
when confirmed. This file is the progress record; `MEMORY.md` is the working
memory; `README.md` is the public-facing description.
