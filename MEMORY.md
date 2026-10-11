# MEMORY — SOC Tool (Network Inspection Module)

> Working memory for the current task sequence only. Read before starting
> similar work; do not carry unrelated facts across tasks.

## Current task sequence — Session 2026-10-11 (later)

**Task: add the first unit tests (the file-ownership and verification gap).**

### Performed

1. **Installed Go 1.25.0** at `$HOME/sdk/go1.25.0` (host had no `go`).
   Use: `export PATH="$HOME/sdk/go1.25.0/bin:$PATH"`.
2. **New test files** (all offline, no external services):
   - `internal/core/target/target_test.go` — ParseTarget forms
     (bare/`host:port`/IPv4/empty/non-numeric port), Addr, SortTargets
     ordering, ParseSingle ≡ ParseTarget.
   - `internal/core/finding/findings_test.go` — severity constructors,
     ascending order, Name() incl. UNKNOWN, FR-S7 field presence.
   - `internal/core/audit/audit_test.go` — new files default to
     `audit.jsonl` when path is empty; single write = one line of JSONL;
     concurrency safety (20 goroutines → 20 lines); Rotate prunes by
     entry timestamp and is a no-op when disabled.
   - `internal/core/dnscheck/dns_test.go` — in-process UDP DNS fixture
     server (`newDNSFixture`); verifies FR-D12 custom-resolver behavior,
     record values A/AAAA/CAA, missing-record severities (A/CAA medium,
     AAAA info), direct LookupA/AAAA/CAA.
3. **Fixed bugs found by the new tests** (fixed the cause, did not weaken
   assertions):
   - `internal/core/target/target.go`: ParseTarget silently discarded
     explicit ports (`trimPort` removed the port before split could see
     it) — FR-C2 `host:port` was never honored. Removed trimPort entirely;
     splitHostPort now does the parsing. Added empty-input error,
     port 1–65535 range check, non-numeric port error.
   - `internal/core/dnscheck/dns.go`: `ctx.CustomResolver` was ignored —
     resolvers were hard-coded. Added `Context.resolverList()` honoring
     FR-D12; all three lookup helpers now route through it.
4. **Rebuilt** `build/nettools-linux-amd64`, `-arm64`,
   `nettools-windows-amd64.exe` with `CGO_ENABLED=0` (arm64 not runnable
   on this host; only compile-verified).

### Verification

`go test ./... -count=1` → all pass; `go vet ./...` clean; `gofmt -l .`
clean; multi-arch build OK; live CLI run for `example.com` and
`example.com:8443` returned findings for both targets.

## Decisions (record now, not later)

- **Go toolchain location** — installed to `$HOME/sdk/go1.25.0`, not the
  default `~/go`, to avoid a GOPATH/GOROOT collision warning.
- **`dnscheck` stays self-contained** — only the resolver-list helper was
  added; engine.Context struct is untouched.
- **JSONL convention** — one entry per line, encoder-supplied trailing
  newline; tests assert line counts via `strings.TrimSuffix`+Split.
- **No lint config** — verification means `go test`, `go vet`, `gofmt`.

## Next step (what I'd do next if asked)

1. Wire `report.WriteText` into `runHeadless` (replaces ad-hoc
   `printReport`) — that completes the M1-ish CLI: findings → structured
   text report. Then compare against `openssl s_client`.
2. TLS **server** fixtures need a trust seam: `dialTLS` hard-codes the
   system pool; add optional `Context.RootCAs *x509.CertPool` so
   in-process servers with self-signed test CAs can be exercised
   end-to-end (expiry/self-signed/weak paths).
3. `engine.Run` currently ignores `TLSContext` entirely — tunnel
   `tlscheck.Run` into the flow and test both paths.
4. `cmd/nettools` tests for `runHeadless` arg routing.

### Session 2 additions (record now)

- **tlscheck tests** (`tls_test.go`): hand-built certs (RSA-2048,
  self-signed) test `hostnameFinding` (FR-C5 Critical on mismatch, Info
  on match, Critical on nil leaf), `daysRemaining` (+30d ≈ 30; past < 0;
  zero == 0), `isUnreachable` (refused/no-such-host/timeout → true;
  trust errors → false; real `net.Error` timeout → true), severity name
  stability. Server-level tests deferred until RootCAs seam exists.
- **report package** (`report.go`): `WriteText` produces all five FR-R4
  sections in fixed order; metadata (tool/operator/started/targets,
  FR-R5); findings sorted severity-desc and grouped; remediation lines
  deduped per kind (FR-R6); ToolName required. Tests in `report_test.go`
  cover all sections, ordering, empty run, metadata, dedup, required
  fields.
- Fixtures helper `mustCert(t, host, notBefore, notAfter)` lives in
  `tls_test.go` — reuse for future chain fixtures.

## Conventions

- Single flat flagset; headless runs through `runHeadless(fs.Args())`.
- No CGO in `internal/core/`.
- One results model (`finding.Finding`); TUI and web UI consume it.
- Audit log: JSONL, `op`, `act`, `tgt`, `ts`, `res` (+optional `findings`).
- Custom resolver is honored only through `Context.resolverList()` /
  shared `dns.Context`; no hard-coded IPs elsewhere.
