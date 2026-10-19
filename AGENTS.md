# dnsvigil — Agent Guidance

## Core Architecture
- Entry point: `cmd/dnsvigil/main.go` routes `--headless|--tui|--gui` (first mode flag wins)
- Shared core: `engine.Context` carries every opt-in switch to both DNS/TLS checks (FR-S1/S2)
- Single results model: `finding.Finding` is rendered by CLI, TUI, and web UI — no interface-exclusive capability
- Web UI is `go:embed`'d (`internal/webui/assets/`) and loopback-only (FR-A9)
- History/export are file-based under the working directory; no database (decision D5)

## Essential Commands
**Build** (run from `cmd/dnsvigil`; output goes to `../build/`):
```bash
CGO_ENABLED=0 go build -o ../build/dnsvigil-linux-amd64 .
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o ../build/dnsvigil-linux-arm64 .
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o ../build/dnsvigil-windows-amd64.exe .
```

**Verification** (always run all three after a change):
```bash
go test ./...        # offline suite; no network except explicit live runs
go vet ./...
gofmt -l .           # must print nothing
```

## Key Development Notes
1. **Go version**: `go 1.26.0` from go.mod (README says 1.25.0+, stale). Newer toolchains build it.
2. **Flag ordering**: headless flags precede the target list (FR-S8). `reorderHeadlessArgs` moves them internally, so `--headless example.com --expiry-warn 68` works, but flags-first is the documented form.
3. **Boolean flags in `valuedHeadlessFlags`**: `false` means "does not consume the next arg" (e.g. `log-findings`, `enumerate`). Do not assume every entry takes a value.
4. **Runtime artifacts**: `.dnsvigil/` (history + `settings.json`) and `audit.jsonl` are git-ignored; CLI `--report-dir` defaults to `.dnsvigil/reports/`.
5. **Opt-in checks (multiply per target)**:
   - `--deep`: SRV/DKIM/TLSA/MTA-STS/TLS-RPT/reverse-DNS/TTL/delegation
   - `--enumerate`: protocol/cipher/SNI enumeration (weak ciphers flagged HIGH)
   - `--check-revocation`: OCSP/CRL/CT
   - Network-reaching (off by default, FR-S8): `--doh`, `--discover`, `--discover-ct`, `--axfr`
6. **TUI ctrl-layer** (parity with web form; state always rendered as words, FR-S5):
   `ctrl+p` provider, `ctrl+d` deep, `ctrl+o` DoH, `ctrl+w` discovery, `ctrl+t` CT, `ctrl+x` AXFR, `ctrl+r` revocation, `ctrl+e` enumerate, `ctrl+b` budget, `ctrl+l` wordlist path.
7. **Test seams**: TUI has package var `runCheck`, web UI has `runEngine`; both default to `engine.Run` and are replaced in tests to run offline. `webui.Server.historyDir` lets tests redirect history away from `.dnsvigil/`.

## Web Export, History & Dashboard
- Routes: `POST /export/{json,csv,md,html}` stream the same `report.Write*` output as CLI `--export`; unknown format → 400; export writes nothing to disk.
- `history.Entry` carries `Findings []finding.Finding` (`omitempty`); `Store.AppendEntry` / `Store.RecentFindings` back history. Home shows a "Recent activity" preview (last 5) linking to the dedicated `GET /history` page (all runs newest-first, expandable findings, `?target=` filter, 200-row cap).
- `POST /history/clear` is criteria-driven (modes `all` / `target` / `age` / `target-age`). Without `confirm=yes` it previews the affected count and deletes nothing; with `confirm=yes` it calls `history.Store.ClearMatching` and redirects to `/history?cleared=N`. POST-only, rejects cross-origin posts (`sameOrigin`); `audit.jsonl` and exported reports are never touched.
- Domain matching normalizes target to lowercase + no port (`history.NormalizeTarget`); subdomains stay distinct. Age uses presets in `agePresets`.
- **History retention**: `history.DefaultRetention` (30 days) prunes on every `AppendEntry`, so CLI and web both prune. Configurable via `--history-retention` (default `720h`, `0` disables) — distinct from `--retention`, which is the audit log (FR-A5).
- Reports and history are owner-only: files `0o600`, dirs `0o700` (FR-A6). Do not regress to `os.Create`; history rewrites go through `Store.writeLocked` (temp+rename).
- GUI smoke-testing: start with `BIN --gui & GUI=$!` and `kill $GUI`. Do NOT use `setsid` (it leaks a server on :8089); find leaks with `ss -ltnp | grep 8089`.

## Settings (shared CLI/web defaults)
- `internal/core/settings` persists a `Settings` struct to `.dnsvigil/settings.json` (atomic, `0o600`). `Settings`/`Duration`/`Default`/`Path`/`Load`/`Save`.
- Web: `GET /settings` renders the form, `POST /settings` saves (blank durations keep defaults; bad duration → re-render, no write) and `303`s to `/settings?saved=1`. Cross-origin posts rejected (`sameOrigin`). Nav has a Settings link.
- Runtime: the settings file pre-fills the home run form and supplies flag defaults in `settingsDefaults()` (`cmd/dnsvigil/main.go`) and `runWebUI`; explicit flags still win. `handleRun` seeds its budget from settings, `handleExport` its operator, and `runChecks` threads resolver/timeout/expiry into `engine.Context`.
- Retention precedence: the settings file's `history_retention` is authoritative for the web server over the startup `--history-retention` (`Server.effectiveRetention`).
- Settings holds **no file paths** (audit, report dir, wordlist stay CLI/run-form only).
- Build gotcha: `go build -o ../build/...` resolves against the shell's cwd, which is easy to get wrong here (a stray `cmd/build/dnsvigil-linux-amd64` proved it). Use an absolute `-o` path; a stale tracked binary makes `/settings` fall through to home with no compile error. Re-verify the binary right before smoke-testing.

## Testing & Verification
- **Current state**: `go test ./... -count=1` green (all packages, incl. the new `internal/core/settings`), `go vet` clean, `gofmt -l .` clean, `go build ./...` ok.
- **`internal/tui` tests were red before this session**: `tui.go` and `tui_test.go` were out of sync and the two failing tests were mutually contradictory. Completing the ctrl-layer and correcting the assertions fixed them; keep them aligned when touching the TUI.
- Reference comparison for Tier 1 is against `openssl s_client` (subject, issuer, validity dates, serial).
- **DNSSEC scope**: validates one delegation level (parent DS ↔ served DNSKEY + RRSIG over the DNSKEY set); never claims a full path to the root anchor.
- **Timeouts**: `--timeout` (default 5s) bounds each DNS query and each TLS connect/handshake (NFR-3); `--budget` bounds the whole per-target run.
- **Change detection**: FR-C9 compares the current SHA-256 fingerprint against `.dnsvigil/history.jsonl` and adds a `tls-cert-change` finding when it differs.

## Important Files
- `README.md` — overview/build/tree (its "not implemented" list is stale)
- `MEMORY.md` — per-session work memory; append a session entry after non-trivial work
- `progress.md` — long-term ownership/evidence (its "remaining work" list predates Tier 2/3 completion)
- `project-plan.md` — M0-approved plan; M1+ milestone table is outdated
- `docs/003-tier2-tier3-completion.md` — Tier 2/3 decisions and scope trade-offs

## Genuinely Not Implemented
- OS-native desktop window (FR-D10) — the "desktop interface" is the local web UI only
- Multi-user roles (single-user v1 by decision D3)
- Cross-platform parity gaps possible — ship linux-first for non-parity items
