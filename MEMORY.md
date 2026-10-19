## Session 2026-10-19 (latest) — Settings page (shared CLI/web defaults)

- **New package `internal/core/settings`:** `Duration` (marshals as a Go duration
  string), `Settings` (operator, timeout, expiry-warn, resolvers, budget, audit +
  history retention, the opt-in check toggles, DoH provider), `Default()`,
  `Path`/`Load`/`Save`. Persisted to `.dnsvigil/settings.json` (atomic temp+
  rename, `0o600`, FR-A6); `Load` starts from `Default` so missing fields keep
  their default. Deliberately holds **no file paths** (audit path, report dir,
  wordlist) — those stay CLI/run-form only so a browser form cannot point the
  tool at arbitrary files.
- **Web `/settings` page (FR-S1/S2):** `GET` renders the form from the file;
  `POST` saves (`settingsFromForm`, blank durations keep their default, bad
  duration re-renders an error and writes nothing) then `303 /settings?saved=1`.
  Cross-origin posts rejected via `sameOrigin`; `server.go` nav gained a Settings
  link. The home run form is now pre-filled from the shared settings file.
- **Runtime wiring:** `runChecks(raw, checks, st)` threads
  `Resolver`/`SecondResolver`/`Timeout`/`ExpiryWarnDays` into `engine.Context`;
  `handleRun` uses the settings budget as its default; `handleExport` falls back
  to the settings operator. `Server.store()`/`effectiveRetention()` make the
  settings-file `history_retention` authoritative over the startup
  `--history-retention` value, and the history page's note now reflects it.
- **CLI:** `settingsDefaults()` seeds the headless flag defaults from the file
  (explicit flags still win); `runWebUI` seeds its default retention the same
  way.
- **Tests:** settings (Duration JSON round-trip, Load default/not-found,
  Save perms); webui (`/settings` render, save+redirect+persisted values+0o600,
  cross-origin 403, bad duration 400-ish + no write, home prefill, settings
  retention overrides startup). cmd (`settingsDefaults` reads `.dnsvigil`).
- **Build-path gotcha:** `go build -o ../build/dnsvigil-linux-amd64` resolves
  against the shell's cwd. The relative path silently wrote the binary to
  `cmd/build/` instead of the tracked `build/` while the stale tracked binary
  kept serving `/settings` as the home page (no compile error). Use an absolute
  `-o` path (`build/dnsvigil-linux-amd64`) and re-verify right before
  smoke-testing: `/settings` must render `<h1>Settings</h1>`. Backgrounding
  `BIN --gui & GUI=$!` then `kill $GUI` is the safe form.
- **Verification:** `go test ./... -count=1` green, `go vet ./...` clean,
  `gofmt -l .` clean, `go build ./...` ok. Live: `/settings` renders + saves,
  `.dnsvigil/settings.json` written, `--headless -h` shows the file's values as
  flag defaults (`operator "smoke"`, `timeout 8s`, `budget 45s`,
  `history-retention 168h`, `expiry-warn 20`, `doh-provider "quad9"`).

## Session 2026-10-19 (latest) — Selective clear + history retention

- **Selective clear (web):** `POST /history/clear` is now a two-step,
  criteria-driven action. Modes: `all`, `target`, `age`, `target-age`
  (`clearCriteria` in `webui.go`). Without `confirm=yes` it preflights with
  `CountMatching` and re-renders the page showing "This will delete N run(s)."
  with a Confirm button (deletes nothing); with `confirm=yes` it calls
  `ClearMatching` and redirects `303 /history?cleared=N`. Still POST-only and
  cross-origin-rejecting. UI: mode `<select>`, target `<select>` (populated from
  `Store.Targets()` with counts), age `<select>` (`agePresets`: 1d/7d/30d/90d/1y,
  default 30d), plus JS to show/hide by mode.
- **Domain matching:** `history.NormalizeTarget` lowercases and strips the port
  (`example.com:443` → `example.com`); subdomains stay distinct (no
  public-suffix dependency). The dropdown lists normalized targets.
- **Retention / auto-prune:** `history.DefaultRetention = 30 days`. `Store` takes
  a `WithRetention(d)` option (0 disables); `AppendEntry` prunes entries older
  than the window after each write, so **every interface** that records a run
  (CLI, web) prunes without a scheduler. New CLI/GUI flag
  `--history-retention` (default `720h`, `0` disables). Note `--retention`
  already means the *audit* log (FR-A5); the history knob is deliberately
  differently named.
- **History package rework:** `Store.mu` was per-instance (one per web request),
  which cannot serialise concurrent writers — promoted to a package-level
  `fileMu`. Rewrites go through `writeLocked` (temp file + rename, `0o600`, with
  a Windows remove-then-rename fallback) so a crash cannot half-write history.
  `Clear()` (whole file) kept; added `ClearCriteria`, `CountMatching`,
  `ClearMatching`, `NormalizeTarget`, `Targets`, `TargetCount`. Entries with a
  zero timestamp are kept (not pruned, not age-matched).
- **Flag plumbing:** `headlessOptions.HistoryRetention` + `valuedHeadlessFlags`
  entry; `history.New("", history.WithRetention(...))`. `webui.Run(retention)` /
  `webui.NewWithRetention`; `runWebUI(args)` parses `--history-retention`;
  `main()` forwards `--gui` trailing args.
- **Tests:** history — `NormalizeTarget`, `ClearMatching` by target/age/combined/
  everything, `CountMatching`↔`ClearMatching` agreement, auto-prune on append,
  retention-disabled keeps old, `Targets` distinct/counted. webui — preview
  counts + deletes nothing, confirm redirects `?cleared=N`, by-target, by-age,
  bad selection (400), cross-origin (403), GET (405), clear controls/retention
  note rendered. cmd — `--history-retention` consumes its value in
  `reorderHeadlessArgs`.
- **Verification:** `go test ./... -count=1` green, `go vet` clean, `gofmt -l .`
  clean, `go build ./...` ok. Live against rebuilt `build/dnsvigil-linux-amd64`:
  preview-by-target left the file untouched, confirm-by-target removed only
  `example.com`, age preview counted the 2020 entry, dashboard showed the
  retention note.

## Session 2026-10-19 (earlier) — History page + clear history (web mode)

- **Dedicated history view:** new `GET /history` route + `handleHistory` in
  `internal/webui/webui.go`. Lists every recorded run newest-first with an
  expandable `<details>` of each run's findings, a summary line (runs · targets ·
  date range), a `?target=` filter, and a 200-row cap (`historyMaxRows`). Home is
  now a compact "Recent activity" preview (`historyPreview = 5`) linking to
  `/history`. The home `pageData.HistFindings` field was replaced by a
  `[]historyRow` view model (adds a shortened fingerprint via `ShortFP`).
- **Clear history:** new `POST /history/clear` + `handleHistoryClear`, backed by
  `history.Store.Clear()` (removes `history.jsonl`; missing file is a no-op).
  POST-only, requires `confirm=yes`, and rejects cross-origin browser posts via
  `sameOrigin` (checks `Sec-Fetch-Site`/`Origin`; non-browser clients with no
  `Origin` are allowed). Success → `303 /history?cleared=1`. Scope is run
  history only — `audit.jsonl` and exported reports are deliberately untouched.
  UI button is red (`class="danger"`) with a JS `confirm()` and hidden
  `confirm=yes`.
- **Tests:** `history` — `TestClearRemovesHistory`, `TestClearMissingFileIsNoop`;
  `webui` — recent-activity preview, `/history` populated/empty/filtered, clear
  requires POST, requires confirmation, rejects cross-origin, removes file +
  redirects (and the cleared banner). Retargeted `TestHomeShowsHistoricalFindings`
  → `TestHomeShowsRecentActivityPreview`.
- **Ops gotcha:** backgrounding the GUI with `setsid` made `kill $!` kill the
  wrapper, leaking a server on :8089. Start the GUI directly (`BIN --gui & GUI=$!`)
  and `kill $GUI`; find leaks with `ss -ltnp | grep 8089`.
- **Verification:** `go test ./... -count=1` green (one pre-existing flaky
  `tlscheck` timeout test passed on re-run), `go vet` clean, `gofmt -l .` clean,
  `go build ./...` ok. Live: home preview + `/history` + clear round-trip
  verified against the rebuilt `build/dnsvigil-linux-amd64`.

## Session 2026-10-19 (earlier) — Export + dashboard + data safety

- **Web export (FR-R1/R2/F-S1/S2):** added `/export/{json,csv,md,html}` routes
  in `internal/webui/webui.go`. Each streams the same `report.Write*` output the
  CLI `--export` produces, with `Content-Type` + `Content-Disposition`
  attachment headers; unknown formats return 400. `assets/index.html` gained
  Download buttons (browser fetches `/export/<fmt>` and saves the blob). Exports
  stream to the browser and write nothing to disk.
- **Dashboard history (FR-R8/R9):** `history.Entry` now carries
  `Findings []finding.Finding` (omitempty, so old fingerprint-only entries still
  parse). New `Store.AppendEntry` + `Store.RecentFindings(limit)`; the web home
  page renders a "Historical findings (N, newest first)" table. Both the CLI and
  the web `handleRun` now record findings, not just the SHA-256.
- **Data safety (FR-A6):** `exportReport` now writes reports with
  `os.OpenFile(..., 0o600)` instead of `os.Create` (which is 0o666&umask →
  world-readable). Audit, history, and export files are 0o600; their dirs 0o700.
- **Shared handler helpers:** `parseCheckSwitches`, `splitTargetLines`,
  `runChecks`, `fingerprintOf`, and a package-level `runEngine` seam so handlers
  can be tested offline. `Server.historyDir` lets tests point history at a temp
  dir instead of `.dnsvigil/`.
- **Fixed a pre-existing red suite:** `internal/tui` tests and `tui.go` were out
  of sync (a half-finished commit: duplicate `New` comment, `Enumerate` wired to
  `opts.Deep`, `pathEntry` never routed typing, options line missing
  provider/wordlist/revocation/enumerate). The two failing TUI tests were also
  mutually contradictory (one required `DoHProvider=="google"` with no key
  pressed; the other required `==""` after cycling to google). Completed the
  ctrl-layer implementation and corrected the contradictory assertions to one
  coherent spec. TUI tests now pass.
- **Verification:** `go test ./... -count=1` all green; `go vet ./...` clean;
  `gofmt -l .` clean; `go build ./...` ok. Live smoke: CLI `--export json`
  wrote an owner-only report; web `/export/json` returned 200 + attachment; the
  dashboard rendered 26 historical findings; `/export/pdf` → 400.

## Session 2026-10-19 (earlier) — TUI/web-UI control parity

- Wired the full TUI keyboard surface to match the web form's control
  layer: ctrl+p cycles the DoH provider, ctrl+x toggles AXFR, ctrl+b
  opens/edits the per-run budget, ctrl+r toggles revocation checking,
  ctrl+e toggles enumeration, ctrl+l opens the wordlist path. The
  options line renders every switch as words, never relying on colour.
- All opt-in switches now flow through the shared-core run context and
  are queryable in `engine.Context` so the CLI, TUI, and web UI stay one
  capability set (FR-S1/S2).
- Added `internal/tui/tui_test.go` with the keyboard-only acceptance
  flow (typed target, ctrl toggles, run, severity-labelled findings,
  quit) plus a provider-cycle + wordlist-path test.
- Remaining gap: the TUI does not yet expose every web form field or the
  filtered run-options pane (targets entry, deeper preset toggles),
  only the ctrl-layer. Fix by adding the missing form fields before
  claiming full parity.
- Note: AGENTS.md and MEMORY.md record this session; the TUI code is the
  source of truth for the controls.
