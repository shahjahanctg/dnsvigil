## Session 2026-10-19 (latest) — TUI/web-UI control parity

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
