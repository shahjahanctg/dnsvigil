# Project Plan — Network Inspection Module (v1)

**Project:** Security & Network Assessment Toolkit (internal, defensive)
**Module:** Network Inspection (TLS certificate verification + DNS intelligence)
**Plan version:** 1.0 — 2026-10-11
**Status:** AWAITING APPROVAL — no application code to be written until approved

---

## Objective

Deliver the first working module of an internal, cross-platform (Windows + Linux) security tool that answers certificate and DNS questions about the organisation's own assets, records the evidence, and runs from a single dependency-free binary with both a terminal interface and a local web interface.

## Approved scope and exclusions

- **Approved scope:** Network Inspection module only — Tier 1 features (`requirements-spec.md`), plus the shared shell, reporting, and audit logging.
- **Excluded:** the other 18 tools; MITM/interception; wireless auditing; port scanning; OSINT; blacklist checks; CIS hardening; encoding suite; built-in scheduler; multi-user roles; cloud sync; PDF (T3).
- **Out of scope by decision:** OS-native window shell (deferred, optional — see D10).

## Recommendation and alternatives considered

- **Recommended and chosen:** Go with a pure-Go core (no CGO), Bubble Tea TUI, headless CLI, and an embedded local web UI.
- **Alternatives rejected:** Rust (stronger single-UI option via a ratatui/egui hybrid; slower iteration and more toolchain friction for one-machine builds); Python (fastest to build, weakest portable no-install distribution).
- **Rationale:** the top stated priority is portable, dependency-free distribution from one build machine. Only the pure-Go path satisfies all three of NFR-1, NFR-8, and one-machine cross-compilation simultaneously.

## Requirements / success criteria

Source of truth: `requirements-spec.md` v1.0. In summary:

1. A 10-host certificate + DNS audit plus export completes in ≤5 minutes (baseline: under 15 minutes manually).
2. 100% coverage of the organisation's public TLS endpoints on a monthly schedule.
3. Zero misses — no expiring certificate or misconfiguration is first reported by an outside source.
4. The operator stops reaching for other tools for certificate/DNS questions.
5. Architecture proof — module #2 costs measurably less effort than module #1.

## Assumptions and unresolved nonblocking questions

- **Assumptions:** single-user v1; the organisation authorises testing only its own assets; the operator will confirm the web UI feels acceptable before it is built upon (M3 checkpoint).
- **Nonblocking open questions:** exact Tier 2 inclusion depends on remaining time; the TLS library needed for revocation/stapling (M6) is not yet selected.

## Architecture or workflow

```
soc-tool/
├─ cmd/nettools/          entry point: --tui | --gui | headless
├─ internal/
│  ├─ core/               PURE GO — no UI, no CGO
│  │  ├─ target/          target parsing & loading            (FR-C1, C2)
│  │  ├─ tlscheck/        certificate checks                  (FR-C3–C21)
│  │  ├─ dnscheck/        DNS & record checks                 (FR-D1–D23)
│  │  ├─ finding/         severity model + plain-language text (FR-S7)
│  │  ├─ report/          text / JSON / CSV / MD / HTML        (FR-R1–R7)
│  │  ├─ audit/           JSONL audit log, retention           (FR-A1–A5)
│  │  └─ engine/          orchestration, concurrency, timeouts (NFR-2–5, FR-S9)
│  ├─ tui/                Bubble Tea front-end                (FR-S1, S4, S5)
│  ├─ cli/                headless mode                       (FR-S3)
│  └─ webui/              embedded HTTP server                (FR-S1)
├─ web/                   HTML/CSS/JS assets (go:embed)
├─ testdata/              fixtures: expired, self-signed, mismatch, weak
└─ docs/                  specification and decision records
```

**Load-bearing decisions:**

1. **One results model, two renderers.** `finding.Finding` is the only structure the TUI and web UI consume, so interface parity is structural rather than maintained by discipline.
2. **`core/` imports no UI.** Enforces "no interface-exclusive capability" and permits testing with no network, terminal, or browser.
3. **Network access behind interfaces.** Enables unit tests with fakes; real-network checks are reserved for fixtures and reference comparisons.

## Deliverables

- Working application: TUI, local web UI, headless CLI, from one binary per target.
- Report output (plain text in T1) with structured sections.
- JSONL audit log with retention setting.
- Documentation: this plan, the specification, decision records, install/run notes.

## Dependencies and prerequisites

- Go toolchain on the build machine (exact version chosen at M0).
- A Go DNS library for record-level queries beyond the standard resolver.
- Test fixtures: known expired, self-signed, hostname-mismatched, and weak-crypto endpoints (lab VMs).
- Reference tools available for verification: `openssl s_client`, `dig`.
- No paid services, no cloud accounts, no admin/root rights required.

## Milestones and task checkpoints

| ID | Task | Depends on | Deliverable | Acceptance check | Risk/isolation | Status |
|---|---|---|---|---|---|---|
| M0 | Project skeleton + build pipeline | — | `--version` binary built for Windows x64, Linux x64, Linux ARM64, WSL | All four targets build from one machine with `CGO_ENABLED=0` | Low; fully reversible | Completed — 2026-10-11 |
| M1 | Core + first certificate check, end to end | M0 | CLI checks a host: chain, issuer, validity, expiry → text report + audit entry | Output matches `openssl s_client` on fixed hosts | Medium: validates the TLS approach | Not started |
| M2 | Terminal UI | M1 | Bubble Tea front-end over the same core | Keyboard-only; colour-independent; verdict + detail shown | Low | Not started |
| M3 | Local web UI | M2 | Embedded server + assets rendering the same findings | Parity check against M2; operator confirms the feel | Medium: user-experience checkpoint | Not started |
| M4 | Tier 1 complete | M3 | Full T1 certificate set (expiry threshold, SAN match, trust, protocol/cipher) + T1 DNS set (core records, SPF, DMARC) + structured report + metadata | Fixtures + reference comparison | Medium: bulk of Tier 1 | Not started |
| M5 | Verification | M4 | Fixture suite (expired, self-signed, mismatch, weak), reference comparisons, acceptance checklist, parity test | Full Tier 1 acceptance run passes | Low but mandatory | Not started |
| M6 | Tier 2 (only if time remains) | M5 | OCSP/CRL, CT presence, fingerprint/serial, change detection, TLS/cipher enumeration, DNSSEC, dangling CNAME, wildcard, resolver comparison, extra formats, dashboard, history | Per-item tests | Medium; may require an additional TLS library | Not started |

## Verification and review plan

- **Unit tests** for target parsing, DNS record parsing, severity mapping, report rendering, and audit logging.
- **Fixtures** proving known-bad configurations are detected with the correct severity.
- **Reference comparison** against `openssl s_client` and `dig` on a fixed host set.
- **Parity test** driving the same scenarios through the TUI and the web UI.
- **Manual acceptance checklist** walked by the operator, including keyboard-only and colour-independent review.
- **Two review passes** per the skill: requirements conformance, then quality/safety review.

## Risks, cost/effort, and constraints

| Risk | Likelihood / Impact | Mitigation |
|---|---|---|
| Tier 1 scope still large | Medium / Medium | Milestones are ordered so a usable CLI exists at M1; T2 items are strictly optional |
| Web UI fails to feel like a desktop app | Medium / Medium | M3 is an explicit operator checkpoint before further investment |
| TLS library gaps for revocation/stapling | Medium / Low | Contained to M6; swap libraries behind the existing interface |
| Cross-compilation surprises (ARM, WSL) | Low / Medium | Proven at M0, before any feature code exists |
| Confidential findings exposure | Low / High | Secrets never logged (FR-A6/A7); local-only operation (FR-A8/A9) |
| Effort creep against a single operator | Medium / Medium | Tiering is enforced; T2/T3 require a new decision |

**Cost:** zero recurring cost. Effort is measured in milestones, not calendar time, until the build cadence is known.

## Approval gates

1. **This plan** — approval required before M0.
2. **M3** — operator confirms the web UI experience before building further.
3. **M6 / Tier 2** — separate decision; not authorized by this plan.
4. **Any distribution, publication, or install of third-party packages** — requires separate approval.

## Rollback/recovery

- Nothing existing is modified; the project is additive, so abandoning costs only time.
- Every milestone ends with a working build, so any regression can be recovered by returning to the previous milestone tag.
- No destructive or irreversible operations are planned.

## Decision and approval record

| Decision | Date | Status |
|---|---|---|
| D1–D8: anchor module, tiering, scope decisions | 2026-10-11 | Approved |
| D9: Stack = Go (pure Go, no CGO) | 2026-10-11 | Approved |
| D10: Desktop interface = embedded local web UI | 2026-10-11 | Approved |
| D11: Success emphasis = consistency, coverage, evidence | 2026-10-11 | Approved |
| Approval to begin M0 | 2026-10-11 | **APPROVED** — operator approved M0 |
