# Requirements Specification v1.0 — Network Inspection Module

**Project:** Security & Network Assessment Toolkit (internal, defensive)
**Module:** Network Inspection (TLS certificate verification + DNS intelligence)
**Status:** APPROVED (v1.0) — 2026-10-11
**Priority key:** T1 = v1 must · T2 = v1 if time · T3 = later

---

## Outcome and context

- **Problem/opportunity:** Certificate and DNS checks are scattered across single-purpose tools with per-OS install quirks. There is no single place to run an audit and record the evidence.
- **Intended outcome:** One internal Windows + Linux application, offering both a terminal (TUI) and a desktop interface from one shared core, that answers certificate and DNS questions and produces reusable evidence.
- **Users/audience:** The operator (single user) for v1 — designed so multi-user support is not blocked later.
- **Domain and operating context:** Internal defensive security auditing of the organisation's own assets. Local-first, no accounts, no telemetry, confidential internal findings.

## Scope

- **In scope:** The Network Inspection module (TLS certificate verification + DNS intelligence) inside a dual-interface shell, with reporting and audit logging.
- **Out of scope (v1):** The other 18 tools · traffic interception / MITM · wireless auditing · port scanning · OSINT (username/phone) · blacklist checks · CIS hardening · encoding/decoding suite · files/notes/data/automation/monitoring tools · built-in scheduler · multi-user roles · cloud sync · whole-file report encryption.
- **Deliverables:** Working application (TUI + local web UI + headless CLI) · report output · audit log · documentation.
- **Constraints/dependencies:** Zero recurring cost · no admin/root required · portable manual-copy build · broad OS support (including Linux ARM and WSL) · optional proxy support.

## Technology stack (decided)

- **Language:** Go — pure Go with no CGO in the core, TUI, and CLI paths.
- **Core:** Go standard library (`crypto/tls`, `net`) plus a Go DNS library.
- **Terminal:** Bubble Tea TUI, plus a headless mode for scripting and OS-scheduled runs.
- **Desktop interface:** an embedded local web UI served by the same binary (a local web interface, not an OS-native window).
- **Distribution:** one static binary per target; a single machine cross-compiles Windows, Linux, ARM, and WSL via `GOOS`/`GOARCH`.
- **Rationale and rejected alternatives:** see decision log entries D9 and D10.

## Requirements

Verification methods: RC = reference comparison against `openssl s_client` / `dig`; FX = fixture with a known-bad or known-good configuration; IT = integration test in the lab; UT = unit test; NO = network observation; MA = manual acceptance.

### Certificate verification

| ID | Requirement | Priority | Acceptance criterion | Verification |
|---|---|---|---|---|
| FR-C1 | Accept targets via single entry, pasted list, or imported file | T1 | All three routes load the same target set | UT + MA |
| FR-C2 | Accept `host:port` per target; any port | T1 | A non-443 TLS service checks correctly | IT |
| FR-C3 | Display served chain, issuer, subject, and validity window | T1 | Matches `openssl s_client` on fixed hosts | RC |
| FR-C4 | Days-to-expiry with configurable warning threshold | T1 | 20-day cert flagged; 200-day cert not | FX |
| FR-C5 | Verify the certificate covers the requested hostname (SAN/CN) | T1 | Mismatch fixture flagged Critical | FX |
| FR-C6 | Detect untrusted, self-signed, and internal-CA chains | T1 | Self-signed fixture flagged | FX |
| FR-C7 | Report negotiated protocol and cipher; flag weak/outdated | T1 | TLS 1.0 host flagged | FX |
| FR-C8 | Record SHA-256 fingerprint and serial number | T2 | Values captured and stable across runs | UT |
| FR-C9 | Detect certificate change versus the previous run | T2 | Rotation flagged | FX |
| FR-C10 | Optional OCSP/CRL revocation check (off by default) | T2 | Toggle changes behaviour | IT |
| FR-C11 | Report OCSP stapling status | T2 | Stapled host reported | IT |
| FR-C12 | Report Certificate Transparency (SCT) presence | T2 | CT-logged host reported | IT |
| FR-C13 | Check signature algorithm and key strength | T2 | SHA-1 fixture flagged High | FX |
| FR-C14 | Flag validity periods beyond the CA/B max (398 days) | T2 | 400-day fixture flagged | FX |
| FR-C15 | Enumerate protocol versions offered by the server | T2 | Legacy TLS version reported | IT |
| FR-C16 | Enumerate accepted cipher suites | T2 | Weak cipher reported | IT |
| FR-C17 | Detect chain completeness issues (missing/misordered intermediates) | T2 | Incomplete chain flagged | FX |
| FR-C18 | Check CAA records governing issuance | T2 | CAA presence reported | RC |
| FR-C19 | Classify DV/OV/EV and CA hierarchy | T2 | Classification matches known certificates | FX |
| FR-C20 | Detect multiple certificates presented per host (SNI) | T3 | Certificate count reported | IT |
| FR-C21 | Flag clock-skew anomalies in validity dates | T3 | Skewed fixture flagged | FX |

### DNS & subdomain intelligence

| ID | Requirement | Priority | Acceptance criterion | Verification |
|---|---|---|---|---|
| FR-D1 | Query A, AAAA, CNAME, MX, TXT, NS, SOA | T1 | Matches `dig` | RC |
| FR-D4 | Check SPF presence and validity | T1 | Missing/permissive SPF flagged | FX |
| FR-D5 | Check DMARC presence and policy | T1 | `p=none` flagged as weak | FX |
| FR-D2 | Query PTR, SRV, CAA | T2 | Matches `dig` | RC |
| FR-D3 | Query DNSSEC records (DS, DNSKEY, RRSIG); report validation status | T2 | Signed/unsigned zones reported | RC |
| FR-D9 | Detect dangling CNAME / subdomain takeover risk | T2 | Dangling fixture flagged Critical | FX |
| FR-D10 | Detect wildcard DNS entries | T2 | Wildcard reported | FX |
| FR-D11 | Compare answers across resolvers; report inconsistency | T2 | Divergence reported | IT |
| FR-D12 | Support a configurable custom resolver | T2 | Queries honour the configured resolver | IT |
| FR-D19 | Forward-confirmed reverse DNS check for mail | T2 | Mismatch reported | FX |
| FR-D20 | NS redundancy / single-point-of-failure detection | T2 | Single-NS condition flagged | FX |
| FR-D6 | Probe common DKIM selectors for published keys | T3 | Published key found | IT |
| FR-D7 | Check MTA-STS and TLS-RPT presence | T3 | Presence reported | IT |
| FR-D8 | Check TLSA records | T3 | Presence reported | IT |
| FR-D13 | DNS-over-HTTPS resolution option | T3 | DoH query succeeds | IT |
| FR-D14 | Subdomain discovery from a wordlist | T3 | Known names discovered | IT |
| FR-D15 | Subdomain discovery via Certificate Transparency logs | T3 | Known names discovered | IT |
| FR-D16 | Zone transfer (AXFR) attempt and leak reporting | T3 | Zone leak reported | IT |
| FR-D17 | Dictionary + permutation name generation | T3 | Candidates generated | UT |
| FR-D18 | Manual entry / import of known names | T3 | Imported names checked | UT |
| FR-D21 | CNAME chain and loop detection | T3 | Loop detected | FX |
| FR-D22 | TTL analysis | T3 | TTLs reported | RC |
| FR-D23 | Parent/child delegation consistency; lame delegation detection | T3 | Inconsistency reported | IT |

### Shell & interfaces

| ID | Requirement | Priority | Acceptance criterion | Verification |
|---|---|---|---|---|
| FR-S1 | Run as TUI and desktop interface (local web UI) with **identical capability** | T1 | Parity checklist passes | MA |
| FR-S2 | Shared core; no interface-exclusive capability | T1 | Same results in both interfaces | MA + review |
| FR-S3 | Headless CLI mode for scripting and OS-scheduled runs | T1 | Unattended run produces a report | IT |
| FR-S4 | Keyboard-only operation | T1 | Full flow completed without a mouse | MA |
| FR-S5 | No meaning conveyed by colour alone | T1 | Colourless output remains readable | MA |
| FR-S7 | Every finding carries a severity and a plain-language reason | T1 | Report shows both | MA |
| FR-S8 | Operator-supplied targets only; no discovery or scanning | T1 | Only named targets are contacted | NO |
| FR-S6 | Configurable verbosity | T2 | Levels produce the expected detail | MA |
| FR-S9 | Bounded parallel execution with per-run limits | T2 | Concurrency cap respected | IT |

### Reporting

| ID | Requirement | Priority | Acceptance criterion | Verification |
|---|---|---|---|---|
| FR-R1 | Export plain text | T1 | File produced | MA |
| FR-R4 | Structured report: summary → scope → findings by severity → remediation → methodology | T1 | All sections present | MA |
| FR-R5 | Run metadata: operator, timestamp, targets, tool version | T1 | Fields present | MA |
| FR-R2 | Export JSON, CSV, Markdown, and HTML | T2 | Each format validated | UT + MA |
| FR-R6 | Remediation guidance per finding | T2 | Guidance present | MA |
| FR-R7 | Evidence suitable for compliance records | T2 | Accepted as evidence | MA |
| FR-R8 | File-based, browsable run history | T2 | Past runs listed and opened | MA |
| FR-R9 | Central dashboard view (desktop) | T2 | Findings render on the dashboard | MA |
| FR-R3 | Export PDF | T3 | PDF produced | MA |

### Audit, privacy, and data

| ID | Requirement | Priority | Acceptance criterion | Verification |
|---|---|---|---|---|
| FR-A1 | Configurable audit log; default records every query (target, time, operator, action, outcome) | T1 | Fields present in the log | UT |
| FR-A3 | Failures and warnings are always logged | T1 | A failure appears in the log | UT |
| FR-A4 | Structured log file (JSON Lines) | T1 | Log parses as JSONL | UT |
| FR-A6 | Never write secrets into logs or reports | T1 | No credential values present | Security review |
| FR-A7 | Proxy credentials via environment variable or prompt only; never plaintext | T1 | No plaintext credentials on disk | Security review |
| FR-A8 | No telemetry; outbound calls only to named targets, optional proxy, and revocation services | T1 | Traffic audit shows nothing else | NO |
| FR-A9 | No accounts or cloud dependency; results stay local | T1 | Offline operation verified | MA |
| FR-A2 | Optional full-result logging | T2 | Toggle records results | UT |
| FR-A5 | Configurable retention | T2 | Setting respected | UT |

## Nonfunctional / domain-specific criteria

- **Portability (NFR-1):** Must run on Windows 10/11, Windows Server, Ubuntu LTS, Debian/RHEL family, Linux ARM, and WSL.
- **Performance (NFR-2/3):** A single-host check completes within a few seconds; a batch run has an overall bound and never hangs indefinitely.
- **Reliability (NFR-4/5):** One bounded retry; an unreachable target is a recorded result, not a crash or a silent skip; sane default timeouts, overridable per run.
- **Security/privacy (NFR-6/10):** Runs as a standard user, no admin/root required. Zero recurring cost; no paid services. Proxy support optional.
- **Accessibility (NFR-11):** Keyboard-only operation and colour-independent output are mandatory; reports must be readable by a generalist with full detail available for a specialist.
- **Operations (NFR-8):** Portable build, manually copied. No installer, no update service.
- **Maintainability:** A shared core with thin front-ends, so a second module can reuse the shell. This is the primary architectural success test.

## Assumptions and open questions

- **Assumptions:**
  - The operator (single user) is the only user of v1.
  - The organisation authorises testing only against assets it owns.
  - A portable stack exists that satisfies NFR-1 and the dual-interface requirement.
  - **Baseline (CONFIRMED):** the current manual baseline is **under 15 minutes** per 10-host certificate + DNS audit (operator-confirmed 2026-10-11). Because the manual process is already quick, raw time saved is a weak success measure; v1's primary value is **consistency, coverage, and evidence production**. Target: ≤5 minutes for the same audit including export.
- **Blocking questions:** None. The baseline is confirmed and the technology stack is decided (see decision log).
- **Contradictions resolved:**
  - Serving generalists vs. single-user scope → single-user now, no choices that block multi-user later.
  - Accessibility "none required" vs. future teammates → two zero-cost wins kept (keyboard-only, colour-independent output).
  - "All report formats" vs. approved tiering → tiering followed: text in T1; JSON/CSV/Markdown/HTML in T2; PDF in T3.
  - "Desktop window" vs. portable, dependency-free distribution → resolved: the desktop **interface** is a local web UI rendered by the same pure-Go binary; an OS-native window shell is deferred and optional.
- **Decisions needed:** None blocking. Next gated step: approval of the architecture and milestone plan before any code is written.

## Success criteria

1. A 10-host certificate + DNS audit plus export completes in **≤5 minutes** (baseline: under 15 minutes manually). Given the quick manual baseline, criteria 2–5 matter more than this one.
2. **100% coverage** of the organisation's public TLS endpoints on a monthly schedule (via OS-scheduled CLI runs).
3. **Zero misses** — no expiring certificate or misconfiguration is first reported by an outside source that this tool did not already flag.
4. The operator stops reaching for other tools for certificate/DNS questions.
5. **Architecture proof** — building module #2 requires measurably less effort than module #1 because the shell and core are reusable.

## Risks and recovery

| Risk | Likelihood / Impact | Mitigation | Recovery |
|---|---|---|---|
| Scope growth (20+ tools) | High / High | Approved T1/T2/T3 tiering; other tools explicitly out of scope | Defer any T2/T3 item to a later module |
| No stack chosen; operator directs AI | Medium / High | Dedicated, documented stack decision before any code | Change stack only before module code exists |
| Unauthorised use / legal exposure | Low / High | Operator-supplied targets only (FR-S8); audit log (FR-A1); no discovery | Disable network features; restore from a clean build |
| Cross-platform parity | Medium / Medium | Portable-first sequencing; never promise undeliverable parity | Ship Linux-first for any item that cannot reach parity |
| Free-data limits | Medium / Low | v1 avoids all paid-data features | Convert such features to BYO-key later |
| Confidential findings exposure | Low / High | Secrets never logged (FR-A6/A7); local-only (FR-A8/A9) | Rotate any credential that touched a report |

## Release gate

- All Tier 1 features working on every target OS.
- Identical TUI and desktop capability.
- Zero critical or high defects open (known issues documented and deferred).
- Report export verified end to end.
- The operator would use it for a real audit.

## Approval

- **Approved scope/version:** v1.0 — Network Inspection module.
- **Approver:** Operator (approved by delegation: "do as your recommendation"), 2026-10-11.
- **Explicitly excluded actions until further approval:** no application code written; no technology stack committed without a recorded decision; no third-party packages installed; nothing published or distributed.

## Decision log

| # | Decision | Date | Rationale |
|---|---|---|---|
| D1 | Anchor module = Network Inspection (certificates + DNS) | 2026-10-11 | Read-only, cross-platform, lowest legal risk, exercises the reusable network core |
| D2 | v1 priority = narrow + deep | 2026-10-11 | Beats breadth-first for a 20+ tool ambition |
| D3 | Single-user v1, no blockers for future teams | 2026-10-11 | Fastest path to useful; avoids a multi-user subsystem |
| D4 | Tiering T1/T2/T3 accepted | 2026-10-11 | Bounds scope; makes the plan deliverable |
| D5 | History = files on disk, no database | 2026-10-11 | Free, inspectable, sufficient for change detection |
| D6 | Scheduling = CLI mode called by the OS scheduler | 2026-10-11 | Reuses existing OS capability; no daemon |
| D7 | Encrypt sensitive fields only; never plaintext secrets | 2026-10-11 | Protects credentials without whole-file friction |
| D8 | Technology stack selection deferred to its own decision | 2026-10-11 | NFR-1 and FR-S1/S2 must drive it, not preference |
| D9 | **Stack = Go**, pure Go with no CGO | 2026-10-11 | Best fit for NFR-1/NFR-8: single static binary, trivial one-machine cross-compilation, strong stdlib TLS/DNS support. Rejected: Rust (better single-UI story, slower iteration, toolchain friction) and Python (weakest portable distribution). |
| D10 | **Desktop interface = embedded local web UI**, not an OS-native window | 2026-10-11 | Native-widget Go toolkits (Fyne/Gio) require CGO, breaking one-machine builds and adding runtime graphics dependencies. The local web UI keeps the binary dependency-free and reduces TUI/desktop parity to one results model with two renderers. |
| D11 | **Success emphasis = consistency, coverage, evidence** rather than time saved | 2026-10-11 | Confirmed baseline is under 15 minutes, so speed is a weak differentiator. |
