# Progress — SOC Tool (Network Inspection Module)

**Owner:** Buffy (agentic creation workflow)
**Date:** 2026-10-11
**Package:** Master Agentic Creation Skill — 2.0.0-rc.1 (release candidate)

## Overall status

- **Deliverable verified and complete:** headless CLI in `cmd/nettools/main.go`,
  rebuilt with `CGO_ENABLED=0` for linux-amd64, linux-arm64, windows-amd64.
- **Latest session (2026-10-18):** 30 tests across 9 packages, all offline.
  Three more real bugs found and fixed by tests (see task 8).
- **Checks:** `go test ./... -count=1` clean; `go vet ./...` clean;
  `gofmt -l .` clean; multi-arch rebuild OK; live CLI run of
  `--headless example.com` shows DNS + TLS findings through the report
  writer; parse-error audit path verified live (`example.com:99999`).
- **Limitations:** `docs/`, `testdata/`, `web/`, `internal/core/dns/` still
  empty/untested; arm64/wsl binaries not runnable on this host; M1 remains
  incomplete until full chain/issuer checks land (task 9 below).

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

8. **Third bug harvest + full local test coverage** (2026-10-18):
   - `internal/core/tlscheck/tls.go`: `dialTLS` passed `t.Addr()` as the
     *network* argument of `tls.DialWithDialer` — every TLS check was a
     dial error in disguise. Now dials `"tcp"`. Caught by the first
     end-to-end engine tests.
   - `internal/core/engine/engine.go`: `Run` ignored `TLSContext`
     entirely — no TLS findings were ever produced. Now merges DNS and
     TLS findings; TLS errors take precedence when both paths fail.
   - `internal/core/report/report.go`: remediation listed guidance for
     INFO findings (e.g. "add A record" while the record exists).
     Remediation now only covers Medium+ (FR-R6); new test.
   - `cmd/nettools/main.go`: removed dead `printReport`/`severityIdx`
     (report package superseded them).
   - New tests: `engine_test.go` (in-process DNS + TLS server fixtures;
     happy path, expired cert, unknown-CA self-signed, unreachable),
     `audit_test.go` failure path (FR-A1/A3 complete),
     `cmd/nettools/main_test.go` (headless arg routing).
   - TLS server fixtures work via the `RootCAs` trust seam added to
     `tlscheck.Context`.

## Remaining work (next session)

1. T2 items (M6): OCSP/CRL (FR-C10), CT presence (FR-C12), fingerprint
   stability (FR-C8), change detection (FR-C9), protocol/cipher
   enumeration vs single negotiated value (FR-C15/C16).
2. `testadata/`-style external fixture set for M5 acceptance run
   (in-process fixtures already cover expired/self-signed/mismatch).
3. `docs/` decision records.
4. Web UI operator checkpoint (M3 gate): the operator must confirm the
   web UI experience before building further on it.

## Session 2026-10-18 (part 2) — Tier 1 closure, M2, M3

- **FR-C3** served-chain enumeration (`tls-chain-served`, chain_depth +
  per-depth subject/issuer/serial) — verified live AND against
  `openssl s_client` (subject, issuer, both dates, serial all match).
- **FR-C4** `--expiry-warn` (default 30) — verified live: `--expiry-warn
  400` produced a HIGH finding at that threshold; unit-tested.
- **FR-C6** trust failures are now findings, not dead errors:
  expired → tls-expiry Critical; unknown authority/self-signed →
  tls-chain Critical "untrusted chain"; hostname mismatch → Critical.
- **FR-C7** negotiated protocol + cipher reported; TLS 1.0 or
  3DES/RC4/NULL/CBC (pre-TLS 1.3) → High findings; verified live on
  TLS 1.3 / AES-GCM.
- **FR-D1** dnscheck queries CNAME/MX/TXT/NS/SOA (+A/AAAA/CAA); missed
  records are INFO facts except SPF/DMARC; **FR-D4** SPF present/
  permissive(+all/?all → High)/missing (Medium); **FR-D5** DMARC
  present/p=none weak (Medium)/missing (Medium).
- **dnscheck fixture bug found:** miekg/dns packs only FQDNs; the
  fixture's MX/NS/SOA answers (Mx/Ns/Mbox without trailing dots) never
  left the server — those lookup paths had never been exercised until
  today's FR-D1 tests. Fixed; expectations use trailing dots.
- **tlscheck trust unwrapping:** `tls.CertificateVerificationError`
  wraps x509 errors as VALUE types; errors.As must target value types
  (`x509.UnknownAuthorityError`, not pointer).
- **FR-C1** `--targets file` import; pasted multi-line lists; comments;
- **FR-A2/A5** `--log-findings`, `--audit path`, `--retention` +
  Rotate() wired after every run; **FR-R5** `--operator`.
- **M2 TUI** (`internal/tui/`, Bubble Tea): target entry, enter runs the
  shared engine, findings listed severity-first with text labels; q/
  Ctrl-C quit; keyboard-only; offline model tests.
- **M3 web UI** (`internal/webui/` + embedded `assets/index.html`):
  loopback-only server (127.0.0.1:8089), POST /run renders the same
  findings the CLI reports; verified live (form, comment-only error,
  parse-error render); offline httptest suite.
- **CLI arg flow fix:** routing now splits on the first mode flag so
  `--targets`-style flags after `--headless` reach the headless flagset.
- **openssl RC:** live run vs `openssl s_client -connect example.com:443`
  matched on subject, issuer, notBefore, notAfter.
- Cleanup: removed `bin/` scratch build and stray root `nettools`
  binary; rebuilt all four targets (linux amd64/arm64/wsl + windows).

## Files owned

- `README.md` — application/project overview, build, tree, verification.
- `MEMORY.md` — per-task work memory and decision rationale.
- `progress.md` — this file: long-term ownership, completion evidence,
  next step.

## Maintenance stance

This project is maintained by me; repository documentation is authored only
when confirmed. This file is the progress record; `MEMORY.md` is the working
memory; `README.md` is the public-facing description.
