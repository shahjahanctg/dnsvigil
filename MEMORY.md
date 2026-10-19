# MEMORY — SOC Tool (Network Inspection Module)

> Working memory for the current task sequence only. Read before starting
> similar work; do not carry unrelated facts across tasks.

## Session 2026-10-19 (latest) — skill swap, tier 2/3 completion, runtime bounds

### Skill set changed

- **`god-mode-skill/` deleted** (was tracked; removal committed). Its
  templates and workflows are superseded by the superpowers skill set.
- **superpowers installed** from `https://github.com/obra/superpowers` via
  `npx skills add obra/superpowers --all --yes`, landing in
  `.agents/skills/` (15 skills). Agent rules moved to `AGENTS.md`.
- Skill usage is now mandatory here: `brainstorming` before new work,
  `test-driven-development` for code, `verification-before-completion`
  before any success claim, `systematic-debugging` for bugs.

### Bugs the verification passes caught (all fixed, never shipped)

- **Unbounded TLS dial (the original user complaint):** `dialTLS` used a bare
  `net.Dialer` and `tls.DialWithDialer` runs the handshake with no deadline,
  so a host that drops the TCP connect never returned — a run was still going
  after 120s and had to be killed. Now `Context.DialTimeout()` (default 5s,
  from `--timeout`) bounds the connect via the dialer and the handshake via
  `tls.Dialer.DialContext` with a context deadline; timeouts classify as
  unreachable. Regression test: `TestDialTLSTimesOutOnSilentServer`.
- **DNSSEC read without the EDNS0 DO bit:** RRSIG is not a queryable type;
  requesting type RRSIG returns nothing, so a correctly signed zone (and a
  correctly absent RRSIG) looked identical. Signatures must be read out of the
  answer that covers them (`lookupDO`).
- **Lame delegation false positive:** a non-recursive SOA probe answered by a
  forwarder/interceptor (ra/ad set) was blamed on a healthy nameserver.
  `classifyDelegationReply` now separates *authoritative*, *lame*, and
  *proxied* (reported Low as "not verifiable from this network").
- **DKIM revocation counted as a key:** `v=DKIM1; p=` is the published
  withdrawal marker; counting it produced "12 keys" for a domain with none.
  `dkimPublishedKey` requires non-empty key material.
- **Chain completeness false alarm:** a cross-signed root was called
  incomplete; completeness is now decided by building a verification path
  (`verifyServedChain`) rather than by testing for a self-signed terminal.
- **Headless flag ordering:** `--headless example.com --expiry-warn 68`
  treated the flags as extra *targets* (contacting `--expiry-warn:443`) and
  ignored the threshold. `reorderHeadlessArgs` moves flags ahead of the
  positionals (FR-S8).
- **Resolver typos were silent:** `--resolver "not a host"` produced "no A
  record" for a host that resolves. `normalizeResolver` validates up front and
  exits 2.

### Facts worth not rediscovering

- **Runtime (NFR-2/3), measured on this host:** responsive host ~1.0s default,
  ~3.2s `--deep`; unreachable host 7.0s default, 13.8s `--deep`; 3-target
  batch including an unreachable host 14.4s.
- **This sandbox intercepts DNS:** UDP/53 to arbitrary addresses (including
  TEST-NET and a Cloudflare NS IP) is answered by a local recursive resolver,
  and `_domainkey` names return `v=DKIM1; p=`. Checks must therefore be
  written so interception shows up as "not verifiable", never as a finding
  about the target. `crt.sh` returns HTTP 429 here.
- **Registered kinds** (grep before inventing one): the full list is in the
  README check catalogue; `dns-dnssec` carries validation state,
  `tls-chain-incomplete` carries completeness.
- **Go toolchain path:** `export PATH="$HOME/sdk/go1.25.0/bin:$PATH"`.

### Decision records added

`docs/003-tier2-tier3-completion.md` (opt-in gating, `--deep`, DNSSEC scope,
interception heuristic, DKIM revocation) and the superpowers design doc under
`docs/superpowers/specs/`.

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

1. M6 Tier-2 items only after a separate approval decision: OCSP/CRL,
   CT presence, fingerprint stability, change detection, protocol/
   cipher enumeration, extra report formats, run history.
2. M5 acceptance run: external `testdata/` fixture set + operator
   manual checklist (keyboard-only, colour-independent).
3. M3 operator checkpoint before investing further in the web UI.

### Session 2026-10-18 (part 2, record now)

- **Trust-failure findings (FR-C6):** `tls.CertificateVerificationError`
  wraps x509 errors as VALUE types — `errors.As(err, x509.UnknownAuthorityError{})`
  (value target, not pointer). Expired → tls-expiry Critical;
  unknown CA → tls-chain Critical; hostname error → Critical.
- **miekg/dns FQDN rule:** RR domain values must end with a dot or
  `WriteMsg` silently fails to pack (fixture MX/NS/SOA were silently
  broken until today's tests exercised them).
- **CLI routing:** main scans for the first mode flag and hands the rest
  to that mode's flagset; headless flags come after `--headless`.
- **Live evidence:** `--expiry-warn 400` → HIGH at 68 days left with
  warn_days=400 in detail; chain_depth=4 on example.com; protocol
  TLS 1.3 + AES-GCM reported; openssl s_client comparison matched
  subject/issuer/dates/serial; web UI verified by curl (home form,
  comment-only → 'no targets provided', bad port → parse error text);
  audit entries carry operator + findings when --log-findings.
- **TUI/web tests stay offline:** no live network in tests; model and
  httptest only.

### Session 2026-10-18 (record now)

- **Bugs found by the new engine tests and fixed (root causes, tests
  strengthened not weakened):**
  - `tlscheck.dialTLS`: `tls.DialWithDialer(&dial, t.Addr(), t.Host, …)`
    — network/addr arguments swapped; TLS checks never dialed correctly.
    Fixed to `"tcp"`.
  - `engine.Run`: ignored `TLSContext`; now runs `tlscheck.Run`, merges
    findings after the DNS ones, TLS error wins when both fail.
  - `report.remediationLines`: emitted guidance for INFO findings
    ("add A record" for an existing record). Now Medium and above only.
- **report.WriteText was already wired** into `runHeadless`; the only
  CLI change was deleting dead `printReport`/`severityIdx`.
- **New test files:** `internal/core/engine/engine_test.go` (in-process
  UDP DNS fixture + real TLS server fixture; cert builder covers
  127.0.0.1 via IP SAN so x509 IP-literal verification passes; expired
  and unknown-CA paths assert trust-error wording,
  unreachable → `tls-connect` Medium), `internal/core/audit/audit_test.go`
  failure-path test, `cmd/nettools/main_test.go` (arg routing).
- **Live verification:** `--headless example.com` → 7 findings DNS+TLS,
  exit 0; `--headless example.com:99999` → stderr error + JSONL
  `"act":"parse-error"` line in `audit.jsonl`.

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
