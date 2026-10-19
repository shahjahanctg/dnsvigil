# SOC Tool — Network Inspection

A security tool that checks TLS certificates and DNS records for your own assets, records the evidence, and ships as a single dependency-free binary with a headless CLI, terminal UI, and local web UI.

## Version
`0.1.0-dev`

## Setup

1. Install Go 1.25.0+
2. Build the binaries:

```bash
cd cmd/nettools
CGO_ENABLED=0 go build -o ../build/nettools-linux-amd64 .
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ../build/nettools-linux-wsl .
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o ../build/nettools-linux-arm64 .
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o ../build/nettools-windows-amd64.exe .
```

2. Run the three interfaces:

```bash
./nettools-linux-amd64 --version              # show version
./nettools-linux-amd64 --headless example.com # full TLS + DNS report
./nettools-linux-amd64 --tui                  # Bubble Tea terminal UI
./nettools-linux-amd64 --gui                  # embedded web UI (loopback only, http://127.0.0.1:8089)
```

## Real Examples

### Check example.com TLS + DNS

```bash
./nettools --headless example.com
```

Output highlights:

```
=== SUMMARY ===
tool:       nettools 0.1.0-dev
operator:   cli
started:    2026-10-18T22:19:41+06:00
targets:    1
findings:   22 total
  MEDIUM   1
  INFO     21

=== SCOPE ===
  example.com:443

=== FINDINGS ===
  -- MEDIUM --
  [MEDIUM] no CAA record
    because: no CAA record was found for example.com
    detail:  no CAA record for example.com
  -- INFO --
  [INFO] a=104.20.23.154
    because: an A record exists for example.com
  [INFO] aaaa=2606:4700:10::ac42:93f3
    because: an AAAA record exists for example.com
  [INFO] no CNAME
    because: no CNAME record exists for example.com (normal when not applicable)
  [INFO] mx=0 .
    because: MX records exist for example.com
    detail:  0 .
  [INFO] txt=v=spf1 -all | _k2n1y4vw3qtb4skdx9e7dxt97qrmmq9
    because: TXT records exist for example.com
    detail:  v=spf1 -all
  [INFO] protocol=TLS 1.3 cipher=TLS_AES_128_GCM_SHA256
    because: the connection negotiated TLS protocol TLS 1.3 with cipher suite TLS_AES_128_GCM_SHA256
  issuer=CN=Cloudflare TLS Issuing ECC CA 3,O=SSL Corporation,C=US
    detail:  depth=0 subject=example.com issuer=Cloudflare TLS Issuing ECC CA 3 serial=2569673129085639595562975411803018896
```

### Check a bad port (how failures are recorded)

```bash
./nettools --headless example.com:9999
```

The run continues past the parse error and records a JSONL audit entry for the failure path.

### Use a targets file

```bash
./nettools --headless --targets hosts.txt --operator "red-team"
```

`hosts.txt` can contain one host:port per line, with `#` comments ignored.

### Query a specific resolver, or compare two

```bash
./nettools --headless --resolver 1.1.1.1:53 --second-resolver 8.8.8.8:53 example.com
```

Every DNS query goes to `--resolver`; setting `--second-resolver` adds a divergence finding (MEDIUM) when the two disagree.

### Enumerate protocols and ciphers, and check revocation

```bash
./nettools --headless --enumerate --check-revocation example.com
```

`--enumerate` makes more connections per target (one per protocol version and cipher suite, plus an SNI probe) and flags weak ciphers HIGH; `--check-revocation` queries the certificate's OCSP responder and its CRL distribution points.

### Run the deeper DNS checks

```bash
./nettools --headless --deep example.com
```

`--deep` adds SRV, DKIM, TLSA, MTA-STS, TLS-RPT, reverse DNS (with forward confirmation), TTL and delegation checks. It multiplies the number of DNS queries, so it is off by default.

### Resolve over DNS-over-HTTPS, discover names, or try a zone transfer

```bash
./nettools --headless --doh example.com
./nettools --headless --discover example.com            # built-in subdomain wordlist
./nettools --headless --discover-ct example.com         # Certificate Transparency names
./nettools --headless --axfr example.com                # zone transfer attempt
```

These reach beyond the target's own records (a DoH resolver, a CT log, an AXFR attempt), so they are off by default and only ever ask about the operator-supplied domain (FR-S8).

## Check Catalogue

Every finding carries a severity, a plain-language reason, and technical detail. Checks marked *opt-in* only run when their flag is passed (or their switch is toggled in the TUI/web UI).

| Question the check answers | Flag | Kinds |
|---|---|---|
| Is the certificate served, and who issued it? | — | `tls-identity`, `tls-chain`, `tls-chain-served` |
| Does it cover the requested name, and when does it expire? | `--expiry-warn` | `tls-hostname`, `tls-validity`, `tls-expiry`, `tls-expiry-ok`, `tls-validity-length` |
| Is the chain complete, ordered, and anchored? | — | `tls-chain-incomplete` |
| How strong are the signature and key? | — | `tls-signature`, `tls-key` |
| Is it DV, OV or EV? | — | `tls-classification` |
| What protocol and cipher were negotiated? | `--enumerate` | `tls-protocol`, `tls-protocol-weak`, `tls-cipher-weak`, `tls-protocols-offered`, `tls-ciphers-accepted` |
| Does the host present different certificates per SNI name? | `--enumerate` | `tls-sni` |
| Was a fingerprint recorded, is it stapled, is it revoked, is it in CT? | `--check-revocation` | `tls-fingerprint`, `tls-ocsp-stapling`, `tls-revocation`, `tls-crl`, `tls-ct` |
| Which DNS records exist? | — | `dns-a`, `dns-aaaa`, `dns-cname`, `dns-mx`, `dns-txt`, `dns-ns`, `dns-soa`, `dns-caa` |
| Is mail policy sound? | `--deep` | `dns-spf`, `dns-dmarc`, `dns-dkim`, `dns-mta-sts`, `dns-tls-rpt` |
| Is the zone signed, and does the delegation validate? | — | `dns-dnssec` |
| Are there alias, wildcard or takeover risks? | — | `dns-cname-chain`, `dns-cname-loop`, `dns-dangling-cname`, `dns-wildcard` |
| Does reverse DNS confirm forwardly? | `--deep` | `dns-ptr`, `dns-fcrdns` |
| Is any delegated nameserver broken? | `--deep` | `dns-lame-delegation` |
| How long may answers be cached? | `--deep` | `dns-ttl` |
| Is the service pinned in DNS, and where is it? | `--deep` | `dns-tlsa`, `dns-srv` |
| Do two resolvers agree? | `--second-resolver`, `--doh` | `dns-resolver-divergence`, `dns-doh` |
| Which names exist beyond the ones typed in? | `--discover`, `--discover-ct` | `dns-subdomain` |
| Can the whole zone be transferred? | `--axfr` | `dns-zone-transfer` |
| Did the certificate change since the last run? | — | `tls-cert-change` |

### Set custom expiry warning

```bash
./nettools --headless --expiry-warn 68 example.com
```

Warns if the certificate has more than 68 days remaining.

### Run with audit log and retention

```bash
./nettools --headless --log-findings --retention 720h example.com
```

Finds are recorded to `audit.jsonl`; entries older than 720 hours are removed on `--rotate`.

### Export the run (JSON, CSV, Markdown, HTML)

```bash
./nettools --headless --export json --report-dir .nettools/reports example.com
```

Prints the written path on stderr (for example `exported: .nettools/reports/nettools-20261019-070210.json`).

> Headless flags come **before** the target list. Flags written after a target are still parsed (the tool reorders them), but flags-first is the documented form.

## Real Feature Names (renamed from FR-*)

| Old Code | Real Feature |
|----------|-------------|
| FR-C1 | Target Import & List |
| FR-C2 | File-Based Target Import |
| FR-C3 | Certificate Chain Depth & Details |
| FR-C4 | Expiry Warning Threshold |
| FR-C5 | Hostname Matching |
| FR-C6 | Trust Failure Findings |
| FR-C7 | Protocol & Cipher Enumeration |
| FR-C8 | Fingerprint Recording |
| FR-C7 | Protocol & Cipher Details |
| FR-D1 | DNS Record Joining |
| FR-D4 | SPF Policy Evaluation |
| FR-D5 | DMARC Policy Evaluation |
| FR-A1 | No Plaintext Credentials Logged |
| FR-A2 | Audit Log Recording |
| FR-A3 | Retention Policy |
| FR-A4 | Localhost-Only Bind |
| FR-A5 | No Telemetry |
| FR-A6 | Secrets Never Logged |
| FR-A7 | Offline Operation |
| FR-A8 | TUI Interface |
| FR-A9 | Web UI (loopback only) |
| FR-R1 | Text Report Output |
| FR-R2 | JSON/CSV/Markdown/HTML Exporters |
| FR-R3 | Remediation Guidance |
| FR-R4 | Report Tiers |
| FR-R5 | Operator Tagging |
| FR-R6 | History Dashboard |
| FR-R7 | findings Summary |
| FR-R8 | Run History Store |
| FR-R9 | Web UI Dashboard |

## Milestones (renamed from M1-M3)

| Old Code | Real Milestone |
|----------|---------------|
| M1 | Tier 1 Complete — Core certificate and DNS checks verified against `openssl s_client` reference comparison |
| M2 | Terminal UI — Bubble Tea front-end over shared core, keyboard-only navigation, text severity labels, offline model tests |
| M3 | Web UI — `go:embed` assets, loopback-only server, renders identical findings; verified live via curl plus httptest suite |

## What's in the Tree
| Path | Purpose |
|------|---------|
| `cmd/nettools/main.go` | Entry point routing: `--headless \| --tui \| --gui` |
| `cmd/build/build.go` | Build pipeline note (documented, no Go package) |
| `internal/core/target/` | `Target` parsing/validation (`target.go`, `helpers.go`) |
| `internal/core/finding/` | Severity model + `Finding` results model consumed by TUI/web UI |
| `internal/core/engine/` | Orchestration: `Context` + `Run(ctx, target)` — DNS and TLS both routed through |
| `internal/core/dnscheck/` | DNS checks: A/AAAA/CAA + CNAME/MX/TXT/NS/SOA + SPF/DMARC policy |
| `internal/core/dns/` | Shared Go DNS client (`dns.Lookup`, `dns.LookupA`, ..., `dns.LookupCNAMERecord`) |
| `internal/core/tlscheck/` | TLS certificate checks: identity, validity, expiry (configurable threshold), SAN/CN, served chain, trust failures as findings, protocol/cipher with weak flags |
| `internal/core/audit/` | JSONL audit log (`audit.go`) with retention/rotate |
| `internal/core/report/` | Structured text report |
| `internal/tui/` | Bubble Tea terminal front-end over the shared core |
| `internal/webui/` | Embedded local web UI (`assets/` served via go:embed, loopback only) |
| `go.mod` / `go.sum` | Module + dependencies (`github.com/miekg/dns`, `bubbletea`) |

## Verification

```bash
go test ./...          # run all tests (offline suite, no network except explicit live runs)
CGO_ENABLED=0 go vet ./...   # static analysis
gofmt -l .             # formatting check
```

Live reference comparison passed against `openssl s_client` on example.com (subject, issuer, validity dates, serial).

Release binaries embed VCS metadata: `go version -m ./nettools` shows `vcs.revision` and `vcs.modified`. A binary built while the worktree has uncommitted changes reports `vcs.modified=true` — that reflects the build environment, not a local patch, because committing the rebuilt binary is itself a pending change.

## Known State

- **Milestone status:** Tier 1 Complete (M1 accepted via openssl reference comparison); M2 (TUI) and M3 (web UI) built with tests
- **Tier 2 and the deferred Tier 3 network checks are implemented**, each with tests: CRL revocation, DV/OV/EV classification, signature and key strength, chain completeness, SNI enumeration, DNSSEC delegation validation, SRV, reverse DNS with forward confirmation, MTA-STS, TLS-RPT, TLSA, DKIM, CNAME chain/loop detection, TTL reporting, lame delegation, DoH comparison, wordlist and CT-log discovery, and AXFR
- **Default runs stay short (NFR-2):** the multi-query checks sit behind `--deep`, and the checks that reach beyond the target's own records sit behind `--doh`, `--discover`, `--discover-ct`, and `--axfr`
- **Bounded, never hanging (NFR-3):** `--timeout` bounds each DNS query and each TLS connect/handshake attempt (default 5s), so an unreachable host is recorded as a result instead of stalling the run. Measured on this machine: a responsive host ~1.0s (default) / 3.2s (`--deep`); an unreachable host 6.7s (default) / 13.8s (`--deep`); a 3-target batch including an unreachable host 14.4s
- **DNSSEC scope:** validation links the parent's DS record to a served DNSKEY and verifies the RRSIG over the DNSKEY set. A full path to the root trust anchor is not built, so a zone is never reported as fully validated — only that its delegation validates one level
- **Not implemented:** PDF export (FR-R3, Tier 3), a custom wordlist file (the built-in list is used), and choosing the DoH provider (Cloudflare is used)
- `docs/`: the tier 2/3 decision record; `testdata/`: readable DNS fixtures; `bin/`: removed

## License

Project scope is reserved; authorise the license before any distribution.

---

*For full details on real feature names, milestone meanings, and acceptance criteria, see `project-plan.md` and `requirements-spec.md`.*