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
./nettools --targets hosts.txt --operator "red-team"
```

`hosts.txt` can contain one host:port per line, with `#` comments ignored.

### Set custom expiry warning

```bash
./nettools --headless example.com --expiry-warn 68
```

Warns if the certificate has more than 68 days remaining.

### Run with audit log and retention

```bash
./nettools --headless example.com --log-findings --retention 720h
```

Finds are recorded to `audit.jsonl`; entries older than 720 hours are removed on `--rotate`.

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

## Known State

- **Milestone status:** Tier 1 Complete (M1 accepted via openssl reference comparison); M2 (TUI) and M3 (web UI) built with tests
- **Tier 2 items:** OCSP/CRL, CT, fingerprint caching, protocol enumeration, extra export formats — intentionally not started; need separate decision
- `docs/` and `testdata/`: empty; `bin/`: removed

## License

Project scope is reserved; authorise the license before any distribution.

---

*For full details on real feature names, milestone meanings, and acceptance criteria, see `project-plan.md` and `requirements-spec.md`.*