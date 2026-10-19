# 003 — Tier 2 / Tier 3 check completion

**Date:** 2026-10-19
**Status:** decided and implemented (tests in `internal/core/{tlscheck,dnscheck}/*_test.go`)
**Approver:** operator (delegated: "do as your recommendation")

## Context

The v1.0 requirements spec deferred everything below Tier 1. The remaining
specified checks were closed in this change, and four judgement calls had to be
made along the way. They are recorded here because each one trades coverage
against a risk the spec calls out explicitly.

## Decisions

### D12 — Network-reaching checks are opt-in, not default

CT-log lookups (`--discover-ct`), wordlist probing (`--discover`), DNS-over-HTTPS
(`--doh`) and zone transfers (`--axfr`) leave the target's own records and touch
third parties or attempt an intrusive query. FR-S8 says only operator-supplied
targets are contacted, and the spec's risk table lists legal exposure as a
high-impact risk. All four therefore default to off, only ever ask about the
operator-supplied domain, and are documented as such in the README and in the
interface (TUI switches, web UI checkboxes) so they cannot be enabled by accident.

Rejected alternative: enabling them by default with a `--safe` opt-out. Rejected
because a default that performs AXFR attempts and outbound CT queries is exactly
the behaviour the spec's risk mitigation was written to prevent.

### D13 — The multi-query checks sit behind `--deep`

NFR-2 requires a single-host check to complete in a few seconds and never hang.
SRV (9 prefixes), DKIM (12 selectors), TLSA, MTA-STS, TLS-RPT, TTL and delegation
would add ~25 queries per target, and each is bounded by `--timeout`, so on an
unresponsive domain the default run would multiply its worst case by 25.

Decision: DNSSEC validation and CNAME chain/loop detection stay on by default
(2–3 extra queries, high evidence value); everything else is `--deep`.
Rejected alternative: running them concurrently. Concurrency bounds wall-clock
time but not query volume, and it makes the failure output harder to attribute.

### D14 — DNSSEC validation is one delegation level, and says so

Full validation needs a trust anchor and a signature path from the root. The
implementation links the parent's DS record to a served DNSKEY (digest match) and
verifies the RRSIG over the DNSKEY set, reporting `dnssec validated`,
`dnssec unvalidated`, `dnssec bogus`, or `dnssec insecure` (no DS published).
A zone is never reported as fully validated, and the `Because` text states that a
full path to the root anchor is not built.

Two implementation details are load-bearing:
- RRSIG is not a queryable type. Signatures must be requested with the EDNS0 DO
  bit and read out of the answer that covers them, otherwise a correctly signed
  zone looks unsigned. Verified against a live resolver before and after the fix.
- The key-tag match is used to pick the verifying key, because the DNSKEY set is
  normally signed by the KSK the DS record commits to, not by every served key.

### D15 — "Lame delegation" must not blame a local resolver

A non-recursive SOA probe to a delegated nameserver is answered by the target
server on a clean network, but by a forwarder, VPN split DNS or an intercepting
resolver on many corporate and sandbox networks — which would produce a false
"lame delegation" finding about a healthy zone (observed directly during
verification). Replies carrying recursion available or authenticated data are
therefore classified as *not verifiable from this network* (Low, with the flags
in the detail) rather than lame (Medium). Lame stays reserved for a reply that
claims nothing but arrives without authority, or no reply at all.

### D16 — An empty DKIM `p=` is a revocation, not a key

`v=DKIM1; p=` is DKIM's published marker for a withdrawn key. Counting it as a
key produced a false "12 keys found" result for a domain with no DKIM at all
during verification. The check now requires non-empty key material and reports
`dkim key revoked` separately when only empty records are found.

## Consequence for the parity requirement (FR-S1/S2)

Adding CLI switches re-opened a parity gap: a CLI-only flag would make the TUI
and web UI less capable than the headless path. Every new switch is therefore
exposed in all three interfaces — `ctrl+d/o/w/t/x` in the TUI (states rendered as
words, FR-S5) and as checkboxes in the web form — and the TUI test asserts that a
toggled switch reaches the shared core context.

## Verification recorded with this decision

- `go test -count=1 ./...` — 13/13 packages, exit 0; `go vet`, `gofmt` clean
- Live `example.com` default run: 26 findings, no false positives; `dnssec
  validated`, `chain complete and in order`, `signature=ECDSA-SHA256`,
  `key=ECDSA-256 bits`, `validation=DV`
- Live opt-in runs confirmed: `--deep` 34 findings, `--doh` agrees,
  `--discover` found `www.example.com`, `--axfr` refused, `--enumerate` flagged
  four CBC cipher suites HIGH and reported `sni_certificates=1`,
  `--check-revocation` reported `ocsp good` plus an unreadable CRL endpoint
- Conditions the tool cannot control are reported honestly rather than hidden:
  the CT log returned HTTP 429 (rate limit) and one CRL endpoint returned a
  malformed document; both appear as detail text on the finding
