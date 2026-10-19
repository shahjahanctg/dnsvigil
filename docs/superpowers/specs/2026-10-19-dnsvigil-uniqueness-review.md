# dnsvigil Uniqueness Review

> Status: working draft for operator review, not yet voted on.

## Intent

What is this application, and what would make it worth reaching for instead of
the scattered certificate/DNS utilities an operator already has?

This doc does **not** propose new features yet. It first names the existing
differentiation honestly, then proposes only the feature count and categories
needed to make that differentiation real rather than aspirational.

## What already exists

- One dependency-free static binary per target: **headless CLI**, **Bubble Tea
  TUI**, and **loopback-only embedded web UI** over one shared core.
- Operator-supplied targets only; no scanning, no OSINT, no discovery of
  third-party names. Network options (DoH, CT, wordlist, AXFR, enumeration,
  revocation) are **opt-in**.
- Findings model with severity + plain-language `Because` + technical `Detail`.
- Tier-1 certificate checks and Tier-1 DNS checks are present, plus a large
  deeper-dive surface behind switches: DNSSEC chain validation to a root
  anchor, resolver divergence, lame delegation, DKIM selector probing, TLSA,
  MTA-STS/TLS-RPT, wildcard, dangling CNAME, CNAME chain/loop, reverse DNS,
  TTL, fingerprint, stapling, CT presence, OCSP/CRL, protocol/cipher/SNI
  enumeration.
- Multi-format evidence export beyond text: JSON, CSV, Markdown, HTML, PDF.
- File-based run history with per-target certificate fingerprint comparison.
- Offline test suite covering parsing, core checks, trust failures, and both
  interface parity flows.

So the starting position is already broader than “cert expiry checker” or
“dig wrapper”.

## What the project says its value is

From `requirements-spec.md`:

- Primary value: **consistency, coverage, evidence production** — not raw speed
  (manual baseline already under 15 minutes per 10-host audit).
- v1 is a **single operator** internal defensive tool for the org’s own assets.
- One of the success tests is that **module #2 costs less** because the shell +
  core are reusable.
- Web UI is an explicit **operator checkpoint** before more investment.

## What “unique” would have to mean here

The repo is not trying to win by feature count alone. The plausible
differentiation is narrower:

1. **One binary, three interfaces, identical capability.** Not unique per se,
   but uncommon at this depth in a pure-Go no-CGO portables-first build.
2. **Audit-grade DNS/TLS evidence, not just yes/no.** The differentiator is
   the richness and local retention of factual findings plus exports, with
   opt-in network probing kept explicit.
3. **A reusable Network Inspection shell.** If module #2 reuses `internal/core`
   and the three front-ends, the app becomes a platform bet, not a one-tool
   bet.

So the honest uniqueness claim is not “we are the first to do X”. It is
closer to: **deep network inspection evidence in a single portable binary with
three parity interfaces and a reusable core**, aimed at one operator auditing
their own assets.

## What is missing from that claim today

If the above is the thesis, then a few gaps still sit between “exists” and
“clearly differentiated”:

1. **No operator-facing “what is this for” surface in the app itself.** README
   and spec carry the mission; the app carries the capability. A first-run
   line in TUI, a small README block in web UI, or a `--help` summary that
   says the thesis in one sentence would help the value feel real.
2. **No named workflow beyond “run, read, export”.** The app currently does
   point-in-time checks. If you want it to feel like an asset audit tool
   rather than a query tool, the history/compare/export path needs to read as
   a workflow, not just storage.
3. **Coverage of the deeper switches is uneven.** A lot of checks exist; not
   all are equally validated through the interfaces or exercised against live
   hosts in the repo’s own evidence. That is fine for v1, but it limits how
   strongly the app can claim depth.
4. **No explicit differentiation statement in the product texts.** The spec
   says what success is, but the user-facing copy does not yet synthesize it
   into “why this app.”

## Feature count question

Do **not** read this as “the app needs N features to be unique”. It needs
enough features to make the differentiation coherent. A reasonable bar for
uniqueness at this stage is not a raw number; it is whether the app can say
in one sentence what it does, and then deliver on that sentence through its
interfaces.

That said, if we want a sizing answer for planning, a plausible read of the
current surface is:

- The **already-built depth** is roughly a dozen-plus distinct DNS/TLS checks
  and multi-format export plus history. That is already more than a typical
  single-purpose cert/DNS utility.
- What would make it feel unique is **not another dozen isolated checks**. It
  is a small number of things that connect the dots: clear operator-facing
  mission, a usable point-in-time audit workflow (run → review → export → keep
  record → compare), and enough validation that the deeper checks can be
  trusted as evidence.

If I had to give a concrete planning range without inventing detail: the app’s
uniqueness is already plausibly in the **core + a few connected workflow pieces**
rather than in reaching for 50 features. The question is which few pieces make
the existing depth feel intentional.

## Next step

This doc should be turned into a short operator decision: agree on the
differentiation statement, then choose the smallest set of additions that make
that statement true in the interfaces. Before any number is committed, I’d ask:
do you want this to be a point-in-time audit tool, a recurring record of your
own asset posture, or the first module of a broader multi-tool platform?
