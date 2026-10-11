# Verification and Review

## Two-pass review
1. **Requirements conformance:** Compare the result with each approved requirement and acceptance criterion.
2. **Quality review:** Assess correctness, safety, security, privacy, usability, accessibility, maintainability, performance, provenance, and other domain-relevant properties.

Use an independent reviewer/agent when available and justified by risk or complexity. If unavailable, conduct a distinct review pass and say it was not independent.

## Domain-specific checks
Choose methods that fit the deliverable:
- Software: tests, static analysis, dependency/security scans, integration checks, deployment validation.
- Research: source quality, claim-to-source alignment, counter-evidence, date/freshness, uncertainty.
- Design: requirements fit, consistency, accessibility, visual inspection, user feedback when available.
- Business/process: stakeholder fit, feasibility, reconciliation, controls, approvals, operational ownership.
- GRC/security: control applicability, evidence quality, traceability, risk treatment, authorization, auditability.
- Learning content: learning objectives, factual accuracy, progression, examples, assessment alignment.
- Data work: schema/quality checks, reconciliation, provenance, privacy, reproducibility.

## Critical findings
Critical unresolved defects block completion. Do not conceal failures or silently lower acceptance criteria. If a safe and authorized disposition is possible, document the issue, rationale, owner, residual risk, and explicit acceptance. Otherwise pause.

## Evidence statuses
Use `Passed`, `Failed`, `Blocked`, `Not run`, `Not applicable`, or `Inferred`. Report commands/tools actually used when relevant, but avoid exposing secrets or sensitive output.
