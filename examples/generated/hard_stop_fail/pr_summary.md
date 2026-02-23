# Security Decision Report

## 1. Executive Decision Summary
- Decision: **NO-GO**
- Decision request: Go/No-Go decision for merge and release progression
- Audience: Engineering leadership, security reviewers, release managers
- Profile: `known_provenance`
- Evidence requirement: `standard`
- Provenance: `human` (confidence: high)

## 2. Scope & Context
- Scan scope method: `env_hint`
- Changed files in scope: 2
- Assessed assets: 2

## 3. Key Metrics & Gate Outcome
- Hard-stop status: **FAIL**
- New critical findings: 0
- New high findings: 2
- Secrets in delta: 1
- Delta vulnerability density (/KLOC): None
- Compliance score: 50.0
- Coverage (changed code): 100.0

## 4. Policy Compliance & Exceptions
- Policy compliance score: 50.0
- Blocking rule failures: 2
- Active exceptions: 0

## 5. Action Plan with Accountability
- [P1] Resolve high-severity findings in changed code before merge. | owner role: Backend Engineering Lead | follow-up: Before merge
- [P0] Rotate and revoke exposed credential material; remove secret from code and history. | owner role: Application Security Engineer | follow-up: Before merge
- [P2] Address 1 finding(s) in category 'sql_injection' and add regression checks. | owner role: Backend Engineering Lead | follow-up: Next sprint
- [P2] Address 1 finding(s) in category 'secret' and add regression checks. | owner role: Application Security Engineer | follow-up: Next sprint

## 6. Limitations & Confidence Statement
- Confidence: high
- Limitations:
  - Metrics are based on configured scanner outputs and parsed scope only. | why still usable: Report remains decision-useful because thresholds, scope, and provenance are explicit.
  - No-finding states can still contain residual risk due to tool blind spots. | why still usable: Report remains decision-useful because thresholds, scope, and provenance are explicit.

## 7. Evidence Appendix
- Generated at: 2026-02-23T19:44:22.650187+00:00
- Tool versions: n/a
- Config hashes captured: 7
- Baseline source: none
