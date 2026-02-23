# Security Decision Report

## 1. Executive Decision Summary
- Decision: **CONDITIONAL_GO**
- Decision request: Go/No-Go decision for merge and release progression
- Audience: Engineering leadership, security reviewers, release managers
- Profile: `known_provenance`
- Evidence requirement: `standard`
- Provenance: `human` (confidence: high)

## 2. Scope & Context
- Scan scope method: `env_hint`
- Changed files in scope: 1
- Assessed assets: 1

## 3. Key Metrics & Gate Outcome
- Hard-stop status: **PASS**
- New critical findings: 0
- New high findings: 0
- Secrets in delta: 0
- Delta vulnerability density (/KLOC): None
- Compliance score: 90.0
- Coverage (changed code): 100.0

## 4. Policy Compliance & Exceptions
- Policy compliance score: 90.0
- Blocking rule failures: 0
- Active exceptions: 0

## 5. Action Plan with Accountability
- [P2] Address 4 finding(s) in category 'weak_crypto' and add regression checks. | owner role: Security Champion | follow-up: Next sprint

## 6. Limitations & Confidence Statement
- Confidence: high
- Limitations:
  - Metrics are based on configured scanner outputs and parsed scope only. | why still usable: Report remains decision-useful because thresholds, scope, and provenance are explicit.
  - No-finding states can still contain residual risk due to tool blind spots. | why still usable: Report remains decision-useful because thresholds, scope, and provenance are explicit.
  - Required scan signals missing in this run: secrets. | why still usable: Report remains decision-useful because thresholds, scope, and provenance are explicit.

## 7. Evidence Appendix
- Generated at: 2026-02-23T19:44:22.805859+00:00
- Tool versions: n/a
- Config hashes captured: 7
- Baseline source: none
