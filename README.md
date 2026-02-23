# Security Gate + Audit Report (RQ1/RQ2 POC)

This repository implements a deterministic, CI-friendly security gate and an audit-ready report model aligned with:
- RQ1: quantitative CI gate metrics with hard-stop + soft gate semantics
- RQ2: decision-useful reporting (decision -> rationale -> accountability -> traceability)

## What is implemented

### Pipeline architecture
The implementation is split into explicit components under `tools/reportlib/`:
- `ingestion.py`: scanner ingestion + normalization to canonical findings
- `delta.py`: baseline-aware and changed-scope-aware new finding calculation
- `rq_metrics.py`: required RQ1 metric computation
- `coverage.py`: changed-scope scan coverage metrics
- `compliance.py`: policy-as-code rule evaluation and compliance scoring
- `provenance.py`: provenance classification (`known`, `partial_ai`, `ai_or_unknown`) + confidence
- `gate.py`: deterministic hard-stop + soft warning evaluation
- `evidence.py`: reproducibility metadata (tools/config hashes/scope/baseline)
- `reporting.py`: RQ2 report structure + markdown rendering

The orchestration entrypoint is `tools/report_step.py`.

## Config-as-code
All threshold and policy logic is centralized in `security_config/`:
- `profiles.yaml`: profile thresholds (hard-stop, soft gate, targets)
- `policies.yaml`: policy rules and weights for compliance score
- `severity_mapping.yaml`: canonical severity rules
- `coverage_targets.yaml`: coverage targets and scope patterns
- `tooling.yaml`: tool-to-signal mapping and scan metadata
- `provenance.yaml`: provenance classification rules
- `exceptions.yaml`: traceable temporary exceptions

These files are versioned and included in the evidence appendix via SHA-256 hashes.

## CI workflow
Workflow: `.github/workflows/audit.yml`

Stages:
1. provenance validation (PR events)
2. scanner jobs (Gitleaks, Semgrep, CodeQL)
3. metrics/report job (`python tools/report_step.py`)
4. deterministic gate enforcement (`enforce_quality_gate.py`)

Artifacts generated:
- `artifacts/security-report.json` (machine-readable structured report)
- `artifacts/security-report.md` (human-readable report)
- `artifacts/security-metrics.json` (compact CI metrics)
- `artifacts/gate-result.json` (gate decision payload)
- `artifacts/report.html`

## How gate decisions are made

### Hard-stop (blocking)
Default hard-stop checks (profile-driven):
- `new_critical_findings_count <= max_new_critical`
- `new_high_findings_count <= max_new_high`
- `secrets_count_delta <= max_secrets_in_delta`

Any hard-stop violation returns a failing CI outcome (non-zero exit).

### Soft gate (non-blocking by default)
Warnings are emitted for:
- medium/low deltas above warn thresholds
- vulnerability density drift
- coverage below profile target
- compliance score below profile target

Soft warnings do not fail by default.

## Profile switching and provenance
Profiles:
- `known_provenance`
- `partial_ai_provenance`
- `ai_or_unknown_provenance`

Selection:
- automatic from PR provenance trailer (`Provenance: ...`) via `provenance.yaml`
- optional override via `SECURITY_PROFILE` env var
- ambiguous/missing provenance falls back to stricter `ai_or_unknown_provenance`

## Local usage
From repository root:

```bash
python tools/report_step.py \
  --repo-root . \
  --artifacts-dir artifacts \
  --sarif-dir sarif
```

Optional delta inputs:

```bash
python tools/report_step.py \
  --repo-root . \
  --artifacts-dir artifacts \
  --sarif-dir sarif \
  --base-sha <base_sha> \
  --head-sha <head_sha> \
  --baseline-findings artifacts/baseline_findings.json
```

Gate enforcement only:

```bash
python .github/workflows/scripts/enforce_quality_gate.py \
  --gate-file artifacts/gate-result.json \
  --metrics-file artifacts/security-metrics.json
```

## Limitations and confidence interpretation
- Passing hard-stop means policy threshold compliance within measured scope, not complete security.
- Coverage and provenance confidence are explicit in the report and should be used when interpreting decisions.
- If exact changed-scope diffing is unavailable, fallback behavior is documented in report limitations.

## Migration notes (from legacy PR-threshold gate)
- Numeric PR-body thresholds are replaced by centralized `security_config/` policy and profile config.
- Gate provenance now drives profile-aware thresholds.
- The main decision artifact is now `security-report.json` and `security-report.md`.
