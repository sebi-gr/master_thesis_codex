# Example Fixtures and Generated Outputs

This folder provides deterministic example scenarios for CI gate and report validation.

## Fixtures
- `fixtures/hard_stop_fail/normalized_findings.json`
  - Includes a new high finding and a secret in changed scope.
  - Expected: hard-stop fail (`NO-GO`).

- `fixtures/soft_warning/normalized_findings.json`
  - Includes multiple medium findings without hard-stop violations.
  - Expected: soft warnings only (`CONDITIONAL_GO`, CI pass).

- `fixtures/ai_unknown_strict/normalized_findings.json`
  - Includes medium findings under unknown provenance profile.
  - Expected: stricter profile behavior with warnings (`CONDITIONAL_GO`, CI pass).

## Generated examples
- `generated/hard_stop_fail/security-report.json`
- `generated/hard_stop_fail/security-report.md`
- `generated/soft_warning/security-report.json`
- `generated/soft_warning/security-report.md`
- `generated/ai_unknown_strict/security-report.json`
- `generated/ai_unknown_strict/security-report.md`

## Re-generate locally
From `nist_auditor/`:

```bash
PYTHONPATH=. PROVENANCE=human CHANGED_FILES='src/main/java/com/example/PaymentController.java\nsrc/main/resources/application.properties' \
python3 -m tools.report_step --repo-root . --artifacts-dir examples/generated/hard_stop_fail --sarif-dir /tmp/nonexistent

PYTHONPATH=. PROVENANCE=human CHANGED_FILES='src/main/java/com/example/CryptoUtil.java' \
python3 -m tools.report_step --repo-root . --artifacts-dir examples/generated/soft_warning --sarif-dir /tmp/nonexistent

PYTHONPATH=. PROVENANCE=unknown CHANGED_FILES='src/main/java/com/example/FileExportController.java\npom.xml' \
python3 -m tools.report_step --repo-root . --artifacts-dir examples/generated/ai_unknown_strict --sarif-dir /tmp/nonexistent
```
