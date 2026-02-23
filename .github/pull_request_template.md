### Provenance (required)
Please set one: `ai` / `human` / `external` / `mixed` / `unknown`

Provenance: unknown

---

### Security Gate Profile (optional override)
The pipeline selects a profile automatically from provenance:
- `human` -> `known_provenance`
- `mixed` -> `partial_ai_provenance`
- `ai` / `unknown` / `external` -> `ai_or_unknown_provenance`

Use this only when you need an explicit override accepted by repository policy.

Security-Profile-Override:

---

### Baseline Source (optional)
If this PR should be evaluated against a specific baseline findings artifact, link it here.

Baseline-Findings-Artifact:
