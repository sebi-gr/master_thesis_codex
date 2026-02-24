from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any


def _h(value: Any) -> str:
    return html.escape(str(value if value is not None else "n/a"))


def _pretty(value: Any) -> str:
    return _h(json.dumps(value, indent=2, sort_keys=True))


def _status_class(status: str) -> str:
    s = (status or "").lower()
    if s in ("fail", "no-go"):
        return "bad"
    if s in ("pass_with_warnings", "conditional_go"):
        return "warn"
    return "good"


def _render_list(items: list[Any]) -> str:
    if not items:
        return "<li>None</li>"
    return "".join(f"<li>{_h(item)}</li>" for item in items)


def _render_kpis(metrics: dict[str, Any]) -> str:
    cards = [
        ("New Critical", metrics.get("new_critical_findings_count")),
        ("New High", metrics.get("new_high_findings_count")),
        ("Secrets (Delta)", metrics.get("secrets_count_delta")),
        ("Compliance", metrics.get("compliance_score")),
        ("Coverage %", metrics.get("coverage_overall_changed_code_percent")),
    ]
    return "".join(
        """
        <div class='kpi'>
          <div class='k'>{key}</div>
          <div class='v'>{value}</div>
        </div>
        """.format(key=_h(key), value=_h(value))
        for key, value in cards
    )


def _render_table(rows: list[tuple[str, Any]]) -> str:
    body = "".join(
        "<tr><th>{}</th><td>{}</td></tr>".format(_h(k), _h(v))
        for k, v in rows
    )
    return f"<table>{body}</table>"


def _render_policy_rows(rules: list[dict[str, Any]]) -> str:
    if not rules:
        return "<tr><td colspan='6'>No policy rules evaluated.</td></tr>"

    out: list[str] = []
    for rule in rules:
        status = "PASS" if rule.get("passed") else "FAIL"
        row_cls = "good" if rule.get("passed") else "bad"
        out.append(
            "<tr>"
            f"<td>{_h(rule.get('id'))}</td>"
            f"<td>{_h(rule.get('metric'))}</td>"
            f"<td>{_h(rule.get('value'))}</td>"
            f"<td>{_h(rule.get('comparator'))} {_h(rule.get('threshold'))}</td>"
            f"<td>{_h(rule.get('exception_id') or '-')}</td>"
            f"<td><span class='pill {row_cls}'>{_h(status)}</span></td>"
            "</tr>"
        )
    return "".join(out)


def _render_actions(actions: list[dict[str, Any]]) -> str:
    if not actions:
        return "<tr><td colspan='4'>No actions generated.</td></tr>"
    return "".join(
        "<tr>"
        f"<td>{_h(a.get('priority'))}</td>"
        f"<td>{_h(a.get('item'))}</td>"
        f"<td>{_h(a.get('owner_role'))}</td>"
        f"<td>{_h(a.get('follow_up'))}</td>"
        "</tr>"
        for a in actions
    )


def _render_risk_cards(risks: list[dict[str, Any]]) -> str:
    if not risks:
        return "<div class='card'><p>No key risks recorded.</p></div>"

    cards: list[str] = []
    for risk in risks:
        sev = str(risk.get("severity") or "UNKNOWN").upper()
        sev_cls = "bad" if sev in ("CRITICAL", "HIGH") else "warn"
        cards.append(
            "<div class='card'>"
            f"<div class='row'><span class='pill {sev_cls}'>{_h(sev)}</span><strong>{_h(risk.get('category'))}</strong></div>"
            f"<p>Count: {_h(risk.get('count'))}</p>"
            "</div>"
        )
    return "".join(cards)


def _render_findings_cards(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return "<div class='card'><p>No delta findings in appendix.</p></div>"

    cards: list[str] = []
    for finding in findings[:30]:
        sev = str(finding.get("severity") or "MEDIUM").upper()
        sev_cls = "bad" if sev in ("CRITICAL", "HIGH") else "warn"
        cards.append(
            "<details class='card'>"
            f"<summary><span class='pill {sev_cls}'>{_h(sev)}</span>"
            f"<strong>{_h(finding.get('rule_id') or finding.get('category'))}</strong>"
            f"<span class='muted'>[{_h(finding.get('tool'))}]</span></summary>"
            "<div class='body'>"
            f"<p><b>File:</b> {_h(finding.get('file'))}:{_h(finding.get('start_line'))}</p>"
            f"<p><b>Message:</b> {_h(finding.get('message'))}</p>"
            f"<p><b>Category:</b> {_h(finding.get('category'))} | <b>Signal:</b> {_h(finding.get('signal'))}</p>"
            "</div></details>"
        )
    return "".join(cards)


def _render_rmf_rows(rmf_mapping: dict[str, Any]) -> str:
    functions = (rmf_mapping.get("functions") or {}) if isinstance(rmf_mapping, dict) else {}
    rows: list[str] = []
    for fn_name in ("MAP", "MEASURE", "MANAGE", "GOVERN"):
        fn = functions.get(fn_name) or {}
        rows.append(
            "<tr>"
            f"<td><span class='pill'>{_h(fn_name)}</span></td>"
            f"<td>{_h(fn.get('objective'))}</td>"
            f"<td>{_h(', '.join(fn.get('implemented_by') or []))}</td>"
            f"<td>{_h(', '.join(fn.get('key_outputs') or []))}</td>"
            "</tr>"
        )
    return "".join(rows) or "<tr><td colspan='4'>No RMF mapping available.</td></tr>"


def render_html(report: dict, template_path: Path) -> str:
    # Keep signature compatible with existing callsites; template_path is intentionally unused.
    _ = template_path

    meta = report.get("metadata") or {}
    exec_summary = report.get("executive_decision_summary") or {}
    scope = report.get("scope_context") or {}
    gate_outcome = report.get("key_metrics_gate_outcome") or {}
    metrics = gate_outcome.get("metrics") or {}
    gate = gate_outcome.get("gate") or {}
    policy = report.get("policy_compliance_exceptions") or {}
    rmf_mapping = report.get("rmf_function_mapping") or {}
    actions = report.get("action_plan_with_accountability") or []
    limitation_stmt = report.get("limitations_confidence_statement") or {}
    evidence = report.get("evidence_appendix") or {}

    decision = str(exec_summary.get("decision") or "UNKNOWN")
    decision_cls = _status_class(decision)
    gate_status = str(gate.get("status_for_ci") or "unknown")
    gate_cls = _status_class(gate_status)

    hard_violations = (gate.get("hard_stop") or {}).get("violations") or []
    soft_warnings = (gate.get("soft_gate") or {}).get("warnings") or []

    limitation_items = limitation_stmt.get("limitations") or []
    limitation_html = "".join(
        "<li><b>{}</b><br/><span class='muted'>{}</span></li>".format(
            _h(item.get("statement")),
            _h(item.get("usability_note")),
        )
        for item in limitation_items
    ) or "<li>None</li>"

    evidence_rows = _render_table(
        [
            ("Generated At (UTC)", evidence.get("generated_at_utc")),
            ("Profile", evidence.get("profile")),
            ("Tool Versions", ", ".join(evidence.get("tool_versions") or []) or "n/a"),
            ("Baseline Source", (evidence.get("baseline") or {}).get("source")),
            ("Changed Scope Method", (evidence.get("scan_scope") or {}).get("method")),
            ("Changed Files", len((evidence.get("scan_scope") or {}).get("changed_files") or [])),
            ("Config Hash Files", len(evidence.get("config_hashes_sha256") or {})),
        ]
    )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Security Decision Report</title>
  <style>
    :root {{
      --bg: #f6f8fb;
      --card: #ffffff;
      --text: #1f2937;
      --muted: #667085;
      --line: #d5dbe3;
      --good: #137333;
      --good-bg: #e6f4ea;
      --warn: #8a5a00;
      --warn-bg: #fff4d6;
      --bad: #b42318;
      --bad-bg: #fee4e2;
      --shadow: 0 8px 24px rgba(16, 24, 40, 0.06);
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif; color: var(--text); background: radial-gradient(circle at 0% 0%, #eaf0ff 0, var(--bg) 45%); }}
    .wrap {{ max-width: 1120px; margin: 28px auto; padding: 0 16px 40px; }}
    .hero {{ background: linear-gradient(135deg, #fff, #eef2ff); border: 1px solid var(--line); border-radius: 16px; padding: 18px; box-shadow: var(--shadow); }}
    h1 {{ margin: 0 0 8px; font-size: 30px; }}
    h2 {{ margin: 0 0 12px; font-size: 20px; }}
    h3 {{ margin: 0 0 10px; font-size: 16px; }}
    .muted {{ color: var(--muted); }}
    .row {{ display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }}
    .pill {{ display: inline-block; padding: 4px 10px; border-radius: 999px; font-size: 12px; font-weight: 700; border: 1px solid transparent; }}
    .pill.good {{ color: var(--good); background: var(--good-bg); border-color: #b7e1c1; }}
    .pill.warn {{ color: var(--warn); background: var(--warn-bg); border-color: #f2cf7a; }}
    .pill.bad {{ color: var(--bad); background: var(--bad-bg); border-color: #f4b3ae; }}
    .grid {{ display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 10px; margin-top: 14px; }}
    .kpi {{ background: var(--card); border: 1px solid var(--line); border-radius: 12px; padding: 12px; box-shadow: var(--shadow); }}
    .kpi .k {{ color: var(--muted); font-size: 12px; margin-bottom: 6px; }}
    .kpi .v {{ font-size: 22px; font-weight: 700; }}
    .section {{ margin-top: 16px; background: var(--card); border: 1px solid var(--line); border-radius: 14px; padding: 14px; box-shadow: var(--shadow); }}
    .split {{ display: grid; grid-template-columns: 1.4fr 1fr; gap: 12px; }}
    .card {{ border: 1px solid var(--line); border-radius: 12px; padding: 10px; margin-bottom: 10px; background: #fff; }}
    .body {{ padding-top: 8px; }}
    summary {{ cursor: pointer; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ text-align: left; padding: 8px; border-bottom: 1px solid var(--line); vertical-align: top; }}
    th {{ color: var(--muted); width: 32%; font-weight: 600; }}
    ul {{ margin: 8px 0 0 20px; padding: 0; }}
    li {{ margin: 6px 0; }}
    pre {{ background: #f8fafc; border: 1px solid var(--line); border-radius: 10px; padding: 10px; overflow: auto; max-height: 360px; }}
    @media (max-width: 980px) {{
      .grid {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      .split {{ grid-template-columns: 1fr; }}
      h1 {{ font-size: 24px; }}
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <h1>Security Decision Report</h1>
      <div class="row">
        <span class="pill {decision_cls}">Decision: {_h(decision)}</span>
        <span class="pill {gate_cls}">Gate: {_h(gate_status).upper()}</span>
        <span class="pill">Profile: {_h(exec_summary.get('gate_profile'))}</span>
        <span class="pill">Evidence: {_h(exec_summary.get('evidence_requirement_level'))}</span>
        <span class="pill">Provenance: {_h((exec_summary.get('provenance') or {{}}).get('raw_value'))}</span>
      </div>
      <p class="muted">Audience: {_h(exec_summary.get('audience'))}</p>
      <p class="muted">Decision Request: {_h(exec_summary.get('decision_request'))}</p>
      <div class="grid">
        {_render_kpis(metrics)}
      </div>
    </section>

    <section class="section">
      <div>
        <h2>NIST AI RMF Mapping</h2>
        <table>
          <tr><th>Function</th><th>Objective</th><th>Implemented By</th><th>Key Outputs</th></tr>
          {_render_rmf_rows(rmf_mapping)}
        </table>
        <h3 style="margin-top: 14px;">RMF Constraints</h3>
        <ul>{_render_list((rmf_mapping.get('constraints') or []))}</ul>
      </div>
    </section>

    <section class="section split">
      <div>
        <h2>Scope & Context</h2>
        {_render_table([
            ('Assessed Assets', len(scope.get('assessed_assets') or [])),
            ('Scope Method', (scope.get('scan_scope') or {}).get('method')),
            ('Changed Files', len((scope.get('scan_scope') or {}).get('changed_files') or [])),
            ('Changed LOC', (scope.get('scan_scope') or {}).get('changed_loc')),
            ('Repo', meta.get('repo')),
            ('Commit', meta.get('commit_sha')),
        ])}
        <h3>Exposure Assumptions</h3>
        <ul>{_render_list(scope.get('exposure_assumptions') or [])}</ul>
      </div>
      <div>
        <h2>Key Risks</h2>
        {_render_risk_cards(exec_summary.get('key_risks') or [])}
      </div>
    </section>

    <section class="section split">
      <div>
        <h2>Gate Outcome</h2>
        <h3>Hard-stop Violations</h3>
        <ul>{_render_list([v.get('reason') for v in hard_violations])}</ul>
        <h3>Soft Warnings</h3>
        <ul>{_render_list([w.get('reason') for w in soft_warnings])}</ul>
      </div>
      <div>
        <h2>Policy Compliance</h2>
        <p><b>Score:</b> {_h(policy.get('compliance_score'))}</p>
        <p><b>Blocking Failures:</b> {_h(len(policy.get('blocking_failures') or []))}</p>
        <p><b>Active Exceptions:</b> {_h(len(policy.get('active_exceptions') or []))}</p>
      </div>
    </section>

    <section class="section">
      <h2>Policy Rule Results</h2>
      <table>
        <tr>
          <th>ID</th>
          <th>Metric</th>
          <th>Value</th>
          <th>Threshold</th>
          <th>Exception</th>
          <th>Status</th>
        </tr>
        {_render_policy_rows(policy.get('rules') or [])}
      </table>
    </section>

    <section class="section">
      <h2>Action Plan with Accountability</h2>
      <table>
        <tr><th>Priority</th><th>Action</th><th>Owner Role</th><th>Follow-up</th></tr>
        {_render_actions(actions)}
      </table>
    </section>

    <section class="section split">
      <div>
        <h2>Limitations & Confidence</h2>
        <p><b>Confidence:</b> {_h(limitation_stmt.get('confidence'))}</p>
        <ul>{limitation_html}</ul>
      </div>
      <div>
        <h2>Evidence Summary</h2>
        {evidence_rows}
      </div>
    </section>

    <section class="section">
      <h2>Delta Findings (Evidence Appendix)</h2>
      {_render_findings_cards(evidence.get('raw_delta_findings') or [])}
      <details class="card">
        <summary><strong>Raw Report JSON</strong></summary>
        <div class="body"><pre>{_pretty(report)}</pre></div>
      </details>
    </section>
  </div>
</body>
</html>
"""
