"""Render an :class:`AssessmentReport` as Markdown or JSON.

Both renderers consume the exact same normalized model — neither has its own
domain logic, and neither recomputes a Finding/Control/Retest/Regression
conclusion. They only format what is already in the report.
"""
from __future__ import annotations

import json
from typing import Any, Dict

from orion.reports.assessment import AssessmentReport

LIMITATIONS = [
    "This report summarizes evidence available to Orion at generation time.",
    "Absence of a Finding does not establish absence of vulnerability.",
    "Assessment lifecycle status does not represent a security certification.",
    "A Control marked as applied is not considered effective unless verified by Retest.",
    "Manual Security Regression results represent the latest explicitly executed "
    "local validation available to Orion.",
    "Unavailable or missing evidence is reported explicitly and is not interpreted "
    "as safe behavior.",
]


def render_json(report: AssessmentReport) -> str:
    """The same normalized model, serialized deterministically."""
    return json.dumps(report.to_dict(), indent=2, sort_keys=False, default=str)


# --------------------------------------------------------------------------- #
# Markdown
# --------------------------------------------------------------------------- #
def _fmt(value: Any) -> str:
    if value is None:
        return "UNKNOWN"
    if isinstance(value, bool):
        return str(value)
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value) if value else "—"
    return str(value)


def _kv_table(rows: Dict[str, Any]) -> str:
    lines = ["| Field | Value |", "| --- | --- |"]
    for key, value in rows.items():
        lines.append(f"| {key} | {_fmt(value)} |")
    return "\n".join(lines)


def _section(title: str) -> str:
    return f"\n## {title}\n"


def render_markdown(report: AssessmentReport) -> str:
    r = report.to_dict()
    a = r["assessment"]
    out = [f"# Orion AI Security Assessment Report", ""]
    out.append(f"Report version: `{r['report_version']}`  ")
    out.append(f"Generated at: `{r['generated_at']}` (report artifact timestamp, "
               "not the Assessment's own timeline)")

    out.append(_section("Assessment"))
    out.append(_kv_table({
        "Assessment ID": a["assessment_id"], "Name": a["name"], "Description": a["description"],
        "Lifecycle status": a["lifecycle_status"], "Created at": a["created_at"],
        "Updated at": a["updated_at"],
    }))
    out.append("\nAssessment lifecycle status is not a security verdict.")

    out.append(_section("Scope"))
    if r["scope"]:
        out.append(_kv_table(r["scope"]))
    else:
        out.append("UNKNOWN — scope not defined.")

    out.append(_section("System / Target / Environment"))
    profiles = r["profiles"]
    for kind in ("system", "target", "environment"):
        if kind not in profiles:
            continue
        prof = profiles[kind]
        out.append(f"\n### {kind.title()}\n")
        if not prof:
            out.append("UNKNOWN — profile unavailable.")
            continue
        rows = {k.replace("_", " ").title(): v for k, v in prof.items() if k != "kind"}
        out.append(_kv_table(rows))

    out.append(_section("Analysis Context"))
    if r["analysis_context"]:
        for c in r["analysis_context"]:
            out.append(f"- `{c['analysis_context_id']}` — coverage: {_fmt(c.get('coverage'))}")
    else:
        out.append("No analysis context recorded.")

    out.append(_section("Threat Models"))
    if r["threat_models"]:
        for tm in r["threat_models"]:
            if tm["available"]:
                out.append(f"- `{tm['threat_model_id']}` — available via plan `{tm['source_plan_id']}`")
            else:
                out.append(f"- `{tm['threat_model_id']}` — UNAVAILABLE")
    else:
        out.append("No threat models recorded.")

    out.append(_section("Plans and Experiments"))
    out.append("### Plans\n")
    if r["plans"]:
        out.append("| Plan ID | Status | Approved by human | Threat model | Experiments |")
        out.append("| --- | --- | --- | --- | --- |")
        for p in r["plans"]:
            out.append(f"| `{p['plan_id']}` | {p['status']} | {p['approved_by_human']} | "
                      f"{_fmt(p['threat_model_id'])} | {len(p['experiment_proposal_ids'])} |")
    else:
        out.append("No plans recorded.")
    out.append("\n### Experiments\n")
    if r["experiments"]:
        out.append("| Experiment ID | Attack | Family | Target | Stage | Finding |")
        out.append("| --- | --- | --- | --- | --- | --- |")
        for e in r["experiments"]:
            out.append(f"| `{e['experiment_id']}` | {_fmt(e['attack_id'])} | {_fmt(e['family'])} | "
                      f"{_fmt(e['target'])} | {_fmt(e['lifecycle_state'])} | {_fmt(e['finding_id'])} |")
    else:
        out.append("No experiments recorded.")

    out.append(_section("Findings"))
    if r["findings"]:
        for f in r["findings"]:
            out.append(f"\n### {f['finding_id']} — {f['title']}\n")
            out.append(_kv_table({
                "Status": f["status"], "Severity": f["severity"], "Confidence": f["confidence"],
                "Target": f["affected_target"], "Component": f["affected_component"],
                "Attack ID": f["attack_id"], "Family": f["family"],
                "Trust path": " → ".join(f["trust_path"]) if f["trust_path"] else "UNKNOWN",
                "Boundary crossed": f["boundary_crossed"] or "UNKNOWN",
                "Success condition": f["success_condition"] or "UNKNOWN",
                "Applied control": f["applied_control"] or "None applied",
                "Retest status": f["retest_status"] or "NOT RETESTED",
                "Evidence": ", ".join(f["evidence_refs"]) or "—",
            }))
            corr = f.get("corroboration") or {}
            if corr.get("legacy"):
                out.append("\nCorroboration: **UNKNOWN / LEGACY** (pre-dates per-criterion corroboration).")
            elif corr:
                out.append(f"\nCorroboration: {corr.get('trial_count', 0)} independent run(s), "
                          f"{corr.get('successful_trials', 0)} successful, "
                          f"reproduced criteria: {_fmt(corr.get('criteria_reproduced'))}, "
                          f"confirmation eligible: {corr.get('confirmation_eligible')}.")
    else:
        out.append("No Findings recorded. Absence of a Finding does not establish absence of vulnerability.")

    out.append(_section("Controls and Retests"))
    out.append("### Controls\n")
    if r["controls"]:
        out.append("| Control | Implementation | Finding | Applied Status | "
                   "Verification Status | Retest Result | Retest Run |")
        out.append("| --- | --- | --- | --- | --- | --- | --- |")
        for c in r["controls"]:
            retest_result = c.get("retest_result") or "— (no retest)"
            out.append(f"| {_fmt(c['control_ref'])} | {_fmt(c['implementation'])} | "
                      f"{_fmt(c['finding_id'])} | {c['applied_status']} | {c['verification_status']} | "
                      f"{retest_result} | {_fmt(c.get('retest_run_id'))} |")
    else:
        out.append("No controls recorded.")
    out.append("\nApplied ≠ Effective: a Control's verification status records only whether a Retest was "
               "run, never that it worked. The Retest Result column carries the originating Finding's "
               "existing outcome; effectiveness is never inferred from the presence of a Retest.\n")
    out.append("### Retests\n")
    if r["retests"]:
        out.append("| Retest Run | Finding | Control | Result |")
        out.append("| --- | --- | --- | --- |")
        for rt in r["retests"]:
            out.append(f"| `{rt['retest_run_id']}` | {rt['finding_id']} | {_fmt(rt['control_ref'])} | "
                      f"{rt['result']} |")
    else:
        out.append("No retests recorded.")

    out.append(_section("Manual Security Regressions"))
    if r["security_regressions"]:
        for reg in r["security_regressions"]:
            out.append(f"\n### {reg['regression_id']} — {reg['name']}\n")
            sig = reg["success_signature"] or {}
            expected = reg["expected_security_state"] or {}
            out.append(_kv_table({
                "Status": reg["status"], "Source finding": reg["source_finding_id"],
                "Control": reg["control"], "Attack": reg["attack_id"], "Target": reg["target"],
                "Latest manual result": reg["latest_result"], "Latest run": reg["latest_run_id"] or "—",
                "Last evaluated at": reg["last_evaluated_at"] or "—",
            }))
            out.append(f"\nOriginal security failure (Success Signature): {_fmt(sig)}  ")
            out.append(f"Expected protected behavior (Expected Security State): {_fmt(expected)}")
    else:
        out.append("No Manual Security Regressions recorded.")

    out.append(_section("Current Factual Posture"))
    out.append(_kv_table(r["posture_summary"]))
    out.append("\nThese are counts of existing recorded state, not a security score or verdict.")

    out.append(_section("Evidence Index"))
    if r["evidence_index"]:
        for ev in r["evidence_index"]:
            refs = ", ".join(f"{k}={v}" for k, v in ev.items() if k not in ("run_id", "type") and v)
            out.append(f"- `{ev['run_id']}` — {ev['type']}" + (f" ({refs})" if refs else ""))
    else:
        out.append("No evidence recorded.")

    out.append(_section("Provenance"))
    out.append(_kv_table(r["provenance"]))

    out.append(_section("Unknowns and Unavailable References"))
    if r["unknowns"]:
        out.append("### Unknown counts\n")
        for u in r["unknowns"]:
            out.append(f"- `{u['field']}`: UNKNOWN — {u['reason']}")
    if r["unavailable_references"]:
        out.append("\n### Unavailable references\n")
        for u in r["unavailable_references"]:
            out.append(f"- `{u['id']}` ({u['type']}): {u['reason']}")
    if not r["unknowns"] and not r["unavailable_references"]:
        out.append("None recorded.")

    out.append(_section("Limitations"))
    for line in LIMITATIONS:
        out.append(f"- {line}")

    return "\n".join(out) + "\n"
