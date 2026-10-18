"""Basic Assessment Report: a read-only, normalized export of existing
Assessment state — never a second security engine.

Reuses the canonical Assessment fixtures from test_assessments.py (effort,
plan, snapshot) so the report is exercised against the same real domain
objects the rest of the suite already trusts.
"""
import json

import pytest

from orion.assessments import AssessmentService
from orion import experiments as EXP
from orion import findings as F
from orion import security_regressions as SR
from orion.evidence import EvidenceStore
from tests.security_cases.test_assessments import effort, plan, snapshot


def _mitigated_assessment(tmp_path):
    """Assessment -> Plan -> Experiment -> Finding -> Control -> EFFECTIVE Retest
    -> Security Regression, all linked through the real Assessment service."""
    service = AssessmentService(tmp_path)
    a = effort(tmp_path, status="ACTIVE")
    ws = service.create_experiment(a.assessment_id, plan(tmp_path).plan_id)
    EXP.run_agentic_attack(ws, {"attack_id": "ORN-ATTACK-PI-002"}, str(tmp_path))
    m = EXP.measure(ws, str(tmp_path))
    fid = m["finding_id"]
    EXP.apply_defense(ws, {"control_id": "tool_authorization"}, str(tmp_path))
    EXP.retest(ws, str(tmp_path))
    reg = SR.create_from_finding(fid, str(tmp_path))
    return service, a, ws, fid, reg


# ------------------------------- §49 normal ---------------------------------- #
def test_normal_report_contains_all_major_sections(tmp_path):
    from orion.reports import build_assessment_report
    service, a, ws, fid, reg = _mitigated_assessment(tmp_path)
    report = build_assessment_report(a.assessment_id, str(tmp_path))

    assert report.assessment["assessment_id"] == a.assessment_id
    assert any(p["plan_id"] == ws.plan_id for p in report.plans)
    assert any(tm["threat_model_id"] == ws.threat_model_id for tm in report.threat_models)
    assert any(e["experiment_id"] == ws.experiment_workspace_id for e in report.experiments)
    assert any(f["finding_id"] == fid for f in report.findings)
    assert any(c["finding_id"] == fid for c in report.controls)
    assert any(r["finding_id"] == fid for r in report.retests)
    assert any(r["regression_id"] == reg.regression_id for r in report.security_regressions)
    assert report.report_version == "1"
    assert report.generated_at


# ------------------------------ §50 no findings ------------------------------ #
def test_no_findings_report_does_not_claim_secure(tmp_path):
    from orion.reports import build_assessment_report, render_markdown, render_json
    a = effort(tmp_path)
    report = build_assessment_report(a.assessment_id, str(tmp_path))
    assert report.findings == []
    assert report.posture_summary["findings_total"] == 0        # reliably known: zero
    md, js = render_markdown(report), render_json(report)
    assert "SECURE" not in md.upper().replace("SECURITY", "")
    assert "SECURE" not in json.dumps(json.loads(js)).upper().replace("SECURITY", "")


# -------------------------------- §51 unknown --------------------------------- #
def test_unknown_stays_explicit_not_zero(tmp_path):
    from orion.reports import build_assessment_report, render_markdown
    service = AssessmentService(tmp_path)
    a = effort(tmp_path)
    ws = service.create_experiment(a.assessment_id, plan(tmp_path).plan_id)
    (tmp_path / ws.experiment_workspace_id / "workspace.json").unlink()   # corrupt reference

    report = build_assessment_report(a.assessment_id, str(tmp_path))
    assert report.posture_summary["experiments_total"] is None
    assert report.posture_summary["findings_total"] is None
    assert any(u["field"] == "experiments_total" for u in report.unknowns)
    assert any(e["id"] == ws.experiment_workspace_id for e in report.unavailable_references)
    md = render_markdown(report)
    assert "`experiments_total`: UNKNOWN" in md
    assert "experiments_total | 0" not in md.replace(" ", "")  # never silently zero


# --------------------- §52 control applied without retest -------------------- #
def test_control_applied_without_retest_is_not_verified(tmp_path):
    from orion.reports import build_assessment_report, render_markdown
    service = AssessmentService(tmp_path)
    a = effort(tmp_path, status="ACTIVE")
    ws = service.create_experiment(a.assessment_id, plan(tmp_path).plan_id)
    EXP.run_agentic_attack(ws, {"attack_id": "ORN-ATTACK-PI-002"}, str(tmp_path))
    EXP.measure(ws, str(tmp_path))
    EXP.apply_defense(ws, {"control_id": "tool_authorization"}, str(tmp_path))

    report = build_assessment_report(a.assessment_id, str(tmp_path))
    assert len(report.controls) == 1
    control = report.controls[0]
    assert control["applied_status"] == "APPLIED"
    assert control["verification_status"] == "NOT_VERIFIED"
    assert control["retest_result"] is None           # no retest -> no result, never EFFECTIVE
    assert report.retests == []                        # no retest evidence yet
    md = render_markdown(report)
    # The Control table row must never imply the control was retested, effective or mitigated.
    controls_block = md.split("### Controls")[1].split("### Retests")[0]
    control_rows = [ln for ln in controls_block.splitlines()
                    if ln.startswith("|") and "---" not in ln and "Control |" not in ln]
    rows_text = " ".join(control_rows).upper().replace("NOT_VERIFIED", "")
    assert "RETESTED" not in rows_text
    assert "EFFECTIVE" not in rows_text and "MITIGATED" not in rows_text
    # And no EFFECTIVE/MITIGATED verdict anywhere in the report body (outside Limitations).
    body = md.split("## Limitations")[0].upper().replace("NOT_VERIFIED", "")
    assert "EFFECTIVE" not in md and "MITIGATED" not in body


# ------------------------------ §53 effective retest -------------------------- #
def test_effective_retest_is_reported_from_existing_state(tmp_path):
    from orion.reports import build_assessment_report, render_markdown
    service, a, ws, fid, reg = _mitigated_assessment(tmp_path)
    finding = F.load_finding(fid, str(tmp_path))
    assert finding.retest_status == "EFFECTIVE"

    report = build_assessment_report(a.assessment_id, str(tmp_path))
    retest_entries = [r for r in report.retests if r["finding_id"] == fid]
    assert len(retest_entries) == 1
    assert retest_entries[0]["result"] == "EFFECTIVE"
    assert retest_entries[0]["retest_run_id"] == finding.retest_refs[0]

    # The Control reflects the Finding's existing EFFECTIVE result via retest_result —
    # it is RETESTED, never independently "verified"/"mitigated" by the report.
    control = next(c for c in report.controls if c["finding_id"] == fid)
    assert control["applied_status"] == "APPLIED"
    assert control["verification_status"] == "RETESTED"
    assert control["retest_result"] == "EFFECTIVE"
    assert "MITIGATED" not in control.values()          # control is never relabeled MITIGATED
    md = render_markdown(report)
    controls_block = md.split("### Controls")[1].split("### Retests")[0]
    assert "RETESTED" in controls_block and "EFFECTIVE" in controls_block
    assert "MITIGATED" not in controls_block            # the control row never says MITIGATED


# --------------------- §53b ineffective retest (RETESTED != EFFECTIVE) -------- #
def test_ineffective_retest_is_retested_but_not_effective(tmp_path):
    """A retested control whose retest did NOT work is RETESTED with an
    INEFFECTIVE result — existence of a Retest never implies effectiveness."""
    from orion.reports import build_assessment_report, render_markdown
    service = AssessmentService(tmp_path)
    a = effort(tmp_path, status="ACTIVE")
    ws = service.create_experiment(a.assessment_id, plan(tmp_path).plan_id)
    EXP.run_agentic_attack(ws, {"attack_id": "ORN-ATTACK-PI-002"}, str(tmp_path))
    m = EXP.measure(ws, str(tmp_path))
    fid = m["finding_id"]
    EXP.apply_defense(ws, {"control_id": "output_filtering"}, str(tmp_path))   # does not mitigate PI-002
    EXP.retest(ws, str(tmp_path))

    finding = F.load_finding(fid, str(tmp_path))
    assert finding.retest_status == "INEFFECTIVE"       # existing domain result, not recomputed

    report = build_assessment_report(a.assessment_id, str(tmp_path))
    control = next(c for c in report.controls if c["finding_id"] == fid)
    assert control["applied_status"] == "APPLIED"
    assert control["verification_status"] == "RETESTED"  # a retest ran …
    assert control["retest_result"] == "INEFFECTIVE"     # … and it did not work
    md = render_markdown(report)
    controls_block = md.split("### Controls")[1].split("### Retests")[0]
    assert "INEFFECTIVE" in controls_block
    # The report must never present this control as effective or mitigated.
    assert "MITIGATED" not in controls_block
    # EFFECTIVE must not appear as a standalone token (INEFFECTIVE contains it as a substring).
    import re
    assert not re.search(r"(?<!IN)EFFECTIVE", controls_block)


# ------------------------- §53c profile normalization ------------------------- #
def _with_profiles(tmp_path):
    from orion.context.store import save_profile
    from orion.context.self_profile import build_self_profile
    from orion.context.target import build_target_profile
    from orion.context.environment import build_environment_profile
    sp = build_self_profile({"system_type": "generative_ai",
                             "capabilities": {"tools": True, "rag": True, "gradients": False},
                             "generative_ai": {"fingerprint": {"subtype": "llm_agent"}}})
    tp = build_target_profile({"name": "Agent", "target_type": "ai_agent", "objective": "summarize",
                               "security_objective": "no exfil",
                               "known_interfaces": ["/chat", "/api"], "self_profile_id": sp.self_profile_id})
    ep = build_environment_profile({"target": "http://agent", "endpoints": ["/chat", "/api/v1"],
                                    "report_markdown": "langchain openai chromadb mcp"},
                                   target_reference="http://agent")
    save_profile(sp.self_profile_id, sp.to_dict(), str(tmp_path))
    save_profile(tp.target_profile_id, tp.to_dict(), str(tmp_path))
    save_profile(ep.environment_profile_id, ep.to_dict(), str(tmp_path))
    a = effort(tmp_path, system_profile_id=sp.self_profile_id, target_id=tp.target_profile_id,
               environment_id=ep.environment_profile_id)
    return a, sp, tp, ep


def test_profiles_are_normalized_concisely(tmp_path):
    from orion.reports import build_assessment_report, render_markdown
    a, sp, tp, ep = _with_profiles(tmp_path)
    report = build_assessment_report(a.assessment_id, str(tmp_path))

    system = report.profiles["system"]
    assert system["id"] == sp.self_profile_id            # authoritative identifier retained
    assert system["system_type"] == "generative_ai"
    assert system["capabilities"] == ["rag", "tools"]    # enabled only, sorted deterministically

    target = report.profiles["target"]
    assert target["id"] == tp.target_profile_id
    assert target["target_type"] == "ai_agent"
    assert target["interfaces"] == ["/api", "/chat"]     # sorted (order carries no domain meaning)

    environment = report.profiles["environment"]
    assert environment["id"] == ep.environment_profile_id
    assert environment["ai_dependencies"] == sorted(environment["ai_dependencies"])
    assert "MCP server" in environment["mcp_servers"]

    md = render_markdown(report)
    sys_section = md.split("### System")[1].split("### Target")[0]
    assert sp.self_profile_id in sys_section
    assert "| Field | Value |" in sys_section            # rendered as a table, never a raw dict
    assert "{" not in sys_section and "'" not in sys_section


def test_normalized_profile_is_not_the_raw_profile_dump(tmp_path):
    """The normalized summary must not be the raw Profile.to_dict(): large raw
    payloads (fingerprints, recon output, nested dependency/trust dicts) stay out."""
    from orion.reports import build_assessment_report
    a, sp, tp, ep = _with_profiles(tmp_path)
    report = build_assessment_report(a.assessment_id, str(tmp_path))

    assert report.profiles["system"] != sp.to_dict()
    assert report.profiles["target"] != tp.to_dict()
    assert report.profiles["environment"] != ep.to_dict()
    # None of the large/raw fields leak into the normalized system/environment summaries.
    assert "profile" not in report.profiles["system"]          # model fingerprints
    assert "security_posture" not in report.profiles["system"]
    for raw_field in ("assets", "trust_relationships", "topology", "findings", "counts", "endpoints"):
        assert raw_field not in report.profiles["environment"]
    # ai_dependencies is a concise list of names, never the raw list of dicts.
    assert all(isinstance(d, str) for d in report.profiles["environment"]["ai_dependencies"])


def test_missing_profile_is_unknown_and_tracked(tmp_path):
    """A referenced-but-unloadable profile normalizes to None (UNKNOWN in
    Markdown) and is still recorded in unavailable_references — never dropped."""
    from orion.reports import build_assessment_report, render_markdown
    a = effort(tmp_path, system_profile_id="ORN-SELF-DEADBEEF")   # valid id, never saved
    report = build_assessment_report(a.assessment_id, str(tmp_path))

    assert report.profiles["system"] is None
    assert any(u["type"] == "profile" and u["id"] == "ORN-SELF-DEADBEEF"
               for u in report.unavailable_references)
    md = render_markdown(report)
    sys_section = md.split("### System")[1].split("### Target")[0]
    assert "UNKNOWN" in sys_section


# ------------------------- §54 regression never run --------------------------- #
def test_regression_never_run_reports_not_run(tmp_path):
    from orion.reports import build_assessment_report, render_markdown
    service, a, ws, fid, reg = _mitigated_assessment(tmp_path)
    report = build_assessment_report(a.assessment_id, str(tmp_path))
    entry = next(r for r in report.security_regressions if r["regression_id"] == reg.regression_id)
    assert entry["latest_result"] == "NOT_RUN"
    assert entry["latest_run_id"] is None
    md = render_markdown(report)
    assert "NOT_RUN" in md


# ---------------------------- §55 regression pass ------------------------------ #
def test_regression_pass_reports_pass_with_run_id(tmp_path):
    from orion.reports import build_assessment_report
    service, a, ws, fid, reg = _mitigated_assessment(tmp_path)
    result = SR.run_regression(reg.regression_id, str(tmp_path))
    assert result.result == "PASS"

    report = build_assessment_report(a.assessment_id, str(tmp_path))
    entry = next(r for r in report.security_regressions if r["regression_id"] == reg.regression_id)
    assert entry["latest_result"] == "PASS"
    assert entry["latest_run_id"] == result.run_id
    # No historical percentage / pass-rate / history list — latest result only.
    assert "history" not in entry and "pass_rate" not in entry


# ------------------------------- §56 regression fail --------------------------- #
def test_regression_fail_does_not_mutate_finding(tmp_path, monkeypatch):
    from orion.reports import build_assessment_report
    service, a, ws, fid, reg = _mitigated_assessment(tmp_path)
    finding_before = F.load_finding(fid, str(tmp_path)).to_dict()

    from orion.evidence import ExperimentRecord
    def _vulnerable(regression, base_dir, provenance):
        return ExperimentRecord(trace_id="REGRESSED-RUN", family="agentic_ai",
            adversarial_result={"authorization_decision": "ALLOW", "tool_executed": True,
                                "security_impact": "CONFIRMED", "influence_detected": True,
                                "privileged_tool_requested": "admin_export"},
            metrics={"attack_success": {"value": True}})
    monkeypatch.setattr(SR.service, "_execute", _vulnerable, raising=True)
    result = SR.run_regression(reg.regression_id, str(tmp_path))
    assert result.result == "FAIL"

    report = build_assessment_report(a.assessment_id, str(tmp_path))
    entry = next(r for r in report.security_regressions if r["regression_id"] == reg.regression_id)
    assert entry["latest_result"] == "FAIL"
    assert F.load_finding(fid, str(tmp_path)).to_dict() == finding_before
    assert service.get(a.assessment_id).status == "ACTIVE"    # assessment security state untouched


# ----------------------------- §57 missing evidence ---------------------------- #
def test_missing_evidence_produces_partial_report(tmp_path):
    from orion.reports import build_assessment_report
    from orion.findings import FindingStore
    from orion.findings.model import Finding
    service = AssessmentService(tmp_path)
    a = effort(tmp_path)
    f = Finding(status="OBSERVED", evidence_refs=["RUN-404"])
    FindingStore(tmp_path).save(f)
    service.link_finding(a.assessment_id, f.id)

    report = build_assessment_report(a.assessment_id, str(tmp_path))   # must not raise
    assert any(f.id == entry["finding_id"] for entry in report.findings)
    assert any(u["id"] == "RUN-404" for u in report.unavailable_references)


# ---------------------------- §58 corrupt experiment ---------------------------- #
def test_corrupt_experiment_is_represented_not_hidden(tmp_path):
    from orion.reports import build_assessment_report
    service = AssessmentService(tmp_path)
    a = effort(tmp_path)
    ws = service.create_experiment(a.assessment_id, plan(tmp_path).plan_id)
    (tmp_path / ws.experiment_workspace_id / "workspace.json").write_text("not json")

    report = build_assessment_report(a.assessment_id, str(tmp_path))   # must not raise
    assert any(u["id"] == ws.experiment_workspace_id for u in report.unavailable_references)
    assert report.experiments == []                                   # unresolved, not fabricated


# -------------------------------- §59 read only --------------------------------- #
def test_report_generation_is_read_only(tmp_path):
    from orion.reports import build_assessment_report, write_report
    service, a, ws, fid, reg = _mitigated_assessment(tmp_path)
    before = snapshot(tmp_path)

    report = build_assessment_report(a.assessment_id, str(tmp_path))   # no write at all
    assert snapshot(tmp_path) == before

    write_report(report, "markdown", str(tmp_path))
    write_report(report, "json", str(tmp_path))
    after = set(snapshot(tmp_path))
    before_paths = set(before)
    new_paths = after - before_paths
    assert new_paths == {
        f"{a.assessment_id}/reports/assessment-report.md",
        f"{a.assessment_id}/reports/assessment-report.json",
    }
    # Every pre-existing file is byte-for-byte unchanged.
    for path in before_paths:
        assert snapshot(tmp_path)[path] == before[path]


# ------------------------ §60 markdown/json equivalence -------------------------- #
def test_markdown_json_semantic_equivalence(tmp_path):
    from orion.reports import build_assessment_report, render_markdown, render_json
    service, a, ws, fid, reg = _mitigated_assessment(tmp_path)
    result = SR.run_regression(reg.regression_id, str(tmp_path))

    report = build_assessment_report(a.assessment_id, str(tmp_path))
    md = render_markdown(report)
    js = json.loads(render_json(report))

    assert js["assessment"]["assessment_id"] == a.assessment_id and a.assessment_id in md
    assert js["assessment"]["lifecycle_status"] in md
    finding = js["findings"][0]
    assert finding["finding_id"] in md and finding["status"] in md and finding["severity"] in md
    control = js["controls"][0]
    assert control["verification_status"] in md
    retest = js["retests"][0]
    assert retest["result"] in md
    regression = js["security_regressions"][0]
    assert regression["regression_id"] in md and regression["latest_result"] in md
    for ev in js["evidence_index"]:
        assert ev["run_id"] in md


# ------------------------- §61 deterministic report model ------------------------ #
def test_deterministic_report_model_ignoring_generated_at(tmp_path):
    from orion.reports import build_assessment_report
    service, a, ws, fid, reg = _mitigated_assessment(tmp_path)

    r1 = build_assessment_report(a.assessment_id, str(tmp_path)).to_dict()
    r2 = build_assessment_report(a.assessment_id, str(tmp_path)).to_dict()
    r1.pop("generated_at"); r2.pop("generated_at")
    assert r1 == r2


# --------------------------- §62 archived assessment ----------------------------- #
def test_archived_assessment_is_still_reportable(tmp_path):
    from orion.reports import build_assessment_report
    service, a, ws, fid, reg = _mitigated_assessment(tmp_path)
    service.complete(a.assessment_id)
    service.archive(a.assessment_id)

    report = build_assessment_report(a.assessment_id, str(tmp_path))
    assert report.assessment["lifecycle_status"] == "ARCHIVED"
    assert any(f["finding_id"] == fid for f in report.findings)


# -------------------------- §63 completed assessment ------------------------------ #
def test_completed_assessment_report_does_not_say_secure(tmp_path):
    from orion.reports import build_assessment_report, render_markdown, render_json
    service, a, ws, fid, reg = _mitigated_assessment(tmp_path)
    service.complete(a.assessment_id)

    report = build_assessment_report(a.assessment_id, str(tmp_path))
    assert report.assessment["lifecycle_status"] == "COMPLETED"
    md, js = render_markdown(report), render_json(report)
    assert "SECURE" not in md.upper().replace("SECURITY", "")
    assert "SECURE" not in js.upper().replace("SECURITY", "")


# ------------------- §64 archived security regression, no execution -------------- #
def test_archived_security_regression_shown_without_execution(tmp_path, monkeypatch):
    from orion.reports import build_assessment_report
    service, a, ws, fid, reg = _mitigated_assessment(tmp_path)
    SR.run_regression(reg.regression_id, str(tmp_path))
    SR.set_status(reg.regression_id, SR.ARCHIVED, str(tmp_path))

    calls = []
    monkeypatch.setattr(SR.service, "_execute", lambda *a, **k: calls.append(1), raising=True)
    report = build_assessment_report(a.assessment_id, str(tmp_path))

    entry = next(r for r in report.security_regressions if r["regression_id"] == reg.regression_id)
    assert entry["status"] == "ARCHIVED"
    assert entry["latest_result"] == "PASS"            # the prior result is still shown
    assert calls == []                                 # never executed by reporting


# ------------------------------------ API ---------------------------------------- #
def test_api_report_preview_and_generate(tmp_path, monkeypatch):
    import app as orion_app
    import orion.integrations.flask_blueprint as bp
    monkeypatch.setattr(bp, "ARTIFACT_DIR", str(tmp_path), raising=True)
    client = orion_app.app.test_client()

    service, a, ws, fid, reg = _mitigated_assessment(tmp_path)

    preview = client.get(f"/api/assessments/{a.assessment_id}/report")
    assert preview.status_code == 200
    assert preview.get_json()["assessment"]["assessment_id"] == a.assessment_id
    assert not (tmp_path / a.assessment_id / "reports").exists()   # preview never writes

    gen = client.post(f"/api/assessments/{a.assessment_id}/report", json={"format": "markdown"})
    assert gen.status_code == 200
    body = gen.get_json()
    assert body["format"] == "markdown" and fid in body["content"]
    assert (tmp_path / a.assessment_id / "reports" / "assessment-report.md").exists()

    assert client.post(f"/api/assessments/{a.assessment_id}/report",
                       json={"format": "bogus"}).status_code == 400
    assert client.get("/api/assessments/ORN-ASMT-MISSING/report").status_code == 404


# ------------------------------------ CLI ----------------------------------------- #
def test_cli_assessment_report(tmp_path, capsys):
    from orion import cli
    service, a, ws, fid, reg = _mitigated_assessment(tmp_path)

    rc = cli.main(["--artifacts", str(tmp_path), "assessment", "report", a.assessment_id,
                  "--format", "json"])
    assert rc == 0
    out = capsys.readouterr().out
    assert a.assessment_id in out
    assert (tmp_path / a.assessment_id / "reports" / "assessment-report.json").exists()

    rc = cli.main(["--artifacts", str(tmp_path), "assessment", "report", "ORN-ASMT-MISSING"])
    assert rc == 1
