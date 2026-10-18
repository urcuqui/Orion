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
    assert report.retests == []                       # no retest evidence yet
    md = render_markdown(report)
    assert "EFFECTIVE" not in md and "MITIGATED" not in md.upper().split("## Limitations")[0].upper().replace(
        "NOT_VERIFIED", "")


# ------------------------------ §53 effective retest -------------------------- #
def test_effective_retest_is_reported_from_existing_state(tmp_path):
    from orion.reports import build_assessment_report
    service, a, ws, fid, reg = _mitigated_assessment(tmp_path)
    finding = F.load_finding(fid, str(tmp_path))
    assert finding.retest_status == "EFFECTIVE"

    report = build_assessment_report(a.assessment_id, str(tmp_path))
    retest_entries = [r for r in report.retests if r["finding_id"] == fid]
    assert len(retest_entries) == 1
    assert retest_entries[0]["result"] == "EFFECTIVE"
    assert retest_entries[0]["retest_run_id"] == finding.retest_refs[0]


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
