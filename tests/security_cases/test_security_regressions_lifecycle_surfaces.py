"""Backend-authoritative enforcement of the SecurityRegression lifecycle across
the surfaces that can trigger manual execution: the HTTP API and the CLI. The
UI only hides the button for non-ACTIVE regressions — these tests prove the
rejection holds even when a client calls the endpoint/command directly.
"""
import pytest

import app as orion_app
import orion.integrations.flask_blueprint as bp
from orion import cli
from orion import experiments as EXP
from orion import plans as PL
from orion import security_regressions as SR


def _plan(tmp_path):
    from orion.target_analysis import build_assessment_from_summary
    assessment = build_assessment_from_summary({
        "target": "http://agent", "endpoints": ["/chat"],
        "report_markdown": "ai agent with tool calling and retrieval rag",
        "findings": [{"id": "f", "title": "ml_inference_response", "severity": "info"}]})
    plan = PL.build_plan_from_target_analysis(assessment)
    PL.approve_plan(plan)
    PL.save_plan(plan, base_dir=str(tmp_path))
    return plan


def _mitigated_regression(tmp_path) -> str:
    ws = EXP.create_from_plan(_plan(tmp_path), base_dir=str(tmp_path))
    EXP.run_agentic_attack(ws, {"attack_id": "ORN-ATTACK-PI-002"}, base_dir=str(tmp_path))
    m = EXP.measure(ws, base_dir=str(tmp_path))
    fid = m["finding_id"]
    EXP.apply_defense(ws, {"control_id": "tool_authorization"}, base_dir=str(tmp_path))
    EXP.retest(ws, base_dir=str(tmp_path))
    reg = SR.create_from_finding(fid, str(tmp_path))
    return reg.regression_id


@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setattr(bp, "ARTIFACT_DIR", str(tmp_path), raising=True)
    return orion_app.app.test_client(), str(tmp_path)


# --------------------------------- API --------------------------------------- #
def test_api_runs_active_regression(api):
    client, artifacts = api
    reg_id = _mitigated_regression(artifacts)
    r = client.post(f"/api/regressions/{reg_id}/run")
    assert r.status_code == 200
    assert r.get_json()["result"] in ("PASS", "FAIL", "ERROR")


def test_api_rejects_disabled_regression_with_409(api, monkeypatch):
    client, artifacts = api
    reg_id = _mitigated_regression(artifacts)
    SR.set_status(reg_id, SR.DISABLED, artifacts)

    calls = []
    monkeypatch.setattr(SR.service, "_execute", lambda *a, **k: calls.append(1), raising=True)

    r = client.post(f"/api/regressions/{reg_id}/run")
    assert r.status_code == 409
    body = r.get_json()
    assert "DISABLED" in body["error"] and reg_id in body["error"]
    assert calls == []                                        # attack runner never invoked


def test_api_rejects_archived_regression_with_409(api, monkeypatch):
    client, artifacts = api
    reg_id = _mitigated_regression(artifacts)
    SR.set_status(reg_id, SR.ARCHIVED, artifacts)

    calls = []
    monkeypatch.setattr(SR.service, "_execute", lambda *a, **k: calls.append(1), raising=True)

    r = client.post(f"/api/regressions/{reg_id}/run")
    assert r.status_code == 409
    assert calls == []


def test_api_unknown_regression_is_still_404(api):
    client, _ = api
    r = client.post("/api/regressions/ORN-REG-DOESNOTEXIST/run")
    assert r.status_code == 404


def test_api_rejects_reactivating_archived_regression_with_409(api):
    client, artifacts = api
    reg_id = _mitigated_regression(artifacts)

    assert SR.set_status(reg_id, SR.ARCHIVED, artifacts).status == SR.ARCHIVED

    r = client.post(f"/api/regressions/{reg_id}/status", json={"status": "ACTIVE"})
    assert r.status_code == 409
    body = r.get_json()
    assert "ARCHIVED" in body["error"] and reg_id in body["error"]

    # The rejected transition changed nothing.
    still_archived = SR.get(reg_id, artifacts)
    assert still_archived.status == SR.ARCHIVED


# --------------------------------- CLI --------------------------------------- #
def test_cli_runs_active_regression(tmp_path, capsys):
    reg_id = _mitigated_regression(tmp_path)
    rc = cli.main(["--artifacts", str(tmp_path), "regression", "run", reg_id])
    assert rc == 0
    out = capsys.readouterr().out
    assert reg_id in out


def test_cli_rejects_disabled_regression(tmp_path, capsys, monkeypatch):
    reg_id = _mitigated_regression(tmp_path)
    SR.set_status(reg_id, SR.DISABLED, str(tmp_path))

    calls = []
    monkeypatch.setattr(SR.service, "_execute", lambda *a, **k: calls.append(1), raising=True)

    rc = cli.main(["--artifacts", str(tmp_path), "regression", "run", reg_id])
    assert rc != 0                                            # non-success exit
    assert calls == []
    out = capsys.readouterr().out
    assert "DISABLED" in out


def test_cli_rejects_archived_regression(tmp_path, capsys, monkeypatch):
    reg_id = _mitigated_regression(tmp_path)
    SR.set_status(reg_id, SR.ARCHIVED, str(tmp_path))

    calls = []
    monkeypatch.setattr(SR.service, "_execute", lambda *a, **k: calls.append(1), raising=True)

    rc = cli.main(["--artifacts", str(tmp_path), "regression", "run", reg_id])
    assert rc != 0
    assert calls == []
    out = capsys.readouterr().out
    assert "ARCHIVED" in out
