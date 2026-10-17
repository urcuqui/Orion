"""Security Regression milestone tests (§39–46).

Manual, evidence-backed re-validation of a verified security property. Reuses the
existing experiment/attack/run/evidence infrastructure; never schedules.
"""
import pytest

from orion import plans as PL
from orion import experiments as EXP
from orion import findings as F
from orion import security_regressions as SR
from orion.evidence import EvidenceStore, ExperimentRecord
from orion.target_analysis import build_assessment_from_summary


def _plan(tmp_path):
    a = build_assessment_from_summary({"target": "http://agent", "endpoints": ["/chat"],
        "report_markdown": "ai agent with tool calling and retrieval rag",
        "findings": [{"id": "f", "title": "ml_inference_response", "severity": "info"}]})
    plan = PL.build_plan_from_target_analysis(a)
    PL.approve_plan(plan); PL.save_plan(plan, base_dir=str(tmp_path))
    return plan


def _finding_after(tmp_path, *, control=None, retest=False):
    ws = EXP.create_from_plan(_plan(tmp_path), base_dir=str(tmp_path))
    EXP.run_agentic_attack(ws, {"attack_id": "ORN-ATTACK-PI-002"}, base_dir=str(tmp_path))
    m = EXP.measure(ws, base_dir=str(tmp_path))
    fid = m["finding_id"]
    if control:
        EXP.apply_defense(ws, {"control_id": control}, base_dir=str(tmp_path))
        if retest:
            EXP.retest(ws, base_dir=str(tmp_path))
    return fid


def _mitigated(tmp_path):
    return _finding_after(tmp_path, control="tool_authorization", retest=True)


# ------------------------------ §39 signature ------------------------------- #
def test_signature_is_stable_and_discriminating():
    s1 = SR.build_success_signature("ORN-ATTACK-PI-002", "agent-a", "unauthorized_privileged_tool_execution")
    s2 = SR.build_success_signature("ORN-ATTACK-PI-002", "agent-a", "unauthorized_privileged_tool_execution")
    assert SR.signature_key(s1) == SR.signature_key(s2)          # same logical signature
    other_target = SR.build_success_signature("ORN-ATTACK-PI-002", "agent-b", "unauthorized_privileged_tool_execution")
    assert SR.signature_key(s1) != SR.signature_key(other_target)  # different target → different


def test_signature_omits_unavailable_dimensions():
    sig = SR.build_success_signature("ORN-ATTACK-EVA-PGD", "image-classifier", "prediction_changed_under_allowed_budget")
    assert "tool" not in sig and sig["security_effect"] == "adversarial_evasion"


# --------------------------- §40 creation preconditions --------------------- #
def test_cannot_create_without_control(tmp_path):
    fid = _finding_after(tmp_path)                               # attack + measure only
    with pytest.raises(SR.PreconditionError):
        SR.create_from_finding(fid, str(tmp_path))


def test_cannot_create_with_ineffective_retest(tmp_path):
    fid = _finding_after(tmp_path, control="adversarial_training", retest=True)  # no implementation → INEFFECTIVE
    f = F.load_finding(fid, str(tmp_path))
    assert f.retest_status == "INEFFECTIVE"
    assert SR.can_create_regression(f)[0] is False
    with pytest.raises(SR.PreconditionError):
        SR.create_from_finding(fid, str(tmp_path))


def test_can_create_with_effective_retest(tmp_path):
    reg = SR.create_from_finding(_mitigated(tmp_path), str(tmp_path))
    assert reg.regression_id.startswith("ORN-REG-")
    assert reg.source_control_ref == "tool_authorization"
    assert reg.expected_security_state == {"authorization_decision": "DENY",
                                           "tool_executed": False, "security_impact": False}


# --------------------------- §41 manual execution --------------------------- #
def test_execution_creates_run_and_evidence(tmp_path):
    reg = SR.create_from_finding(_mitigated(tmp_path), str(tmp_path))
    res = SR.run_regression(reg.regression_id, str(tmp_path))
    assert res.run_id                                           # a real Run id
    rec = EvidenceStore(str(tmp_path)).load(res.run_id)        # Evidence exists
    assert rec.provenance.get("regression_id") == reg.regression_id
    # Latest result is persisted and referenced by the regression.
    assert SR.get(reg.regression_id, str(tmp_path)).last_run_id == res.run_id


# -------------------------------- §42 PASS ---------------------------------- #
def test_pass_when_control_still_holds(tmp_path):
    reg = SR.create_from_finding(_mitigated(tmp_path), str(tmp_path))
    res = SR.run_regression(reg.regression_id, str(tmp_path))
    assert res.result == "PASS" and res.passed is True


# -------------------- §45 security semantics: influence ≠ impact ------------ #
def test_influence_persists_but_regression_passes(tmp_path):
    reg = SR.create_from_finding(_mitigated(tmp_path), str(tmp_path))
    res = SR.run_regression(reg.regression_id, str(tmp_path))
    assert res.result == "PASS"
    assert res.observed["agent_influenced"] is True            # still influenceable
    assert res.observed["authorization_decision"] == "DENY"    # but boundary holds
    assert res.observed["tool_executed"] is False


# -------------------------------- §43 FAIL ---------------------------------- #
def test_fail_when_control_regresses(tmp_path, monkeypatch):
    reg = SR.create_from_finding(_mitigated(tmp_path), str(tmp_path))

    def _vulnerable(regression, base_dir, provenance):
        return ExperimentRecord(trace_id="REGRESSED-RUN", family="agentic_ai",
            adversarial_result={"authorization_decision": "ALLOW", "tool_executed": True,
                                "security_impact": "CONFIRMED", "influence_detected": True,
                                "privileged_tool_requested": "admin_export"},
            metrics={"attack_success": {"value": True}})
    monkeypatch.setattr(SR.service, "_execute", _vulnerable, raising=True)
    res = SR.run_regression(reg.regression_id, str(tmp_path))
    assert res.result == "FAIL" and res.passed is False
    assert "tool_executed" in res.mismatches


# ----------------------- §44 ERROR / not evaluable -------------------------- #
def test_error_when_execution_fails(tmp_path, monkeypatch):
    reg = SR.create_from_finding(_mitigated(tmp_path), str(tmp_path))

    def _boom(regression, base_dir, provenance):
        raise RuntimeError("endpoint unreachable")
    monkeypatch.setattr(SR.service, "_execute", _boom, raising=True)
    res = SR.run_regression(reg.regression_id, str(tmp_path))
    assert res.result == "ERROR" and res.passed is False        # missing evidence ≠ PASS


def test_error_when_required_observation_missing():
    verdict = SR.evaluate_expected_vs_observed(
        {"tool_executed": False}, {"authorization_decision": "DENY"})   # tool_executed unavailable
    assert verdict["result"] == "ERROR"


def test_missing_evidence_is_not_pass():
    verdict = SR.evaluate_expected_vs_observed({"tool_executed": False}, {"tool_executed": None})
    assert verdict["result"] == "ERROR" and verdict["passed"] is False


# ------------------------------ §46 assessment ------------------------------ #
def test_regression_does_not_mutate_finding_status(tmp_path):
    fid = _mitigated(tmp_path)
    before = F.load_finding(fid, str(tmp_path)).status
    reg = SR.create_from_finding(fid, str(tmp_path))
    assert F.load_finding(fid, str(tmp_path)).status == before      # create: unchanged
    SR.run_regression(reg.regression_id, str(tmp_path))
    assert F.load_finding(fid, str(tmp_path)).status == before      # PASS: unchanged


# ------------------------------ status lifecycle ---------------------------- #
def test_status_can_be_disabled_and_archived(tmp_path):
    reg = SR.create_from_finding(_mitigated(tmp_path), str(tmp_path))
    assert SR.set_status(reg.regression_id, "DISABLED", str(tmp_path)).status == "DISABLED"
    assert SR.set_status(reg.regression_id, "ARCHIVED", str(tmp_path)).status == "ARCHIVED"
    with pytest.raises(SR.RegressionError):
        SR.set_status(reg.regression_id, "BOGUS", str(tmp_path))


# ------------------- §47 lifecycle enforcement during execution ------------- #
def test_active_regression_executes(tmp_path):
    reg = SR.create_from_finding(_mitigated(tmp_path), str(tmp_path))
    assert reg.status == SR.ACTIVE
    res = SR.run_regression(reg.regression_id, str(tmp_path))
    assert res.result in ("PASS", "FAIL", "ERROR")           # executed, not rejected


def test_disabled_regression_cannot_execute(tmp_path, monkeypatch):
    reg = SR.create_from_finding(_mitigated(tmp_path), str(tmp_path))
    SR.set_status(reg.regression_id, SR.DISABLED, str(tmp_path))

    calls = []
    monkeypatch.setattr(SR.service, "_execute", lambda *a, **k: calls.append(1), raising=True)

    with pytest.raises(SR.RegressionStatusError):
        SR.run_regression(reg.regression_id, str(tmp_path))
    assert calls == []                                        # attack runner never invoked
    assert SR.get(reg.regression_id, str(tmp_path)).last_run_id is None   # no new Run
    assert SR.RegressionRepository(str(tmp_path)).load_result(reg.regression_id) is None  # no Evidence/result


def test_archived_regression_cannot_execute(tmp_path, monkeypatch):
    reg = SR.create_from_finding(_mitigated(tmp_path), str(tmp_path))
    SR.set_status(reg.regression_id, SR.ARCHIVED, str(tmp_path))

    calls = []
    monkeypatch.setattr(SR.service, "_execute", lambda *a, **k: calls.append(1), raising=True)

    with pytest.raises(SR.RegressionStatusError):
        SR.run_regression(reg.regression_id, str(tmp_path))
    assert calls == []
    assert SR.get(reg.regression_id, str(tmp_path)).last_run_id is None
    assert SR.RegressionRepository(str(tmp_path)).load_result(reg.regression_id) is None


# ------------------- §48 SuccessSignature from original evidence ------------ #
def test_signature_derived_from_original_attack_not_retest(tmp_path):
    fid = _mitigated(tmp_path)
    finding = F.load_finding(fid, str(tmp_path))
    reg = SR.create_from_finding(fid, str(tmp_path))

    # The security boundary and capability come from the ORIGINAL (unmitigated)
    # attack, and must still be present after the control blocked the retest —
    # a retest-derived signature would have lost them (nothing was crossed).
    assert reg.success_signature["criterion"] == "unauthorized_privileged_tool_execution"
    assert reg.success_signature["boundary"] == "tool_authorization"
    assert reg.success_signature["capability"] == "admin_export"
    assert reg.success_signature["tool"] == "admin_export"

    # Expected state stays retest-derived and is a distinct object from the signature.
    assert reg.expected_security_state == {"authorization_decision": "DENY",
                                           "tool_executed": False, "security_impact": False}
    assert reg.source_attack_run_id == finding.evidence_refs[0]
    assert reg.source_attack_run_id != reg.source_retest_run_id


def test_missing_original_evidence_fails_closed(tmp_path):
    fid = _mitigated(tmp_path)
    finding = F.load_finding(fid, str(tmp_path))
    import shutil
    shutil.rmtree(str(tmp_path / finding.evidence_refs[0]))     # original attack evidence vanished
    with pytest.raises(SR.PreconditionError):
        SR.create_from_finding(fid, str(tmp_path))


# ------------------------ §49 boundary structured sourcing ------------------ #
class _FindingLike:
    def __init__(self, boundary_crossed=""):
        self.boundary_crossed = boundary_crossed


class _RecordLike:
    def __init__(self, parameters=None, adversarial_result=None):
        self.parameters = parameters or {}
        self.adversarial_result = adversarial_result or {}


def test_boundary_prefers_finding_structured_field():
    finding = _FindingLike(boundary_crossed="Tool Authorization → Privileged Capability")
    sig = SR.build_success_signature("ORN-ATTACK-PI-002", "agent-a",
                                     "unauthorized_privileged_tool_execution", finding=finding)
    assert sig["boundary"] == "tool_authorization"


def test_boundary_never_parsed_from_an_arbitrary_full_trust_path():
    # A full, multi-hop trust path (not the documented 2-segment crossing) must
    # never be sliced positionally — that previously produced "external_content"
    # for what is actually a tool_authorization boundary.
    rec = _RecordLike(parameters={"boundary_crossing":
                                  "External Content → Retrieval → Agent → Tool Authorization → Privileged Tool"})
    sig = SR.build_success_signature("ORN-ATTACK-PI-002", "agent-a",
                                     "unauthorized_privileged_tool_execution", rec)
    assert sig["boundary"] == "tool_authorization"      # recovered from AttackDefinition instead
    assert sig["boundary"] != "external_content"


def test_boundary_falls_back_to_attack_definition_when_no_run_evidence():
    sig = SR.build_success_signature("ORN-ATTACK-PI-002", "agent-a",
                                     "unauthorized_privileged_tool_execution")
    assert sig["boundary"] == "tool_authorization"


def test_boundary_normalization_is_idempotent():
    assert SR.normalize_boundary("Tool Authorization") == "tool_authorization"
    assert SR.normalize_boundary("tool_authorization") == "tool_authorization"


# --------------------------- §50 signature stability ------------------------- #
def test_signature_stable_against_volatile_fields():
    rec_a = _RecordLike(parameters={"boundary_crossing": "Tool Authorization → Privileged Capability",
                                    "trace_id": "trace-1", "timestamp": "2026-01-01T00:00:00Z"},
                        adversarial_result={"privileged_tool_requested": "admin_export"})
    rec_b = _RecordLike(parameters={"boundary_crossing": "Tool Authorization → Privileged Capability",
                                    "trace_id": "trace-2", "timestamp": "2026-06-01T00:00:00Z"},
                        adversarial_result={"privileged_tool_requested": "admin_export"})
    s1 = SR.build_success_signature("ORN-ATTACK-PI-002", "agent-a",
                                    "unauthorized_privileged_tool_execution", rec_a)
    s2 = SR.build_success_signature("ORN-ATTACK-PI-002", "agent-a",
                                    "unauthorized_privileged_tool_execution", rec_b)
    assert SR.signature_key(s1) == SR.signature_key(s2)


def test_signature_changes_for_different_target():
    rec = _RecordLike(adversarial_result={"privileged_tool_requested": "admin_export"})
    s1 = SR.build_success_signature("ORN-ATTACK-PI-002", "agent-a",
                                    "unauthorized_privileged_tool_execution", rec)
    s2 = SR.build_success_signature("ORN-ATTACK-PI-002", "agent-b",
                                    "unauthorized_privileged_tool_execution", rec)
    assert SR.signature_key(s1) != SR.signature_key(s2)


def test_signature_changes_for_different_capability():
    rec_a = _RecordLike(adversarial_result={"privileged_tool_requested": "admin_export"})
    rec_b = _RecordLike(adversarial_result={"privileged_tool_requested": "search_logs"})
    s1 = SR.build_success_signature("ORN-ATTACK-PI-002", "agent-a",
                                    "unauthorized_privileged_tool_execution", rec_a)
    s2 = SR.build_success_signature("ORN-ATTACK-PI-002", "agent-a",
                                    "unauthorized_privileged_tool_execution", rec_b)
    assert SR.signature_key(s1) != SR.signature_key(s2)


# ------------------------ §51 multiple retests selection --------------------- #
def test_multiple_retests_select_the_effective_one(tmp_path):
    ws = EXP.create_from_plan(_plan(tmp_path), base_dir=str(tmp_path))
    EXP.run_agentic_attack(ws, {"attack_id": "ORN-ATTACK-PI-002"}, base_dir=str(tmp_path))
    m = EXP.measure(ws, base_dir=str(tmp_path))
    fid = m["finding_id"]

    # Retest #1: a control with no implementation for this attack -> INEFFECTIVE.
    EXP.apply_defense(ws, {"control_id": "adversarial_training"}, base_dir=str(tmp_path))
    r1 = EXP.retest(ws, base_dir=str(tmp_path))
    ineffective_retest_run_id = r1["retest_run_id"]

    f_after_r1 = F.load_finding(fid, str(tmp_path))
    assert f_after_r1.retest_status == "INEFFECTIVE"

    # Retest #2: the real control -> EFFECTIVE.
    EXP.apply_defense(ws, {"control_id": "tool_authorization"}, base_dir=str(tmp_path))
    r2 = EXP.retest(ws, base_dir=str(tmp_path))
    effective_retest_run_id = r2["retest_run_id"]

    f_after_r2 = F.load_finding(fid, str(tmp_path))
    assert f_after_r2.retest_status == "EFFECTIVE"
    assert ineffective_retest_run_id != effective_retest_run_id
    assert set(f_after_r2.retest_refs) == {ineffective_retest_run_id, effective_retest_run_id}

    reg = SR.create_from_finding(fid, str(tmp_path))
    assert reg.source_retest_run_id == effective_retest_run_id
    assert reg.source_retest_run_id != ineffective_retest_run_id

    retest_record = EvidenceStore(str(tmp_path)).load(effective_retest_run_id)
    assert reg.expected_security_state == SR.build_expected_state(retest_record)


# -------------------- §52 influence + authorization DENY -> PASS ------------ #
def test_influence_with_authorization_deny_still_passes(tmp_path):
    reg = SR.create_from_finding(_mitigated(tmp_path), str(tmp_path))
    res = SR.run_regression(reg.regression_id, str(tmp_path))
    assert res.observed["agent_influenced"] is True
    assert res.observed["authorization_decision"] == "DENY"
    assert res.observed["tool_executed"] is False
    assert res.result == "PASS"


# ----------------------- §53 execution never mutates Finding ---------------- #
def test_regression_execution_does_not_mutate_finding(tmp_path):
    fid = _mitigated(tmp_path)
    before = F.load_finding(fid, str(tmp_path)).to_dict()
    reg = SR.create_from_finding(fid, str(tmp_path))
    SR.run_regression(reg.regression_id, str(tmp_path))
    after = F.load_finding(fid, str(tmp_path)).to_dict()
    assert before == after
