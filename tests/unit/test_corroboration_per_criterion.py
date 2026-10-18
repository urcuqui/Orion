"""Per-criterion corroboration: a criterion is REPRODUCED only when it held
independently across enough runs — never a union across different runs (§38)."""
import pytest

from orion.evidence import ExperimentRecord
from orion.findings import model as FM


def _rec(trace_id, crit_results, attack="ORN-ATTACK-PI-002", target="agent"):
    """crit_results: {criterion: bool} for this single run."""
    criteria = [{"criterion": c, "result": r} for c, r in crit_results.items()]
    any_true = any(crit_results.values())
    return ExperimentRecord(
        trace_id=trace_id,
        status="ATTACK_SUCCESS" if any_true else "ATTACK_BLOCKED",
        target={"model_name": target},
        parameters={"attack_id": attack, "success_evaluation": {"result": any_true, "criteria": criteria}},
        metrics={"attack_success_rate": {"value": 1.0 if any_true else 0.0}})


def _finding():
    f = FM.Finding(attack_id="ORN-ATTACK-PI-002", affected_target="agent", status=FM.OBSERVED)
    return f


def test_criterion_in_one_run_is_not_reproduced():
    recs = [_rec("R1", {"A": True}), _rec("R2", {"A": False}), _rec("R3", {"A": False})]
    meta = FM.evaluate_corroboration(_finding(), recs)
    assert meta["per_criterion"]["A"]["successes"] == 1
    assert meta["per_criterion"]["A"]["success_rate"] == pytest.approx(1 / 3, abs=1e-4)
    assert meta["per_criterion"]["A"]["reproduced"] is False
    assert "A" not in meta["criteria_reproduced"]


def test_same_criterion_across_required_runs_is_reproduced():
    recs = [_rec(f"R{i}", {"A": True}) for i in range(1, 4)]
    meta = FM.evaluate_corroboration(_finding(), recs)
    assert meta["per_criterion"]["A"]["reproduced"] is True
    assert meta["criteria_reproduced"] == ["A"]
    assert meta["confirmation_eligible"] is True


def test_distributed_criteria_do_not_falsely_reproduce():
    # Union semantics would wrongly report [A, B]; per-criterion reports neither.
    recs = [_rec("R1", {"A": True, "B": False}),
            _rec("R2", {"A": False, "B": True}),
            _rec("R3", {"A": False, "B": False})]
    meta = FM.evaluate_corroboration(_finding(), recs)
    assert meta["per_criterion"]["A"]["reproduced"] is False
    assert meta["per_criterion"]["B"]["reproduced"] is False
    assert meta["criteria_reproduced"] == []
    assert meta["confirmation_eligible"] is False


def test_per_criterion_success_rate_is_exact():
    recs = [_rec("R1", {"A": True}), _rec("R2", {"A": True}), _rec("R3", {"A": False})]
    stat = FM.evaluate_corroboration(_finding(), recs)["per_criterion"]["A"]
    assert stat["independent_runs"] == 3 and stat["successes"] == 2
    assert stat["success_rate"] == pytest.approx(2 / 3, abs=1e-4)
    assert stat["reproduced"] is True          # 0.667 ≥ 0.66 policy


def test_legacy_findings_without_criteria_load_and_are_honest():
    # Records lacking success_evaluation.criteria (legacy) → UNKNOWN / LEGACY.
    legacy = [ExperimentRecord(trace_id=f"L{i}", status="ATTACK_SUCCESS",
                               target={"model_name": "agent"},
                               parameters={"attack_id": "ORN-ATTACK-PI-002"}) for i in range(3)]
    meta = FM.evaluate_corroboration(_finding(), legacy)
    assert meta["legacy"] is True
    assert meta["per_criterion"] == {}
    assert meta["confirmation_eligible"] is False
    assert "LEGACY" in meta["reason"]


def test_mixed_target_blocks_reproduction():
    recs = [_rec("R1", {"A": True}, target="agent"),
            _rec("R2", {"A": True}, target="other"),
            _rec("R3", {"A": True}, target="agent")]
    meta = FM.evaluate_corroboration(_finding(), recs)
    assert meta["confirmation_eligible"] is False      # not the same condition
