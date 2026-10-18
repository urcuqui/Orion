"""Basic Assessment Report: a read-only, normalized view over existing Orion
state — never a second security engine.

    Existing Orion State
            |
    Normalized AssessmentReport
            |
      +-----+-----+
   Markdown       JSON

Finding status, control effectiveness and Regression PASS/FAIL/ERROR all come
from their existing domain logic (``orion.findings``, ``orion.security_regressions``)
and from :class:`orion.assessments.service.AssessmentService`'s existing
deterministic summary — this module only reshapes and renders that state. It
never recomputes a Finding's status, a Retest's effectiveness or a Regression's
result, and it never mutates any domain object it reads.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

REPORT_VERSION = "1"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class AssessmentReport:
    """The single normalized source of truth both renderers consume."""
    report_version: str = REPORT_VERSION
    generated_at: str = field(default_factory=_now)

    assessment: Dict[str, Any] = field(default_factory=dict)
    scope: Dict[str, Any] = field(default_factory=dict)

    profiles: Dict[str, Any] = field(default_factory=dict)
    analysis_context: List[Dict[str, Any]] = field(default_factory=list)
    threat_models: List[Dict[str, Any]] = field(default_factory=list)
    plans: List[Dict[str, Any]] = field(default_factory=list)

    experiments: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    controls: List[Dict[str, Any]] = field(default_factory=list)
    retests: List[Dict[str, Any]] = field(default_factory=list)
    security_regressions: List[Dict[str, Any]] = field(default_factory=list)

    posture_summary: Dict[str, Any] = field(default_factory=dict)

    evidence_index: List[Dict[str, Any]] = field(default_factory=list)
    provenance: Dict[str, Any] = field(default_factory=dict)
    unknowns: List[Dict[str, str]] = field(default_factory=list)
    unavailable_references: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Builder
# --------------------------------------------------------------------------- #
def build_assessment_report(assessment_id: str, base_dir: str = "artifacts") -> AssessmentReport:
    """Build the normalized report for ``assessment_id``.

    Fails clearly (raises) only when the Assessment itself cannot be loaded.
    Every other unresolved reference degrades to an entry in
    ``unavailable_references`` rather than aborting report generation — the
    same "partial, honest" posture :func:`AssessmentService.summary` already
    uses.
    """
    from orion.assessments.service import AssessmentService
    from orion import plans as PL
    from orion.context.store import load_profile
    from orion.security_regressions import RegressionRepository

    service = AssessmentService(base_dir)
    assessment = service.get(assessment_id)           # LookupError propagates: fail clearly
    summary = service.summary(assessment_id)

    unavailable: List[Dict[str, Any]] = [
        {"type": e["kind"], "id": e["id"], "reason": e["error"]} for e in summary["errors"]
    ]

    # ---- Plans ------------------------------------------------------------ #
    plan_entries: List[Dict[str, Any]] = []
    plan_by_threat_model: Dict[str, Any] = {}
    for plan_id in sorted(assessment.plan_ids):
        try:
            plan = PL.load_plan(plan_id, base_dir)
            if plan is None:
                raise ValueError("plan not found")
        except (ValueError, TypeError, OSError, AttributeError) as exc:
            unavailable.append({"type": "plan", "id": plan_id, "reason": str(exc)})
            continue
        if plan.threat_model_id:
            plan_by_threat_model.setdefault(plan.threat_model_id, plan)
        plan_entries.append({
            "plan_id": plan.plan_id,
            "source_type": plan.source_type,
            "status": plan.status,
            "approved_by_human": plan.approved_by_human,
            "approved_at": plan.approved_at,
            "created_at": plan.created_at,
            "threat_model_id": plan.threat_model_id,
            "analysis_context_id": plan.analysis_context_id,
            "experiment_proposal_ids": [p.experiment_id for p in plan.proposals],
        })

    # ---- Analysis context -------------------------------------------------- #
    context_entries: List[Dict[str, Any]] = []
    for ctx_id in sorted(assessment.analysis_context_ids):
        try:
            data = load_profile(ctx_id, base_dir)
            if data is None:
                raise ValueError("analysis context not found")
        except (ValueError, TypeError, OSError) as exc:
            unavailable.append({"type": "analysis_context", "id": ctx_id, "reason": str(exc)})
            continue
        context_entries.append({
            "analysis_context_id": ctx_id,
            "self_profile_id": data.get("self_profile_id"),
            "target_profile_id": data.get("target_profile_id"),
            "environment_profile_id": data.get("environment_profile_id"),
            "coverage": data.get("coverage"),
            "created_at": data.get("created_at"),
        })

    # ---- Threat models ------------------------------------------------------ #
    threat_model_entries: List[Dict[str, Any]] = []
    for tm_id in sorted(assessment.threat_model_ids):
        source_plan = plan_by_threat_model.get(tm_id)
        if source_plan is not None:
            threat_model_entries.append({
                "threat_model_id": tm_id,
                "available": True,
                "source_plan_id": source_plan.plan_id,
                "summary": source_plan.threat_model,
            })
        else:
            threat_model_entries.append({"threat_model_id": tm_id, "available": False})
            unavailable.append({"type": "threat_model", "id": tm_id,
                                "reason": "source plan/context unavailable"})

    # ---- Experiments -------------------------------------------------------- #
    experiment_entries: List[Dict[str, Any]] = [{
        "experiment_id": ws.get("experiment_workspace_id"),
        "plan_id": ws.get("plan_id"),
        "threat_model_id": ws.get("threat_model_id"),
        "attack_id": ws.get("attack_catalog_id") or ws.get("active_experiment_id"),
        "family": ws.get("family"),
        "target": ws.get("target_profile_id"),
        "lifecycle_state": ws.get("current_stage"),
        "finding_id": ws.get("finding_id"),
        "attack_run_id": ws.get("attack_run_id"),
        "retest_run_id": ws.get("retest_run_id"),
        "attack_result": ws.get("result"),
    } for ws in summary["experiment_records"]]

    # ---- Findings (+ corroboration, already computed by Finding logic) ----- #
    finding_entries: List[Dict[str, Any]] = [{
        "finding_id": f["id"],
        "title": f.get("title"),
        "description": f.get("description"),
        "status": f.get("status"),
        "severity": f.get("severity"),
        "confidence": f.get("confidence"),
        "attack_id": f.get("attack_id"),
        "family": f.get("family"),
        "affected_target": f.get("affected_target"),
        "affected_component": f.get("affected_component"),
        "trust_path": f.get("trust_path", []),
        "boundary_crossed": f.get("boundary_crossed"),
        "success_condition": f.get("success_condition"),
        "evidence_refs": f.get("evidence_refs", []),
        "recommended_controls": f.get("recommended_controls", []),
        "applied_control": f.get("applied_control"),
        "control_implementation": f.get("control_implementation"),
        "retest_status": f.get("retest_status"),
        "retest_refs": f.get("retest_refs", []),
        "framework_mappings": f.get("framework_mappings", {}),
        "corroboration": f.get("corroboration") or {},
    } for f in summary["finding_records"]]

    # ---- Controls (Applied != Effective; effectiveness lives in Retests) --- #
    control_entries: List[Dict[str, Any]] = [{
        "control_ref": c.get("control"),
        "implementation": c.get("implementation"),
        "finding_id": c.get("finding_id"),
        "experiment_id": c.get("experiment_id"),
        "applied_status": "APPLIED",
        "verification_status": "NOT_VERIFIED" if c.get("awaiting_retest") else "VERIFIED_BY_RETEST",
        "retest_run_id": c.get("retest_run_id"),
    } for c in summary["control_records"]]

    # ---- Retests: existing per-Finding retest_status, never recomputed ----- #
    retest_entries: List[Dict[str, Any]] = sorted((
        {
            "retest_run_id": run_id,
            "finding_id": f["id"],
            "control_ref": f.get("applied_control"),
            "result": f.get("retest_status") or "UNKNOWN",
            "evidence_reference": run_id,
        }
        for f in summary["finding_records"] for run_id in f.get("retest_refs", [])
    ), key=lambda r: (r["finding_id"], r["retest_run_id"]))

    # ---- Manual Security Regressions (latest result only — no history) ----- #
    regressions = sorted(
        (r for r in RegressionRepository(base_dir).list() if r.assessment_id == assessment_id),
        key=lambda r: r.regression_id)
    regression_entries: List[Dict[str, Any]] = [{
        "regression_id": r.regression_id,
        "name": r.name,
        "status": r.status,
        "source_finding_id": r.source_finding_id,
        "source_experiment_id": r.source_experiment_id,
        "source_attack_run_id": r.source_attack_run_id,
        "source_retest_run_id": r.source_retest_run_id,
        "control": r.source_control_ref,
        "attack_id": r.attack_id,
        "family": r.family,
        "target": r.target,
        "success_signature": r.success_signature,
        "expected_security_state": r.expected_security_state,
        "latest_result": r.last_result or "NOT_RUN",
        "latest_run_id": r.last_run_id,
        "last_evaluated_at": r.last_evaluated_at,
    } for r in regressions]

    # ---- Evidence index (references only — never raw trace payloads) ------- #
    evidence_index: List[Dict[str, Any]] = []
    _seen_evidence: set = set()

    def _add_evidence(run_id: Optional[str], kind: str, **refs: Any) -> None:
        if not run_id or run_id in _seen_evidence:
            return
        _seen_evidence.add(run_id)
        evidence_index.append({"run_id": run_id, "type": kind, **refs})

    for exp in experiment_entries:
        _add_evidence(exp["attack_run_id"], "attack_run", experiment_id=exp["experiment_id"],
                     finding_id=exp["finding_id"])
    for f in finding_entries:
        for run_id in f["evidence_refs"]:
            _add_evidence(run_id, "attack_run", finding_id=f["finding_id"])
        for run_id in f["retest_refs"]:
            _add_evidence(run_id, "retest", finding_id=f["finding_id"], control=f["applied_control"])
    for r in regression_entries:
        _add_evidence(r["latest_run_id"], "security_regression_run",
                     regression_id=r["regression_id"], result=r["latest_result"])
    evidence_index.sort(key=lambda e: e["run_id"])

    # ---- Posture summary: counts only, never a verdict ---------------------- #
    posture: Dict[str, Any] = {
        "experiments_total": summary["experiments"]["total"],
        "findings_total": summary["findings"]["total"],
        "findings_confirmed": summary["findings"].get("confirmed"),
        "findings_observed": summary["findings"].get("observed"),
        "findings_hypothesis": summary["findings"].get("hypothesis"),
        "findings_high_or_critical": summary["posture"].get("high_critical"),
        "controls_applied": summary["controls"]["applied"],
        "controls_awaiting_retest": summary["controls"]["awaiting_retest"],
        "retests_effective": summary["retests"]["mitigated"],
        "retests_partially_effective": summary["retests"]["partial"],
        "retests_ineffective": summary["retests"]["not_mitigated"],
        "security_regressions_total": len(regression_entries),
        "security_regressions_active": sum(1 for r in regression_entries if r["status"] == "ACTIVE"),
        "security_regressions_disabled": sum(1 for r in regression_entries if r["status"] == "DISABLED"),
        "security_regressions_archived": sum(1 for r in regression_entries if r["status"] == "ARCHIVED"),
        "latest_regression_pass": sum(1 for r in regression_entries if r["latest_result"] == "PASS"),
        "latest_regression_fail": sum(1 for r in regression_entries if r["latest_result"] == "FAIL"),
        "latest_regression_error": sum(1 for r in regression_entries if r["latest_result"] == "ERROR"),
        "latest_regression_not_run": sum(1 for r in regression_entries if r["latest_result"] == "NOT_RUN"),
    }
    # UNKNOWN != 0: a count stays None (never silently 0) when its sources are unresolved.
    unknowns: List[Dict[str, str]] = [
        {"field": key, "reason": "one or more supporting references are unavailable"}
        for key, value in posture.items() if value is None
    ]

    provenance: Dict[str, Any] = {
        "assessment_id": assessment.assessment_id,
        "system_profile_id": assessment.system_profile_id,
        "target_id": assessment.target_id,
        "environment_id": assessment.environment_id,
        "analysis_context_ids": list(assessment.analysis_context_ids),
        "threat_model_ids": list(assessment.threat_model_ids),
        "plan_ids": list(assessment.plan_ids),
        "experiment_ids": list(assessment.experiment_ids),
        "finding_ids": [f["finding_id"] for f in finding_entries],
        "control_refs": [c["control_ref"] for c in control_entries if c["control_ref"]],
        "retest_run_ids": [r["retest_run_id"] for r in retest_entries],
        "security_regression_ids": [r["regression_id"] for r in regression_entries],
    }

    return AssessmentReport(
        report_version=REPORT_VERSION,
        generated_at=_now(),
        assessment={
            "assessment_id": assessment.assessment_id,
            "name": assessment.name,
            "description": assessment.description,
            "lifecycle_status": assessment.status,
            "created_at": assessment.created_at,
            "updated_at": assessment.updated_at,
        },
        scope=assessment.scope or {},
        profiles=summary["profiles"],
        analysis_context=context_entries,
        threat_models=threat_model_entries,
        plans=plan_entries,
        experiments=experiment_entries,
        findings=finding_entries,
        controls=control_entries,
        retests=retest_entries,
        security_regressions=regression_entries,
        posture_summary=posture,
        evidence_index=evidence_index,
        provenance=provenance,
        unknowns=unknowns,
        unavailable_references=sorted(unavailable, key=lambda u: (u["type"], str(u["id"]))),
    )
