"""SecurityRegression + RegressionResult domain models.

A SecurityRegression turns a verified mitigation into a deterministic,
evidence-backed security property an operator can re-validate manually. It
references (never duplicates) the Finding / Experiment / Control / Retest that
justify it.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# Definition lifecycle (not the execution result).
ACTIVE, DISABLED, ARCHIVED = "ACTIVE", "DISABLED", "ARCHIVED"
STATUSES = (ACTIVE, DISABLED, ARCHIVED)

# Execution result.
PASS, FAIL, ERROR = "PASS", "FAIL", "ERROR"


def new_regression_id() -> str:
    return "ORN-REG-" + uuid.uuid4().hex[:8].upper()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class SecurityRegression:
    regression_id: str = field(default_factory=new_regression_id)
    name: str = ""
    description: str = ""
    status: str = ACTIVE

    assessment_id: Optional[str] = None
    source_finding_id: Optional[str] = None
    source_experiment_id: Optional[str] = None       # workspace id
    source_attack_run_id: Optional[str] = None
    source_retest_run_id: Optional[str] = None
    source_control_ref: Optional[str] = None          # control id
    control_implementation: Optional[str] = None

    attack_id: str = ""
    family: str = ""
    target: str = ""

    success_signature: Dict[str, Any] = field(default_factory=dict)
    # The protected state that must still hold (attack-family aware).
    expected_security_state: Dict[str, Any] = field(default_factory=dict)

    # Latest manual result (small, for UI usability — not a history product).
    last_result: Optional[str] = None                 # PASS | FAIL | ERROR
    last_run_id: Optional[str] = None
    last_evaluated_at: Optional[str] = None

    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = dict(self.__dict__)
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecurityRegression":
        r = cls(regression_id=data.get("regression_id", new_regression_id()))
        for k, v in data.items():
            if hasattr(r, k):
                setattr(r, k, v)
        return r


@dataclass
class RegressionResult:
    regression_id: str
    run_id: Optional[str]
    expected: Dict[str, Any]
    observed: Dict[str, Any]
    result: str                                       # PASS | FAIL | ERROR
    passed: bool
    mismatches: List[str] = field(default_factory=list)
    note: str = ""
    evaluated_at: str = field(default_factory=_now)

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.__dict__)


def evaluate_expected_vs_observed(expected: Dict[str, Any],
                                  observed: Dict[str, Any]) -> Dict[str, Any]:
    """Compare expected protected state against observed evidence.

        PASS  — every expected security condition was reproduced.
        FAIL  — a condition was observed but violated.
        ERROR — a required observation was unavailable (missing evidence ≠ PASS).
    """
    if not expected:
        return {"result": ERROR, "passed": False, "mismatches": [],
                "note": "No expected security state defined."}
    missing, mismatches = [], []
    for key, want in expected.items():
        if key not in observed or observed.get(key) is None:
            missing.append(key)
        elif observed[key] != want:
            mismatches.append(key)
    if missing:
        return {"result": ERROR, "passed": False, "mismatches": mismatches,
                "note": "Missing evidence for: " + ", ".join(missing) + " (missing evidence is not PASS)."}
    if mismatches:
        return {"result": FAIL, "passed": False, "mismatches": mismatches,
                "note": "Security expectation violated for: " + ", ".join(mismatches) + "."}
    return {"result": PASS, "passed": True, "mismatches": [],
            "note": "Expected security behavior reproduced."}
