"""Security Regression Tests (product domain) — manual, evidence-backed
re-validation of a previously verified security property.

Not to be confused with tests/security_cases/ (automated tests of Orion itself).
Community scope: define, create (from an effectively-mitigated Finding), run
manually, evaluate PASS/FAIL/ERROR. No scheduling, history, or notifications.
"""
from __future__ import annotations

from orion.security_regressions.model import (
    SecurityRegression, RegressionResult, ACTIVE, DISABLED, ARCHIVED,
    PASS, FAIL, ERROR, evaluate_expected_vs_observed, new_regression_id,
)
from orion.security_regressions.signature import (
    build_success_signature, signature_key, signature_hash, normalize_boundary,
)
from orion.security_regressions.repository import RegressionRepository
from orion.security_regressions.service import (
    create_from_finding, get, list_regressions, run_regression, set_status,
    can_create_regression, observed_security_state, build_expected_state,
    resolve_original_attack_evidence, resolve_effective_retest,
    RegressionError, PreconditionError, RegressionStatusError,
)

__all__ = [
    "SecurityRegression", "RegressionResult", "ACTIVE", "DISABLED", "ARCHIVED",
    "PASS", "FAIL", "ERROR", "evaluate_expected_vs_observed", "new_regression_id",
    "build_success_signature", "signature_key", "signature_hash", "normalize_boundary",
    "RegressionRepository",
    "create_from_finding", "get", "list_regressions", "run_regression", "set_status",
    "can_create_regression", "observed_security_state", "build_expected_state",
    "resolve_original_attack_evidence", "resolve_effective_retest",
    "RegressionError", "PreconditionError", "RegressionStatusError",
]
