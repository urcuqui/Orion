"""SuccessSignature: a deterministic, normalized identity for a reproduced
security condition.

It is NOT a copy of the experiment configuration — it captures just enough
context to distinguish one security failure from another (attack, target,
criterion, boundary, capability, security effect). Fields are attack-family
aware; absent dimensions are simply omitted rather than invented.

The signature describes the ORIGINAL security failure (the thing a Regression
exists to keep from reappearing) — never the mitigated Retest state. Callers
must pass the original, pre-mitigation attack evidence (and/or the Finding
that recorded it), not a Retest record.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Optional

from orion.catalog import attacks as CAT

# criterion / family -> a stable, human-readable security effect
_EFFECT_BY_CRITERION = {
    "unauthorized_tool_action": "unauthorized_external_action",
    "privilege_boundary_crossed": "privilege_escalation",
    "secret_leakage": "sensitive_data_disclosure",
    "policy_violation": "policy_bypass",
    "injected_instruction_followed": "instruction_override",
    "prediction_changed": "adversarial_evasion",
    "decision_changed": "adversarial_evasion",
    "unauthorized_privileged_tool_execution": "unauthorized_external_action",
    "restricted_instruction_followed": "policy_bypass",
    "prediction_changed_under_allowed_budget": "adversarial_evasion",
}
_EFFECT_BY_FAMILY = {
    "traditional_ml": "adversarial_evasion",
    "generative_ai": "policy_bypass",
    "agentic_ai": "unauthorized_external_action",
}


def normalize_boundary(value: Optional[str]) -> str:
    """The one place a structured boundary name is normalized (e.g. "Tool
    Authorization" -> "tool_authorization"). Already-normalized values pass
    through unchanged. Do not reimplement this per page/service."""
    if not value:
        return ""
    return value.strip().lower().replace(" ", "_").replace("-", "_")


def _boundary_gate(crossing: Optional[str]) -> str:
    """Extract the security gate from a crossing value, but ONLY when its format
    is unambiguous:

        - no separator at all -> the value already IS the boundary name.
        - exactly one "<Gate> -> <Dest>" hop -> the gate is the first segment.

    A longer, multi-hop string (e.g. the full trust path) is never parsed
    positionally — guessing a boundary from where it sits in an arbitrary chain
    is exactly the bug this normalizes away. Callers fall back to the next,
    more structured source instead.
    """
    if not crossing:
        return ""
    sep = "→" if "→" in crossing else ("->" if "->" in crossing else None)
    if sep is None:
        return normalize_boundary(crossing)
    parts = [p.strip() for p in crossing.split(sep) if p.strip()]
    if len(parts) != 2:
        return ""
    return normalize_boundary(parts[0])


def _resolve_boundary(attack, finding, original_record) -> str:
    """Structured-data priority, never inferred from textual position in the
    full trust path:

        1. Finding.boundary_crossed (already the specific crossed segment)
        2. The original attack evidence's structured boundary crossing
        3. The AttackDefinition's declared security boundary
        4. Parsing a crossing string, only in its one documented format
    """
    boundary_crossed = getattr(finding, "boundary_crossed", None) if finding is not None else None
    gate = _boundary_gate(boundary_crossed)
    if gate:
        return gate

    if original_record is not None:
        params = getattr(original_record, "parameters", None) or {}
        adv = getattr(original_record, "adversarial_result", None) or {}
        crossing = params.get("boundary_crossing") or adv.get("boundary_crossing")
        gate = _boundary_gate(crossing)
        if gate:
            return gate

    if attack is not None and attack.security_boundaries:
        gate = attack.security_boundaries[0].get("from")
        if gate:
            return normalize_boundary(gate)

    return ""


def build_success_signature(attack_id: str, target: str, criterion: str,
                            original_record: Any = None, *,
                            finding: Any = None) -> Dict[str, Any]:
    """Normalize a reproduced criterion into a SuccessSignature.

    ``original_record`` is the ORIGINAL (pre-mitigation) attack ExperimentRecord
    — not the Retest. ``finding`` supplies the structured ``boundary_crossed``
    when available, taking priority over inference from the run's evidence.
    Only dimensions actually present in the structured data are included; an
    unavailable optional dimension is omitted, never invented.
    """
    attack = CAT.get(attack_id)
    family = attack.family if attack else ""
    sig: Dict[str, Any] = {
        "attack_id": attack.id if attack else attack_id,
        "target": target or "unknown",
        "criterion": criterion,
        "security_effect": _EFFECT_BY_CRITERION.get(criterion) or _EFFECT_BY_FAMILY.get(family, "security_impact"),
    }
    if family in ("agentic_ai", "generative_ai"):
        boundary = _resolve_boundary(attack, finding, original_record)
        if boundary:
            sig["boundary"] = boundary
        adv = (getattr(original_record, "adversarial_result", None) or {}) if original_record is not None else {}
        tool = adv.get("privileged_tool_requested")
        if tool:
            sig["capability"] = tool
            sig["tool"] = tool
    return {k: v for k, v in sig.items() if v not in (None, "")}


def signature_key(sig: Dict[str, Any]) -> str:
    """A stable key for comparing signatures (ignores field order, drops empties)."""
    relevant = {k: sig[k] for k in sorted(sig) if sig.get(k) not in (None, "")}
    return json.dumps(relevant, sort_keys=True, separators=(",", ":"))


def signature_hash(sig: Dict[str, Any]) -> str:
    return hashlib.sha256(signature_key(sig).encode("utf-8")).hexdigest()[:16]
