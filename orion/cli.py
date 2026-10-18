"""A lightweight Orion CLI.

    python -m orion list
    python -m orion run scenarios/pgd_evasion.yaml --mode attack
    python -m orion replay <trace_id> --mode hardened
    python -m orion report <trace_id>
    python -m orion compare <baseline_trace> <hardened_trace>
    python -m orion validate scenarios/pgd_evasion.yaml

The web UI is unaffected; this is an additional interface.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from orion import __version__
from orion.evidence import EvidenceStore
from orion.experiments import compare as compare_traces
from orion.experiments import replay as replay_trace
from orion.experiments import run_scenario
from orion.scenarios.loader import list_scenarios, load_scenario, validate_scenario


def _cmd_list(args: argparse.Namespace) -> int:
    scenarios = list_scenarios(args.dir)
    if not scenarios:
        print(f"No scenarios found in {args.dir}/")
        return 0
    print(f"Scenarios in {args.dir}/:")
    for s in scenarios:
        flag = "" if s.get("valid") == "yes" else "  [INVALID]"
        print(f"  - {s['name']}: {s['description']}{flag}")
        print(f"      file={s['path']} phase={s.get('phase','?')} technique={s.get('technique','?')}")
    traces = EvidenceStore(args.artifacts).list_traces()
    if traces:
        print(f"\nEvidence traces in {args.artifacts}/:")
        for t in traces:
            print(f"  - {t}")
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    scenario = load_scenario(args.scenario)
    record = run_scenario(scenario, mode=args.mode, base_dir=args.artifacts)
    print(f"[{record.status}] {record.scenario_name} mode={record.mode}")
    print(f"trace_id: {record.trace_id}")
    _print_metrics(record.metrics)
    print(f"evidence: {Path(args.artifacts) / record.trace_id}/")
    return 0


def _cmd_replay(args: argparse.Namespace) -> int:
    record = replay_trace(args.trace_id, mode=args.mode, base_dir=args.artifacts)
    print(f"Replayed {args.trace_id} -> {record.trace_id} [{record.status}] mode={record.mode}")
    _print_metrics(record.metrics)
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    store = EvidenceStore(args.artifacts)
    report_path = store.trace_dir(args.trace_id) / "report.md"
    if not report_path.exists():
        print(f"No report for trace_id {args.trace_id!r} (expected {report_path})")
        return 1
    print(report_path.read_text(encoding="utf-8"))
    return 0


def _cmd_compare(args: argparse.Namespace) -> int:
    result = compare_traces(args.baseline, args.hardened, base_dir=args.artifacts)
    print(json.dumps(result, indent=2))
    print()
    for k, v in result["metrics"].items():
        arrow = "->"
        print(f"{k}: {v['before']} {arrow} {v['after']}  (delta {v['delta']:+})")
    print(f"\n{result['note']}")
    return 0


def _cmd_validate(args: argparse.Namespace) -> int:
    problems = validate_scenario(args.scenario)
    if not problems:
        print(f"OK: {args.scenario} is a valid scenario.")
        return 0
    print(f"INVALID: {args.scenario}")
    for p in problems:
        print(f"  - {p}")
    return 1


def _cmd_regression_list(args: argparse.Namespace) -> int:
    from orion import security_regressions as SR
    regs = SR.list_regressions(args.artifacts)
    if not regs:
        print("No security regressions.")
        return 0
    print("Security regressions:")
    for r in regs:
        print(f"  - {r.regression_id}: {r.name} [{r.status}] last={r.last_result or '-'}")
    return 0


def _cmd_regression_create(args: argparse.Namespace) -> int:
    from orion import security_regressions as SR
    try:
        reg = SR.create_from_finding(args.finding_id, args.artifacts)
    except SR.RegressionError as exc:
        print(f"Cannot create regression: {exc}")
        return 1
    print(f"Created {reg.regression_id} from {args.finding_id}")
    return 0


def _cmd_regression_run(args: argparse.Namespace) -> int:
    """Manually execute a security regression (operator-initiated only)."""
    from orion import security_regressions as SR
    try:
        res = SR.run_regression(args.regression_id, args.artifacts)
    except SR.RegressionError as exc:
        print(f"Error: {exc}")
        return 1
    print(f"[{res.result}] {args.regression_id}  run_id={res.run_id}")
    for k, want in (res.expected or {}).items():
        got = (res.observed or {}).get(k)
        flag = "" if k not in (res.mismatches or []) and got is not None else "   <-- mismatch"
        print(f"  {k}: expected={want} observed={got}{flag}")
    print(res.note)
    return 0 if res.result == "PASS" else 1


def _print_metrics(metrics: dict) -> None:
    for name in ("clean_accuracy", "robust_accuracy", "attack_success_rate",
                 "perturbation_linf", "confidence_shift"):
        entry = metrics.get(name)
        if isinstance(entry, dict) and "value" in entry:
            print(f"  {name}: {entry['value']}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="orion", description="Orion AI security framework CLI")
    parser.add_argument("--version", action="version", version=f"orion {__version__}")
    parser.add_argument("--artifacts", default="artifacts", help="evidence directory (default: artifacts)")
    sub = parser.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list", help="list scenarios and evidence traces")
    p_list.add_argument("--dir", default="scenarios", help="scenario directory")
    p_list.set_defaults(func=_cmd_list)

    p_run = sub.add_parser("run", help="run a scenario")
    p_run.add_argument("scenario")
    p_run.add_argument("--mode", default="attack", choices=["baseline", "attack", "hardened"])
    p_run.set_defaults(func=_cmd_run)

    p_replay = sub.add_parser("replay", help="replay a trace with the same parameters")
    p_replay.add_argument("trace_id")
    p_replay.add_argument("--mode", default=None, choices=["baseline", "attack", "hardened"])
    p_replay.set_defaults(func=_cmd_replay)

    p_report = sub.add_parser("report", help="print a trace's Markdown report")
    p_report.add_argument("trace_id")
    p_report.set_defaults(func=_cmd_report)

    p_compare = sub.add_parser("compare", help="compare two traces (e.g. attack vs hardened)")
    p_compare.add_argument("baseline")
    p_compare.add_argument("hardened")
    p_compare.set_defaults(func=_cmd_compare)

    p_validate = sub.add_parser("validate", help="validate a scenario file")
    p_validate.add_argument("scenario")
    p_validate.set_defaults(func=_cmd_validate)

    p_reg = sub.add_parser("regression", help="security regressions (manual re-validation)")
    reg_sub = p_reg.add_subparsers(dest="reg_command", required=True)
    r_list = reg_sub.add_parser("list", help="list security regressions")
    r_list.set_defaults(func=_cmd_regression_list)
    r_create = reg_sub.add_parser("create", help="create from an effectively-mitigated finding")
    r_create.add_argument("finding_id")
    r_create.set_defaults(func=_cmd_regression_create)
    r_run = reg_sub.add_parser("run", help="manually run a security regression")
    r_run.add_argument("regression_id")
    r_run.set_defaults(func=_cmd_regression_run)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)
