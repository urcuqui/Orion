"""Persist a rendered Assessment Report under the Assessment's own artifact
directory — the only write a report operation performs. Report generation
never mutates the Assessment, Experiment, Finding, Control, Retest, Evidence
or SecurityRegression it reads from.
"""
from __future__ import annotations

from pathlib import Path

from orion.reports.assessment import AssessmentReport
from orion.reports.renderers import render_markdown, render_json

REPORT_FILENAMES = {"markdown": "assessment-report.md", "json": "assessment-report.json"}


def write_report(report: AssessmentReport, fmt: str, base_dir: str = "artifacts") -> Path:
    """Render ``report`` as ``fmt`` ("markdown" | "json") and write it under
    ``artifacts/<assessment_id>/reports/``. Returns the written file path."""
    if fmt not in REPORT_FILENAMES:
        raise ValueError(f"unsupported report format {fmt!r}; expected one of {sorted(REPORT_FILENAMES)}")
    content = render_markdown(report) if fmt == "markdown" else render_json(report)
    rdir = Path(base_dir) / report.assessment["assessment_id"] / "reports"
    rdir.mkdir(parents=True, exist_ok=True)
    path = rdir / REPORT_FILENAMES[fmt]
    path.write_text(content, encoding="utf-8")
    return path
