"""Basic Assessment Report (Community): a deterministic, read-only export of
existing Orion Assessment state as Markdown and JSON.

    Existing Orion State -> AssessmentReport -> Markdown | JSON

No new Findings, severity, corroboration or Regression results are computed
here — this module only reshapes and renders state that already exists.
"""
from __future__ import annotations

from orion.reports.assessment import AssessmentReport, REPORT_VERSION, build_assessment_report
from orion.reports.renderers import render_markdown, render_json
from orion.reports.writer import write_report, REPORT_FILENAMES

__all__ = [
    "AssessmentReport", "REPORT_VERSION", "build_assessment_report",
    "render_markdown", "render_json", "write_report", "REPORT_FILENAMES",
]
