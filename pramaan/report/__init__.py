"""Lane G — the trust report.

Everything else in Pramaan measures. This lane publishes, which makes it the
one place where a mistake becomes permanent and public. So the module worth
reading first is `redaction`: it is the disclosure gate (D17), and
`trust_report.render` cannot return a document that fails it.

  * `redaction`  — the gate. Classification, a withheld-token ledger and a scan
    over the finished HTML that raises rather than publishes.
  * `charts`     — hand-rolled inline SVG. No matplotlib, no JavaScript, no CDN.
  * `summary`    — PCI DSS 6.3.3 and RBI SLA clocks, and a breach forecast that
    refuses to fit a velocity model on no closure history.
  * `trust_report` — the page. Self-contained HTML, light and dark, printable.

Nothing here recomputes a statistic. Precision, ECE, tau, pass^k and the
injection ASRs are read off Lane F's result objects and rendered with the
uncertainty those objects carry.
"""

from pramaan.report.charts import (
    CHART_FALLBACKS,
    chart_theme_css,
    confidence_histogram_svg,
    confusion_matrix_svg,
    empty_chart_svg,
    funnel_svg,
    injection_channel_svg,
    reliability_diagram_svg,
)
from pramaan.report.redaction import (
    SYNTHETIC_TARGET_ALLOWLIST,
    Disclosure,
    DisclosureViolation,
    Leak,
    RedactionLedger,
    assert_clean,
    build_ledger,
    classify,
    is_synthetic_target,
    scan,
    scrub_secrets,
    token_hash,
)
from pramaan.report.summary import (
    CLOCKS,
    BreachForecast,
    ClockSpec,
    RiskSummary,
    SlaClock,
    forecast_breaches,
    summarise,
    vapt_period_export,
)
from pramaan.report.trust_report import (
    ReportInputs,
    Withholding,
    render,
    render_to_file,
    report_manifest,
)

__all__ = [
    "CHART_FALLBACKS", "chart_theme_css", "confidence_histogram_svg",
    "confusion_matrix_svg", "empty_chart_svg", "funnel_svg",
    "injection_channel_svg", "reliability_diagram_svg",
    "SYNTHETIC_TARGET_ALLOWLIST", "Disclosure", "DisclosureViolation", "Leak",
    "RedactionLedger", "assert_clean", "build_ledger", "classify",
    "is_synthetic_target", "scan", "scrub_secrets", "token_hash",
    "CLOCKS", "BreachForecast", "ClockSpec", "RiskSummary", "SlaClock",
    "forecast_breaches", "summarise", "vapt_period_export",
    "ReportInputs", "Withholding", "render", "render_to_file",
    "report_manifest",
]
