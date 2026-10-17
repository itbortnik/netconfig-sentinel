"""Fixed five-class OVR reliability panels, without source/entity labels or text."""

from ml.evaluation.contracts import COHORTS
from ml.evaluation.severity import SeverityEvaluationReport
from ml.evaluation.severity_contracts import SEVERITY_CLASSES


def severity_reliability_svg(report: SeverityEvaluationReport) -> str:
    report = SeverityEvaluationReport.model_validate(report.model_dump(warnings=False))
    parts = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="1120" height="820" '
        'viewBox="0 0 1120 820" role="img" aria-label="Severity class OVR reliability by origin">',
        '<rect width="1120" height="820" fill="white"/>',
        '<g font-family="sans-serif" fill="#203047">',
        '<text x="35" y="28" font-size="18">Offline severity class reliability</text>',
        '<text x="35" y="49" font-size="12">'
        "x: predicted class probability; y: observed class fraction. Dashed line: ideal.</text>",
    ]
    for row_index, cohort in enumerate(COHORTS):
        summary = report.cohorts[cohort].summary
        for column, label in enumerate(SEVERITY_CLASSES):
            x, y, size = 45 + 220 * column, 95 + row_index * 232, 155
            parts.append(f'<text x="{x}" y="{y - 15}" font-size="13">{cohort}: {label}</text>')
            parts.append(
                f'<path d="M{x},{y} V{y + size} H{x + size}" stroke="#405064" fill="none"/>'
            )
            parts.append(
                f'<path d="M{x},{y + size} L{x + size},{y}" stroke="#8492a5" stroke-dasharray="4"/>'
            )
            calibration = summary.classes[column].calibration if summary else None
            if calibration is not None and summary is not None:
                points = []
                for bucket in calibration.bins:
                    if bucket.mean_probability is None or bucket.positive_fraction is None:
                        continue
                    px = x + size * bucket.mean_probability
                    py = y + size * (1 - bucket.positive_fraction)
                    points.append(f"{px:.3f},{py:.3f}")
                    parts.append(
                        f'<circle cx="{px:.3f}" cy="{py:.3f}" r="3.5" fill="#1765a8">'
                        f"<title>n={bucket.count}</title></circle>"
                    )
                parts.append(
                    f'<polyline points="{" ".join(points)}" stroke="#1765a8" fill="none"/>'
                )
                note = f"ECE={calibration.ece:.4f}; n={summary.cases}"
            else:
                note = "missing data"
            parts.append(f'<text x="{x}" y="{y + size + 22}" font-size="12">{note}</text>')
    parts.append(
        '<text x="35" y="805" font-size="12">'
        "Severity classifier only; no fused-risk update, "
        "physical independence or quality attestation."
        "</text></g></svg>"
    )
    return "\n".join(parts) + "\n"
