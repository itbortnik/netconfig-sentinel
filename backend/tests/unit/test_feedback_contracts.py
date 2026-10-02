"""Bounded assessments do not accept fabricated approval, actors or quality labels."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from app.api.feedback_contracts import FeedbackRecord, SubmitFeedback
from app.detection.policy_engine import evaluate_policies
from app.domain.fingerprints import finding_fingerprint
from app.explanation.local import explain_finding
from app.parsers import parse_configuration


def submission():
    return {
        "feedback_id": str(uuid4()),
        "analysis_id": str(uuid4()),
        "finding_sha256": "a" * 64,
        "verdict": "needs_investigation",
        "comment": "Проверить с инженером.\nНе применять автоматически.",  # noqa: RUF001
    }


@pytest.mark.parametrize(
    "change",
    [
        {"comment": ""},
        {"comment": " \n\t"},
        {"comment": " padded"},
        {"comment": "private\x00input"},
        {"comment": "private\u202einput"},
        {"comment": "private\ud800input"},
        {"comment": "x" * 2001},
        {"verdict": "approved"},
        {"verdict": "fixed"},
        {"actor": "admin"},
        {"ground_truth": True},
        {"finding_sha256": "invalid"},
    ],
)
def test_feedback_rejects_invalid_content(change) -> None:
    with pytest.raises(ValueError):
        SubmitFeedback.model_validate(submission() | change)


def test_required_idempotency_and_analysis_identity() -> None:
    for missing in ("feedback_id", "analysis_id", "finding_sha256", "comment", "verdict"):
        data = submission()
        del data[missing]
        with pytest.raises(ValueError):
            SubmitFeedback.model_validate(data)
    request = SubmitFeedback.model_validate(submission())
    assert request.comment.startswith("Проверить")
    with pytest.raises(ValueError):
        request.comment = "changed"


def test_comment_limit_counts_unicode_codepoints_not_utf16_units() -> None:
    request = SubmitFeedback.model_validate(submission() | {"comment": "🙂" * 2000})
    assert len(request.comment) == 2000
    with pytest.raises(ValueError):
        SubmitFeedback.model_validate(submission() | {"comment": "🙂" * 2001})


def test_shared_fingerprint_matches_existing_explanations() -> None:
    config = parse_configuration("hostname test\n", filename="test.cfg")
    finding = evaluate_policies(config, device_id=uuid4())[0]
    explanation = explain_finding(finding, config)
    assert finding_fingerprint(finding) == explanation.finding_sha256
    assert (
        finding_fingerprint(finding.model_copy(update={"confidence": 0.1}))
        != explanation.finding_sha256
    )


def test_feedback_record_is_typed_bound_and_timezone_aware() -> None:
    data = submission() | {
        "finding_id": str(uuid4()),
        "configuration_id": str(uuid4()),
        "device_id": str(uuid4()),
        "source_sha256": "b" * 64,
        "created_at": datetime.now(UTC),
    }
    record = FeedbackRecord.model_validate(data)
    assert record.actor == "shared_service_token"
    assert FeedbackRecord.model_validate_json(record.model_dump_json()) == record
    with pytest.raises(ValueError):
        FeedbackRecord.model_validate(data | {"created_at": datetime(2026, 1, 1)})
