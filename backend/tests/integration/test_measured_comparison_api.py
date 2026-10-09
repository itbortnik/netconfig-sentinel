"""Measured peers require saved source accounting, not inferred historical coverage."""

from copy import deepcopy
from uuid import UUID, uuid4

import pytest
import test_expanded_comparison_api as comparison_tests
from app.api.contracts import AnalysisResult, MeasuredComparisonContext
from app.main import create_app
from fastapi.testclient import TestClient
from sqlalchemy import text
from test_expanded_comparison_api import (
    HEADERS,
    analyze,
    upload,
)


@pytest.fixture
def measured_api(tmp_path):
    population = comparison_tests.expanded_api.__wrapped__(tmp_path)
    selected_api = next(population)
    try:
        yield selected_api
    finally:
        population.close()
        selected_api[1].close()


def source(form, host, address="192.0.2.10", partial=False, small=False):
    if form == "ios":
        line = f"ntp server {address}\n"
        return (
            f"hostname {host}\nip ssh version 2\n"
            + line * (100 if small else 1)
            + ("unknown PRIVATE_COMMAND\n" if partial else "")
            + "end\n"
        )
    if form == "set":
        line = f"set system ntp server {address}\n"
        return (
            f"set system host-name {host}\nset system services ssh\n"
            + line * (100 if small else 1)
            + ("set unknown PRIVATE_COMMAND\n" if partial else "")
        )
    line = f"  server {address};\n"
    return (
        f"system {{\n host-name {host};\n services {{\n  ssh;\n }}\n ntp {{\n"
        + line * (100 if small else 1)
        + " }\n"
        + (" unknown PRIVATE_COMMAND;\n" if partial else "")
        + "}\n"
    )


def selected(client, form="ios", partial=False, small=False):
    peers = [upload(client, source(form, f"peer-{number}")) for number in range(3)]
    target = upload(client, source(form, "target", "192.0.2.99", partial, small))
    options = {"peer_configuration_ids": [item["configuration_id"] for item in peers]}
    return peers, target, options


@pytest.mark.parametrize("form", ["ios", "set", "blocks"])
@pytest.mark.parametrize("partial", [False, True])
def test_actual_measurements_persist_explain_and_restart_without_upgrading_old_runs(
    measured_api, form, partial
):
    client, store, settings = measured_api
    _, target, options = selected(client, form, partial)
    old = analyze(client, target, **options, comparison_version="0.2.0").json()
    response = analyze(client, target, **options, comparison_version="0.3.0")
    assert response.status_code == 201, response.text
    result = response.json()
    assert result["version"] == "analysis-api-0.5.0"
    context = result["comparison"]
    assert context["version"] == "comparison-context-0.3.0"
    report = context["peer_evaluation"]
    assert report["coverage"] == target["parser_coverage"]
    assert report["findings"] == [
        item for item in result["findings"] if item["detector"] == "peer_baseline"
    ]
    assert report["status"] == result["status"] == ("partial" if partial else "completed")
    assert len(report["skipped_features"] if partial else report["compared_features"]) == 19
    assert "PRIVATE_COMMAND" not in response.text
    assert (result["risk"] is None) == partial
    assert isinstance(AnalysisResult.model_validate(result).comparison, MeasuredComparisonContext)
    for finding in report["findings"]:
        local = next(
            item for item in result["explanations"] if item["finding_id"] == finding["finding_id"]
        )
        if partial:
            assert finding["category"] == "baseline.parser.unparsed_fraction_high"
            assert (
                "source-line" in local["summary"]
                and "not fault probability" in (local["technical_explanation"])
            )
        request = {"analysis_id": result["analysis_id"], "finding_sha256": local["finding_sha256"]}
        explained = client.post(
            f"/api/v1/findings/{finding['finding_id']}/explain", headers=HEADERS, json=request
        )
        assert explained.status_code == 200, explained.text
        bundle = explained.json()
        assert bundle["knowledge_version"] == "project-knowledge-0.4.0"
        assert bundle["documents"][0]["section"] == "measured-parser-coverage"
        assert bundle["explanation"] == local and local["formal_verification"] == "not_run"
        with TestClient(create_app(settings)) as restarted:
            assert (
                restarted.post(
                    f"/api/v1/findings/{finding['finding_id']}/explain",
                    headers=HEADERS,
                    json=request,
                ).json()
                == bundle
            )
    with TestClient(create_app(settings)) as restarted:
        for recorded in (old, result):
            assert (
                restarted.get(f"/api/v1/analyses/{recorded['analysis_id']}", headers=HEADERS).json()
                == recorded
            )
    with store.engine.connect() as connection:
        encrypted = connection.execute(text("SELECT payload FROM analyses")).scalars().all()
        assert all(
            "parser-coverage" not in row and "peer_evaluation" not in row for row in encrypted
        )
        assert (
            connection.execute(text("SELECT count(*) FROM configuration_sources")).scalar_one() == 0
        )


@pytest.mark.parametrize("form", ["ios", "set", "blocks"])
def test_below_tolerance_partial_is_not_a_successful_property_comparison(measured_api, form):
    client, _, _ = measured_api
    _, target, options = selected(client, form, partial=True, small=True)
    result = analyze(client, target, **options, comparison_version="0.3.0").json()
    report = result["comparison"]["peer_evaluation"]
    assert 0 < report["coverage"]["unparsed_fraction"] <= 0.05
    assert result["risk"] is None and report["status"] == "partial"
    assert report["findings"] == [] and report["compared_features"] == []
    assert len(report["skipped_features"]) == 19


@pytest.mark.parametrize("scope", ["target", "peer"])
def test_historical_unmeasured_sources_are_not_silently_reparsed(measured_api, scope):
    client, store, _ = measured_api
    peers, target, options = selected(client)
    old = target if scope == "target" else peers[0]
    snapshot = store.get_configuration(UUID(old["configuration_id"]))
    assert snapshot is not None
    legacy = snapshot.model_copy(update={"configuration_id": uuid4(), "parser_coverage": None})
    store.add_configuration(legacy)
    if scope == "target":
        target = {**target, "configuration_id": str(legacy.configuration_id)}
    else:
        options["peer_configuration_ids"][0] = str(legacy.configuration_id)
    assert analyze(client, target, **options, comparison_version="0.2.0").status_code == 201
    response = analyze(client, target, **options, comparison_version="0.3.0")
    assert response.status_code == 400 and "PRIVATE_COMMAND" not in response.text
    with store.engine.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM analyses")).scalar_one() == 1
    assert store.get_configuration(legacy.configuration_id).parser_coverage is None


@pytest.mark.parametrize(
    "case",
    [
        "version",
        "profile",
        "report",
        "source",
        "device",
        "coverage",
        "threshold",
        "peers",
        "findings",
        "status",
    ],
)
def test_measured_saved_result_rejects_context_substitution(measured_api, case):
    client, _, _ = measured_api
    _, target, options = selected(client, partial=True)
    result = analyze(client, target, **options, comparison_version="0.3.0").json()
    changed = deepcopy(result)
    context = changed["comparison"]
    report = context["peer_evaluation"]
    if case == "version":
        changed["version"] = "analysis-api-0.4.0"
    elif case == "profile":
        context["peer_baseline"]["properties"]["consensus_threshold"] = 0.9
    elif case == "report":
        report["baseline_sha256"] = "a" * 64
    elif case == "source":
        report["source_sha256"] = "a" * 64
    elif case == "device":
        report["device_id"] = "00000000-0000-0000-0000-000000000001"
    elif case == "coverage":
        context["peer_baseline"]["coverage"][0]["units"][0]["raw_text_sha256"] = "a" * 64
    elif case == "threshold":
        context["peer_baseline"]["unparsed_fraction_limit"] = 0.9
    elif case == "peers":
        context["peers"][0]["source_sha256"] = "a" * 64
    elif case == "findings":
        report["findings"] = []
    else:
        changed["status"] = "completed"
    with pytest.raises(ValueError):
        AnalysisResult.model_validate(changed)


def test_no_selected_inputs_do_not_claim_a_measured_comparison(measured_api):
    client, _, _ = measured_api
    target = upload(client, source("ios", "target"))
    result = analyze(client, target, comparison_version="0.3.0").json()
    assert result["version"] == "analysis-api-0.1.0" and result["comparison"] is None


@pytest.mark.parametrize("form", ["ios", "set", "blocks"])
@pytest.mark.parametrize("legacy", [False, True])
def test_reference_only_keeps_expected_v2_without_requiring_measured_peers(
    measured_api, form, legacy
):
    client, store, settings = measured_api
    reference = upload(client, source(form, "target"))
    target = upload(client, source(form, "target", "192.0.2.99"), reference["device_id"])
    if legacy:
        for wire in (reference, target):
            snapshot = store.get_configuration(UUID(wire["configuration_id"]))
            assert snapshot is not None
            historical = snapshot.model_copy(
                update={"configuration_id": uuid4(), "parser_coverage": None}
            )
            store.add_configuration(historical)
            wire["configuration_id"] = str(historical.configuration_id)
    options = {"reference_configuration_id": reference["configuration_id"]}
    old = analyze(client, target, **options, comparison_version="0.2.0").json()
    response = analyze(client, target, **options, comparison_version="0.3.0")
    assert response.status_code == 201, response.text
    result = response.json()
    assert result["version"] == "analysis-api-0.5.0" and result["risk"] == old["risk"]
    context = result["comparison"]
    assert context["version"] == "comparison-context-0.3.0"
    assert context["reference"]["configuration_id"] == reference["configuration_id"]
    assert context["peers"] == []
    assert context["peer_baseline"] is None and context["peer_evaluation"] is None
    assert result["findings"] == old["findings"]
    expected = [item for item in result["findings"] if item["detector"] == "expected_configuration"]
    assert len(expected) == 1 and expected[0]["model_version"] == "expected-config-0.2.0"
    bundle = comparison_tests.explain(client, result, expected[0])
    assert bundle["knowledge_version"] == "project-knowledge-0.3.0"
    with TestClient(create_app(settings)) as restarted:
        for recorded in (old, result):
            assert (
                restarted.get(f"/api/v1/analyses/{recorded['analysis_id']}", headers=HEADERS).json()
                == recorded
            )
    if legacy:
        for wire in (reference, target):
            assert store.get_configuration(UUID(wire["configuration_id"])).parser_coverage is None


@pytest.mark.parametrize("form", ["ios", "set", "blocks"])
@pytest.mark.parametrize("partial", [False, True])
def test_measured_nonconsensus_remains_distinct_from_incomplete_parse(measured_api, form, partial):
    client, _, _ = measured_api
    peers = [upload(client, source(form, f"peer-{n}", f"192.0.2.{n + 1}")) for n in range(3)]
    target = upload(client, source(form, "target", "192.0.2.99", partial=partial))
    response = analyze(
        client,
        target,
        comparison_version="0.3.0",
        peer_configuration_ids=[item["configuration_id"] for item in peers],
    )
    assert response.status_code == 201, response.text
    result = response.json()
    context = result["comparison"]
    assert context["peer_baseline"]["properties"]["omitted_features"] == ["management.ntp_servers"]
    report = context["peer_evaluation"]
    assert len(report["profile_features"]) == 18
    assert len(report["skipped_features"] if partial else report["compared_features"]) == 18
    assert report["compared_features"] == [] if partial else report["skipped_features"] == []
    assert all(
        item["category"] == "baseline.parser.unparsed_fraction_high" for item in report["findings"]
    )
    assert len(report["findings"]) == int(partial)
    assert report["status"] == result["status"] == ("partial" if partial else "completed")
    assert (result["risk"] is None) == partial


@pytest.mark.parametrize("form", ["ios", "set", "blocks"])
def test_measured_reference_peers_and_actual_forest_preserve_each_detector_release(
    measured_api, form
):
    client, _, settings = measured_api
    training = [upload(client, source(form, f"train-{n}", f"192.0.2.{n + 20}")) for n in range(8)]
    trained = client.post(
        "/api/v1/models/isolation-forest",
        headers=HEADERS,
        json={"configuration_ids": [item["configuration_id"] for item in training]},
    )
    assert trained.status_code == 201, trained.text
    model = trained.json()
    peers = [upload(client, source(form, f"peer-{n}")) for n in range(3)]
    reference = upload(client, source(form, "target"))
    target = upload(client, source(form, "target", "192.0.2.99"), reference["device_id"])
    options = {
        "peer_configuration_ids": [item["configuration_id"] for item in peers],
        "reference_configuration_id": reference["configuration_id"],
        "statistical_model_id": model["model_id"],
    }
    old = analyze(client, target, **options, comparison_version="0.2.0").json()
    response = analyze(client, target, **options, comparison_version="0.3.0")
    assert response.status_code == 201, response.text
    result = response.json()
    assert result["version"] == "analysis-api-0.5.0"
    assert result["statistical"] == old["statistical"]
    assert result["statistical"]["model"] == model
    assert result["risk"]["assessment_id"] != old["risk"]["assessment_id"]
    for recorded in (old, result):
        for component in recorded["risk"]["components"]:
            detector = {
                "policy": "policy_engine",
                "peer_group": "peer_baseline",
                "statistical": "isolation_forest",
            }.get(component["source"])
            assert set(component["finding_ids"]) == {
                item["finding_id"] for item in recorded["findings"] if item["detector"] == detector
            }
    new_scores, old_scores = deepcopy(result["risk"]), deepcopy(old["risk"])
    for scores in (new_scores, old_scores):
        scores.pop("assessment_id")
        for component in scores["components"]:
            component.pop("finding_ids")
    assert new_scores == old_scores
    assert {
        item["source"] for item in result["risk"]["components"] if item["status"] == "completed"
    } == {"policy", "peer_group", "statistical"}
    assert {
        item["model_version"]
        for item in result["findings"]
        if item["detector"] in {"expected_configuration", "peer_baseline"}
    } == {"expected-config-0.2.0", "peer-baseline-0.3.0"}
    for item in result["findings"]:
        local = next(e for e in result["explanations"] if e["finding_id"] == item["finding_id"])
        explained = client.post(
            f"/api/v1/findings/{item['finding_id']}/explain",
            headers=HEADERS,
            json={"analysis_id": result["analysis_id"], "finding_sha256": local["finding_sha256"]},
        )
        assert explained.status_code == 200, explained.text
        release = {
            "policy_engine": "project-knowledge-0.2.0",
            "expected_configuration": "project-knowledge-0.3.0",
            "peer_baseline": "project-knowledge-0.4.0",
            "isolation_forest": "project-knowledge-0.1.0",
        }[item["detector"]]
        assert explained.json()["knowledge_version"] == release
        assert explained.json()["explanation"] == local
    with TestClient(create_app(settings)) as restarted:
        for recorded in (old, result):
            assert (
                restarted.get(f"/api/v1/analyses/{recorded['analysis_id']}", headers=HEADERS).json()
                == recorded
            )
