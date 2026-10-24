"""Authored raw-envelope controls; these tests make no engine or SDK session calls."""

import copy
import io
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from app.verification import batfish, batfish_worker
from app.verification.ingress_scope import BatfishScopeExecution, IngressScopeObservation
from app.verification.ingress_scope_worker import (
    _COLUMNS,
    IngressExtractionError,
    canonical_id,
    derived_fields,
    empty_scope,
    extract_side,
    location_rendering,
    observe_scope,
    raw_rows,
)
from test_batfish_execution import envelope, pair, request
from test_batfish_session_contract import Question, Session
from test_reachability_impact import Answer as DirectionalAnswer
from test_reachability_impact import Flow, Trace, row


def raw_answer(question, rows, *, node="edge"):
    """Minimal full envelope with the flags/summaries observed in the owned raw probes."""
    summary = dict(
        notes=f"Found {len(rows)} results", numFailed=0, numPassed=0, numResults=len(rows)
    )
    q = dict(assertion=None, exclusions=None, differential=False)
    if question == "interfaceProperties":
        q.update(
            {"class": "org.batfish.question.interfaceproperties.InterfacePropertiesQuestion"},
            nodes=json.dumps(node),
            interfaces=None,
            excludeShutInterfaces=False,
            properties="Active,Switchport,All_Prefixes,Interface_Type",
        )
    else:
        q.update(
            {"class": "org.batfish.question.specifiers.SpecifiersQuestion"},
            locationSpecifierInput=json.dumps(node),
            specifierFactoryVersion="V2",
            queryType="LOCATION"
            if question == "resolveLocationSpecifier"
            else "IP_SPACE_OF_LOCATION",
        )
    return dict(
        status="SUCCESS",
        question=q,
        summary=summary
        if question == "interfaceProperties"
        else dict(notes="", numFailed=0, numPassed=0, numResults=0),
        answerElements=[
            {
                "class": "org.batfish.datamodel.table.TableAnswerElement",
                "excludedRows": [],
                "warnings": [],
                "rows": rows,
                "summary": summary if question == "interfaceProperties" else None,
                "metadata": {
                    "textDesc": "Authored raw shape",
                    "columnMetadata": [
                        dict(name=name, schema=schema, isKey=key, isValue=value, description=name)
                        for name, (schema, key, value) in _COLUMNS[question].items()
                    ],
                },
            }
        ],
    )


def answers(interfaces=None, *, node="edge", source="EmptyIpSpace"):
    if interfaces is None:
        interfaces = [("GigabitEthernet0/0", True, False, ["192.0.2.1/30"])]
    return {
        "resolveLocationSpecifier": raw_answer(
            "resolveLocationSpecifier",
            [dict(Location=location_rendering(node, name)) for name, *_ in interfaces],
            node=node,
        ),
        "interfaceProperties": raw_answer(
            "interfaceProperties",
            [
                dict(
                    Interface=dict(hostname=node, interface=name),
                    Active=active,
                    Switchport=switchport,
                    All_Prefixes=prefixes,
                    Interface_Type="PHYSICAL",
                )
                for name, active, switchport, prefixes in interfaces
            ],
            node=node,
        ),
        "resolveIpsOfLocationSpecifier": raw_answer(
            "resolveIpsOfLocationSpecifier",
            [
                dict(Locations=f"[{location_rendering(node, name)}]", IP_Space=source)
                for name, *_ in interfaces
            ],
            node=node,
        ),
    }


def observed_payload(before=None, after=None, options=None):
    options = options or request()
    before = extract_side(before or answers(), options["scope"]["start_node"])
    after = extract_side(after or answers(), options["scope"]["start_node"])
    result = empty_scope(options, "observed", "query_completed")
    result.update(before=before, after=after, **derived_fields(before, after))
    return result


class RawAnswer:
    def __init__(self, raw):
        self.raw = raw

    def dict(self):
        return copy.deepcopy(self.raw)

    def frame(self):
        pytest.fail("scope extraction coerced raw rows through a DataFrame")


class ScopeSession(Session):
    def __init__(self, mode="unchanged", *, before=None, after=None):
        super().__init__(mode)
        self.sides = {"before": before or answers(), "after": after or answers()}

    def set_network(self, name):
        self.network = name

    def __getattr__(self, name):
        def question(**params):
            def answer(**options):
                if name not in _COLUMNS and name != "differentialReachability":
                    return Question(self, name, params).answer(**options)
                self.calls.append((name, params, options))
                if name == "differentialReachability":
                    return DirectionalAnswer([row()] if self.mode == "changed" else [])
                if self.mode == "scope_failed":
                    raise RuntimeError("private engine diagnostic and source lines")
                return RawAnswer(self.sides[options["snapshot"]][name])

            return SimpleNamespace(answer=answer)

        return question


def test_acquisition_runs_exactly_six_questions_after_reachability_and_quotes_all_nodes():
    options = request()
    node = "1edge_test-1"
    options["scope"]["start_node"] = node
    options["nodes"] = {"configs/device.cfg": node}
    session = ScopeSession(before=answers(node=node), after=answers(node=node))
    # Parse-status fixture carries the node named edge, so adapt just this authored input.
    options["nodes"] = {"configs/device.cfg": "edge"}
    result = batfish_worker.evaluate_session(
        session,
        options,
        dict,
        dict,
        directional=True,
        ingress_scope=True,
        flow_type=Flow,
        trace_type=Trace,
    )
    assert result["status"] == "no_differences_in_scope"
    assert result["ingress_scope"]["acquisition_state"] == "observed"
    calls = [call for call in session.calls if call[0] in _COLUMNS]
    assert len(calls) == 6
    names = [call[0] for call in session.calls]
    assert names.index("differentialReachability") < names.index("resolveLocationSpecifier")
    for name, params, _ in calls:
        assert params["nodes" if name == "interfaceProperties" else "locations"] == json.dumps(node)
    for name, params, _ in session.calls:
        if name in {"reachability", "differentialReachability"}:
            assert params["pathConstraints"] == {"startLocation": json.dumps(node)}
    assert len(session.uploads) == 2 and session.deleted == [options["network_name"]]


@pytest.mark.parametrize(
    "mode,reason",
    [
        ("scope_failed", "query_failed"),
        ("cleanup_failed", "cleanup_unconfirmed"),
    ],
)
def test_scope_failure_keeps_original_result_and_allowed_direction(mode, reason):
    session = ScopeSession(mode)
    result = batfish_worker.evaluate_session(
        session,
        request(),
        dict,
        dict,
        directional=True,
        ingress_scope=True,
        flow_type=Flow,
        trace_type=Trace,
    )
    assert result["status"] == "no_differences_in_scope" and result["difference_count"] == 0
    assert result["ingress_scope"]["acquisition_state"] == "unknown"
    assert result["ingress_scope"]["reason"] == reason
    assert result["ingress_scope"]["before"] is None
    if mode == "scope_failed":
        assert result["reachability_impact"]["direction"] == "no_witnesses_returned"
    assert "private" not in json.dumps(result)


def test_bad_scope_raw_schema_does_not_erase_retained_loss_witness():
    session = ScopeSession("changed")
    session.sides["after"]["interfaceProperties"]["answerElements"][0]["rows"][0]["Active"] = 1
    result = batfish_worker.evaluate_session(
        session,
        request(),
        dict,
        dict,
        directional=True,
        ingress_scope=True,
        flow_type=Flow,
        trace_type=Trace,
    )
    assert result["status"] == "differences_found"
    assert result["reachability_impact"]["direction"] == "loss_found"
    assert result["ingress_scope"]["reason"] == "unsupported_answer"


@pytest.mark.parametrize(
    "field,value",
    [
        ("Active", 1),
        ("Active", "true"),
        ("Switchport", 0),
        ("All_Prefixes", "192.0.2.1/30"),
        ("All_Prefixes", [4]),
        ("All_Prefixes", ["2001:db8::1/64"]),
        ("All_Prefixes", ["invalid"]),
        ("Interface_Type", 4),
        ("Interface_Type", "PHYSICAL\nsecret"),
    ],
)
def test_invalid_raw_scalars_never_become_observed(field, value):
    data = answers()
    data["interfaceProperties"]["answerElements"][0]["rows"][0][field] = value
    result = observe_scope(ScopeSession(before=data), request())
    assert result["acquisition_state"] == "unknown" and result["before"] is None


@pytest.mark.parametrize(
    "mutation",
    [
        "status",
        "extra_element",
        "excluded",
        "warning",
        "top_truncated",
        "table_truncated",
        "duplicate_column",
        "schema",
        "key_flag",
        "value_flag",
        "missing_column",
        "summary_count",
        "summary_failure",
        "summary_boolean",
        "resolver_sentinel",
        "missing_rows",
        "extra_row_column",
    ],
)
def test_full_raw_envelope_and_schema_fail_closed(mutation):
    data = answers()
    raw = data["interfaceProperties"]
    table = raw["answerElements"][0]
    cols = table["metadata"]["columnMetadata"]
    if mutation == "status":
        raw["status"] = "FAILURE"
    elif mutation == "extra_element":
        raw["answerElements"].append(copy.deepcopy(table))
    elif mutation == "excluded":
        table["excludedRows"] = [{}]
    elif mutation == "warning":
        table["warnings"] = ["private"]
    elif mutation == "top_truncated":
        raw["truncated"] = True
    elif mutation == "table_truncated":
        table["truncated"] = True
    elif mutation == "duplicate_column":
        cols[1] = copy.deepcopy(cols[0])
    elif mutation == "schema":
        cols[1]["schema"] = "String"
    elif mutation == "key_flag":
        cols[0]["isKey"] = 1
    elif mutation == "value_flag":
        cols[1]["isValue"] = False
    elif mutation == "missing_column":
        cols.pop()
    elif mutation == "summary_count":
        table["summary"]["numResults"] = 2
    elif mutation == "summary_failure":
        raw["summary"]["numFailed"] = 1
    elif mutation == "summary_boolean":
        raw["summary"]["numResults"] = True
    elif mutation == "resolver_sentinel":
        data["resolveLocationSpecifier"]["summary"]["numResults"] = 1
    elif mutation == "missing_rows":
        table["rows"] = None
    else:
        table["rows"][0]["Other"] = "private"
    assert observe_scope(ScopeSession(before=data), request())["acquisition_state"] == "unknown"


@pytest.mark.parametrize(
    "mutation",
    [
        "duplicate_selection",
        "other_node",
        "unsupported_link",
        "duplicate_interface",
        "missing_interface",
        "duplicate_assignment",
        "missing_assignment",
        "grouped_assignment",
        "wrong_location",
        "nonstring_assignment",
        "empty_rendering",
        "control_rendering",
    ],
)
def test_identity_and_assignment_coverage_are_exact(mutation):
    data = answers()
    selection = data["resolveLocationSpecifier"]["answerElements"][0]["rows"]
    properties = data["interfaceProperties"]["answerElements"][0]["rows"]
    assignment = data["resolveIpsOfLocationSpecifier"]["answerElements"][0]["rows"]
    if mutation == "duplicate_selection":
        selection *= 2
    elif mutation == "other_node":
        properties[0]["Interface"]["hostname"] = "other"
    elif mutation == "unsupported_link":
        selection[0]["Location"] = "InterfaceLinkLocation{nodeName=edge, interfaceName=eth0}"
    elif mutation == "duplicate_interface":
        properties *= 2
    elif mutation == "missing_interface":
        selection.clear()
    elif mutation == "duplicate_assignment":
        assignment *= 2
    elif mutation == "missing_assignment":
        assignment.clear()
    elif mutation == "grouped_assignment":
        assignment[0]["Locations"] = assignment[0]["Locations"][:-1] + ", other]"
    elif mutation == "wrong_location":
        assignment[0]["Locations"] = "[other]"
    elif mutation == "nonstring_assignment":
        assignment[0]["IP_Space"] = 1
    elif mutation == "empty_rendering":
        assignment[0]["IP_Space"] = ""
    else:
        assignment[0]["IP_Space"] = "private\nsource"
    assert observe_scope(ScopeSession(before=data), request())["acquisition_state"] == "unknown"


@pytest.mark.parametrize(
    "kind", ["selection", "properties", "assignments", "prefixes", "opaque", "raw", "total"]
)
def test_each_admission_budget_rejects_whole_observation(kind):
    data = answers()
    if kind in {"selection", "properties", "assignments"}:
        key = {
            "selection": "resolveLocationSpecifier",
            "properties": "interfaceProperties",
            "assignments": "resolveIpsOfLocationSpecifier",
        }[kind]
        data[key]["answerElements"][0]["rows"] *= 257
    elif kind == "prefixes":
        data["interfaceProperties"]["answerElements"][0]["rows"][0]["All_Prefixes"] *= 65
    elif kind == "opaque":
        data = answers(source="x" * 4097)
    elif kind == "raw":
        data["resolveLocationSpecifier"]["question"]["extra"] = "x" * 262145
    else:
        data = answers(
            [(f"eth{i}", True, False, ["192.0.2.1/30"]) for i in range(20)], source="x" * 4096
        )
    result = observe_scope(ScopeSession(before=data), request())
    assert (result["acquisition_state"], result["reason"]) == ("unknown", "budget_exceeded")
    assert result["before"] is None and result["common_eligible"] is None


@pytest.mark.parametrize(
    "interface", ["x" * 129, "ge0, interfaceName=other", "x]", "x{", "x\n", "ю"]
)
def test_unsupported_or_ambiguous_interface_names_are_rejected(interface):
    reason = "budget_exceeded" if len(interface.encode()) > 128 else "unsupported_location"
    with pytest.raises(IngressExtractionError, match=reason):
        location_rendering("edge", interface)


def test_optional_native_table_answer_preserves_full_raw_before_string_coercion():
    module = pytest.importorskip("pybatfish.datamodel.answer.table")
    payload = raw_answer("resolveLocationSpecifier", [{"Location": 42}])
    answer = module.TableAnswer(payload)
    assert answer.frame().to_dict(orient="records")[0]["Location"] == "42"
    data = answers()
    data["resolveLocationSpecifier"] = answer.dict()
    with pytest.raises(IngressExtractionError):
        extract_side(data, "edge")


def test_isolated_loader_uses_only_sibling_stdlib_module():
    loaded = batfish_worker._ingress_helper()
    assert (
        Path(loaded.__file__).resolve()
        == Path(batfish_worker.__file__).with_name("ingress_scope_worker.py").resolve()
    )
    assert loaded.canonical_id("edge", "eth0") == canonical_id("edge", "eth0")


def test_v4_main_envelopes_valid_bounded_scope_and_retains_sdk_metadata(monkeypatch, capsys):
    options = request() | {"protocol": "batfish-execution-0.4.0"}
    monkeypatch.setattr(batfish_worker.sys, "stdin", io.StringIO(json.dumps(options)))
    monkeypatch.setattr(batfish_worker, "_session", lambda: ScopeSession())
    monkeypatch.setattr(batfish_worker, "_sdk_metadata", lambda: ("2026.8.19.3660", "observed"))
    monkeypatch.setattr(
        batfish_worker.importlib,
        "import_module",
        lambda _: SimpleNamespace(
            HeaderConstraints=dict, PathConstraints=dict, Flow=Flow, Trace=Trace
        ),
    )
    batfish_worker.main()
    captured = capsys.readouterr()
    result = BatfishScopeExecution.model_validate_json(captured.out)
    assert result.ingress_scope.acquisition_state == "observed" and captured.err == ""
    assert len(captured.out.encode()) <= 262144


@pytest.mark.parametrize("fault", ["none", "timeout", "oversized", "binding"])
def test_v4_parent_protocol_binding_output_bound_and_shared_timeout(monkeypatch, fault):
    before, after, scope = pair()
    monkeypatch.setattr(batfish.importlib.util, "find_spec", lambda _: object())

    def run(*args, **kwargs):
        options = json.loads(kwargs["input"])
        assert options["protocol"] == "batfish-execution-0.4.0"
        assert kwargs["timeout"] == 7 and args[0][1] == "-I"
        if fault == "timeout":
            raise subprocess.TimeoutExpired("private", 7)
        response = envelope(options) | {
            "version": options["protocol"],
            "ingress_scope": observed_payload(options=options),
            "reachability_impact": batfish_worker._directional_impact(
                DirectionalAnswer([]), options["scope"], Flow, Trace
            ),
        }
        if fault == "binding":
            response["ingress_scope"]["before_sha256"] = "f" * 64
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps(response) + (" " * 262145 if fault == "oversized" else ""),
        )

    monkeypatch.setattr(batfish.subprocess, "run", run)
    result = batfish.check_with_batfish_scope_evidence(
        before, after, scope, allow_local_upload=True, timeout_seconds=7
    )
    if fault == "none":
        assert result.ingress_scope.acquisition_state == "observed"
    else:
        assert result.result.reason == ("timeout" if fault == "timeout" else "worker_failed")
        assert result.ingress_scope.acquisition_state == "not_observed"
        assert result.sdk_observation == "not_observed"


def test_resolver_null_summary_sentinel_is_not_a_row_count():
    payload = raw_answer("resolveLocationSpecifier", [{"Location": "unsupported"}])
    assert len(raw_rows(payload, "resolveLocationSpecifier", json.dumps("edge"))) == 1
    assert IngressScopeObservation.model_validate(observed_payload()).eligibility_complete is True


@pytest.mark.parametrize("question", ["resolveLocationSpecifier", "resolveIpsOfLocationSpecifier"])
@pytest.mark.parametrize(
    "selector",
    [
        "filterSpecifierInput",
        "interfaceSpecifierInput",
        "ipSpaceSpecifierInput",
        "nodeSpecifierInput",
    ],
)
@pytest.mark.parametrize("value", ["0.0.0.0/0", 42])
def test_resolvers_reject_nondefault_unused_selectors(question, selector, value):
    payload = answers()[question]
    payload["question"][selector] = value
    with pytest.raises(IngressExtractionError, match="unsupported_answer"):
        raw_rows(payload, question, json.dumps("edge"))
