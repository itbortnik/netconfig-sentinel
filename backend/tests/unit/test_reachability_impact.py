"""Direction and boundary controls; simulated frames do not establish live quality."""

import json
from types import SimpleNamespace

import pytest
from app.verification import batfish, batfish_worker
from app.verification.batfish import check_with_batfish_directional
from app.verification.reachability_impact import (
    BatfishDirectionalExecution,
    ReachabilityImpact,
    ReachabilityWitness,
)
from test_batfish_execution import envelope, pair

SCHEMA = {
    "Flow": "Flow",
    "Snapshot_Traces": "Set<Trace>",
    "Snapshot_TraceCount": "Integer",
    "Reference_Traces": "Set<Trace>",
    "Reference_TraceCount": "Integer",
}
SCOPE = {"start_node": "edge", "destination": "192.0.2.0/24"}


class Flow:
    def __init__(self, destination="192.0.2.1"):
        self.data = dict(
            dscp=0,
            dstIp=destination,
            dstPort=80,
            ecn=0,
            fragmentOffset=0,
            icmpCode=None,
            icmpVar=None,
            ingressInterface=None,
            ingressNode="edge",
            ingressVrf="default",
            ipProtocol="TCP",
            packetLength=512,
            srcIp="198.51.100.1",
            srcPort=49152,
            tcpFlagsAck=0,
            tcpFlagsCwr=0,
            tcpFlagsEce=0,
            tcpFlagsFin=0,
            tcpFlagsPsh=0,
            tcpFlagsRst=0,
            tcpFlagsSyn=1,
            tcpFlagsUrg=0,
        )

    def dict(self):
        return self.data


class Trace:
    def __init__(self, disposition):
        self.disposition = disposition


def row(before=("ACCEPTED",), after=("NULL_ROUTED",), destination="192.0.2.1"):
    return {
        "Flow": Flow(destination),
        "Reference_Traces": [Trace(x) for x in before],
        "Snapshot_Traces": [Trace(x) for x in after],
        "Reference_TraceCount": len(before),
        "Snapshot_TraceCount": len(after),
    }


class Answer:
    def __init__(self, rows):
        self.records = rows
        self.rows = [
            {
                "Flow": r["Flow"].dict(),
                "Reference_Traces": [
                    {"disposition": t.disposition, "hops": []} for t in r["Reference_Traces"]
                ],
                "Snapshot_Traces": [
                    {"disposition": t.disposition, "hops": []} for t in r["Snapshot_Traces"]
                ],
                "Reference_TraceCount": r["Reference_TraceCount"],
                "Snapshot_TraceCount": r["Snapshot_TraceCount"],
            }
            for r in rows
        ]
        self.columns = list(SCHEMA)
        self.metadata = SimpleNamespace(
            column_metadata=[SimpleNamespace(name=k, schema=v) for k, v in SCHEMA.items()]
        )

    def frame(self):
        return self

    def __len__(self):
        return len(self.records)

    def to_dict(self, *, orient):
        assert orient == "records"
        return self.records


def impact(answer):
    return ReachabilityImpact.model_validate(
        batfish_worker._directional_impact(answer, SCOPE, Flow, Trace)
    )


@pytest.mark.parametrize("success", ["ACCEPTED", "DELIVERED_TO_SUBNET", "EXITS_NETWORK"])
@pytest.mark.parametrize(
    "failure",
    ["DENIED_IN", "DENIED_OUT", "NO_ROUTE", "NULL_ROUTED", "NEIGHBOR_UNREACHABLE", "LOOP"],
)
def test_complete_flow_orientation_uses_fates_not_totals(success, failure):
    lost = impact(Answer([row((failure, success), (failure,))]))
    gained = impact(Answer([row((failure,), (success, failure))]))
    assert lost.direction == "loss_found" and lost.lost_witness_count == 1
    assert gained.direction == "gain_found" and gained.gained_witness_count == 1
    assert lost.witnesses[0].flow_sha256 == gained.witnesses[0].flow_sha256
    assert lost.witnesses[0].before_trace_count == 2


def test_mixed_equal_totals_are_two_different_flow_witnesses():
    result = impact(Answer([row(), row(("NULL_ROUTED",), ("ACCEPTED",), "192.0.2.2")]))
    assert result.direction == "loss_and_gain_found"
    assert result.lost_witness_count == result.gained_witness_count == 1
    assert len({r.flow_sha256 for r in result.witnesses}) == 2
    assert impact(Answer([])).direction == "no_witnesses_returned"


@pytest.mark.parametrize("count", [True, "1", 1.0, 1.2, None, 0, -1, 2, 17])
def test_raw_sdk_counts_cannot_be_coerced_into_complete_observation(count):
    answer = Answer([row()])
    answer.rows[0]["Snapshot_TraceCount"] = count
    result = impact(answer)
    assert (result.state, result.reason) == ("unknown", "incomplete_traces")
    assert result.witnesses == () and result.lost_witness_count is None


@pytest.mark.parametrize(
    "fates,reason",
    [
        (("INSUFFICIENT_INFO",), "insufficient_information"),
        (("NEW_DISPOSITION",), "unknown_disposition"),
        (("ACCEPTED",), "ambiguous_witness"),
    ],
)
def test_unsupported_or_ambiguous_after_never_becomes_loss(fates, reason):
    result = impact(Answer([row(after=fates)]))
    assert (result.state, result.reason) == ("unknown", reason)


@pytest.mark.parametrize(
    "mutation",
    [
        "columns",
        "schema",
        "row_key",
        "raw_rows",
        "parsed_rows",
        "wrong_node",
        "wrong_dst",
        "ipv6",
        "wrong_flow_type",
    ],
)
def test_unrecognized_frame_or_flow_scope_is_unknown(mutation):
    answer = Answer([row()])
    if mutation == "columns":
        answer.columns.append("Flow")
    elif mutation == "schema":
        answer.metadata.column_metadata[0].schema = "String"
    elif mutation == "row_key":
        answer.rows[0]["unreviewed"] = 1
    elif mutation == "raw_rows":
        answer.rows = None
    elif mutation == "parsed_rows":
        answer.records = []
    elif mutation == "wrong_node":
        answer.records[0]["Flow"].data["ingressNode"] = "other"
    elif mutation == "wrong_dst":
        answer.records[0]["Flow"].data["dstIp"] = "203.0.113.1"
    elif mutation == "ipv6":
        answer.records[0]["Flow"].data["srcIp"] = "2001:db8::1"
    else:
        answer.records[0]["Flow"] = object()
    assert impact(answer).state == "unknown"


def test_duplicate_overflow_and_hidden_success_do_not_return_partial_witnesses():
    assert impact(Answer([row(), row()])).reason == "ambiguous_witness"
    assert impact(Answer([row() for _ in range(65)])).reason == "witness_limit_exceeded"
    answer = Answer([row()])
    answer.rows[0]["Snapshot_TraceCount"] = 2
    assert impact(answer).reason == "incomplete_traces"
    answer = Answer([row(), row(after=("NEW_DISPOSITION",), destination="192.0.2.2")])
    assert impact(answer).witnesses == ()


@pytest.mark.parametrize("change", ["direction", "counts", "duplicate", "limits", "limitations"])
def test_resealed_impact_does_not_accept_internal_contradictions(change):
    data = impact(Answer([row()])).model_dump(mode="json")
    if change == "direction":
        data["direction"] = "gain_found"
    elif change == "counts":
        data["lost_witness_count"] = True
    elif change == "duplicate":
        data["witnesses"] *= 2
    elif change == "limits":
        data["max_traces"] = 32
    else:
        data["limitations"] = []
    with pytest.raises(ValueError):
        ReachabilityImpact.model_validate(data)


def test_witness_model_rejects_truncated_or_inconsistent_fates():
    value = impact(Answer([row()])).witnesses[0].model_dump(mode="json")
    value["after_trace_count"] = 2
    with pytest.raises(ValueError):
        ReachabilityWitness.model_validate(value)


@pytest.mark.parametrize("raw_count", ["1", True, 1.2])
def test_actual_optional_sdk_raw_count_coercion_is_checked_before_parsed_frame(raw_count):
    module = pytest.importorskip("pybatfish.datamodel.answer.table")
    flow = pytest.importorskip("pybatfish.datamodel.flow")
    raw = Answer([row()]).rows[0]
    raw["Snapshot_TraceCount"] = raw_count
    answer = module.TableAnswer(
        {
            "answerElements": [
                {
                    "metadata": {
                        "columnMetadata": [{"name": k, "schema": v} for k, v in SCHEMA.items()]
                    },
                    "rows": [raw],
                }
            ]
        }
    )
    assert answer.frame().to_dict(orient="records")[0]["Snapshot_TraceCount"] == 1
    result = batfish_worker._directional_impact(answer, SCOPE, flow.Flow, flow.Trace)
    assert result["state"] == "unknown" and result["reason"] == "incomplete_traces"


@pytest.mark.parametrize("padding", [0, 33_000, 131_073])
def test_new_parent_transport_keeps_exact_bindings_and_its_own_byte_limit(monkeypatch, padding):
    before, after, scope = pair()
    monkeypatch.setattr(batfish.importlib.util, "find_spec", lambda _: object())

    def run(*args, **kwargs):
        options = json.loads(kwargs["input"])
        assert options["protocol"] == "batfish-execution-0.3.0"
        response = envelope(options)
        response["version"] = options["protocol"]
        response["reachability_impact"] = impact(Answer([])).model_dump(mode="json")
        return SimpleNamespace(returncode=0, stdout=json.dumps(response) + " " * padding)

    monkeypatch.setattr(batfish.subprocess, "run", run)
    result = check_with_batfish_directional(before, after, scope, allow_local_upload=True)
    if padding > 131_072:
        assert result.result.reason == "worker_failed"
        assert result.reachability_impact.state == "not_observed"
    else:
        assert result.reachability_impact.direction == "no_witnesses_returned"
        assert result.result.before_sha256 == before.digest


def test_new_execution_does_not_upgrade_unconfirmed_cleanup():
    before, after, scope = pair()
    options = {
        "before_sha256": before.digest,
        "after_sha256": after.digest,
        "scope": scope.model_dump(mode="json"),
        "network_name": "sentinel-" + "a" * 32,
    }
    response = envelope(options)
    response["version"] = "batfish-execution-0.3.0"
    response["reachability_impact"] = impact(Answer([])).model_dump(mode="json")
    response["result"]["cleanup_complete"] = False
    with pytest.raises(ValueError):
        BatfishDirectionalExecution.model_validate(response)
    response["reachability_impact"] = batfish_worker._empty_impact("unknown", "cleanup_unconfirmed")
    assert (
        BatfishDirectionalExecution.model_validate(response).reachability_impact.state == "unknown"
    )


@pytest.mark.parametrize(
    "key,value",
    [
        ("dscp", True),
        ("dscp", 0.9),
        ("srcPort", "49152"),
        ("srcPort", 49152.2),
        ("packetLength", "512"),
        ("ingressVrf", 42),
        ("dstIp", True),
        ("ecn", 4),
        ("fragmentOffset", 8192),
        ("tcpFlagsSyn", 2),
        ("srcPort", 65536),
    ],
)
def test_actual_optional_sdk_raw_flow_types_and_ranges_cannot_be_coerced(key, value):
    module = pytest.importorskip("pybatfish.datamodel.answer.table")
    flow = pytest.importorskip("pybatfish.datamodel.flow")
    raw = Answer([row()]).rows[0]
    raw["Flow"][key] = value
    answer = module.TableAnswer(
        {
            "answerElements": [
                {
                    "metadata": {
                        "columnMetadata": [{"name": k, "schema": v} for k, v in SCHEMA.items()]
                    },
                    "rows": [raw],
                }
            ]
        }
    )
    result = batfish_worker._directional_impact(answer, SCOPE, flow.Flow, flow.Trace)
    assert result["state"] == "unknown" and result["reason"] == "unsupported_frame"


def test_actual_optional_sdk_complete_supported_frame_is_interpreted():
    module = pytest.importorskip("pybatfish.datamodel.answer.table")
    flow = pytest.importorskip("pybatfish.datamodel.flow")
    answer = module.TableAnswer(
        {
            "answerElements": [
                {
                    "metadata": {
                        "columnMetadata": [{"name": k, "schema": v} for k, v in SCHEMA.items()]
                    },
                    "rows": Answer([row()]).rows,
                }
            ]
        }
    )
    result = batfish_worker._directional_impact(answer, SCOPE, flow.Flow, flow.Trace)
    assert ReachabilityImpact.model_validate(result).direction == "loss_found"


@pytest.mark.parametrize("field,value", [("max_traces", 16.0), ("max_witnesses", 64.0)])
def test_literal_bounds_do_not_accept_float_equality(field, value):
    payload = impact(Answer([])).model_dump(mode="json")
    payload[field] = value
    with pytest.raises(ValueError):
        ReachabilityImpact.model_validate(payload)


@pytest.mark.parametrize(
    "aux,accepted",
    [
        ({"state": "NEW", "tag": "tag"}, True),
        ({"state": "NEW"}, False),
        ({"tag": "tag"}, False),
        ({"state": "ESTABLISHED", "tag": "tag"}, False),
        ({"state": "NEW", "tag": "other"}, False),
        ({"state": None, "tag": "tag"}, False),
        ({"state": True, "tag": "tag"}, False),
        ({"state": "NEW", "tag": 42}, False),
    ],
)
def test_pinned_legacy_flow_fields_are_supported_only_as_observed_and_hashed(aux, accepted):
    module = pytest.importorskip("pybatfish.datamodel.answer.table")
    flow = pytest.importorskip("pybatfish.datamodel.flow")
    raw = Answer([row()]).rows[0]
    raw["Flow"].update(aux)
    answer = module.TableAnswer(
        {
            "answerElements": [
                {
                    "metadata": {
                        "columnMetadata": [{"name": k, "schema": v} for k, v in SCHEMA.items()]
                    },
                    "rows": [raw],
                }
            ]
        }
    )
    result = ReachabilityImpact.model_validate(
        batfish_worker._directional_impact(answer, SCOPE, flow.Flow, flow.Trace)
    )
    if accepted:
        assert result.direction == "loss_found"
        assert result.witnesses[0].flow_sha256 != impact(Answer([row()])).witnesses[0].flow_sha256
    else:
        assert result.state == "unknown" and result.reason == "unsupported_frame"
