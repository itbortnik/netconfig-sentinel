"""Actual objective training, exact source masking and isolated semantic exposure."""

import json

import pytest
import torch
from app.domain import Vendor

from ml.datasets import DatasetSplit
from ml.preprocessing.blocks import digest, segment_configuration
from ml.preprocessing.tokenization import TokenizerPolicy, encode_block, train_config_tokenizer
from ml.training.classification_smoke import classification_fixtures
from ml.training.masking import IGNORE_LABEL
from ml.training.pretraining import (
    PretrainingPolicy,
    PretrainingReport,
    _run_objectives,
    load_pretraining,
    pretraining_identity,
    save_pretraining,
    train_configuration_objectives,
)
from ml.training.pretraining_data import (
    TASKS,
    PretrainingWeights,
    _command_spans,
    _mask_spans,
    _parameter_spans,
    prepare_pretraining,
)
from ml.training.pretraining_smoke import SCOPE, pretraining_fixtures
from ml.training.transformer import EncoderPolicy


@pytest.fixture(scope="module")
def source_data():
    splits, pairs = pretraining_fixtures()
    tokenizer = train_config_tokenizer(
        splits, policy=TokenizerPolicy(vocab_size=300, context_length=128)
    )
    return splits, pairs, tokenizer


@pytest.fixture(scope="module")
def trained(source_data):
    splits, pairs, tokenizer = source_data
    return train_configuration_objectives(
        splits,
        tokenizer,
        semantic_pairs=pairs,
        encoder_policy=EncoderPolicy(
            hidden_size=16, layers=1, heads=2, feedforward_size=32, dropout=0
        ),
        training_policy=PretrainingPolicy(epochs=3, embedding_size=8),
        weights=PretrainingWeights(cross_vendor=0.2),
    )


def test_generated_objectives_keep_source_partition_and_use_explicit_scope(source_data):
    splits, pairs, tokenizer = source_data
    data = prepare_pretraining(splits, tokenizer, semantic_pairs=pairs)
    test_hashes = {
        row.sanitized_sha256
        for part in splits.partitions
        if part.split is DatasetSplit.TEST
        for row in part.records
    }
    for split, prepared in data.items():
        allowed = {
            row.sanitized_sha256
            for part in splits.partitions
            if part.split is split
            for row in part.records
        }
        assert prepared.records == len(allowed)
        assert set(prepared.counts()) == set(TASKS)
        assert all(value > 0 for value in prepared.counts().values())
        assert prepared.semantic_scopes == (SCOPE,)
        for row in prepared.replaced_line:
            assert row.parent_sha256 in allowed and row.donor_sha256 in allowed
            assert row.parent_sha256 not in test_hashes
            assert row.positions and all(
                row.window.source_lines[index] == (row.source_line,) for index in row.positions
            )
        for name in ("same_device", "cross_vendor"):
            assert {row.positive for row in getattr(prepared, name)} == {False, True}
            for pair in getattr(prepared, name):
                assert {pair.left_sha256, pair.right_sha256} <= allowed
        assert len(prepared.replaced_line) % 2 == 0
        for offset in range(0, len(prepared.replaced_line), 2):
            original, derived = prepared.replaced_line[offset : offset + 2]
            assert not original.replaced and derived.replaced
            assert original.window.input_ids != derived.window.input_ids
            assert original.parent_sha256 == derived.parent_sha256


def test_authored_semantic_labels_only_compare_declared_static_route_slice(source_data):
    from app.parsers import get_parser

    splits, pairs, _ = source_data
    records = {row.sanitized_sha256: row for part in splits.partitions for row in part.records}
    parsers = {Vendor.CISCO: get_parser("cisco_ios"), Vendor.JUNIPER: get_parser("juniper_junos")}
    for pair in pairs:
        signatures = []
        for fingerprint in (pair.left_sha256, pair.right_sha256):
            row = records[fingerprint]
            parsed = parsers[row.vendor_hint].parse(row.sanitized_text, filename="authored.cfg")
            signatures.append(
                tuple((route.destination, route.next_hop) for route in parsed.static_routes)
            )
        assert pair.equivalent == (signatures[0] == signatures[1])
        assert signatures[0] and signatures[1]
        assert pair.scope == SCOPE and pair.origin == "synthetic"


def test_whole_commands_parameters_unicode_and_literal_control_strings(source_data):
    splits, _, tokenizer = source_data
    row = next(
        row for part in splits.partitions for row in part.records if row.vendor_hint is Vendor.CISCO
    )
    text = (
        "hostname unicode-host\ninterface GigabitEthernet0/77\n"
        " description сеть [MASK] 123 192.0.2.77\n"
        " ip address 192.0.2.1 255.255.255.0\n"
        "router bgp 64512\n neighbor 192.0.2.2 remote-as 65535\n"
    )
    assert _parameter_spans(" description сеть 192.0.2.77\n", Vendor.CISCO) == ()
    spans = _parameter_spans(text, Vendor.CISCO)
    values = {text[start:end] for start, end in spans}
    assert values == {"192.0.2.1", "255.255.255.0", "64512", "192.0.2.2", "65535"}
    assert _command_spans("set system services ssh\n# comment\n", Vendor.JUNIPER) == ((0, 23),)
    assert _command_spans("system {\n services { ssh; }\n}\n", Vendor.JUNIPER) == ()
    row = row.model_copy(update={"sanitized_text": text, "sanitized_sha256": digest(text)})
    for block in segment_configuration(row):
        windows = encode_block(block, tokenizer)
        masked = _mask_spans(
            block, windows, tokenizer, _command_spans(block.text, Vendor.CISCO), 17
        )
        assert masked
        for item in masked:
            assert any(label != IGNORE_LABEL for label in item.labels)
            assert all(
                token == 4
                for token, label in zip(item.input_ids, item.labels, strict=True)
                if label != IGNORE_LABEL
            )
            assert item.input_ids[0] == 2
            assert all(label >= 5 for label in item.labels if label != IGNORE_LABEL)


def test_span_crossing_windows_is_not_partially_masked(source_data):
    splits, _, tokenizer = source_data
    tokenizer = tokenizer.model_copy(
        update={"policy": tokenizer.policy.model_copy(update={"context_length": 8})}
    )
    row = next(part for part in splits.partitions if part.split is DatasetSplit.TRAIN).records[0]
    block = next(
        block for block in segment_configuration(row) if block.category.value == "interfaces"
    )
    assert (
        _mask_spans(block, encode_block(block, tokenizer), tokenizer, ((0, len(block.text)),), 17)
        == ()
    )


@pytest.mark.parametrize(
    "vendor,text",
    [
        (Vendor.CISCO, "ip route 192.0.2.0 255.255.255.0 192.0.2.1 ! 192.0.2.9\n"),
        (
            Vendor.JUNIPER,
            "set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24 # note\n",
        ),
        (Vendor.JUNIPER, "set routing-options router-id 192.0.2.1 // 192.0.2.99\n"),
    ],
)
def test_ambiguous_inline_comment_commands_are_not_parameter_targets(vendor, text):
    assert _command_spans(text, vendor) == ()
    assert _parameter_spans(text, vendor) == ()


@pytest.mark.parametrize("case", ["cross_split", "test", "same_vendor", "duplicate", "scope"])
def test_unusable_or_leaked_semantic_pairs_fail_closed(source_data, case):
    splits, pairs, tokenizer = source_data
    first = pairs[0]
    if case in ("cross_split", "test"):
        split = DatasetSplit.TEST if case == "test" else DatasetSplit.VALIDATION
        target = next(
            row
            for part in splits.partitions
            if part.split is split
            for row in part.records
            if row.vendor_hint is Vendor.JUNIPER
        )
        altered = (first.model_copy(update={"right_sha256": target.sanitized_sha256}),)
    elif case == "same_vendor":
        target = next(
            row
            for part in splits.partitions
            if part.split is DatasetSplit.TRAIN
            for row in part.records
            if row.vendor_hint is Vendor.CISCO and row.sanitized_sha256 != first.left_sha256
        )
        altered = (first.model_copy(update={"right_sha256": target.sanitized_sha256}),)
    elif case == "duplicate":
        altered = (first, first.model_copy(update={"equivalent": not first.equivalent}))
    else:
        altered = (first, pairs[1].model_copy(update={"scope": "different_scope"}))
    with pytest.raises(ValueError, match="semantic"):
        prepare_pretraining(splits, tokenizer, semantic_pairs=altered)


@pytest.mark.parametrize("budget", ["max_records", "max_windows", "max_examples"])
def test_construction_budgets_reject_without_truncation(source_data, budget):
    splits, pairs, tokenizer = source_data
    with pytest.raises(ValueError, match="budget"):
        prepare_pretraining(splits, tokenizer, semantic_pairs=pairs, **{budget: 1})


def test_missing_enabled_objective_cannot_be_reported_as_trained(source_data):
    splits, _, tokenizer = source_data
    with pytest.raises(ValueError, match="cross_vendor"):
        train_configuration_objectives(
            splits, tokenizer, weights=PretrainingWeights(cross_vendor=1)
        )
    other = classification_fixtures()
    other_tokenizer = train_config_tokenizer(other)
    with pytest.raises(ValueError, match="targets"):
        train_configuration_objectives(other, other_tokenizer)


def test_tokenizer_binding_and_unknown_weights_are_rejected(source_data):
    splits, _, tokenizer = source_data
    with pytest.raises(ValueError, match="different training corpus"):
        prepare_pretraining(splits, tokenizer.model_copy(update={"training_fingerprint": "f" * 64}))
    with pytest.raises(ValueError):
        PretrainingWeights(token=0, command=0, parameter=0, replaced_line=0, same_device=0)
    with pytest.raises(ValueError):
        PretrainingWeights(token=float("nan"))


def test_actual_joint_training_is_repeatable_and_restores_process_state(source_data, trained):
    splits, pairs, tokenizer = source_data
    rng, threads = torch.get_rng_state().clone(), torch.get_num_threads()
    second = train_configuration_objectives(
        splits,
        tokenizer,
        semantic_pairs=pairs,
        encoder_policy=trained.report.encoder_policy,
        training_policy=trained.report.training_policy,
        weights=trained.report.weights,
    )
    assert trained.report == second.report
    assert all(
        torch.equal(value, second.model.state_dict()[name])
        for name, value in trained.model.state_dict().items()
    )
    assert torch.equal(rng, torch.get_rng_state()) and torch.get_num_threads() == threads
    assert trained.report.losses[-1].train_total < trained.report.losses[0].train_total
    assert all(value > 0 for value in trained.report.train_counts.values())
    assert not trained.report.test_evaluated and not trained.report.production_quality_proven
    assert trained.report.semantic_origin_counts == {"synthetic": len(pairs)}
    assert not trained.model.training


def test_weighted_loss_is_exact_and_disabled_objective_is_unmeasured(source_data, trained):
    splits, pairs, tokenizer = source_data
    data = prepare_pretraining(splits, tokenizer, semantic_pairs=pairs)[DatasetSplit.VALIDATION]
    previous_threads = torch.get_num_threads()
    try:
        torch.set_num_threads(1)
        with torch.no_grad():
            weights = PretrainingWeights(
                token=2, command=0.5, parameter=0, replaced_line=0, same_device=0, cross_vendor=0
            )
            components, total = _run_objectives(
                trained.model, data, trained.report.training_policy, weights, backward=False
            )
    finally:
        torch.set_num_threads(previous_threads)
    assert total == pytest.approx(components["token"] * 2 + components["command"] * 0.5)
    assert all(components[name] is None for name in TASKS[2:])


def test_all_enabled_heads_and_encoder_receive_finite_updates(source_data, trained):
    from ml.training.pretraining import ObjectiveEncoder

    _, _, tokenizer = source_data
    with torch.random.fork_rng(devices=[]):
        torch.manual_seed(trained.report.training_policy.seed)
        initial = ObjectiveEncoder(
            tokenizer, trained.report.encoder_policy, trained.report.training_policy
        )
    for prefix in ("encoder.layers", "encoder.head", "replaced_line", "same_device", "projection"):
        parameters = [
            (name, value)
            for name, value in trained.model.state_dict().items()
            if name.startswith(prefix)
        ]
        assert parameters
        assert all(torch.isfinite(value).all() for _, value in parameters)
        assert any(not torch.equal(value, initial.state_dict()[name]) for name, value in parameters)


def test_disabled_tasks_do_not_update_random_heads_or_invent_loss(source_data):
    from ml.training.pretraining import ObjectiveEncoder

    splits, _, tokenizer = source_data
    policy = PretrainingPolicy(epochs=1, embedding_size=8)
    encoder_policy = EncoderPolicy(hidden_size=16, layers=1, heads=2, feedforward_size=32)
    result = train_configuration_objectives(
        splits,
        tokenizer,
        encoder_policy=encoder_policy,
        training_policy=policy,
        weights=PretrainingWeights(command=0, parameter=0, replaced_line=0, same_device=0),
    )
    with torch.random.fork_rng(devices=[]):
        torch.manual_seed(policy.seed)
        initial = ObjectiveEncoder(tokenizer, encoder_policy, policy)
    for name, value in result.model.state_dict().items():
        if not name.startswith("encoder."):
            assert torch.equal(value, initial.state_dict()[name])
    assert result.report.semantic_origin_counts == {} and result.report.semantic_scopes == ()
    assert all(result.report.losses[0].train_components[name] is None for name in TASKS[1:])


def test_only_positive_semantic_pairs_are_not_a_contrastive_corpus(source_data):
    splits, pairs, tokenizer = source_data
    with pytest.raises(ValueError, match="positive and negative"):
        train_configuration_objectives(
            splits,
            tokenizer,
            semantic_pairs=tuple(pair for pair in pairs if pair.equivalent),
            weights=PretrainingWeights(cross_vendor=1),
        )


def test_pair_budget_is_checked_before_training_and_restores_rng(source_data):
    splits, pairs, tokenizer = source_data
    rng = torch.get_rng_state().clone()
    with pytest.raises(ValueError, match="pair window budget"):
        train_configuration_objectives(
            splits,
            tokenizer,
            semantic_pairs=pairs,
            training_policy=PretrainingPolicy(max_pair_windows=1),
            weights=PretrainingWeights(cross_vendor=1),
        )
    assert torch.equal(rng, torch.get_rng_state())


def test_bundle_round_trip_rejects_overwrite_and_checksum_tampering(trained, tmp_path):
    bundle = tmp_path / "bundle"
    save_pretraining(trained, bundle)
    rng = torch.get_rng_state().clone()
    restored = load_pretraining(bundle)
    assert torch.equal(rng, torch.get_rng_state())
    assert restored.report == trained.report
    assert pretraining_identity(restored) == pretraining_identity(trained)
    with pytest.raises(FileExistsError):
        save_pretraining(trained, bundle)
    (bundle / "report.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="checksum"):
        load_pretraining(bundle)


@pytest.mark.parametrize("case", ["marker", "extra", "counts", "total", "parameters", "nonfinite"])
def test_recomputed_manifest_does_not_bypass_structural_checks(trained, tmp_path, case):
    from ml.training.checkpoint import _file_hash

    bundle = tmp_path / case
    save_pretraining(trained, bundle)
    if case in ("marker", "extra"):
        (bundle / (".incomplete" if case == "marker" else "unexpected.txt")).touch()
    elif case == "nonfinite":
        state = torch.load(bundle / "weights.pt", weights_only=True)
        state["replaced_line.bias"][0] = float("nan")
        torch.save(state, bundle / "weights.pt")
    else:
        report = json.loads((bundle / "report.json").read_text(encoding="utf-8"))
        if case == "counts":
            report["train_counts"]["cross_vendor"] = 0
        elif case == "total":
            report["losses"][0]["train_total"] += 1
        else:
            report["parameter_count"] += 1
        (bundle / "report.json").write_text(json.dumps(report), encoding="utf-8")
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    manifest["files"] = {name: _file_hash(bundle / name) for name in manifest["files"]}
    (bundle / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError):
        load_pretraining(bundle)


def test_report_copy_is_revalidated_and_failure_restores_state(source_data, trained, monkeypatch):
    from ml.training import pretraining

    with pytest.raises(ValueError):
        PretrainingReport.model_validate(
            trained.report.model_copy(update={"best_epoch": 100}).model_dump()
        )
    rng, threads = torch.get_rng_state().clone(), torch.get_num_threads()

    def fail(*args, **kwargs):
        raise ValueError("controlled optimizer failure")

    monkeypatch.setattr(pretraining, "_run_objectives", fail)
    splits, pairs, tokenizer = source_data
    with pytest.raises(ValueError, match="controlled"):
        train_configuration_objectives(
            splits, tokenizer, semantic_pairs=pairs, weights=PretrainingWeights(cross_vendor=0.1)
        )
    assert torch.equal(rng, torch.get_rng_state()) and torch.get_num_threads() == threads
