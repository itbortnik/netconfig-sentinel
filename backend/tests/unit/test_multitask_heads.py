"""Five supervised heads, block aggregation and correctly isolated weighted losses."""

import pytest
import torch

from ml.training.multitask import (
    HeadPolicy,
    LossWeights,
    MultiTaskHeads,
    SupervisedTargets,
    multitask_loss,
)


def features():
    return (
        torch.arange(48, dtype=torch.float32).reshape(3, 16) / 20,
        torch.arange(32, dtype=torch.float32).reshape(2, 16) / 10,
    )


def targets(**updates):
    values = dict(
        anomaly=torch.tensor([1.0, 0.0, 1.0, 0.0]),
        categories=torch.tensor([[1.0, 0.0], [0.0, 0.0], [0.0, 1.0], [0.0, 0.0]]),
        severity=torch.tensor([2, -100, 3, -100]),
        lines=torch.tensor([1.0, 0.0, 0.0, 1.0, -100.0]),
        similarity_groups=("a", "a", "b", "b"),
    )
    values.update(updates)
    return SupervisedTargets(**values)


def outputs(model):
    blocks, lines = features()
    return model(
        (blocks, blocks + 0.1, blocks + 0.2, blocks + 0.3), (lines, lines[:1], lines[:1], lines[:1])
    )


def test_all_five_heads_and_attention_pooling_are_differentiable():
    model = MultiTaskHeads(16, HeadPolicy(classes=("routing", "management"), embedding_size=8))
    output = outputs(model)
    assert output.anomaly_logits.shape == (4,)
    assert output.category_logits.shape == (4, 2)
    assert output.severity_logits.shape == (4, 5)
    assert output.line_logits.shape == (5,)
    assert output.embeddings.shape == (4, 8)
    assert torch.allclose(output.embeddings.norm(dim=1), torch.ones(4), atol=1e-6)
    assert all(torch.allclose(value.sum(), torch.tensor(1.0)) for value in output.block_attention)
    loss = multitask_loss(output, targets(), LossWeights())
    assert set(loss.components) == {
        "anomaly",
        "category",
        "localization",
        "severity",
        "contrastive",
    }
    loss.total.backward()
    for module in (
        model.anomaly,
        model.category,
        model.localizer,
        model.severity,
        model.embedding,
        model.pooler,
        model.adapter,
    ):
        assert any(
            parameter.grad is not None and bool(parameter.grad.abs().sum())
            for parameter in module.parameters()
        )


def test_permutation_of_blocks_does_not_change_predictions_or_embedding():
    model = MultiTaskHeads(16, HeadPolicy(classes=("routing",)))
    model.eval()
    blocks, lines = features()
    first, second = model((blocks,), (lines,)), model((blocks.flip(0),), (lines,))
    assert torch.allclose(first.anomaly_logits, second.anomaly_logits, atol=1e-6)
    assert torch.allclose(first.embeddings, second.embeddings, atol=1e-6)
    assert torch.allclose(first.line_logits, second.line_logits, atol=1e-6)
    assert torch.allclose(first.block_attention[0].flip(0), second.block_attention[0], atol=1e-6)


def test_weighted_loss_matches_manual_sum_and_zero_weight_has_no_gradient():
    model = MultiTaskHeads(16, HeadPolicy(classes=("routing", "management")))
    output = outputs(model)
    weights = LossWeights(anomaly=2, category=3, localization=0, severity=0, contrastive=0)
    loss = multitask_loss(output, targets(), weights)
    expected = 2 * torch.nn.functional.binary_cross_entropy_with_logits(
        output.anomaly_logits, targets().anomaly
    )
    expected += 3 * torch.nn.functional.binary_cross_entropy_with_logits(
        output.category_logits, targets().categories
    )
    assert torch.allclose(loss.total, expected)
    loss.total.backward()
    assert model.localizer.weight.grad is None
    assert model.severity.weight.grad is None
    assert model.embedding.weight.grad is None


def test_unknown_labels_are_not_filled_as_negatives_or_safe_severity():
    model = MultiTaskHeads(16, HeadPolicy(classes=("routing", "management")))
    output = outputs(model)
    unknown = targets(severity=torch.full((4,), -100), lines=torch.full((5,), -100.0))
    with pytest.raises(ValueError, match="severity"):
        multitask_loss(output, unknown, LossWeights(localization=0))
    loss = multitask_loss(output, unknown, LossWeights(severity=0, localization=0))
    assert loss.supervised_counts["severity"] == loss.supervised_counts["localization"] == 0
    with pytest.raises(ValueError, match="contrastive"):
        multitask_loss(output, targets(similarity_groups=(None,) * 4), LossWeights())


@pytest.mark.parametrize(
    "values",
    [
        {"anomaly": -1},
        {"category": float("nan")},
        dict(anomaly=0, category=0, localization=0, severity=0, contrastive=0),
    ],
)
def test_invalid_loss_weights_rejected(values):
    with pytest.raises(ValueError):
        LossWeights(**values)


@pytest.mark.parametrize(
    "values",
    [
        {"classes": ()},
        {"classes": ("a", "a")},
        {"adapter_rank": 0},
        {"embedding_size": 1025},
        {"contrastive_margin": float("inf")},
    ],
)
def test_head_policy_is_bounded(values):
    with pytest.raises(ValueError):
        HeadPolicy(**{"classes": ("routing",), **values})


def test_invalid_features_shapes_nonfinite_and_empty_blocks_rejected():
    model = MultiTaskHeads(16, HeadPolicy(classes=("routing",)))
    _, lines = features()
    for blocks in (torch.empty(0, 16), torch.ones(1, 15), torch.full((1, 16), float("nan"))):
        with pytest.raises(ValueError):
            model((blocks,), (lines,))
    with pytest.raises(ValueError):
        model(features()[:1], ())


def test_invalid_targets_are_rejected_before_loss():
    model = MultiTaskHeads(16, HeadPolicy(classes=("routing", "management")))
    output = outputs(model)
    for updates in (
        {"anomaly": torch.tensor([2.0, 0.0, 1.0, 0.0])},
        {"categories": torch.ones(4, 3)},
        {"severity": torch.tensor([5, 1, 2, 3])},
        {"lines": torch.ones(4)},
        {"similarity_groups": ("a",)},
        {"anomaly": torch.full((4,), float("nan"))},
        {"categories": torch.tensor([[1.0, 0.0], [1.0, 0.0], [0.0, 1.0], [0.0, 0.0]])},
    ):
        with pytest.raises(ValueError):
            multitask_loss(output, targets(**updates), LossWeights())


def test_frozen_inputs_are_not_changed_by_adapter_training():
    model = MultiTaskHeads(16, HeadPolicy(classes=("routing", "management")))
    blocks, lines = features()
    before = blocks.clone(), lines.clone()
    optimizer = torch.optim.AdamW(model.parameters(), lr=0.01)
    losses = []
    for _ in range(5):
        output = model(
            (blocks, blocks + 0.1, blocks + 0.2, blocks + 0.3),
            (lines, lines[:1], lines[:1], lines[:1]),
        )
        loss = multitask_loss(output, targets(), LossWeights(contrastive=0))
        losses.append(float(loss.total.detach()))
        optimizer.zero_grad()
        loss.total.backward()
        optimizer.step()
    assert losses[-1] < losses[0]
    assert torch.equal(blocks, before[0]) and torch.equal(lines, before[1])
