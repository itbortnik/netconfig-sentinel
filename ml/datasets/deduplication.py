"""Deterministic exact, normalized, and MinHash-assisted dataset deduplication."""

from __future__ import annotations

import hashlib
import re
import unicodedata
from collections import defaultdict
from dataclasses import dataclass
from enum import StrEnum
from functools import lru_cache
from ipaddress import IPv4Address, ip_address
from itertools import pairwise

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ml.datasets.models import ImportedDatasetRecord

DEDUPLICATION_VERSION = "dataset-dedup-0.1.0"
_MINHASH_PRIME = (1 << 61) - 1
_COMMENT_BLOCK = re.compile(r"/\*.*?\*/", re.S)
_SPACE = re.compile(r"\s+")
_PSEUDONYM = re.compile(
    r"\b(?P<kind>host|user|domain|network|site|device|record|certificate)"
    r"-[0-9a-f]{12}(?:\.invalid)?\b"
)
_QUOTED_VALUE = re.compile(r'"[^"\r\n]*"|\'[^\'\r\n]*\'')
_IPV4 = re.compile(
    r"(?<![A-Za-z0-9_.])(?P<value>(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?)"
    r"(?![A-Za-z0-9_.])"
)
_IPV6 = re.compile(
    r"(?<![0-9A-Fa-f:])(?P<value>[0-9A-Fa-f]*:[0-9A-Fa-f:]+(?:/\d{1,3})?)"
    r"(?![0-9A-Fa-f:])"
)
_LONG_HEX = re.compile(r"\b[0-9a-f]{8,}\b")
_NUMBER = re.compile(r"\d+")


class DeduplicationMethod(StrEnum):
    """Evidence used to connect two records in a duplicate cluster."""

    RAW_SHA256 = "raw_sha256"
    SANITIZED_SHA256 = "sanitized_sha256"
    NORMALIZED_SHA256 = "normalized_sha256"
    MINHASH_TOKEN_SIMILARITY = "minhash_token_similarity"


class DeduplicationPolicy(BaseModel):
    """Versioned, bounded parameters for near-duplicate discovery."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    near_duplicate_threshold: float = Field(default=0.82, ge=0.5, le=1.0)
    minhash_permutations: int = Field(default=64, ge=16, le=256)
    lsh_bands: int = Field(default=8, ge=1, le=64)
    max_candidates_per_bucket: int = Field(default=64, ge=1, le=1024)
    minimum_tokens_for_near_match: int = Field(default=3, ge=1, le=1000)

    @model_validator(mode="after")
    def bands_must_partition_signature(self) -> DeduplicationPolicy:
        if self.minhash_permutations % self.lsh_bands:
            raise ValueError("lsh_bands must evenly divide minhash_permutations")
        return self


class DatasetRecordReference(BaseModel):
    """Stable reference to a sanitized record without copying its text."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_id: str = Field(min_length=1, max_length=64)
    record_id: str = Field(min_length=1, max_length=128)


class DeduplicationFingerprint(BaseModel):
    """Auditable non-content fingerprints computed for one record."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    record: DatasetRecordReference
    raw_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    sanitized_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    normalized_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    template_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    token_count: int = Field(ge=1)


class DuplicateLink(BaseModel):
    """One direct, verified edge in a duplicate cluster spanning tree."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    left: DatasetRecordReference
    right: DatasetRecordReference
    method: DeduplicationMethod
    similarity: float = Field(ge=0.0, le=1.0)

    @model_validator(mode="after")
    def endpoints_must_differ(self) -> DuplicateLink:
        if self.left == self.right:
            raise ValueError("duplicate link endpoints must differ")
        return self


class DuplicateCluster(BaseModel):
    """Connected duplicate family with one deterministic representative."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    cluster_id: str = Field(pattern=r"^duplicate-[0-9a-f]{16}$")
    representative: DatasetRecordReference
    members: tuple[DatasetRecordReference, ...] = Field(min_length=2)
    links: tuple[DuplicateLink, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def cluster_must_be_internally_consistent(self) -> DuplicateCluster:
        member_keys = {
            (item.source_id, item.record_id) for item in self.members
        }
        if len(member_keys) != len(self.members):
            raise ValueError("duplicate cluster members must be unique")
        if self.representative not in self.members:
            raise ValueError("representative must belong to the duplicate cluster")
        if self.cluster_id != _cluster_id(self.members):
            raise ValueError("cluster_id must match the sorted member references")
        if len(self.links) != len(self.members) - 1:
            raise ValueError("duplicate cluster links must form a spanning tree")
        adjacency: dict[tuple[str, str], set[tuple[str, str]]] = defaultdict(set)
        for link in self.links:
            left_key = _reference_key(link.left)
            right_key = _reference_key(link.right)
            if left_key not in member_keys or right_key not in member_keys:
                raise ValueError("duplicate links must connect cluster members")
            if (
                link.method is not DeduplicationMethod.MINHASH_TOKEN_SIMILARITY
                and link.similarity != 1.0
            ):
                raise ValueError("exact duplicate links must have similarity 1.0")
            adjacency[left_key].add(right_key)
            adjacency[right_key].add(left_key)
        visited: set[tuple[str, str]] = set()
        pending = [_reference_key(self.representative)]
        while pending:
            current = pending.pop()
            if current in visited:
                continue
            visited.add(current)
            pending.extend(adjacency[current] - visited)
        if visited != member_keys:
            raise ValueError("duplicate cluster links must be connected")
        return self


class TemplateGroup(BaseModel):
    """Records sharing one literal-abstracted configuration template."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    template_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    members: tuple[DatasetRecordReference, ...] = Field(min_length=2)

    @model_validator(mode="after")
    def members_must_be_unique(self) -> TemplateGroup:
        keys = [_reference_key(member) for member in self.members]
        if len(keys) != len(set(keys)):
            raise ValueError("template group members must be unique")
        return self


class DatasetDeduplicationResult(BaseModel):
    """Representatives plus complete audit evidence for removed copies."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    algorithm_version: str = Field(
        default=DEDUPLICATION_VERSION,
        pattern=r"^dataset-dedup-0\.1\.0$",
    )
    policy: DeduplicationPolicy
    input_count: int = Field(ge=1)
    unique_count: int = Field(ge=1)
    exact_duplicate_count: int = Field(ge=0)
    near_duplicate_count: int = Field(ge=0)
    template_group_count: int = Field(ge=1)
    unique_records: tuple[ImportedDatasetRecord, ...] = Field(min_length=1)
    fingerprints: tuple[DeduplicationFingerprint, ...] = Field(min_length=1)
    duplicate_clusters: tuple[DuplicateCluster, ...]
    template_groups: tuple[TemplateGroup, ...]

    @model_validator(mode="after")
    def counts_must_match_payload(self) -> DatasetDeduplicationResult:
        if len(self.fingerprints) != self.input_count:
            raise ValueError("fingerprint count must equal input_count")
        if len(self.unique_records) != self.unique_count:
            raise ValueError("unique record count must equal unique_count")
        if (
            self.unique_count
            + self.exact_duplicate_count
            + self.near_duplicate_count
            != self.input_count
        ):
            raise ValueError("duplicate counts must account for every input record")
        fingerprint_by_reference = {
            _reference_key(item.record): item for item in self.fingerprints
        }
        if len(fingerprint_by_reference) != self.input_count:
            raise ValueError("fingerprint references must be unique")
        unique_references = {
            (item.source_id, item.record_id) for item in self.unique_records
        }
        if len(unique_references) != self.unique_count:
            raise ValueError("unique record references must be unique")
        cluster_members: set[tuple[str, str]] = set()
        expected_representatives = set(fingerprint_by_reference)
        exact_links = 0
        near_links = 0
        for cluster in self.duplicate_clusters:
            member_keys = {_reference_key(member) for member in cluster.members}
            if not member_keys <= set(fingerprint_by_reference):
                raise ValueError("duplicate cluster references must have fingerprints")
            if cluster_members & member_keys:
                raise ValueError("duplicate clusters must not overlap")
            cluster_members.update(member_keys)
            representative_key = _reference_key(cluster.representative)
            expected_representatives.difference_update(member_keys - {representative_key})
            for link in cluster.links:
                if link.method is DeduplicationMethod.MINHASH_TOKEN_SIMILARITY:
                    near_links += 1
                else:
                    exact_links += 1
        if unique_references != expected_representatives:
            raise ValueError("unique records must match cluster representatives")
        if exact_links != self.exact_duplicate_count:
            raise ValueError("exact duplicate count must match cluster links")
        if near_links != self.near_duplicate_count:
            raise ValueError("near duplicate count must match cluster links")
        template_hashes = {
            item.template_sha256 for item in self.fingerprints
        }
        if len(template_hashes) != self.template_group_count:
            raise ValueError("template group count must match fingerprints")
        repeated_templates: dict[str, set[tuple[str, str]]] = defaultdict(set)
        for fingerprint in self.fingerprints:
            repeated_templates[fingerprint.template_sha256].add(
                _reference_key(fingerprint.record)
            )
        expected_template_groups = {
            template_hash: members
            for template_hash, members in repeated_templates.items()
            if len(members) >= 2
        }
        actual_template_groups = {
            group.template_sha256: {
                _reference_key(member) for member in group.members
            }
            for group in self.template_groups
        }
        if len(actual_template_groups) != len(self.template_groups):
            raise ValueError("template group hashes must be unique")
        if actual_template_groups != expected_template_groups:
            raise ValueError("template groups must match fingerprint assignments")
        return self


@dataclass(frozen=True)
class _PreparedRecord:
    record: ImportedDatasetRecord
    reference: DatasetRecordReference
    fingerprint: DeduplicationFingerprint
    tokens: frozenset[str]
    signature: tuple[int, ...]


@dataclass(frozen=True)
class _Edge:
    left: int
    right: int
    method: DeduplicationMethod
    similarity: float


class _DisjointSet:
    def __init__(self, size: int) -> None:
        self._parents = list(range(size))
        self._ranks = [0] * size

    def find(self, item: int) -> int:
        while self._parents[item] != item:
            self._parents[item] = self._parents[self._parents[item]]
            item = self._parents[item]
        return item

    def union(self, left: int, right: int) -> bool:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root == right_root:
            return False
        if self._ranks[left_root] < self._ranks[right_root]:
            left_root, right_root = right_root, left_root
        self._parents[right_root] = left_root
        if self._ranks[left_root] == self._ranks[right_root]:
            self._ranks[left_root] += 1
        return True


def normalize_configuration_text(text: str) -> str:
    """Normalize formatting and comments without abstracting configured values."""

    normalized_unicode = unicodedata.normalize("NFKC", text)
    without_blocks = _COMMENT_BLOCK.sub(_preserve_comment_newlines, normalized_unicode)
    lines: list[str] = []
    for raw_line in without_blocks.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith(("!", "#", "//")):
            continue
        line = _SPACE.sub(" ", stripped).casefold()
        line = re.sub(r"\s+([;,{}\[\]])", r"\1", line)
        line = re.sub(r"([,{}\[\]])\s+", r"\1", line)
        lines.append(line)
    return "\n".join(lines)


def template_configuration_text(text: str) -> str:
    """Abstract topology-specific literals for deterministic template grouping."""

    normalized = normalize_configuration_text(text)
    templated = _PSEUDONYM.sub(lambda match: f"<{match.group('kind')}>", normalized)
    templated = _IPV6.sub(_replace_template_ip, templated)
    templated = _IPV4.sub(_replace_template_ip, templated)
    templated = _QUOTED_VALUE.sub(_replace_quoted_template_value, templated)
    templated = _LONG_HEX.sub("<hex>", templated)
    return _NUMBER.sub("<number>", templated)


def deduplicate_dataset(
    records: tuple[ImportedDatasetRecord, ...] | list[ImportedDatasetRecord],
    *,
    policy: DeduplicationPolicy | None = None,
) -> DatasetDeduplicationResult:
    """Collapse duplicate families and retain deterministic audit evidence."""

    if not records:
        raise ValueError("at least one imported dataset record is required")
    effective_policy = policy or DeduplicationPolicy()
    _validate_unique_references(records)
    prepared = tuple(
        _prepare_record(record, effective_policy) for record in records
    )
    disjoint_set = _DisjointSet(len(prepared))
    accepted_edges: list[_Edge] = []

    _connect_exact_groups(
        prepared,
        disjoint_set,
        accepted_edges,
        attribute="raw_sha256",
        method=DeduplicationMethod.RAW_SHA256,
    )
    _connect_exact_groups(
        prepared,
        disjoint_set,
        accepted_edges,
        attribute="sanitized_sha256",
        method=DeduplicationMethod.SANITIZED_SHA256,
    )
    _connect_exact_groups(
        prepared,
        disjoint_set,
        accepted_edges,
        attribute="normalized_sha256",
        method=DeduplicationMethod.NORMALIZED_SHA256,
    )

    candidates = _near_duplicate_candidates(prepared, effective_policy)
    scored_candidates: list[tuple[float, tuple[str, str], tuple[str, str], int, int]] = []
    for left, right in candidates:
        if disjoint_set.find(left) == disjoint_set.find(right):
            continue
        left_tokens = prepared[left].tokens
        right_tokens = prepared[right].tokens
        too_few_tokens = (
            min(len(left_tokens), len(right_tokens))
            < effective_policy.minimum_tokens_for_near_match
        )
        if too_few_tokens:
            continue
        similarity = _jaccard_similarity(left_tokens, right_tokens)
        if similarity >= effective_policy.near_duplicate_threshold:
            scored_candidates.append(
                (
                    similarity,
                    _reference_key(prepared[left].reference),
                    _reference_key(prepared[right].reference),
                    left,
                    right,
                )
            )
    scored_candidates.sort(key=lambda item: (-item[0], item[1], item[2]))
    for similarity, _, _, left, right in scored_candidates:
        if disjoint_set.union(left, right):
            accepted_edges.append(
                _Edge(
                    left=left,
                    right=right,
                    method=DeduplicationMethod.MINHASH_TOKEN_SIMILARITY,
                    similarity=similarity,
                )
            )

    return _build_result(
        prepared,
        disjoint_set,
        accepted_edges,
        effective_policy,
    )


def _prepare_record(
    record: ImportedDatasetRecord,
    policy: DeduplicationPolicy,
) -> _PreparedRecord:
    reference = DatasetRecordReference(
        source_id=record.source_id,
        record_id=record.record_id,
    )
    normalized = normalize_configuration_text(record.sanitized_text)
    template = template_configuration_text(record.sanitized_text)
    tokens = _configuration_tokens(normalized)
    fingerprint = DeduplicationFingerprint(
        record=reference,
        raw_sha256=record.raw_sha256,
        sanitized_sha256=record.sanitized_sha256,
        normalized_sha256=_sha256_text(normalized),
        template_sha256=_sha256_text(template),
        token_count=len(tokens),
    )
    return _PreparedRecord(
        record=record,
        reference=reference,
        fingerprint=fingerprint,
        tokens=tokens,
        signature=_minhash_signature(tokens, policy.minhash_permutations),
    )


def _validate_unique_references(
    records: tuple[ImportedDatasetRecord, ...] | list[ImportedDatasetRecord],
) -> None:
    references = [(record.source_id, record.record_id) for record in records]
    if len(references) != len(set(references)):
        raise ValueError("source_id and record_id pairs must be unique")


def _connect_exact_groups(
    prepared: tuple[_PreparedRecord, ...],
    disjoint_set: _DisjointSet,
    accepted_edges: list[_Edge],
    *,
    attribute: str,
    method: DeduplicationMethod,
) -> None:
    buckets: dict[str, list[int]] = defaultdict(list)
    for index, item in enumerate(prepared):
        value = getattr(item.fingerprint, attribute)
        if not isinstance(value, str):
            raise TypeError("fingerprint hash attribute must be a string")
        buckets[value].append(index)
    for value in sorted(buckets):
        members = sorted(buckets[value], key=lambda index: _prepared_key(prepared[index]))
        anchor = members[0]
        for member in members[1:]:
            if disjoint_set.union(anchor, member):
                accepted_edges.append(
                    _Edge(
                        left=anchor,
                        right=member,
                        method=method,
                        similarity=1.0,
                    )
                )


def _near_duplicate_candidates(
    prepared: tuple[_PreparedRecord, ...],
    policy: DeduplicationPolicy,
) -> set[tuple[int, int]]:
    buckets: dict[tuple[object, ...], list[int]] = defaultdict(list)
    band_size = policy.minhash_permutations // policy.lsh_bands
    for index, item in enumerate(prepared):
        for band in range(policy.lsh_bands):
            start = band * band_size
            band_values = item.signature[start : start + band_size]
            buckets[("lsh", band, *band_values)].append(index)
        buckets[("template", item.fingerprint.template_sha256)].append(index)
        buckets[("device", item.record.network_id, item.record.device_id)].append(index)

    candidates: set[tuple[int, int]] = set()
    for bucket_key in sorted(buckets, key=repr):
        members = sorted(
            buckets[bucket_key],
            key=lambda index: (
                len(prepared[index].tokens),
                _prepared_key(prepared[index]),
            ),
        )
        for position, current in enumerate(members):
            window_start = max(0, position - policy.max_candidates_per_bucket)
            for candidate in members[window_start:position]:
                candidates.add((min(candidate, current), max(candidate, current)))
    return candidates


def _build_result(
    prepared: tuple[_PreparedRecord, ...],
    disjoint_set: _DisjointSet,
    accepted_edges: list[_Edge],
    policy: DeduplicationPolicy,
) -> DatasetDeduplicationResult:
    groups: dict[int, list[int]] = defaultdict(list)
    for index in range(len(prepared)):
        groups[disjoint_set.find(index)].append(index)

    cluster_links: dict[int, list[_Edge]] = defaultdict(list)
    for edge in accepted_edges:
        cluster_links[disjoint_set.find(edge.left)].append(edge)

    representatives: list[ImportedDatasetRecord] = []
    duplicate_clusters: list[DuplicateCluster] = []
    for root, raw_members in groups.items():
        members = sorted(raw_members, key=lambda index: _prepared_key(prepared[index]))
        representative_index = min(
            members,
            key=lambda index: (
                prepared[index].record.captured_at,
                *_prepared_key(prepared[index]),
                prepared[index].record.sanitized_sha256,
            ),
        )
        representatives.append(prepared[representative_index].record)
        if len(members) < 2:
            continue
        references = tuple(prepared[index].reference for index in members)
        links = tuple(
            sorted(
                (_render_link(edge, prepared) for edge in cluster_links[root]),
                key=lambda link: (
                    _method_priority(link.method),
                    _reference_key(link.left),
                    _reference_key(link.right),
                ),
            )
        )
        duplicate_clusters.append(
            DuplicateCluster(
                cluster_id=_cluster_id(references),
                representative=prepared[representative_index].reference,
                members=references,
                links=links,
            )
        )

    representatives.sort(key=lambda record: (record.source_id, record.record_id))
    duplicate_clusters.sort(key=lambda cluster: cluster.cluster_id)
    template_buckets: dict[str, list[DatasetRecordReference]] = defaultdict(list)
    for item in prepared:
        template_buckets[item.fingerprint.template_sha256].append(item.reference)
    template_groups = tuple(
        TemplateGroup(
            template_sha256=template_hash,
            members=tuple(sorted(members, key=_reference_key)),
        )
        for template_hash, members in sorted(template_buckets.items())
        if len(members) >= 2
    )
    exact_methods = {
        DeduplicationMethod.RAW_SHA256,
        DeduplicationMethod.SANITIZED_SHA256,
        DeduplicationMethod.NORMALIZED_SHA256,
    }
    exact_count = sum(edge.method in exact_methods for edge in accepted_edges)
    near_count = len(accepted_edges) - exact_count

    return DatasetDeduplicationResult(
        policy=policy,
        input_count=len(prepared),
        unique_count=len(representatives),
        exact_duplicate_count=exact_count,
        near_duplicate_count=near_count,
        template_group_count=len(template_buckets),
        unique_records=tuple(representatives),
        fingerprints=tuple(
            item.fingerprint for item in sorted(prepared, key=_prepared_key)
        ),
        duplicate_clusters=tuple(duplicate_clusters),
        template_groups=template_groups,
    )


def _render_link(
    edge: _Edge,
    prepared: tuple[_PreparedRecord, ...],
) -> DuplicateLink:
    left = prepared[edge.left].reference
    right = prepared[edge.right].reference
    if _reference_key(right) < _reference_key(left):
        left, right = right, left
    return DuplicateLink(
        left=left,
        right=right,
        method=edge.method,
        similarity=round(edge.similarity, 6),
    )


def _configuration_tokens(normalized: str) -> frozenset[str]:
    lines = normalized.splitlines()
    tokens = {f"line:{line}" for line in lines}
    tokens.update(
        f"pair:{left}\0{right}" for left, right in pairwise(lines)
    )
    return frozenset(tokens or {"line:<empty>"})


def _minhash_signature(tokens: frozenset[str], permutations: int) -> tuple[int, ...]:
    values = tuple(
        int.from_bytes(hashlib.sha256(token.encode("utf-8")).digest()[:8], "big")
        % _MINHASH_PRIME
        for token in tokens
    )
    return tuple(
        min((coefficient * value + offset) % _MINHASH_PRIME for value in values)
        for coefficient, offset in _minhash_coefficients(permutations)
    )


@lru_cache(maxsize=8)
def _minhash_coefficients(permutations: int) -> tuple[tuple[int, int], ...]:
    coefficients: list[tuple[int, int]] = []
    for index in range(permutations):
        digest = hashlib.sha256(
            f"{DEDUPLICATION_VERSION}:{index}".encode("ascii")
        ).digest()
        coefficient = int.from_bytes(digest[:8], "big") % (_MINHASH_PRIME - 1) + 1
        offset = int.from_bytes(digest[8:16], "big") % _MINHASH_PRIME
        coefficients.append((coefficient, offset))
    return tuple(coefficients)


def _jaccard_similarity(left: frozenset[str], right: frozenset[str]) -> float:
    return len(left & right) / len(left | right)


def _replace_template_ip(match: re.Match[str]) -> str:
    raw_value = match.group("value")
    address_text, separator, prefix = raw_value.partition("/")
    try:
        address = ip_address(address_text)
    except ValueError:
        return raw_value
    family = "ipv-four" if isinstance(address, IPv4Address) else "ipv-six"
    return f"<{family}>{separator}{prefix}" if separator else f"<{family}>"


def _replace_quoted_template_value(match: re.Match[str]) -> str:
    value = match.group(0)
    inner = value[1:-1]
    if re.fullmatch(r"<[a-z0-9_-]+>", inner):
        return value
    return f"{value[0]}<string>{value[-1]}"


def _preserve_comment_newlines(match: re.Match[str]) -> str:
    return "".join("\n" if character == "\n" else " " for character in match.group(0))


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _reference_key(reference: DatasetRecordReference) -> tuple[str, str]:
    return reference.source_id, reference.record_id


def _prepared_key(item: _PreparedRecord) -> tuple[str, str]:
    return _reference_key(item.reference)


def _cluster_id(references: tuple[DatasetRecordReference, ...]) -> str:
    payload = "\0".join(
        f"{reference.source_id}\0{reference.record_id}"
        for reference in sorted(references, key=_reference_key)
    )
    return f"duplicate-{_sha256_text(payload)[:16]}"


def _method_priority(method: DeduplicationMethod) -> int:
    return {
        DeduplicationMethod.RAW_SHA256: 0,
        DeduplicationMethod.SANITIZED_SHA256: 1,
        DeduplicationMethod.NORMALIZED_SHA256: 2,
        DeduplicationMethod.MINHASH_TOKEN_SIMILARITY: 3,
    }[method]
