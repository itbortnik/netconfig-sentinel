# Future topology detector contract

The Python library provides `TopologyInput`, `topology_fingerprint` and the
`TopologyDetector` protocol. This is interface preparation, not a shipped GNN,
network discovery, an HTTP workflow or a complete-network assessment.

Inputs describe only an explicitly selected subset of devices and snapshots.
Each device binds vendor/platform, source SHA-256 and parser coverage. Vertices
represent devices, interfaces, VRFs or VLANs; non-device vertices need explicit
entity keys. Physical links join interface vertices and are undirected. Logical
links may be directed. Their declared basis is not independently verified.

The contract rejects duplicate identities/entities/connections, missing device
vertices, foreign ownership, dangling edges, self-links, inconsistent platforms,
unknown fields and non-finite numbers. All feature vectors share the ordered
feature schema. Present embeddings must share checkpoint and tokenizer hashes
and dimension; missing embeddings remain allowed and are not invented.

Limits are 512 devices, 2,048 vertices, 8,192 edges, 256 numeric features per
vertex, 1,024 embedding values per vertex, 262,144 numeric values in total and
8 MiB serialized input. Source anchors retain sorted one-based lines, text hashes
and parser confidence without raw configuration text. Input models are frozen
and tuple-based. Entry points revalidate even previously constructed models.

The fingerprint is SHA-256 of canonical JSON. Entity enumeration and the endpoint
order of undirected links do not change it. Identities, source hashes, anchors,
feature names/order and vector values do. It is an integrity binding, not proof
that an inventory, source file or checkpoint is trustworthy.

`analyze_topology(inputs)` returns `unavailable`, not an empty successful network
check. Only an explicitly supplied in-process adapter executes. Its model version
and SHA-256 are required; findings must be unique, cite evidence, belong to selected
devices and identify the same `topology_gnn` model version. Reports are bounded to
500 findings and 512 KiB. Evidence membership in the real source and semantic
truth are not independently attested by this boundary.

Executed adapter reports remain `partial`, with formal verification `not_run`
and risk fusion disabled. Unsupported constructs, uncertain links and missing
vectors do not become verified because they appear in a graph. No production
checkpoint, graph training, accuracy, calibration or real-network coverage is
claimed. Tests use a synthetic adapter solely to check the contract.
