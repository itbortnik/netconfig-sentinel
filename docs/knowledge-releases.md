# Released explanation sources

Explanation retrieval reads immutable, allowlisted internal document releases,
not mutable current Markdown or arbitrary source files. Existing contexts keep
their wire versions and fields; `knowledge_version` now accepts all three supported
releases and is explicitly selected from the recorded detector version.

| Recorded detector version | Knowledge release | Sections |
| --- | --- | --- |
| `policy-rules-0.6.0` | `project-knowledge-0.1.0` | 31 |
| `policy-rules-0.7.0` | `project-knowledge-0.2.0` | 41 |
| `expected-config-0.1.0`, `peer-baseline-0.1.0`, `isolation-forest-0.1.0` | `project-knowledge-0.1.0` | 31 |
| `expected-config-0.2.0`, `peer-baseline-0.2.0` | `project-knowledge-0.3.0` | 43 |

All three releases contain the same eight explicitly reviewed **project document
IDs**, with the appropriate historic bytes. They are not vendor manuals,
organization-approved policies, a proof of reachability or a semantic index.
Each document's source hash and each normalized section's content hash remain
in returned `DocumentChunk` values. Catalog identity includes the selected
release and hashes of all eight documents. Historical citations retain the
original document ID/heading; their text is the returned archived chunk, not a
promise that a current public Markdown link has identical contents.

## Archive provenance and validation

The 0.1.0 files were preserved byte-for-byte from project commit
`cab3cd06255315d20e1da23d9593fd642748b67b`; 0.2.0 from
`c7409db2d68a86d9ef71349fa94f36e60717639b`; 0.3.0 from
`20efc00827f1b0e0bbbd27ac55fd3a75f5167fc1`. The first sixteen files remain unchanged;
the new eight are preserved from that published source commit. Document files are checked
against their original Git blob identities. Their manifests record the source
commit, release, internal-project authority and every document's SHA-256.
Source commits identify historical content, not external licensing or human
approval attestations.

The package stores files under `app/knowledge/versions/<release>/`; the checkout
uses the matching `backend/app/knowledge/versions/` tree. The build hook includes
only the three known releases, their eight document IDs and manifests. Neither
current `docs/` files, workspace files nor runtime-uploaded data become sources.
No network fetch, corpus expansion or new vendor-document license is implied.

Release manifest hashes are anchored in the application registry. Loading checks
that anchor before parsing the manifest, then verifies exact directory/file
inventory, document byte hashes, bounded reads and section syntax/uniqueness.
It rejects symlinks/junctions at archive/file-parent boundaries, missing or extra
files, changed source bytes and a rewritten document **even when its manifest
hash is recomputed**. It never falls back to a mutable current document or another
release. Unknown detector versions or unavailable archives produce a sanitized
503; deterministic explanation/risk stored in the analysis remain intact.

These checks protect against missing/corrupt local resources and accidental
cross-version substitution. Hashes are not publisher signatures. An actor able
to modify application code and its embedded registry can change this trust
boundary; use access-controlled, verified deployment artifacts.

## API, UI and upgrades

`POST /api/v1/findings/{finding_id}/explain` selects the release from the exact
saved analysis/finding pair. It does not rerun the finding under the latest
policy or edit its explanation. The response contains the selected
`knowledge_version`, its catalog hash and exact archived chunks. Backend context
validation and both frontend provider schemas reject incompatible detector/
knowledge versions. The UI displays the source version and keeps historical
and model prose as plain text with the same existing review warnings.

The archive is read-only at runtime. A new release requires a reviewed bounded
snapshot, new manifest/code anchor, explicit detector-to-release mapping,
packaging and regression tests. Never edit a released document in place or
change an old detector's mapping to a new release. Existing files must remain
available to explain prior supported analyses. No database migration is needed:
the detector version already provides the lookup key.

Tests cover old/current release selection, modified/extra/missing files,
manifest-rehash attempts, link gates, forbidden overlays, backend/frontend
version binding and a historical encrypted analysis across server restart.
Source retrieval remains exact-reference retrieval. Semantic ranking, external
approved manuals and real explanation-quality evaluation remain separate work.
