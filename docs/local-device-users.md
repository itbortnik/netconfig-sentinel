# Local device-account parser slice

Fresh Cisco IOS/IOS-XE and JunOS parses use canonical schema `1.1` with
`local_users`. Saved `1.0` snapshots remain readable and serialize without this
new field. They are not reparsed, upgraded or assigned invented user facts.
No database migration is needed for the encrypted versioned payload.

Each account contains its case-preserved name, explicitly configured Cisco
privilege (0–15), JunOS login class/UID (100–64,000), authentication metadata and
source anchors. Absent values remain null/empty, not inferred defaults. This is
device configuration, not application roles, effective access or verified login.

The supported Cisco slice is `username NAME [privilege N]` with an optional
`password`, `secret` or `nopassword`. Password types 0/7 and secret types
0/4/5/8/9 are recognized as declared metadata; implicit types stay `unspecified`.
Credential values must be single tokens; at least one explicit privilege or
authentication property is required. Multiple valid account statements merge
explicit facts; the last statement for a property supplies its value and anchor.
`no username NAME` removes that account from the final normalized inventory.
No algorithm strength, hash validity or precedence between password/secret is
inferred. `algorithm-type`, views, autocommands and other options remain unsupported.
The syntax boundary follows the [Cisco command reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/s1/sec-s1-cr-book/sec-cr-t2.html).

JunOS supports `set system login user NAME` statements and the corresponding
multiline hierarchy for `class`, `uid`, `authentication encrypted-password` and
quoted SSH RSA/ECDSA/ED25519 key values. Login class definitions, inherited groups,
root authentication, key source restrictions, full names, key files, interactive
password commands and other properties remain unsupported. The parser does not
verify credential bytes, SSH key validity, UID uniqueness across the actual
device, class permissions or completeness of an account. See the [Juniper user statement](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/user-edit-system-login.html).

Accepted statements produce only credential kind/declared encoding and line/hash
provenance: never the password, password hash or public-key value. Unknown or
malformed options are rejected atomically for that statement and retained in
`unparsed_fragments`, reducing confidence. Other valid statements about the same
account remain available. This is not a sanitization boundary: unknown raw text,
names, source hashes and provenance can be confidential. Dataset sanitization
remains a separate required step.

The API persists these facts through its existing encrypted snapshot workflow.
The UI validates schema/metadata before showing account details. Normalized
snapshot differences include a `local_users` object per account; rights or
authentication-kind/encoding changes are visible with separate side anchors.
Account and authentication enumeration order is insignificant. Credential-value
changes alone are excluded from object differences, although source SHA-256
changes. An empty diff proves neither credential equality nor equivalent access.
Existing baseline/features do not automatically learn account permissions.
