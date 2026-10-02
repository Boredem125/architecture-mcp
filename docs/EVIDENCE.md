# Evidence export

`sandbox export-evidence` writes one pack that answers, for a sandboxed folder: who approved
or denied what, under which policy files, which governance clauses fired (with their
framework references), and whether the record is intact. `sandbox verify-evidence` checks a
pack offline, using only the pack.

The pack is designed against what examiners ask for under the frameworks in
[COMPLIANCE_MAP.md](COMPLIANCE_MAP.md). It is not a certification or an attestation of
compliance with any of them.

## Usage

```
sandbox export-evidence [PATH] --out pack/            # a new or empty directory
sandbox export-evidence [PATH] --out pack.zip         # or a new zip file
sandbox export-evidence . --out q3.zip --since 2026-07-01 --until 2026-09-30T23:59:59Z

sandbox verify-evidence pack.zip --exporter-key <hex printed at export>
```

`--since` / `--until` take ISO 8601 dates or date-times (UTC when no zone is given) and
select decisions by their `decided_at`. Audit chains are always exported whole, because a
chain can only be verified from its first record.

`verify-evidence` exits 0 only if every check passes, and otherwise lists each failure with
the file it concerns. A failure that was already present when the pack was exported is
marked "already failing at export" or "already broken at export".

## What the pack contains

| Path | Content |
|---|---|
| `manifest.json` | sha256 of every other file, export time, source folder, window; signed with the exporter's Ed25519 key |
| `summary.json` | decisions by outcome, by decision and by reviewer; dual-control approvals by reviewer; open requests; audit chain results; governance hits by clause and by framework reference; policy files with sha256; every failed check; notes and limits |
| `decisions/<request_id>.json` | each signed done-record from `.sandbox/escalations/done/`, byte for byte |
| `decisions/index.json` | one row per decision (who, what, when, outcome, approvers, clauses) with its checks |
| `audit/<session>/records.jsonl` | each audit chain, byte for byte |
| `audit/chains.json` | the verification result and head hash of each chain at export |
| `keys/reviewers.json` | the folder's public key for each reviewer that appears in a decision (never the seeds) |
| `policy/policy.json` | `.sandbox/policy.json` as it is at export |
| `policy/governance_policy.json` | the governance policy the folder points at, as it is at export |
| `alerts/alerts.jsonl` | the folder's alerts (denials, critical escalations, injection hits, rate limits, policy drift), if any |
| `aiuc1/controls.json` | an AIUC-1 index: for each control the gateway produced evidence for, the self-assessed status from [AIUC-1_MAP.md](AIUC-1_MAP.md), how many audit records, decisions and alerts support it, up to five pointers to them (`audit/<session>/records.jsonl#L12`), and the policy settings behind it |

The AIUC-1 index is a self-assessment, not an audit. A test fails if it ever claims a higher status than the published mapping. It is covered by the manifest like every other file, so editing it after export fails `verify-evidence`.

## Checks

Per decision record, at export and again at verify:

- `signature`: the Ed25519 signature verifies over the record's signed fields.
- `signed_fields`: the signature covers at least `request_id`, `reviewer_id`, `decision`,
  `command`.
- `signer_is_folder_key`: the signing key is the folder's key for the record's
  `reviewer_id`. A valid signature from any other key (a forged record) fails here.
- `dual_control` (approved records with `requires_dual`): at least two approvals that each
  verify, approve this exact request (`request_id`, `command`, `fingerprint`), are signed by
  the folder's key for that approver, and come from distinct reviewer ids and keys.
- `request_id_matches_file`: the record was not copied or renamed.

Per audit chain: each record links to the one before (`previous_hash`, `chain_length`) and
its content still matches its `record_hash`. `sandbox verify` runs the same check on every
session in the folder (it used to check only the "default" session, and only the links).

Per pack (verify only): the manifest signature, every file's sha256, no listed file missing,
no unlisted file added, and optionally that the exporter key is the one you expected.

## Limits

- **Keys, not people.** Reviewer and exporter keys live in the control plane
  (`.sandbox/state/keys/`, see [TCB.md](TCB.md)). The pack proves integrity relative to
  those keys. It does not prove which human held a key, or that two reviewer ids were two
  people.
- **Pin the exporter key.** The manifest is signed with a key from the same control plane,
  and the public key is inside the pack. Anyone who can rewrite the whole pack can re-sign
  it with a new key. Record the exporter key printed at export somewhere the pack's holder
  cannot change, and pass it to `--exporter-key`.
- **Policy now, not policy then.** Policy files are copied as they are at export. Since policy
  versioning, each decision carries a signed `policy_version` (folder and governance version
  ids), so a reader can see which version was in force; the pack doesn't yet include those
  versions from `.sandbox/policy_history/` itself.
- **No key history.** Reviewer keys are the folder's current keys. If a reviewer's seed was
  replaced after a decision, that decision fails `signer_is_folder_key`.
- **Governance hits on shell escalations** are carried into the done-record since
  `3441551` and counted; records decided before that don't have them. Governance denials are
  in the audit chain and are counted.
- **Chain tail.** A chain on disk cannot show that its last records were removed or rewritten
  together with their hashes. The pack fixes each chain's head hash and length at export, so
  later changes are visible against the pack, not before it.
- **Audit records mostly lack timestamps**, which is why the time window applies to decisions
  only.
