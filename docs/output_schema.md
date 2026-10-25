# `output.csv` schema (Phase 0)

Source of truth: `problem_statement.md` sections **Required Output**, **Allowed Operations**, and **Rules**; checked against the header and rows in `dataset/output.csv` and `dataset/sample_output.csv`.

## CSV contract

| Position | Column | Required value |
|---|---|---|
| 1 | `case_id` | The request's case identifier. |
| 2 | `deletion_status` | One of `COMPLETE`, `INCOMPLETE`, `NOT_APPLICABLE`. |
| 3 | `steps_json` | A JSON array serialized as one CSV field. |

The header is exactly:

```csv
case_id,deletion_status,steps_json
```

Use comma delimiters. Ordinary fields are unquoted when they contain no CSV-special characters. Quote `steps_json` when required by CSV rules; when a quoted CSV field contains JSON double quotes, escape them as doubled double quotes (`""`) as in `dataset/sample_output.csv`. The JSON itself is an array, not a JSON-encoded string. `NOT_APPLICABLE` uses the empty array `[]` (the sample CSV representation is `[]`).

The challenge requires one row per request, sorted by `case_id`. The requested final root-level file has 518 data rows plus its header. `dataset/output.csv` is a header-only template.

## Step object

Every array item has exactly these seven fields:

```json
{
  "step_no": 1,
  "phase": "FINDING",
  "system_id": "account_service",
  "resource_id": "account_005",
  "operation": "REPORT_REMAINING_RECORD",
  "state": "PRESENT",
  "evidence_id": "evidence_01"
}
```

- `step_no`: integer, starting at `1` and increasing consecutively in array order.
- `phase`: one of `FINDING`, `REMEDIATION`, `VERIFICATION`.
- `system_id`, `resource_id`: identifiers for the system/process and affected resource.
- `operation`, `state`: one of the allowed pairs below; do not introduce other values.
- `evidence_id`: a participant-visible `file_id`, `activity_id`, or `audit_id` where evidence is required. Use the empty string for proposed remediation and future verification steps in an `INCOMPLETE` result.

JSON object-key order and whitespace are immaterial to the grader. Array order is significant. Order phases as findings, remediation, verification; order within a phase by the operation order below, then `system_id` and `resource_id` ascending. The problem statement additionally says that operation ordering should follow its table.

## Allowed operation/state pairs

| Phase | Operation | State | Meaning |
|---|---|---|---|
| `FINDING` | `REPORT_REMAINING_RECORD` | `PRESENT` | A record subject to deletion still exists. |
| `FINDING` | `REPORT_EXPOSED_PII` | `PRESENT` | A record remains with identifiers that policy requires to be redacted or anonymized. |
| `FINDING` | `REPORT_ACTIVE_DATA_FLOW` | `ACTIVE` | An active process can copy or recreate the subject's data. |
| `FINDING` | `REPORT_RESTORE_RISK` | `ACTIVE` | A backup/restore path can bring deleted data back. |
| `REMEDIATION` | `DISABLE_DATA_FLOW` | `DISABLED` | Stop a copying or recreating process. |
| `REMEDIATION` | `BLOCK_RESTORE` | `BLOCKED` | Prevent the affected backup from restoring the subject's data. |
| `REMEDIATION` | `DELETE_RECORD` | `ABSENT` | Remove the whole record. |
| `REMEDIATION` | `REDACT_RECORD` | `REDACTED` | Keep the record but remove identifiers required to be removed. |
| `REMEDIATION` | `ANONYMIZE_RECORD` | `ANONYMIZED` | Keep the record after irreversibly unlinking it from the subject. |
| `VERIFICATION` | `VERIFY_RECORD_ABSENT` | `ABSENT` | Confirm a record is absent. |
| `VERIFICATION` | `VERIFY_RECORD_PRESENT` | `PRESENT` | Confirm a policy-required retained record still exists. |
| `VERIFICATION` | `VERIFY_RECORD_REDACTED` | `REDACTED` | Confirm required identifiers were removed. |
| `VERIFICATION` | `VERIFY_RECORD_ANONYMIZED` | `ANONYMIZED` | Confirm the record is no longer linkable to the subject. |
| `VERIFICATION` | `VERIFY_DATA_FLOW_DISABLED` | `DISABLED` | Confirm a relevant data flow is inactive. |
| `VERIFICATION` | `VERIFY_RESTORE_BLOCKED` | `BLOCKED` | Confirm the affected data cannot be restored. |

## Result-dependent serialization and evidence

- `NOT_APPLICABLE`: `deletion_status` is `NOT_APPLICABLE` and `steps_json` is `[]`. No deletion or deletion verification is authorized.
- `COMPLETE`: only evidence-backed `VERIFICATION` steps proving the state at `audit_at`; each cites a valid evidence ID.
- `INCOMPLETE`: findings, the complete remediation plan, then post-remediation verification checks. Findings cite evidence. Remediation and future verification `evidence_id` values are empty strings (`""`).
- Do not use evidence captured after the request's `audit_at`.
- `reported_status` and activity `reported_result` are claims, not proof of the resource's state.
