# Phase 0 — Recon findings

## Scope and instructions read

Inspected the root `README.md`, `problem_statement.md`, `AGENTS.md`, `CLAUDE.md`, `agent_trace_instructions.md`, and root `log.txt`. `CLAUDE.md` delegates to `AGENTS.md`. The challenge's agent instructions require append-only session and per-turn entries in `log.txt`, located beside the top-level `AGENTS.md`.

The checkout is the nested folder `hackerrank-orchestrate-october26-main/`. The requested sibling `data/` directory does not exist; all supplied tables and evidence are under `dataset/`. No `docs/` directory existed before this recon.

`log.txt` exists at the required repository-root path and contains earlier structured `SESSION START` and per-turn entries (including harness and model fields), so the transcript log has been used previously. The current runtime did not expose its exact model identifier through session metadata or usage records. Since `AGENTS.md` explicitly forbids guessing or logging a placeholder model, this Phase 0 turn was **not** appended; the file is not current through this turn. Resolve this before implementation/logging continues by making the exact runtime model identifier available. Do not overwrite existing log content.

The root README identifies a required `code.zip`, root `output.csv`, and root `log.txt` submission. The problem statement asks for 518 request rows. The October end time is not configured in the repo.

## Exact output contract

The exact schema, quoting rules, allowed enums and operation/state pairs, step shape, and result-specific serialization are recorded in [`output_schema.md`](./output_schema.md). In brief, the output header is `case_id,deletion_status,steps_json`; statuses are `COMPLETE`, `INCOMPLETE`, `NOT_APPLICABLE`; and `steps_json` is a JSON array inside a CSV field. Step objects have exactly seven keys (`step_no`, `phase`, `system_id`, `resource_id`, `operation`, `state`, `evidence_id`). The dataset output template contains only the header. The sample output uses RFC-style CSV quoting for its JSON field (embedded JSON double quotes doubled in the CSV representation).

## CSV inventory

Row counts exclude headers. “Sample rows” below records the first five row identifiers and distinguishing values; this is intentionally not a copy of customer-identifying fields. The full field order is shown in the columns column.

| CSV | Data rows | Columns, in order | Five sample rows |
|---|---:|---|---|
| `dataset/deletion_requests.csv` | 518 | `case_id,email,requested_at,reported_status,reported_at,audit_at,request_text` | `case_33` (COMPLETE), `case_34` (COMPLETE), `case_35` (NOT_STARTED), `case_36` (COMPLETE), `case_37` (COMPLETE) |
| `dataset/deletion_rules.csv` | 15 | `rule_id,data_category,condition,required_action` | `rule_01` USER_PROFILE/DELETE; `rule_02` SECONDARY_IDENTIFIER/DELETE; `rule_03` SEARCH_INDEX_ENTRY/DELETE; `rule_04` CACHE_ENTRY/DELETE; `rule_05` SUPPORT_MESSAGE/REDACT |
| `dataset/evidence_files.csv` | 94 | `file_id,file_path,origin,captured_at` | `evidence_01`–`evidence_05`; paths start with service-event log, snapshot bundle, account handover, account-admin screenshot, and read-replica SQL capture, respectively |
| `dataset/output.csv` | 0 | `case_id,deletion_status,steps_json` | Header-only blank template; no data rows |
| `dataset/sample_deletion_requests.csv` | 32 | `case_id,email,requested_at,reported_status,reported_at,audit_at,request_text` | `case_01`–`case_05`; sample contains multilingual requests and different workflow claims |
| `dataset/sample_output.csv` | 32 | `case_id,deletion_status,steps_json` | `case_01` COMPLETE; `case_02` COMPLETE; `case_03` COMPLETE; `case_04` COMPLETE; `case_05` INCOMPLETE |
| `dataset/system_activity.csv` | 4,011 | `activity_id,event_time,event_type,source_system,target_system,resource_id,reported_result,details` | `activity_01`–`activity_05`: index, index, index, update, update events; results include SUCCESS and FAILED |
| `dataset/user_audit_log.csv` | 306 | `audit_id,user_id,event_time,field_name,old_value,new_value` | `audit_01`–`audit_05`: phone-field history events |
| `dataset/user_identities.csv` | 850 | `user_id,name,email,phone,email_hash,updated_at` | `user_01`–`user_05`; current identity snapshot fields include direct identifiers and an email hash |

Counts were checked against the files. `deletion_requests.csv` has 518 records (519 physical CSV lines including its header), first ID `case_33`, last ID `case_550`. The separate public/labeled sample has 32 requests and 32 matching outputs, from `case_01` through `case_32`. Thus `deletion_requests.csv` is the unlabeled test set; the sample request/output pair is the validation/example set. `dataset/output.csv` is blank, not an expected-output file.

## Files under `dataset/`

The 103 files are 9 CSVs and 94 evidence files. The `data/` path at the checkout root is absent.

### CSVs

- `deletion_requests.csv`
- `deletion_rules.csv`
- `evidence_files.csv`
- `output.csv`
- `sample_deletion_requests.csv`
- `sample_output.csv`
- `system_activity.csv`
- `user_audit_log.csv`
- `user_identities.csv`

### Evidence: `dataset/evidence/databases/` (24 SQL files)

- `customer_accounts_failover_replica_20260902.sql`
- `customer_data_failover_replica_20260920.sql`
- `customer_data_inventory_20260213.sql`
- `customer_data_inventory_20260310.sql`
- `customer_data_inventory_20260404.sql`
- `customer_data_inventory_20260504.sql`
- `customer_data_inventory_20260524.sql`
- `customer_data_inventory_20260618.sql`
- `customer_data_inventory_20260703.sql`
- `customer_data_inventory_20260723.sql`
- `customer_data_inventory_20260817.sql`
- `customer_data_inventory_20260905.sql`
- `customer_data_inventory_20260916.sql`
- `customer_data_read_replica_20260613.sql`
- `customer_data_read_replica_20260708.sql`
- `customer_data_read_replica_20260802.sql`
- `customer_data_read_replica_20260827.sql`
- `customer_data_read_replica_20260921.sql`
- `customer_data_regional_replicas_20260330.sql`
- `customer_data_regional_replicas_20260424.sql`
- `customer_data_regional_replicas_20260519.sql`
- `customer_data_reporting_replica_20260208.sql`
- `customer_data_reporting_replica_20260305.sql`
- `customer_search_primary_20260910.sql`

### Evidence: `dataset/evidence/documents/` (4 PDF files)

- `account_history_report_20260718.pdf`
- `delivery_correction_attachment.pdf`
- `legal_retention_register_20260529.pdf`
- `security_retention_extract.pdf`

### Evidence: `dataset/evidence/images/` (11 PNG files)

- `account_admin_console_20260926.png`
- `analytics_profile_view_20260713.png`
- `backup_restore_console_20260429.png`
- `connector_management_console_20260807.png`
- `customer_export_console_20260618.png`
- `deleted_account_reference_20260310.png`
- `marketing_profile_console.png`
- `object_storage_browser_20260213.png`
- `search_index_inspector_20260901.png`
- `security_audit_explorer_20260905.png`
- `support_ticket_console_20260524.png`

### Evidence: `dataset/evidence/logs/` (26 log files)

- `application_trace_ap_northeast_20260730.log`
- `application_trace_eu_north_20260302.log`
- `cloud_runtime_export_af_south_20260930.log`
- `cloud_runtime_export_us_west_20260608.log`
- `notification_delivery_20260315.log`
- `operations_stream_eu_central_20260705.log`
- `operations_stream_me_central_20260203.log`
- `resource_lookup_trace_20260218_083911.log`
- `resource_lookup_trace_20260310_061801.log`
- `resource_lookup_trace_20260414_054007.log`
- `resource_lookup_trace_20260509_104353.log`
- `resource_lookup_trace_20260529_074313.log`
- `resource_lookup_trace_20260623_053726.log`
- `resource_lookup_trace_20260713_093359.log`
- `resource_lookup_trace_20260728_054417.log`
- `resource_lookup_trace_20260822_103910.log`
- `resource_lookup_trace_20260911_074253.log`
- `resource_lookup_trace_20260926_103856.log`
- `search_index_diagnostic_20260906.log`
- `service_events_ap_south_20260915.log`
- `service_events_sa_east_20260516.log`
- `structured_service_events_ca_central_20260419.log`
- `structured_service_events_eu_west_20260918.log`
- `support_replica.log`
- `syslog_archive_ap_southeast_20260325.log`
- `syslog_archive_us_east_20260824.log`

### Evidence: `dataset/evidence/records/` (29 files: 28 JSON, 1 TXT)

- `connector_configurations_20260812.json`
- `customer_account_handover_20261001.txt`
- `customer_analytics_report_20260907.json`
- `customer_data_snapshot_bundle_20260131.json`
- `customer_data_snapshot_bundle_20260223.json`
- `customer_data_snapshot_bundle_20260322.json`
- `customer_data_snapshot_bundle_20260416.json`
- `customer_data_snapshot_bundle_20260511.json`
- `customer_data_snapshot_bundle_20260605.json`
- `customer_data_snapshot_bundle_20260630.json`
- `customer_data_snapshot_bundle_20260725.json`
- `customer_data_snapshot_bundle_20260819.json`
- `customer_data_snapshot_bundle_20260913.json`
- `customer_data_snapshot_bundle_20260915.json`
- `customer_data_snapshot_bundle_20260917.json`
- `customer_export_jobs_20260914.json`
- `customer_export_manifest_20260409.json`
- `security_audit_ledger_20261001.json`
- `service_resource_export_20260129_114459.json`
- `service_resource_export_20260228_103637.json`
- `service_resource_export_20260320_072349.json`
- `service_resource_export_20260429_083222.json`
- `service_resource_export_20260514_114454.json`
- `service_resource_export_20260603_083457.json`
- `service_resource_export_20260628_062556.json`
- `service_resource_export_20260718_104335.json`
- `service_resource_export_20260807_074104.json`
- `service_resource_export_20260901_053316.json`
- `service_resource_export_20260915_114455.json`

## Media / attachment inspection and PII exposure

Visually inspected all 11 PNG screenshots and attempted to inspect all 4 PDFs under `evidence/images/` and `evidence/documents/`. The two PDFs named below rendered; the other two did not render in the local viewer. Screenshots are operational captures, not safe-to-ignore illustrations:

- `account_admin_console_20260926.png`: customer name, email, phone, stable user ID, support reference, order IDs, and address.
- `analytics_profile_view_20260713.png`: name, email, stable user ID, analytics record ID, behavioral/session and purchase information.
- `backup_restore_console_20260429.png`: account email, backup/archive IDs, object path, region, retention and restore details.
- `connector_management_console_20260807.png`: connector/process IDs, target, email selector, sync mode and delivery state.
- `customer_export_console_20260618.png`: export IDs, owner email addresses, export status, file names and included data categories.
- `deleted_account_reference_20260310.png`: stable user reference linked to order, support and finance record IDs; this is linkable/pseudonymous even without a displayed email.
- `marketing_profile_console.png`: name, email, phone, marketing profile ID, location/segment and consent preferences.
- `object_storage_browser_20260213.png`: support attachment and export object names, customer-data bucket/path, object metadata and version history; underlying objects may contain direct identifiers.
- `search_index_inspector_20260901.png`: display name, email, customer reference/user ID, search record IDs and index timestamps.
- `security_audit_explorer_20260905.png`: stable user ID, account/security events, event references, dates and fingerprint; sensitive linkable audit metadata.
- `support_ticket_console_20260524.png`: customer name/email, ticket/support ID, conversation contents, order/tracking details and agent identity.

`account_history_report_20260718.pdf` was readable in the local PDF viewer and contains customer name, stable user ID, email, statement/order IDs, payment card tail and order/shipping details. `security_retention_extract.pdf` was also inspected; it contains a stable subject user ID, audit event/reference, retention dates and a shortened fingerprint. The local browser viewer failed to render `delivery_correction_attachment.pdf` and `legal_retention_register_20260529.pdf` during this recon; their contents are therefore not verified here. Their names/context indicate potential delivery/contact or legal-hold identifiers. Treat both as potential PII until their contents are extracted and checked. The PDFs and screenshots are evidence that may require OCR/VLM and time-aware matching; filenames alone do not establish case membership.

## Complete `deletion_rules.csv` summary

The rule source has four columns (`rule_id,data_category,condition,required_action`) and 15 data rows. Rules are loaded from the CSV; do not replace them with hardcoded per-case answers.

| Rule | Category | Condition | Required treatment | Retained identifiers / note |
|---|---|---|---|---|
| `rule_01` | USER_PROFILE | Always | DELETE | No user identifiers retained in the record. |
| `rule_02` | SECONDARY_IDENTIFIER | Always | DELETE | Delete identifier record. |
| `rule_03` | SEARCH_INDEX_ENTRY | Always | DELETE | Delete search entry. |
| `rule_04` | CACHE_ENTRY | Always | DELETE | Delete cache entry. |
| `rule_05` | SUPPORT_MESSAGE | Conversation contains shared customer, agent, or order context that must be retained | REDACT | Retain necessary shared context; the CSV does not enumerate an identifier allowlist. |
| `rule_06` | SUPPORT_ATTACHMENT | Attachment belongs only to the deletion subject | DELETE | Delete the subject-only attachment. |
| `rule_07` | ANALYTICS_PROFILE | Record is still attributable to a user | ANONYMIZE | Keep only if irreversibly unlinkable; explicit field allowlist is not supplied. |
| `rule_08` | PRODUCT_TELEMETRY | Record is still attributable to a user | ANONYMIZE | Keep only if irreversibly unlinkable; explicit field allowlist is not supplied. |
| `rule_09` | USER_EXPORT | Always | DELETE | Delete the export. |
| `rule_10` | MARKETING_PROFILE | Always | DELETE | Delete the profile. |
| `rule_11` | EMAIL_DELIVERY_LOG | Log contains a user email address | REDACT | Keep the log but remove the user's email; no broader field allowlist is specified. |
| `rule_12` | SECURITY_AUDIT_LOG | Record is within the supplied retention period | RETAIN | Keep during the supplied retention period. The CSV does not specify which identifiers may remain. |
| `rule_13` | LEGAL_HOLD_RECORD | A supplied legal hold is active | RETAIN | Keep while the supplied hold is active. The CSV does not specify which identifiers may remain. |
| `rule_14` | BACKUP_ARCHIVE | Restore access can be blocked | RETAIN | Retain the archive only with restore access blocked. The CSV does not specify which identifiers may remain. |
| `rule_15` | ACCOUNT_TOMBSTONE | Account is deleted and only a stable internal user_id is needed to preserve references to retained records | REDACT | `user_id` is explicitly permitted; remove name, email, phone, email hash and other direct identifiers. |

## Validation vs. test requests

- Validation/example: `sample_deletion_requests.csv` has 32 requests (`case_01`–`case_32`) and `sample_output.csv` supplies one labeled result for each of those same 32 cases.
- Test: `deletion_requests.csv` has 518 requests (`case_33`–`case_550`). The dataset's `output.csv` is only a blank header. No expected-output rows are supplied for those requests.

## Ambiguities to resolve before implementation

1. **Retained-record identifier allowlists:** only `ACCOUNT_TOMBSTONE` explicitly says the stable `user_id` may remain while direct identifiers are removed. The supplied rules do not enumerate allowed identifiers for `SECURITY_AUDIT_LOG`, `LEGAL_HOLD_RECORD`, or retained `BACKUP_ARCHIVE`, nor the exact field list to keep in redacted support messages/email logs. The implementation must avoid inventing an allowlist; policy/data evidence may need to determine whether these retained records remain attributable.
2. **Transcript model metadata:** `AGENTS.md` requires an exact model identifier for each log entry and forbids `unknown`/guesses. The current runtime did not expose that identifier. Logging this turn correctly requires the runtime to expose it; existing log content was preserved.
3. **Unreadable PDFs:** delivery correction attachment and legal retention register were inaccessible in the local viewer. Extract their text or provide an available PDF/OCR viewer before treating their contents as confirmed.

Phase 0 is complete. No solution code or output predictions were changed.
