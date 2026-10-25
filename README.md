# HackerRank Orchestrate: Ghost Data Still Exists

An autonomous, evidence-driven deletion-audit AI investigation agent that verifies whether customer personal data was truly expunged across distributed systems, databases, read replicas, search indexes, support logs, and backup archives.

---

## Key Capabilities

1. **Evidence-Grounded Deletion Auditing**: Strictly enforces the principle that *absence of evidence is not evidence of absence*. Claims by workflows are verified against participant-visible evidence before the `audit_at` cutoff.
2. **Three Mandatory Phases**: Generates ordered lifecycle operations:
   - **`FINDING`**: Uncovers remaining data copies, exposed PII, active sync flows, and restore risks.
   - **`REMEDIATION`**: Orders safe corrective actions (`DISABLE_DATA_FLOW` -> `BLOCK_RESTORE` -> `DELETE`/`REDACT`/`ANONYMIZE`).
   - **`VERIFICATION`**: Proof checks confirming absent or compliant post-remediation states.
3. **Interactive Investigation Agent & Dashboard**: 7-tab modern web interface with safe multi-format file uploads (CSV, JSON, PDF, logs, ZIP with traversal protection), guided case inspection, and a scoped conversational AI retrieval assistant.

---

## Setup & Execution

### 1. Run the Full Deletion Audit (518 Cases)

Generates the validated official submission CSV:

```bash
python code/main.py --input dataset/deletion_requests.csv --output output.csv
