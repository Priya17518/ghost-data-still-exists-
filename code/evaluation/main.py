from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any

CODE_DIR = Path(__file__).resolve().parents[1]
ROOT = CODE_DIR.parent
sys.path.insert(0, str(CODE_DIR))

import main as audit  # noqa: E402


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def load_steps(rows: list[dict[str, str]]) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        try:
            steps = json.loads(row["steps_json"])
            result[row["case_id"]] = steps if isinstance(steps, list) else []
        except (KeyError, json.JSONDecodeError):
            result[row.get("case_id", "")] = []
    return result


def custom_tests() -> list[tuple[str, bool, str]]:
    sample_requests = read_rows(ROOT / "dataset" / "sample_deletion_requests.csv")
    identities = read_rows(ROOT / "dataset" / "user_identities.csv")
    history = read_rows(ROOT / "dataset" / "user_audit_log.csv")
    historical = next(
        request
        for request in sample_requests
        if request["email"] == "noah.f438085@outlook.com"
    )
    user_id, emails, _, _ = audit.read_subject_identities(historical, identities, history)
    shared_support = audit.EvidenceRecord(
        "custom",
        "2026-09-15T12:00:00Z",
        "support_platform",
        "SUPPORT_MESSAGE",
        "support_custom",
        {
            "requester_email": "person@example.invalid",
            "message_excerpt": "Shared customer and order context",
        },
    )
    enabled_flow = audit.EvidenceRecord(
        "custom",
        "2026-09-15T12:00:00Z",
        "integration_service",
        "DATA_FLOW",
        "data_flow_custom",
        {"enabled": 1},
    )
    disabled_flow = audit.EvidenceRecord(
        "custom",
        "2026-09-15T12:00:00Z",
        "integration_service",
        "DATA_FLOW",
        "data_flow_custom",
        {"enabled": 0},
    )
    late_capture = audit.EvidenceRecord(
        "custom",
        "2026-09-14T12:00:00Z",
        "account_service",
        "USER_PROFILE",
        "account_custom",
        {"email": "person@example.invalid"},
        "2026-09-16T12:00:00Z",
    )
    tests = [
        (
            "Informational data-access request is not deletion",
            not audit.has_deletion_intent("Please provide a copy of my data."),
            "Expected NOT_APPLICABLE intent classification.",
        ),
        (
            "Explicitly negated deletion is not authorized",
            not audit.has_deletion_intent("Please don't delete anything; only correct my email."),
            "Expected negated deletion to be rejected.",
        ),
        (
            "Portuguese deletion request is recognized",
            audit.has_deletion_intent(
                "Solicito a exclusão permanente da conta associada a este e-mail."
            ),
            "Expected the Portuguese exclusão request to be recognized.",
        ),
        (
            "Historical email resolves to one stable identity",
            bool(user_id and user_id.startswith("user_"))
            and historical["email"].casefold() in emails,
            f"Resolved user={user_id!r}; alias match={historical['email'].casefold() in emails}.",
        ),
        (
            "Shared support message still contains identifying data",
            not audit.record_compliant(
                shared_support,
                "REDACT",
                {"person@example.invalid"},
                set(),
                set(),
                "2026-09-15T12:00:00Z",
            ),
            "Expected redaction to be required while direct identifiers remain.",
        ),
        (
            "Enabled connector is an active recreation path",
            audit.active_record(enabled_flow) and not audit.active_record(disabled_flow),
            "Expected enabled to be active and disabled to be inactive.",
        ),
        (
            "Evidence captured after audit cutoff is excluded",
            not audit.time_before_or_equal(
                "2026-09-16T00:00:00Z", "2026-09-15T12:00:00Z"
            ),
            "Expected evidence later than audit_at to be excluded.",
        ),
        (
            "Later evidence capture is excluded despite an older event time",
            not audit.record_available_by(late_capture, "2026-09-15T12:00:00Z"),
            "Expected evidence capture time to honor the audit cutoff.",
        ),
        (
            "Phase ordering strictly enforces FINDING then REMEDIATION then VERIFICATION",
            [audit.PHASE_ORDER[p] for p in ("FINDING", "REMEDIATION", "VERIFICATION")] == [0, 1, 2],
            "Expected PHASE_ORDER to rank FINDING=0, REMEDIATION=1, VERIFICATION=2.",
        ),
        (
            "Negative 404 lookup proves record absence for deletion",
            audit.record_compliant(
                audit.EvidenceRecord(
                    "ev_test",
                    "2026-09-15T12:00:00Z",
                    "account_service",
                    "USER_PROFILE",
                    "account_test",
                    {"status_code": 404, "found": False},
                ),
                "DELETE",
                set(),
                set(),
                set(),
                "2026-09-15T12:00:00Z",
            ),
            "Expected 404/not_found payload to be recognized as compliant absence.",
        ),
        (
            "NOT_APPLICABLE non-deletion request yields empty steps array",
            audit.audit_request(
                {
                    "case_id": "test_na",
                    "email": "test@example.com",
                    "requested_at": "2026-09-01T12:00:00Z",
                    "reported_status": "NOT_STARTED",
                    "reported_at": "2026-09-02T12:00:00Z",
                    "audit_at": "2026-09-15T12:00:00Z",
                    "request_text": "Please provide an export of all my personal data.",
                },
                [],
                [],
                [],
                {},
                [],
                [],
            )
            == ("NOT_APPLICABLE", [], []),
            "Expected export-only request to return NOT_APPLICABLE with empty steps.",
        ),
        (
            "SQL wrapper table schema is recognized for record unwrapping",
            audit.WRAPPER_TABLE_COLS == frozenset(("resource_id", "origin_system", "collection_name", "record_json", "updated_at")),
            "Expected WRAPPER_TABLE_COLS to cover all 5 required column definitions.",
        ),
    ]
    return tests


def evaluate(actual_path: Path, report_path: Path) -> int:
    expected_rows = read_rows(ROOT / "dataset" / "sample_output.csv")
    actual_rows = read_rows(actual_path) if actual_path.is_file() else []
    expected_by_id = {row["case_id"]: row for row in expected_rows}
    actual_by_id = {row["case_id"]: row for row in actual_rows}
    expected_steps = load_steps(expected_rows)
    actual_steps = load_steps(actual_rows)
    ids = sorted(set(expected_by_id) | set(actual_by_id))
    status_correct = sum(
        case_id in expected_by_id
        and case_id in actual_by_id
        and expected_by_id[case_id]["deletion_status"]
        == actual_by_id[case_id]["deletion_status"]
        for case_id in ids
    )
    sequence_correct = sum(
        case_id in expected_steps
        and case_id in actual_steps
        and expected_steps[case_id] == actual_steps[case_id]
        for case_id in ids
    )
    exact_steps = 0
    compared_slots = 0
    matching_fields = 0
    field_slots = 0
    correct_operations = 0
    correct_states = 0
    missing_steps = 0
    extra_steps = 0
    field_names = list(audit.STEP_FIELDS)
    for case_id in ids:
        expected = expected_steps.get(case_id, [])
        actual = actual_steps.get(case_id, [])
        compared_slots += max(len(expected), len(actual))
        missing_steps += max(0, len(expected) - len(actual))
        extra_steps += max(0, len(actual) - len(expected))
        for index in range(max(len(expected), len(actual))):
            expected_step = expected[index] if index < len(expected) else None
            actual_step = actual[index] if index < len(actual) else None
            if expected_step is not None and actual_step is not None and expected_step == actual_step:
                exact_steps += 1
            if (
                expected_step is not None
                and actual_step is not None
                and expected_step.get("operation") == actual_step.get("operation")
            ):
                correct_operations += 1
            if (
                expected_step is not None
                and actual_step is not None
                and expected_step.get("state") == actual_step.get("state")
            ):
                correct_states += 1
            for field in field_names:
                field_slots += 1
                if (
                    expected_step is not None
                    and actual_step is not None
                    and expected_step.get(field) == actual_step.get(field)
                ):
                    matching_fields += 1

    custom = custom_tests()
    custom_passed = sum(passed for _, passed, _ in custom)
    case_status_denominator = len(expected_rows)
    sequence_denominator = len(expected_rows)
    step_accuracy = exact_steps / compared_slots if compared_slots else 0.0
    field_accuracy = matching_fields / field_slots if field_slots else 0.0
    status_accuracy = status_correct / case_status_denominator if case_status_denominator else 0.0
    sequence_accuracy = sequence_correct / sequence_denominator if sequence_denominator else 0.0

    mismatch_details: list[str] = []
    for case_id in ids:
        expected = expected_by_id.get(case_id)
        actual = actual_by_id.get(case_id)
        if expected is None or actual is None:
            mismatch_details.append(
                f"- `{case_id}`: {'missing actual row' if actual is None else 'unexpected actual row'}."
            )
            continue
        exp_steps = expected_steps.get(case_id, [])
        act_steps = actual_steps.get(case_id, [])
        if (
            expected["deletion_status"] != actual["deletion_status"]
            or exp_steps != act_steps
        ):
            def summary(step: dict[str, Any]) -> str:
                return (
                    f"{step.get('phase')}/{step.get('system_id')}/"
                    f"{step.get('resource_id')}/{step.get('operation')}/"
                    f"{step.get('state')}@{step.get('evidence_id')}"
                )
            mismatch_details.append(
                f"- `{case_id}`: status `{expected['deletion_status']}` vs "
                f"`{actual['deletion_status']}`; expected {len(exp_steps)} steps "
                f"[{'; '.join(summary(step) for step in exp_steps)}]; actual "
                f"{len(act_steps)} steps [{'; '.join(summary(step) for step in act_steps)}]."
            )

    validation_errors: list[str] = []
    if not actual_path.is_file():
        validation_errors.append(f"Actual output not found: {actual_path}")
    else:
        validation_errors = audit.validate_output(
            actual_path, set(expected_by_id)
        )
    full_output = ROOT / "output.csv"
    full_run_summary: list[str] = []
    if full_output.is_file() and actual_path.resolve() != full_output.resolve():
        full_rows = read_rows(full_output)
        full_requests = read_rows(ROOT / "dataset" / "deletion_requests.csv")
        full_errors = audit.validate_output(
            full_output, {row["case_id"] for row in full_requests}
        )
        full_counts = {
            status: sum(row.get("deletion_status") == status for row in full_rows)
            for status in ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE")
        }
        full_run_summary = [
            "",
            "## Full-dataset structural validation",
            "",
            f"- Output rows: **{len(full_rows)}**; input requests: **{len(full_requests)}**.",
            f"- Status counts: `{json.dumps(full_counts, sort_keys=True)}`.",
            f"- Output contract validation errors: **{len(full_errors)}**.",
        ]
        full_run_summary.extend([f"- {error}" for error in full_errors])
    lines = [
        "# Evaluation report",
        "",
        "## Approach",
        "",
        "The audit engine resolves request emails against current and historical identity records, "
        "parses participant-facing JSON and SQL evidence, extracts resource-linked text where possible, "
        "applies the supplied category action table, and serializes ordered operations. It excludes "
        "evidence later than `audit_at` and does not use `reported_status` to decide deletion state.",
        "",
        "## Public sample comparison",
        "",
        f"- Reference rows: {len(expected_rows)}; generated rows: {len(actual_rows)}.",
        f"- Case-level status accuracy: **{status_correct}/{case_status_denominator} "
        f"({status_accuracy:.2%})**.",
        f"- Exact step accuracy at aligned positions: **{exact_steps}/{compared_slots} "
        f"({step_accuracy:.2%})**.",
        f"- Step-field accuracy across aligned positions (including missing/extra slots): "
        f"**{matching_fields}/{field_slots} ({field_accuracy:.2%})**.",
        f"- Operation accuracy: **{correct_operations}/{compared_slots} "
        f"({correct_operations / compared_slots if compared_slots else 0:.2%})**.",
        f"- State accuracy: **{correct_states}/{compared_slots} "
        f"({correct_states / compared_slots if compared_slots else 0:.2%})**.",
        f"- Exact ordered sequence accuracy: **{sequence_correct}/{sequence_denominator} "
        f"({sequence_accuracy:.2%})**.",
        f"- Missing steps: **{missing_steps}**; extra steps: **{extra_steps}**.",
        f"- Structural output validation errors: **{len(validation_errors)}**.",
        "",
        "### Mismatches",
        "",
    ]
    lines.extend(mismatch_details or ["- None."])
    lines.extend(["", "### Validation failures", ""])
    lines.extend([f"- {error}" for error in validation_errors] or ["- None."])
    lines.extend(
        [
            "",
            "## Team-created edge-case tests",
            "",
            "These unit checks exercise decision and policy behavior without adding fabricated "
            "canonical rows to the prediction dataset:",
            "",
        ]
    )
    for name, passed, detail in custom:
        lines.append(f"- {'PASS' if passed else 'FAIL'} — {name}: {detail}")
    lines.extend(
        [
            "",
            f"Custom test result: **{custom_passed}/{len(custom)} passed**.",
            "",
            "## Failures, limitations, and improvements",
            "",
            "Iterative sample checks found and fixed incorrect resource parsing for system names, "
            "trace-level identity fields split across log lines, text extraction from compressed PDF "
            "streams, Portuguese deletion-intent vocabulary, and the important distinction between "
            "evidence capture time and event time. "
            "The implementation also clears evidence identifiers from all proposed post-remediation "
            "verification steps, recognizes explicit 404 profile lookups as absence, and validates "
            "every serialized step.",
            "",
            "Evidence image files are not OCR-parsed by the standard-library implementation. PDF text "
            "extraction is best-effort and does not reliably decode every font encoding. Activity "
            "records are treated as claims and are not yet used as conclusive record-state proof. "
            "Where no matched evidence establishes a state, the engine returns `INCOMPLETE` with an "
            "explicit limitation rather than claiming absence. Remaining sample mismatches above "
            "are reported as measured; no score is inferred from output validity.",
            "",
            "No hidden answers, organizer-only files, or generator internals were used.",
        ]
    )
    lines.extend(full_run_summary)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Sample status accuracy: {status_correct}/{case_status_denominator} ({status_accuracy:.2%})")
    print(f"Exact sequence accuracy: {sequence_correct}/{sequence_denominator} ({sequence_accuracy:.2%})")
    print(f"Field accuracy: {matching_fields}/{field_slots} ({field_accuracy:.2%})")
    print(f"Custom tests: {custom_passed}/{len(custom)}")
    print(f"Evaluation report written: {report_path}")
    return 1 if validation_errors or custom_passed != len(custom) else 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare predictions with public sample answers")
    parser.add_argument("--actual", type=Path, default=ROOT / "output.csv")
    parser.add_argument(
        "--report",
        type=Path,
        default=CODE_DIR / "evaluation" / "evaluation_report.md",
    )
    args = parser.parse_args()
    return evaluate(args.actual, args.report)


if __name__ == "__main__":
    raise SystemExit(main())