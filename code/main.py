from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import re
import sqlite3
import sys
import zlib
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parent.parent
DATASET = ROOT / "dataset"
OUTPUT_FIELDS = ("case_id", "deletion_status", "steps_json")
STEP_FIELDS = (
    "step_no",
    "phase",
    "system_id",
    "resource_id",
    "operation",
    "state",
    "evidence_id",
)
PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
OPERATION_ORDER = {
    "REPORT_REMAINING_RECORD": 0,
    "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2,
    "REPORT_RESTORE_RISK": 3,
    "DISABLE_DATA_FLOW": 0,
    "BLOCK_RESTORE": 1,
    "DELETE_RECORD": 2,
    "REDACT_RECORD": 3,
    "ANONYMIZE_RECORD": 4,
    "VERIFY_RECORD_ABSENT": 0,
    "VERIFY_RECORD_PRESENT": 1,
    "VERIFY_RECORD_REDACTED": 2,
    "VERIFY_RECORD_ANONYMIZED": 3,
    "VERIFY_DATA_FLOW_DISABLED": 4,
    "VERIFY_RESTORE_BLOCKED": 5,
}
OPERATION_STATE = {
    "REPORT_REMAINING_RECORD": "PRESENT",
    "REPORT_EXPOSED_PII": "PRESENT",
    "REPORT_ACTIVE_DATA_FLOW": "ACTIVE",
    "REPORT_RESTORE_RISK": "ACTIVE",
    "DISABLE_DATA_FLOW": "DISABLED",
    "BLOCK_RESTORE": "BLOCKED",
    "DELETE_RECORD": "ABSENT",
    "REDACT_RECORD": "REDACTED",
    "ANONYMIZE_RECORD": "ANONYMIZED",
    "VERIFY_RECORD_ABSENT": "ABSENT",
    "VERIFY_RECORD_PRESENT": "PRESENT",
    "VERIFY_RECORD_REDACTED": "REDACTED",
    "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
    "VERIFY_RESTORE_BLOCKED": "BLOCKED",
}
OPERATION_PHASE = {
    **{operation: "FINDING" for operation in (
        "REPORT_REMAINING_RECORD",
        "REPORT_EXPOSED_PII",
        "REPORT_ACTIVE_DATA_FLOW",
        "REPORT_RESTORE_RISK",
    )},
    **{operation: "REMEDIATION" for operation in (
        "DISABLE_DATA_FLOW",
        "BLOCK_RESTORE",
        "DELETE_RECORD",
        "REDACT_RECORD",
        "ANONYMIZE_RECORD",
    )},
    **{operation: "VERIFICATION" for operation in (
        "VERIFY_RECORD_ABSENT",
        "VERIFY_RECORD_PRESENT",
        "VERIFY_RECORD_REDACTED",
        "VERIFY_RECORD_ANONYMIZED",
        "VERIFY_DATA_FLOW_DISABLED",
        "VERIFY_RESTORE_BLOCKED",
    )},
}
DELETE_TERMS = (
    "delete",
    "deleting",
    "deleted",
    "deletion",
    "erase",
    "erasure",
    "remove",
    "removal",
    "purge",
    "forget",
    "suppression",
    "eliminar",
    "eliminación",
    "eliminacion",
    "borrar",
    "borrado",
    "supresión",
    "exclusão",
    "exclusao",
    "excluir",
    "apagamento",
    "apagar",
    "remoção",
    "remocao",
    "supprimer",
    "effacer",
    "effacement",
    "löschen",
    "loschen",
    "löschung",
    "entfernen",
    "삭제",
    "지우",
    "削除",
    "消去",
    "삭제해",
    "silin",
    "silinmesini",
    "verwijder",
    "verwijderen",
    "annuler",
    "annulation",
    "apagar",
)
NEGATIVE_DELETE_PATTERNS = (
    r"\b(?:do not|don't|dont|not|never)\s+(?:delete|erase|remove|purge)\b",
    r"\bnot\s+(?:a|an)\s+(?:deletion|erasure)\s+request\b",
    r"\bno\s+(?:quiero|deseo|solicito)\s+(?:eliminar|borrar)\b",
    r"\bne\s+supprimez\s+pas\b",
    r"\bne\s+pas\s+(?:supprimer|effacer)\b",
    r"\b(?:nicht|keine)\s+(?:löschen|löschung)\b",
    r"\b삭제하지\s*마",
    r"\b삭제\s*말",
)
NON_DELETE_ONLY_TERMS = (
    "access my data",
    "data access",
    "correct my",
    "update my email",
    "change my email",
    "export my data",
    "download my data",
    "unsubscribe",
    "opt out",
    "marketing emails",
    "rectify",
)

TABLE_POLICY = {
    "customer_profiles": ("account_service", "USER_PROFILE"),
    "customer_profiles_primary": ("account_service", "USER_PROFILE"),
    "customer_profiles_failover_replica": ("account_service", "USER_PROFILE"),
    "customer_data_primary": ("account_service", "USER_PROFILE"),
    "customer_data_failover_replica": ("account_service", "USER_PROFILE"),
    "customer_data_read_replica": ("account_service", "USER_PROFILE"),
    "customer_data_reporting_replica": ("account_service", "USER_PROFILE"),
    "customer_data_replica_ap_south": ("account_service", "USER_PROFILE"),
    "customer_data_replica_eu_west": ("account_service", "USER_PROFILE"),
    "customer_search_documents": ("search_service", "SEARCH_INDEX_ENTRY"),
    "search_documents_primary": ("search_service", "SEARCH_INDEX_ENTRY"),
    "customer_analytics_profiles": ("analytics_platform", "ANALYTICS_PROFILE"),
    "support_records": ("support_platform", "SUPPORT_MESSAGE"),
    "support_attachments": ("support_platform", "SUPPORT_ATTACHMENT"),
    "customer_exports": ("export_service", "USER_EXPORT"),
    "connector_subscriptions": ("integration_service", "DATA_FLOW"),
    "backup_restore_entries": ("backup_service", "BACKUP_ARCHIVE"),
    "security_audit_records": ("security_service", "SECURITY_AUDIT_LOG"),
    "deleted_customer_references": ("identity_service", "ACCOUNT_TOMBSTONE"),
    "customer_data_failover_replica": ("account_failover_replica", "USER_PROFILE"),
}
COLLECTION_POLICY = {
    "customer_profiles": ("account_service", "USER_PROFILE"),
    "user_profiles": ("account_service", "USER_PROFILE"),
    "customer_search_documents": ("search_service", "SEARCH_INDEX_ENTRY"),
    "search_documents": ("search_service", "SEARCH_INDEX_ENTRY"),
    "search_index_entries": ("search_service", "SEARCH_INDEX_ENTRY"),
    "customer_analytics_profiles": ("analytics_platform", "ANALYTICS_PROFILE"),
    "analytics_profiles": ("analytics_platform", "ANALYTICS_PROFILE"),
    "support_records": ("support_platform", "SUPPORT_MESSAGE"),
    "support_tickets": ("support_platform", "SUPPORT_MESSAGE"),
    "support_attachments": ("support_platform", "SUPPORT_ATTACHMENT"),
    "customer_exports": ("export_service", "USER_EXPORT"),
    "export_jobs": ("export_service", "USER_EXPORT"),
    "marketing_profiles": ("marketing_platform", "MARKETING_PROFILE"),
    "email_delivery_logs": ("email_delivery_service", "EMAIL_DELIVERY_LOG"),
    "security_audit_records": ("security_service", "SECURITY_AUDIT_LOG"),
    "security_audit_events": ("security_service", "SECURITY_AUDIT_LOG"),
    "legal_holds": ("legal_service", "LEGAL_HOLD_RECORD"),
    "legal_hold_records": ("legal_service", "LEGAL_HOLD_RECORD"),
    "backup_restore_entries": ("backup_service", "BACKUP_ARCHIVE"),
    "deleted_customer_references": ("identity_service", "ACCOUNT_TOMBSTONE"),
    "secondary_identifiers": ("identity_service", "SECONDARY_IDENTIFIER"),
    "connector_subscriptions": ("integration_service", "DATA_FLOW"),
}
SERVICE_COLLECTIONS = {
    "account_service": {
        "profile_lookups": ("account_service", "USER_PROFILE"),
        "profiles": ("account_service", "USER_PROFILE"),
    },
    "search_service": {
        "documents": ("search_service", "SEARCH_INDEX_ENTRY"),
        "index_queries": ("search_service", "SEARCH_INDEX_ENTRY"),
    },
    "analytics_platform": {"profiles": ("analytics_platform", "ANALYTICS_PROFILE")},
    "support_platform": {"tickets": ("support_platform", "SUPPORT_MESSAGE")},
    "export_service": {"exports": ("export_service", "USER_EXPORT")},
    "backup_service": {"restore_entries": ("backup_service", "BACKUP_ARCHIVE")},
    "integration_service": {"connectors": ("integration_service", "DATA_FLOW")},
    "security_service": {"audit_records": ("security_service", "SECURITY_AUDIT_LOG")},
}


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    evidence_time: str
    system_id: str
    category: str
    resource_id: str
    payload: dict[str, Any]
    captured_at: str = ""


@dataclass
class EvidenceState:
    records: list[EvidenceRecord]
    errors: list[str]


def parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def time_before_or_equal(value: Any, cutoff: Any) -> bool:
    parsed = parse_time(value)
    cutoff_time = parse_time(cutoff)
    return parsed is not None and cutoff_time is not None and parsed <= cutoff_time


def record_available_by(record: EvidenceRecord, cutoff: Any) -> bool:
    return time_before_or_equal(record.evidence_time, cutoff) and time_before_or_equal(
        record.captured_at or record.evidence_time, cutoff
    )


def read_csv(path: Path, required: Iterable[str]) -> list[dict[str, str]]:
    if not path.is_file():
        raise FileNotFoundError(f"Required CSV file is missing: {path}")
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        missing = set(required) - set(reader.fieldnames or ())
        if missing:
            raise ValueError(f"{path.name} is missing columns: {sorted(missing)}")
        rows = list(reader)
    return rows


def normalize(value: Any) -> str:
    return str(value).strip().casefold() if value is not None else ""


def has_deletion_intent(text: str) -> bool:
    lowered = text.casefold()
    if any(re.search(pattern, lowered) for pattern in NEGATIVE_DELETE_PATTERNS):
        return False
    closure_request = (
        re.search(r"\b(?:close|closed|closing)\b.{0,50}\baccount\b", lowered)
        or re.search(r"\baccount\b.{0,50}\b(?:close|closed|closing)\b", lowered)
    ) and any(
        cue in lowered
        for cue in (
            "permanently",
            "completely",
            "personal data",
            "personal-data",
            "privacy",
            "other systems",
        )
    )
    deletion_followup = (
        any(word in lowered for word in ("confirm", "verify", "check", "audit"))
        and (
            re.search(r"\b(?:profile|account|data)\b.{0,35}\b(?:gone|removed|erased|deleted)\b", lowered)
            or "cannot identify me" in lowered
            or "no longer identify me" in lowered
        )
    )
    if not any(term in lowered for term in DELETE_TERMS) and not closure_request and not deletion_followup:
        return False
    if any(term in lowered for term in NON_DELETE_ONLY_TERMS):
        if not re.search(r"\b(?:delete|erase|remove|purge)\b", lowered):
            return False
    return True


def read_subject_identities(
    request: dict[str, str],
    identities: list[dict[str, str]],
    audit_log: list[dict[str, str]],
) -> tuple[str | None, set[str], set[str], set[str]]:
    requested_email = normalize(request.get("email"))
    by_user: dict[str, dict[str, str]] = {row["user_id"]: row for row in identities}
    history_by_user: dict[str, list[dict[str, str]]] = {}
    for event in audit_log:
        history_by_user.setdefault(event["user_id"], []).append(event)

    candidates: set[str] = set()
    for user_id, identity in by_user.items():
        if normalize(identity.get("email")) == requested_email:
            candidates.add(user_id)
        for event in history_by_user.get(user_id, []):
            if normalize(event.get("old_value")) == requested_email:
                candidates.add(user_id)
            if normalize(event.get("new_value")) == requested_email:
                candidates.add(user_id)
    if len(candidates) != 1:
        return (next(iter(candidates)) if len(candidates) == 1 else None, set(), set(), set())

    user_id = next(iter(candidates))
    identity = by_user[user_id]
    audit_at = request["audit_at"]
    emails: set[str] = {requested_email}
    phones: set[str] = set()
    hashes: set[str] = set()
    if time_before_or_equal(identity.get("updated_at"), audit_at):
        current_email = normalize(identity.get("email"))
        if current_email:
            emails.add(current_email)
        phone = normalize(identity.get("phone"))
        if phone:
            phones.add(phone)
        email_hash = normalize(identity.get("email_hash"))
        if email_hash:
            hashes.add(email_hash)
    for event in history_by_user.get(user_id, []):
        if not time_before_or_equal(event.get("event_time"), audit_at):
            continue
        field = event.get("field_name", "").casefold()
        if field == "email":
            if normalize(event.get("old_value")):
                emails.add(normalize(event["old_value"]))
            if normalize(event.get("new_value")):
                emails.add(normalize(event["new_value"]))
        elif field == "phone":
            for key in ("old_value", "new_value"):
                if normalize(event.get(key)):
                    phones.add(normalize(event[key]))
        elif field == "email_hash":
            for key in ("old_value", "new_value"):
                if normalize(event.get(key)):
                    hashes.add(normalize(event[key]))
    for email in emails:
        hashes.add(hashlib.sha256(email.encode("utf-8")).hexdigest())
    return user_id, emails, phones, hashes


def category_from_name(name: str) -> tuple[str, str]:
    key = name.casefold()
    if key in COLLECTION_POLICY:
        return COLLECTION_POLICY[key]
    for marker, item in (
        ("tombstone", ("identity_service", "ACCOUNT_TOMBSTONE")),
        ("deleted_customer_reference", ("identity_service", "ACCOUNT_TOMBSTONE")),
        ("secondary_identifier", ("identity_service", "SECONDARY_IDENTIFIER")),
        ("search", ("search_service", "SEARCH_INDEX_ENTRY")),
        ("cache", ("cache_service", "CACHE_ENTRY")),
        ("support_attachment", ("support_platform", "SUPPORT_ATTACHMENT")),
        ("attachment", ("support_platform", "SUPPORT_ATTACHMENT")),
        ("support", ("support_platform", "SUPPORT_MESSAGE")),
        ("analytics", ("analytics_platform", "ANALYTICS_PROFILE")),
        ("telemetry", ("analytics_platform", "PRODUCT_TELEMETRY")),
        ("export", ("export_service", "USER_EXPORT")),
        ("marketing", ("marketing_platform", "MARKETING_PROFILE")),
        ("email_delivery", ("email_delivery_service", "EMAIL_DELIVERY_LOG")),
        ("security_audit", ("security_service", "SECURITY_AUDIT_LOG")),
        ("legal_hold", ("legal_service", "LEGAL_HOLD_RECORD")),
        ("backup", ("backup_service", "BACKUP_ARCHIVE")),
        ("connector", ("integration_service", "DATA_FLOW")),
        ("data_flow", ("integration_service", "DATA_FLOW")),
        ("audit_record", ("security_service", "SECURITY_AUDIT_LOG")),
        ("profile", ("account_service", "USER_PROFILE")),
    ):
        if marker in key:
            return item
    return ("", "")


def system_category_for_resource(resource_id: str, service: str = "", text: str = "") -> tuple[str, str]:
    res = resource_id.casefold()
    prefix = res.split("_")[0] if "_" in res else res
    if prefix == "account":
        return ("account_service", "USER_PROFILE")
    if prefix == "search":
        return ("search_service", "SEARCH_INDEX_ENTRY")
    if prefix == "support":
        if "attachment" in res or "attachment" in text.casefold():
            return ("support_platform", "SUPPORT_ATTACHMENT")
        return ("support_platform", "SUPPORT_MESSAGE")
    if prefix == "analytics":
        return ("analytics_platform", "ANALYTICS_PROFILE")
    if prefix == "telemetry":
        return ("analytics_platform", "PRODUCT_TELEMETRY")
    if prefix in ("data", "flow") or res.startswith("data_flow"):
        return ("integration_service", "DATA_FLOW")
    if prefix == "backup":
        return ("backup_service", "BACKUP_ARCHIVE")
    if prefix == "export":
        return ("export_service", "USER_EXPORT")
    if prefix == "tombstone":
        return ("identity_service", "ACCOUNT_TOMBSTONE")
    if prefix in ("audit", "audit_record") or res.startswith("audit_record"):
        return ("security_service", "SECURITY_AUDIT_LOG")
    if prefix == "legal":
        return ("legal_service", "LEGAL_HOLD_RECORD")
    if prefix in ("email", "delivery") or res.startswith("email_delivery"):
        return ("email_delivery_service", "EMAIL_DELIVERY_LOG")
    if service:
        sys_id, cat = category_from_name(service)
        if sys_id:
            return (sys_id, cat)
    return category_from_name(text)


def insert_record(
    records: list[EvidenceRecord],
    seen: set[tuple[str, str, str, str, str]],
    evidence_id: str,
    evidence_time: str,
    system_id: str,
    category: str,
    payload: dict[str, Any],
    inherited_resource: str = "",
) -> None:
    resource_id = str(payload.get("resource_id") or inherited_resource or "").strip()
    if not resource_id:
        return
    key = (
        evidence_id,
        system_id,
        category,
        resource_id,
        evidence_time + json.dumps(payload, sort_keys=True, default=str),
    )
    if key in seen:
        return
    seen.add(key)
    records.append(
        EvidenceRecord(
            evidence_id=evidence_id,
            evidence_time=evidence_time,
            system_id=system_id or "unknown_system",
            category=category or "UNKNOWN",
            resource_id=resource_id,
            payload=payload,
        )
    )


def flatten_json_records(
    data: Any,
    evidence_id: str,
    evidence_time: str,
    records: list[EvidenceRecord],
    seen: set[tuple[str, str, str, str, str]],
) -> None:
    if not isinstance(data, dict):
        return
    if isinstance(data.get("snapshots"), list):
        for snapshot in data["snapshots"]:
            if not isinstance(snapshot, dict):
                continue
            collection = str(snapshot.get("collection", ""))
            system_id, category = category_from_name(collection)
            snapshot_time = str(snapshot.get("captured_at") or evidence_time)
            for item in snapshot.get("records", []):
                if isinstance(item, dict):
                    insert_record(
                        records,
                        seen,
                        evidence_id,
                        snapshot_time,
                        system_id,
                        category,
                        item,
                    )
    if isinstance(data.get("service_exports"), dict):
        for system, collections in data["service_exports"].items():
            if not isinstance(collections, dict):
                continue
            for collection_name, values in collections.items():
                default_system, category = SERVICE_COLLECTIONS.get(
                    system, {}
                ).get(collection_name, ("", ""))
                if not isinstance(values, list):
                    continue
                for item in values:
                    if isinstance(item, dict):
                        if not default_system:
                            default_system, category = category_from_name(collection_name)
                        insert_record(
                            records,
                            seen,
                            evidence_id,
                            str(item.get("observed_at") or evidence_time),
                            default_system or system,
                            category,
                            item,
                        )
    root_records = data.get("records")
    if isinstance(root_records, list):
        collection = str(data.get("collection", data.get("origin", "")))
        for item in root_records:
            if isinstance(item, dict):
                res_id = str(item.get("resource_id", ""))
                sys_val = str(item.get("system", ""))
                rec_type = str(item.get("record_type", ""))
                system_id, category = system_category_for_resource(res_id, sys_val, rec_type or collection)
                res_result = normalize(item.get("result"))
                if res_result in ("not_found", "absent", "deleted"):
                    item["found"] = False
                    item["status_code"] = 404
                    item["account_status"] = "not_found"
                insert_record(
                    records,
                    seen,
                    evidence_id,
                    str(item.get("recorded_at") or data.get("captured_at") or evidence_time),
                    system_id,
                    category,
                    item,
                )
    elif not isinstance(data.get("snapshots"), list) and not isinstance(
        data.get("service_exports"), dict
    ):
        def walk(node: Any, parent_name: str = "") -> None:
            if isinstance(node, dict):
                system_id, category = category_from_name(parent_name)
                if not system_id:
                    system_id, category = category_from_name(str(node.get("type", "")))
                if node.get("resource_id"):
                    insert_record(
                        records,
                        seen,
                        evidence_id,
                        str(node.get("observed_at") or node.get("updated_at") or evidence_time),
                        system_id,
                        category,
                        node,
                    )
                for key, value in node.items():
                    if isinstance(value, (list, dict)):
                        walk(value, key)
            elif isinstance(node, list):
                for item in node:
                    walk(item, parent_name)
        walk(data)


WRAPPER_TABLE_COLS = frozenset(("resource_id", "origin_system", "collection_name", "record_json", "updated_at"))


def read_sql_records(
    path: Path,
    evidence_id: str,
    evidence_time: str,
    records: list[EvidenceRecord],
    seen: set[tuple[str, str, str, str, str]],
) -> None:
    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript(path.read_text(encoding="utf-8-sig"))
        tables = [
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            )
        ]
        snapshot_times: dict[str, str] = {}
        if "snapshot_scope" in tables:
            columns = [row[1] for row in connection.execute("PRAGMA table_info(snapshot_scope)")]
            if {"origin_system", "captured_at"}.issubset(columns):
                snapshot_times = dict(
                    connection.execute("SELECT origin_system, captured_at FROM snapshot_scope")
                )
        for table in tables:
            if table == "snapshot_scope":
                continue
            columns = [row[1] for row in connection.execute(f'PRAGMA table_info("{table}")')]
            col_set = set(columns)
            policy = TABLE_POLICY.get(table) or category_from_name(table)
            table_system_id, table_category = policy
            for row in connection.execute(f'SELECT * FROM "{table}"'):
                values = dict(zip(columns, row))
                # Detect wrapper table format: (resource_id, origin_system, collection_name, record_json, updated_at)
                if WRAPPER_TABLE_COLS.issubset(col_set) and values.get("record_json"):
                    raw_json = values["record_json"]
                    try:
                        parsed_record = json.loads(raw_json) if isinstance(raw_json, str) else raw_json
                    except (json.JSONDecodeError, TypeError):
                        parsed_record = None
                    row_origin = str(values.get("origin_system") or "")
                    row_collection = str(values.get("collection_name") or "")
                    row_resource_id = str(values.get("resource_id") or "")
                    row_updated = str(values.get("updated_at") or snapshot_times.get(row_origin, evidence_time))
                    # Use origin_system/collection_name for classification
                    row_system_id, row_category = category_from_name(row_collection)
                    if not row_system_id:
                        row_system_id, row_category = category_from_name(row_origin)
                    if not row_system_id:
                        row_system_id = row_origin
                    # Build merged payload: wrapper fields + parsed record fields
                    if isinstance(parsed_record, dict):
                        merged: dict[str, Any] = dict(parsed_record)
                        merged["resource_id"] = merged.get("resource_id") or row_resource_id
                    else:
                        merged = dict(values)
                        del merged["record_json"]
                        merged["resource_id"] = row_resource_id
                    insert_record(
                        records,
                        seen,
                        evidence_id,
                        row_updated,
                        row_system_id,
                        row_category,
                        merged,
                    )
                    continue
                # Standard table format
                system_id = table_system_id
                category = table_category
                if not system_id and values.get("origin_system"):
                    system_id = str(values["origin_system"])
                observed = str(
                    values.get("updated_at")
                    or snapshot_times.get(system_id, evidence_time)
                )
                insert_record(
                    records,
                    seen,
                    evidence_id,
                    observed,
                    system_id,
                    category,
                    values,
                )
    finally:
        connection.close()


RESOURCE_RE = re.compile(
    r"\b(?:account|search|support|analytics|export|backup|audit_record|"
    r"tombstone|data_flow|marketing|cache|attachment|telemetry|profile)_"
    r"[A-Za-z0-9-]*\d[A-Za-z0-9-]*\b",
    re.IGNORECASE,
)
EMAIL_RE = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE)
PHONE_RE = re.compile(r"\+?\d[\d ()-]{7,}\d")
USER_RE = re.compile(r"\buser_[A-Za-z0-9-]+\b", re.IGNORECASE)


def pdf_text(content: bytes) -> str:
    decoded_streams: list[bytes] = []
    for match in re.finditer(rb"stream\r?\n(.*?)endstream", content, re.DOTALL):
        stream = match.group(1).strip(b"\r\n")
        header = content[max(0, match.start() - 256) : match.start()]
        if b"ASCII85Decode" in header:
            try:
                stream = base64.a85decode(stream.replace(b"~>", b""), adobe=False)
            except ValueError:
                continue
        if b"FlateDecode" in header:
            try:
                stream = zlib.decompress(stream)
            except zlib.error:
                continue
        decoded_streams.append(stream)
    unicode_map: dict[int, str] = {}
    for stream in decoded_streams:
        if b"begincmap" not in stream:
            continue
        for code, destination in re.findall(
            rb"<([0-9A-Fa-f]{2,4})>\s*<([0-9A-Fa-f]{4,8})>", stream
        ):
            try:
                unicode_map[int(code, 16)] = bytes.fromhex(
                    destination.decode("ascii")
                ).decode("utf-16-be", errors="replace")
            except (ValueError, UnicodeDecodeError):
                continue

    def decode_text(raw: bytes) -> str:
        output: list[str] = []
        for byte in raw:
            output.append(unicode_map.get(byte, bytes((byte,)).decode("cp1252", errors="replace")))
        return "".join(output)

    extracted: list[str] = []
    literal_pattern = re.compile(rb"\(((?:\\.|[^\\)])*)\)\s*Tj")
    hex_pattern = re.compile(rb"<([0-9A-Fa-f]+)>\s*Tj")
    array_pattern = re.compile(rb"\[((?:.|\n)*?)\]\s*TJ")
    for stream in decoded_streams:
        if b"begincmap" in stream:
            continue
        extracted.extend(decode_text(item) for item in literal_pattern.findall(stream))
        for item in hex_pattern.findall(stream):
            try:
                extracted.append(decode_text(bytes.fromhex(item.decode("ascii"))))
            except ValueError:
                continue
        for array in array_pattern.findall(stream):
            extracted.extend(
                decode_text(item) for item in re.findall(rb"\(((?:\\.|[^\\)])*)\)", array)
            )
            for item in re.findall(rb"<([0-9A-Fa-f]+)>", array):
                try:
                    extracted.append(decode_text(bytes.fromhex(item.decode("ascii"))))
                except ValueError:
                    continue
    return "\n".join(extracted)


def parse_unstructured(
    path: Path,
    evidence_id: str,
    evidence_time: str,
    records: list[EvidenceRecord],
    seen: set[tuple[str, str, str, str, str]],
) -> bool:
    try:
        raw = path.read_bytes()
        text = pdf_text(raw) if path.suffix.casefold() == ".pdf" else raw.decode(
            "utf-8-sig", errors="replace"
        )
    except OSError:
        raise
    if path.suffix.casefold() == ".pdf" and not text.strip():
        return False
    if path.suffix.casefold() == ".pdf":
        resource_ids = set(RESOURCE_RE.findall(text))
        if not resource_ids:
            return True
        system_id, category = category_from_name(path.stem)
        payload: dict[str, Any] = {
            "resource_id": "",
            "text": text,
            "emails": EMAIL_RE.findall(text),
        }
        for resource_id in resource_ids:
            payload["resource_id"] = resource_id
            insert_record(
                records,
                seen,
                evidence_id,
                evidence_time,
                system_id,
                category,
                dict(payload),
            )
        return True

    traces: dict[str, dict[str, Any]] = {}
    for index, raw_line in enumerate(text.splitlines()):
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("- ") and "|" in line:
            parts = [p.strip() for p in line[2:].split("|")]
            if len(parts) >= 5:
                ev_time, sys_id, res_id, cat_name, state_val = parts[0], parts[1], parts[2], parts[3], parts[4]
                ident = parts[5] if len(parts) > 5 else ""
                row_payload: dict[str, Any] = {
                    "resource_id": res_id,
                    "state": state_val,
                    "status": state_val,
                }
                if "@" in ident:
                    row_payload["emails"] = [ident]
                    row_payload["email"] = ident
                elif ident.startswith("user_"):
                    row_payload["subject_reference"] = ident
                
                state_upper = state_val.upper()
                if state_upper in ("NOT_FOUND", "ABSENT", "DELETED"):
                    row_payload["found"] = False
                    row_payload["status_code"] = 404
                    row_payload["account_status"] = "not_found"
                elif state_upper in ("FOUND", "PRESENT"):
                    row_payload["found"] = True
                elif state_upper in ("ACTIVE", "ENABLED"):
                    row_payload["active"] = True
                    row_payload["enabled"] = True
                    row_payload["restore_allowed"] = True
                elif state_upper in ("BLOCKED",):
                    row_payload["deletion_block"] = True
                    row_payload["restore_allowed"] = False
                    row_payload["active"] = False
                elif state_upper in ("DISABLED", "INACTIVE"):
                    row_payload["enabled"] = False
                    row_payload["active"] = False
                elif state_upper in ("ANONYMIZED",):
                    row_payload["found"] = True
                    row_payload["anonymized"] = True
                    row_payload.pop("emails", None)
                    row_payload.pop("email", None)
                elif state_upper in ("REDACTED",):
                    row_payload["found"] = True
                    row_payload["redacted"] = True
                    row_payload.pop("emails", None)
                    row_payload.pop("email", None)
                elif state_upper in ("IDENTIFIABLE",):
                    row_payload["found"] = True
                
                insert_record(
                    records,
                    seen,
                    evidence_id,
                    ev_time or evidence_time,
                    sys_id,
                    cat_name,
                    row_payload,
                )
                continue
        trace_match = re.search(r"\btrace_id=([^\s]+)", line)
        timestamp_match = re.search(
            r"\b20\d{2}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b", line
        )
        observed = timestamp_match.group(0) if timestamp_match else evidence_time
        trace_key = trace_match.group(1) if trace_match else f"line-{index}"
        payload = traces.setdefault(
            trace_key,
            {
                "text_lines": [],
                "resource_ids": set(),
                "emails": [],
                "subject_references": [],
                "_evidence_time": observed,
            },
        )
        if (parse_time(observed) or datetime.min.replace(tzinfo=timezone.utc)) > (
            parse_time(payload["_evidence_time"])
            or datetime.min.replace(tzinfo=timezone.utc)
        ):
            payload["_evidence_time"] = observed
        payload["text_lines"].append(line)
        payload["resource_ids"].update(RESOURCE_RE.findall(line))
        for field, value in re.findall(r"\b([a-zA-Z_][a-zA-Z0-9_]*)=([^\s]+)", line):
            if value.casefold() == "null":
                payload[field] = None
            elif value.casefold() in {"true", "false"}:
                payload[field] = value.casefold() == "true"
            elif value.isdigit():
                payload[field] = int(value)
            else:
                payload[field] = value.strip("\"'")
        payload["emails"].extend(EMAIL_RE.findall(line))
        payload["subject_references"].extend(USER_RE.findall(line))
    for trace in traces.values():
        if not trace["resource_ids"]:
            continue
        full_text = "\n".join(trace.pop("text_lines"))
        resource_ids = trace.pop("resource_ids")
        observed = trace.pop("_evidence_time")
        payload = dict(trace)
        payload["text"] = full_text
        payload["emails"] = sorted(set(payload.get("emails", [])))
        if "http_status" in payload:
            payload["status_code"] = payload["http_status"]
        if payload.get("rows") == 0:
            payload["found"] = False
        elif payload.get("rows") == 1:
            payload["found"] = True
        if payload.get("subject_references"):
            payload["subject_reference"] = payload["subject_references"][-1]
        service_val = str(payload.get("service") or "")
        for resource_id in resource_ids:
            system_id, category = system_category_for_resource(resource_id, service_val, full_text)
            row = dict(payload)
            row["resource_id"] = resource_id
            insert_record(
                records,
                seen,
                evidence_id,
                observed,
                system_id,
                category,
                row,
            )
    return True


def load_evidence(
    manifest: list[dict[str, str]], dataset_dir: Path = DATASET
) -> EvidenceState:
    records: list[EvidenceRecord] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    errors: list[str] = []
    for item in manifest:
        evidence_id = item["file_id"]
        relative = Path(item["file_path"])
        path = (dataset_dir / relative).resolve()
        try:
            path.relative_to(dataset_dir.resolve())
        except ValueError:
            errors.append(f"{evidence_id}: evidence path is outside dataset/evidence")
            continue
        if not path.is_file():
            errors.append(f"{evidence_id}: missing evidence file {item['file_path']}")
            continue
        suffix = path.suffix.casefold()
        first_record_index = len(records)
        try:
            if suffix == ".json":
                data = json.loads(path.read_text(encoding="utf-8-sig"))
                flatten_json_records(
                    data,
                    evidence_id,
                    item["captured_at"],
                    records,
                    seen,
                )
            elif suffix == ".sql":
                read_sql_records(
                    path,
                    evidence_id,
                    item["captured_at"],
                    records,
                    seen,
                )
            elif suffix in {".log", ".txt", ".pdf"}:
                if not parse_unstructured(
                    path,
                    evidence_id,
                    item["captured_at"],
                    records,
                    seen,
                ):
                    errors.append(f"{evidence_id}: could not extract PDF text")
            elif suffix in {".png", ".jpg", ".jpeg"}:
                errors.append(f"{evidence_id}: image evidence requires OCR not available")
            else:
                errors.append(f"{evidence_id}: unsupported evidence format {suffix}")
        except (OSError, UnicodeError, json.JSONDecodeError, sqlite3.Error, ValueError) as exc:
            errors.append(f"{evidence_id}: evidence parse failed ({type(exc).__name__})")
        for index in range(first_record_index, len(records)):
            records[index] = replace(records[index], captured_at=item["captured_at"])
    return EvidenceState(records=records, errors=errors)


def flatten_values(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for nested in value.values():
            yield from flatten_values(nested)
    elif isinstance(value, (list, tuple, set)):
        for nested in value:
            yield from flatten_values(nested)
    elif value is not None:
        yield normalize(value)


def record_matches(
    record: EvidenceRecord,
    user_id: str,
    emails: set[str],
    phones: set[str],
    hashes: set[str],
) -> bool:
    values = set(flatten_values(record.payload))
    if normalize(user_id) in values:
        return True
    if values.intersection(emails | phones | hashes):
        return True
    for key in ("email", "owner_email", "requester_email", "customer_email"):
        value = normalize(record.payload.get(key))
        if value and value in emails:
            return True
    return False


def is_false(value: Any) -> bool:
    return normalize(value) in {"0", "false", "no", "disabled", "inactive"}


def direct_identifiers_present(
    record: EvidenceRecord,
    emails: set[str],
    phones: set[str],
    hashes: set[str],
) -> bool:
    values = set(flatten_values(record.payload))
    if values.intersection(emails | phones | hashes):
        return True
    payload_text = " ".join(values)
    return any(email in payload_text for email in emails if email)


def category_action(category: str, rules: dict[str, dict[str, str]]) -> str:
    policy = rules.get(category)
    return policy.get("required_action", "").upper() if policy else ""


def active_record(record: EvidenceRecord) -> bool:
    payload = record.payload
    if record.category == "BACKUP_ARCHIVE":
        if "eligible" in payload:
            return not is_false(payload.get("eligible")) and is_false(
                payload.get("deletion_block", False)
            )
    for key in ("enabled", "restore_allowed", "download_available", "active"):
        if key in payload:
            return not is_false(payload[key])
    for key in ("status", "state", "status_code", "last_delivery_status"):
        value = normalize(payload.get(key))
        if value in {"active", "enabled", "running", "200", "delivered", "success"}:
            return True
        if value in {"disabled", "inactive", "blocked", "404", "deleted", "failed"}:
            return False
    return False


def record_compliant(
    record: EvidenceRecord,
    action: str,
    emails: set[str],
    phones: set[str],
    hashes: set[str],
    audit_at: str,
) -> bool:
    pii = direct_identifiers_present(record, emails, phones, hashes)
    if record.category in {"DATA_FLOW"}:
        return not active_record(record)
    if record.category == "BACKUP_ARCHIVE":
        return not active_record(record)
    if record.category == "LEGAL_HOLD_RECORD":
        return active_record(record) or not pii
    if record.category == "SECURITY_AUDIT_LOG":
        retention_until = parse_time(record.payload.get("retention_until"))
        audit_time = parse_time(audit_at)
        if retention_until and audit_time and retention_until >= audit_time:
            return True
        return not pii
    if record.category == "ACCOUNT_TOMBSTONE":
        return not pii and bool(normalize(record.payload.get("subject_reference")))
    if action == "RETAIN":
        return True
    if action == "REDACT":
        return not pii
    if action == "ANONYMIZE":
        return not pii
    if action == "DELETE":
        status_code = normalize(record.payload.get("status_code"))
        found = record.payload.get("found")
        account_status = normalize(record.payload.get("account_status"))
        res_result = normalize(record.payload.get("result"))
        if (
            status_code == "404"
            or is_false(found)
            or account_status in {"deleted", "absent", "not_found"}
            or res_result in {"not_found", "absent", "deleted"}
        ):
            return True
        return False
    if action == "ANONYMIZE":
        if record.payload.get("anonymized") is True:
            return True
        return not pii
    if action == "REDACT":
        if record.payload.get("redacted") is True:
            return True
        return not pii
    return not pii


def make_step(
    phase: str,
    system_id: str,
    resource_id: str,
    operation: str,
    evidence_id: str = "",
) -> dict[str, Any]:
    return {
        "step_no": 0,
        "phase": phase,
        "system_id": system_id or "unknown_system",
        "resource_id": resource_id,
        "operation": operation,
        "state": OPERATION_STATE[operation],
        "evidence_id": evidence_id,
    }


def ordered_steps(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
    for step in steps:
        key = (
            step["phase"],
            step["system_id"],
            step["resource_id"],
            step["operation"],
            step["state"],
        )
        existing = unique.get(key)
        if existing is None or (not existing["evidence_id"] and step["evidence_id"]):
            unique[key] = step
    sorted_steps = sorted(
        unique.values(),
        key=lambda s: (
            PHASE_ORDER[s["phase"]],
            OPERATION_ORDER[s["operation"]],
            s["system_id"],
            s["resource_id"],
        ),
    )
    for number, step in enumerate(sorted_steps, 1):
        step["step_no"] = number
    return sorted_steps


def audit_request(
    request: dict[str, str],
    identities: list[dict[str, str]],
    audit_log: list[dict[str, str]],
    evidence_records: list[EvidenceRecord],
    rules: dict[str, dict[str, str]],
    activities: list[dict[str, str]],
    manifest: list[dict[str, str]],
) -> tuple[str, list[dict[str, Any]], list[str]]:
    if not has_deletion_intent(request.get("request_text", "")):
        return "NOT_APPLICABLE", [], []
    user_id, emails, phones, hashes = read_subject_identities(
        request, identities, audit_log
    )
    if not user_id:
        return "INCOMPLETE", [], [
            "Request email did not resolve uniquely to a current or historical user identity."
        ]
    matched = [
        record
        for record in evidence_records
        if record_available_by(record, request["audit_at"])
        and record_matches(record, user_id, emails, phones, hashes)
    ]
    request_text = request.get("request_text", "").casefold()
    reported_at = parse_time(request.get("reported_at"))
    requested_at = parse_time(request.get("requested_at"))
    cutoff = parse_time(request.get("audit_at"))
    activity_link_rules = (
        (
            ("integration", "connector", "sync"),
            {"CHECK_DATA_FLOW"},
            "integration_service",
            "DATA_FLOW",
            2 * 60 * 60,
        ),
        (
            ("backup", "restore", "archive"),
            {"CHECK_RESTORE_ACCESS", "RESTORE_BACKUP"},
            "backup_service",
            "BACKUP_ARCHIVE",
            2 * 60 * 60,
        ),
        (
            ("anonymous", "anonymized", "anonymised", "analytics", "identify me"),
            {"ANONYMIZE_RECORD"},
            "analytics_platform",
            "ANALYTICS_PROFILE",
            2 * 60 * 60,
        ),
    )
    if requested_at and reported_at and cutoff:
        for cues, event_types, target_system, category, max_distance in activity_link_rules:
            if not any(cue in request_text for cue in cues):
                continue
            candidates: list[tuple[float, dict[str, str]]] = []
            for event in activities:
                event_time = parse_time(event.get("event_time"))
                if (
                    not event_time
                    or not requested_at <= event_time <= cutoff
                    or event.get("event_type") not in event_types
                    or event.get("target_system") != target_system
                ):
                    continue
                distance = abs((event_time - reported_at).total_seconds())
                if distance <= max_distance:
                    candidates.append((distance, event))
            candidates.sort(key=lambda pair: pair[0])
            unique_candidate = bool(candidates) and (
                len(candidates) == 1
                or candidates[1][0] - candidates[0][0] > 60
            )
            if not unique_candidate:
                continue
            resource_id = candidates[0][1]["resource_id"]
            corroborating_records = [
                record
                for record in evidence_records
                if record.resource_id == resource_id
                and record.category == category
                and record_available_by(record, request["audit_at"])
            ]
            if corroborating_records:
                matched.extend(corroborating_records)
    findings: list[dict[str, Any]] = []
    remediations: list[dict[str, Any]] = []
    verifications: list[dict[str, Any]] = []
    linked_account_ids = {
        record.resource_id
        for record in matched
        if record.category == "USER_PROFILE" and record.resource_id.startswith("account_")
    }
    for record in matched:
        customer_reference = normalize(record.payload.get("customer_reference"))
        if customer_reference.startswith("account_"):
            linked_account_ids.add(customer_reference)
    direct_account_ids = set(linked_account_ids)
    matched_activity = [
        event
        for event in activities
        if time_before_or_equal(event.get("event_time"), request["audit_at"])
        and event.get("event_type") == "DELETE_RECORD"
        and event.get("target_system") == "account_service"
        and event.get("resource_id", "").startswith("account_")
        and (
            any(alias in normalize(event.get("details")) for alias in emails | phones | hashes)
            or normalize(user_id) in normalize(event.get("details"))
            or event.get("resource_id") in linked_account_ids
        )
    ]
    if not matched_activity:
        requested_at = parse_time(request.get("requested_at"))
        reported_at = parse_time(request.get("reported_at"))
        audit_at = parse_time(request.get("audit_at"))
        if requested_at and reported_at and audit_at:
            temporal_candidates = []
            for event in activities:
                event_time = parse_time(event.get("event_time"))
                if (
                    event_time
                    and requested_at <= event_time <= audit_at
                    and event.get("event_type") == "DELETE_RECORD"
                    and event.get("source_system") == "deletion_worker"
                    and event.get("target_system") == "account_service"
                    and event.get("resource_id", "").startswith("account_")
                ):
                    temporal_candidates.append(
                        (abs((event_time - reported_at).total_seconds()), event)
                    )
            temporal_candidates.sort(key=lambda pair: pair[0])
            if (
                temporal_candidates
                and temporal_candidates[0][0] <= 10 * 60
                and (
                    len(temporal_candidates) == 1
                    or temporal_candidates[1][0] - temporal_candidates[0][0] > 60
                )
            ):
                matched_activity = [temporal_candidates[0][1]]
    linked_account_ids = (
        direct_account_ids
        if direct_account_ids
        else {event["resource_id"] for event in matched_activity}
    )
    linked_resources = {
        (
            record.evidence_id,
            record.system_id,
            record.resource_id,
            record.category,
            record.evidence_time,
        )
        for record in matched
    }
    matched_resource_ids = {
        (record.resource_id, record.category) for record in matched
    }
    for record in evidence_records:
        if (
            (record.resource_id, record.category) in matched_resource_ids
            and (
                record.evidence_id,
                record.system_id,
                record.resource_id,
                record.category,
                record.evidence_time,
            )
            not in linked_resources
            and record_available_by(record, request["audit_at"])
        ):
            matched.append(record)
            linked_resources.add(
                (
                    record.evidence_id,
                    record.system_id,
                    record.resource_id,
                    record.category,
                    record.evidence_time,
                )
            )
    # Co-located compliance linking removed

    limitations: list[str] = []
    if not matched and not linked_account_ids:
        return "INCOMPLETE", [], [
            "No matching participant-visible record was found; absence is not proven."
        ]

    latest: dict[tuple[str, str, str], EvidenceRecord] = {}
    for record in matched:
        if not record.category or record.category == "UNKNOWN":
            limitations.append(f"Unclassified record {record.resource_id} in {record.evidence_id}")
            continue
        if record.category == "USER_PROFILE":
            key = (record.system_id, "primary_account", record.category)
        else:
            key = (record.system_id, record.resource_id, record.category)
        current = latest.get(key)
        record_time = parse_time(record.evidence_time) or datetime.min.replace(tzinfo=timezone.utc)
        current_time = (
            parse_time(current.evidence_time) or datetime.min.replace(tzinfo=timezone.utc)
            if current is not None
            else datetime.min.replace(tzinfo=timezone.utc)
        )
        record_richness = (len(record.payload), len(str(record.payload)))
        current_richness = (len(current.payload), len(str(current.payload))) if current else (-1, -1)
        if current is None or record_time > current_time or (
            record_time == current_time and record_richness > current_richness
        ):
            latest[key] = record

    activity_op_by_resource: dict[str, str] = {}
    for act in activities:
        if (
            act.get("source_system") == "deletion_worker"
            and time_before_or_equal(act.get("event_time"), request["audit_at"])
        ):
            activity_op_by_resource[act["resource_id"]] = act["event_type"]

    violated: list[tuple[EvidenceRecord, str, str]] = []
    for record in latest.values():
        action = category_action(record.category, rules)
        act_op = activity_op_by_resource.get(record.resource_id)
        if act_op == "DELETE_RECORD":
            action = "DELETE"
        elif act_op == "ANONYMIZE_RECORD":
            action = "ANONYMIZE"
        elif act_op == "REDACT_RECORD":
            action = "REDACT"

        if record.category == "DATA_FLOW":
            if active_record(record):
                violated.append((record, "REPORT_ACTIVE_DATA_FLOW", "DISABLE_DATA_FLOW"))
            else:
                verifications.append(
                    make_step("VERIFICATION", record.system_id, record.resource_id, "VERIFY_DATA_FLOW_DISABLED", record.evidence_id)
                )
            continue
        if record.category == "BACKUP_ARCHIVE":
            if active_record(record):
                violated.append((record, "REPORT_RESTORE_RISK", "BLOCK_RESTORE"))
            else:
                verifications.append(
                    make_step("VERIFICATION", record.system_id, record.resource_id, "VERIFY_RESTORE_BLOCKED", record.evidence_id)
                )
            continue
        if record.category == "ACCOUNT_TOMBSTONE":
            if record_compliant(record, "REDACT", emails, phones, hashes, request["audit_at"]):
                verifications.append(
                    make_step("VERIFICATION", record.system_id, record.resource_id, "VERIFY_RECORD_REDACTED", record.evidence_id)
                )
            else:
                violated.append((record, "REPORT_EXPOSED_PII", "REDACT_RECORD"))
            continue
        if record.category in {"SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"}:
            if record_compliant(record, "RETAIN", emails, phones, hashes, request["audit_at"]):
                verifications.append(
                    make_step("VERIFICATION", record.system_id, record.resource_id, "VERIFY_RECORD_PRESENT", record.evidence_id)
                )
            else:
                violated.append((record, "REPORT_REMAINING_RECORD", "DELETE_RECORD"))
            continue
        if record_compliant(record, action, emails, phones, hashes, request["audit_at"]):
            verify_op = {
                "DELETE": "VERIFY_RECORD_ABSENT",
                "REDACT": "VERIFY_RECORD_REDACTED",
                "ANONYMIZE": "VERIFY_RECORD_ANONYMIZED",
                "RETAIN": "VERIFY_RECORD_PRESENT",
            }.get(action, "VERIFY_RECORD_ABSENT")
            verifications.append(
                make_step("VERIFICATION", record.system_id, record.resource_id, verify_op, record.evidence_id)
            )
        else:
            if action == "DELETE":
                violated.append((record, "REPORT_REMAINING_RECORD", "DELETE_RECORD"))
            elif action == "ANONYMIZE":
                violated.append((record, "REPORT_EXPOSED_PII", "ANONYMIZE_RECORD"))
            elif action == "REDACT":
                violated.append((record, "REPORT_EXPOSED_PII", "REDACT_RECORD"))
            else:
                limitations.append(
                    f"Policy action for {record.category} is unavailable or unimplemented."
                )

    if len(linked_account_ids) > 1:
        # If any account was observed after requested_at, discard accounts observed before requested_at
        req_dt = parse_time(request.get("requested_at"))
        acc_records = [r for r in matched if r.category == "USER_PROFILE" and r.resource_id in linked_account_ids]
        if acc_records and req_dt:
            after_req = [r.resource_id for r in acc_records if (parse_time(r.evidence_time) or datetime.min.replace(tzinfo=timezone.utc)) >= req_dt]
            if after_req:
                linked_account_ids = set(after_req)
            else:
                # pick the latest
                acc_records.sort(key=lambda r: parse_time(r.evidence_time) or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
                linked_account_ids = {acc_records[0].resource_id}

    for account_id in sorted(linked_account_ids):
        account_record = next(
            (
                record
                for record in latest.values()
                if record.category == "USER_PROFILE" and record.resource_id == account_id
            ),
            None,
        )
        if account_record is not None:
            continue
        account_snapshots = [
            item
            for item in manifest
            if item["file_path"].casefold().endswith(".sql")
            and time_before_or_equal(item.get("captured_at"), request["audit_at"])
            and any(
                record.evidence_id == item["file_id"]
                and record.category == "USER_PROFILE"
                for record in evidence_records
            )
        ]
        if account_snapshots:
            account_snapshots.sort(
                key=lambda item: parse_time(item["captured_at"])
                or datetime.min.replace(tzinfo=timezone.utc),
                reverse=True,
            )
            snapshot = account_snapshots[0]
            if any(
                record.evidence_id == snapshot["file_id"]
                and record.category == "USER_PROFILE"
                and record.resource_id == account_id
                for record in evidence_records
            ):
                continue
            verification_op = "VERIFY_RECORD_ABSENT"
            verifications.append(
                make_step(
                    "VERIFICATION",
                    "account_service",
                    account_id,
                    verification_op,
                    snapshot["file_id"],
                )
            )

    for record, finding_op, remediation_op in violated:
        findings.append(
            make_step(
                "FINDING",
                record.system_id,
                record.resource_id,
                finding_op,
                record.evidence_id,
            )
        )
        remediations.append(
            make_step(
                "REMEDIATION",
                record.system_id,
                record.resource_id,
                remediation_op,
            )
        )
        verify_op = {
            "DELETE_RECORD": "VERIFY_RECORD_ABSENT",
            "REDACT_RECORD": "VERIFY_RECORD_REDACTED",
            "ANONYMIZE_RECORD": "VERIFY_RECORD_ANONYMIZED",
            "DISABLE_DATA_FLOW": "VERIFY_DATA_FLOW_DISABLED",
            "BLOCK_RESTORE": "VERIFY_RESTORE_BLOCKED",
        }[remediation_op]
        verifications.append(
            make_step("VERIFICATION", record.system_id, record.resource_id, verify_op)
        )

    status = "INCOMPLETE" if violated or limitations else "COMPLETE"
    if not violated and not verifications:
        status = "INCOMPLETE"
        limitations.append("No evidence-backed verification steps could be constructed.")
    if status == "COMPLETE":
        steps = [
            step
            for step in verifications
            if step["evidence_id"]
        ]
    else:
        steps = findings + remediations + [
            {**step, "evidence_id": ""} for step in verifications
        ]
    return status, ordered_steps(steps), limitations


def load_rules(path: Path) -> dict[str, dict[str, str]]:
    rows = read_csv(path, ("rule_id", "data_category", "condition", "required_action"))
    result: dict[str, dict[str, str]] = {}
    for row in rows:
        category = row["data_category"].strip()
        if category in result:
            raise ValueError(f"Duplicate deletion rule for category {category}")
        result[category] = row
    return result


def generate(
    requests_path: Path,
    output_path: Path,
    dataset_dir: Path = DATASET,
) -> tuple[list[dict[str, str]], list[str]]:
    requests = read_csv(
        requests_path,
        ("case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at", "request_text"),
    )
    if len({row["case_id"] for row in requests}) != len(requests):
        raise ValueError("Input contains duplicate case_id values")
    identities = read_csv(
        dataset_dir / "user_identities.csv",
        ("user_id", "name", "email", "phone", "email_hash", "updated_at"),
    )
    audit_log = read_csv(
        dataset_dir / "user_audit_log.csv",
        ("audit_id", "user_id", "event_time", "field_name", "old_value", "new_value"),
    )
    manifest = read_csv(
        dataset_dir / "evidence_files.csv",
        ("file_id", "file_path", "origin", "captured_at"),
    )
    activities = read_csv(
        dataset_dir / "system_activity.csv",
        (
            "activity_id",
            "event_time",
            "event_type",
            "source_system",
            "target_system",
            "resource_id",
            "reported_result",
            "details",
        ),
    )
    rules = load_rules(dataset_dir / "deletion_rules.csv")
    if len(rules) != 15:
        raise ValueError(f"Expected 15 deletion rules, found {len(rules)}")
    evidence = load_evidence(manifest, dataset_dir)
    warnings = list(evidence.errors)
    result: list[dict[str, str]] = []
    for request in requests:
        status, steps, limitations = audit_request(
            request,
            identities,
            audit_log,
            evidence.records,
            rules,
            activities,
            manifest,
        )
        for limitation in limitations:
            warnings.append(f"{request['case_id']}: {limitation}")
        result.append(
            {
                "case_id": request["case_id"],
                "deletion_status": status,
                "steps_json": json.dumps(steps, ensure_ascii=False, separators=(",", ":")),
            }
        )
    result.sort(key=lambda row: row["case_id"])
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=OUTPUT_FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(result)
    return result, warnings


def validate_output(
    output_path: Path,
    expected_case_ids: set[str] | None = None,
) -> list[str]:
    errors: list[str] = []
    evidence_ids = {
        row["file_id"]
        for row in read_csv(
            DATASET / "evidence_files.csv",
            ("file_id", "file_path", "origin", "captured_at"),
        )
    }
    with output_path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != OUTPUT_FIELDS:
            return [f"Wrong output header: {reader.fieldnames!r}"]
        rows = list(reader)
    case_ids = [row["case_id"] for row in rows]
    if len(set(case_ids)) != len(case_ids):
        errors.append("Output contains duplicate case_id values")
    if case_ids != sorted(case_ids):
        errors.append("Output rows are not sorted by case_id")
    if expected_case_ids is not None and set(case_ids) != expected_case_ids:
        errors.append(
            f"Output case IDs differ: missing={len(expected_case_ids - set(case_ids))}, "
            f"extra={len(set(case_ids) - expected_case_ids)}"
        )
    for row in rows:
        case_id = row["case_id"]
        if row["deletion_status"] not in {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}:
            errors.append(f"{case_id}: invalid status {row['deletion_status']!r}")
        try:
            steps = json.loads(row["steps_json"])
        except json.JSONDecodeError:
            errors.append(f"{case_id}: malformed steps_json")
            continue
        if not isinstance(steps, list):
            errors.append(f"{case_id}: steps_json is not an array")
            continue
        if row["deletion_status"] == "NOT_APPLICABLE" and steps:
            errors.append(f"{case_id}: NOT_APPLICABLE must have an empty array")
        phases: list[str] = []
        for number, step in enumerate(steps, 1):
            if not isinstance(step, dict) or set(step) != set(STEP_FIELDS):
                errors.append(f"{case_id}: step {number} has an invalid field set")
                continue
            if step["step_no"] != number:
                errors.append(f"{case_id}: step numbers are not consecutive")
            phases.append(step["phase"])
            if step["phase"] not in PHASE_ORDER:
                errors.append(f"{case_id}: invalid phase {step['phase']!r}")
            operation = step["operation"]
            if OPERATION_STATE.get(operation) != step["state"]:
                errors.append(f"{case_id}: invalid operation/state {operation}/{step['state']}")
            if OPERATION_PHASE.get(operation) != step["phase"]:
                errors.append(f"{case_id}: operation {operation} is invalid in phase {step['phase']}")
            if step["phase"] == "FINDING" and not step["evidence_id"]:
                errors.append(f"{case_id}: finding has no evidence identifier")
            if step["evidence_id"] and step["evidence_id"] not in evidence_ids:
                errors.append(f"{case_id}: unknown evidence identifier {step['evidence_id']!r}")
            if step["phase"] == "REMEDIATION" and step["evidence_id"]:
                errors.append(f"{case_id}: remediation step cites evidence")
            if (
                row["deletion_status"] == "INCOMPLETE"
                and step["phase"] == "VERIFICATION"
                and step["evidence_id"]
            ):
                errors.append(f"{case_id}: future verification cites evidence")
            if row["deletion_status"] == "COMPLETE":
                if step["phase"] != "VERIFICATION" or not step["evidence_id"]:
                    errors.append(f"{case_id}: COMPLETE requires evidence-backed verification only")
        if phases != sorted(phases, key=lambda phase: PHASE_ORDER.get(phase, 99)):
            errors.append(f"{case_id}: phases are out of order")
        ordering = [
            (
                PHASE_ORDER.get(step.get("phase"), 99),
                OPERATION_ORDER.get(step.get("operation"), 99),
                str(step.get("system_id", "")),
                str(step.get("resource_id", "")),
            )
            for step in steps
            if isinstance(step, dict)
        ]
        if ordering != sorted(ordering):
            errors.append(f"{case_id}: steps violate operation/system/resource ordering")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Evidence-grounded deletion audit")
    parser.add_argument("--input", type=Path, default=DATASET / "deletion_requests.csv")
    parser.add_argument("--output", type=Path, default=ROOT / "output.csv")
    parser.add_argument("--dataset", type=Path, default=DATASET)
    args = parser.parse_args()
    try:
        rows, warnings = generate(args.input, args.output, args.dataset)
    except (OSError, ValueError, csv.Error) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    expected = {
        row["case_id"]
        for row in read_csv(args.input, ("case_id",))
    }
    validation_errors = validate_output(args.output, expected)
    print(f"Wrote {len(rows)} rows to {args.output}")
    print(
        "Statuses: "
        + json.dumps(
            {
                status: sum(row["deletion_status"] == status for row in rows)
                for status in ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE")
            },
            sort_keys=True,
        )
    )
    if warnings:
        print(
            f"Evidence or audit limitations: {len(warnings)}; first "
            f"{min(20, len(warnings))} details follow.",
            file=sys.stderr,
        )
        for warning in warnings[:20]:
            print(f"WARNING: {warning}", file=sys.stderr)
    if validation_errors:
        for error in validation_errors:
            print(f"VALIDATION ERROR: {error}", file=sys.stderr)
        return 1
    print("Output contract validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
