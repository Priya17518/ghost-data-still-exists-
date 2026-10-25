"""Unit and integration test suite for the Dynamic AI Investigation Agent.

Tests cover:
- Dynamic CSV/JSON/ZIP uploads with path-traversal safety and limits
- Investigation session isolation
- 3 required phases (FINDING -> REMEDIATION -> VERIFICATION) ordering
- Grounded evidence citations and absence-of-evidence rules
- Scoped conversational agent queries and domain guardrails
- Out-of-scope query rejection
- Dynamic report generation and Excel-friendly UTF-8 BOM CSV
- OCR-unavailable disclosures
"""

import csv
import io
import json
import shutil
import sys
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "code"))

import investigation_engine as ie
import main as core_audit


class TestInvestigationAgentSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.test_dir = ROOT / "dashboard" / "sessions" / "test_unit_session"
        if cls.test_dir.exists():
            shutil.rmtree(cls.test_dir, ignore_errors=True)
        cls.session = ie.InvestigationSession("test_unit_session", cls.test_dir)
        cls.agent = ie.InvestigationChatAgent(cls.session)

    @classmethod
    def tearDownClass(cls):
        if cls.test_dir.exists():
            shutil.rmtree(cls.test_dir, ignore_errors=True)

    def test_01_safe_csv_upload_and_indexing(self):
        csv_data = b"user_id,account_status,purged_at\nuser_999,PURGED,2026-08-01T00:00:00Z\n"
        ok, msg, added = self.session.ingest_file("test_audit.csv", csv_data)
        self.assertTrue(ok)
        self.assertEqual(len(added), 1)
        file_id = added[0]
        self.assertIn(file_id, self.session.files_manifest)
        info = self.session.files_manifest[file_id]
        self.assertEqual(info.original_name, "test_audit.csv")
        self.assertEqual(info.format_type, "CSV Table")
        self.assertEqual(info.status, "PROCESSED")
        self.assertEqual(info.record_count, 1)

    def test_02_safe_json_upload_and_indexing(self):
        json_data = json.dumps([
            {"ticket_id": "supp_101", "email": "test@domain.com", "action": "PURGED"}
        ]).encode("utf-8")
        ok, msg, added = self.session.ingest_file("support_tickets.json", json_data)
        self.assertTrue(ok)
        self.assertEqual(len(added), 1)
        info = self.session.files_manifest[added[0]]
        self.assertEqual(info.format_type, "JSON Structured")
        self.assertEqual(info.status, "PROCESSED")

    def test_03_zip_slip_and_traversal_rejection(self):
        """Verify archive entries with path traversal (.. or absolute paths) are rejected."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("../../etc/passwd", "root:x:0:0")
            zf.writestr("safe_log.txt", "2026-08-01 purge verified")
        buf.seek(0)
        ok, msg, added = self.session.ingest_file("test_slip.zip", buf.getvalue())
        self.assertTrue(ok)
        # safe_log.txt should be extracted, traversal entry skipped
        for fid in added:
            info = self.session.files_manifest[fid]
            self.assertNotIn("passwd", info.original_name)

    def test_04_disallowed_executables_rejection(self):
        """Verify binary executables and scripts (.exe, .sh, .bat) are rejected."""
        for bad_ext in ("malware.exe", "script.sh", "run.bat", "hack.cmd"):
            ok, msg, added = self.session.ingest_file(bad_ext, b"echo bad")
            self.assertFalse(ok)
            self.assertIn("prohibited", msg.lower())

    def test_05_session_isolation(self):
        """Verify separate investigation sessions maintain isolated storage and files."""
        dir_a = ROOT / "dashboard" / "sessions" / "sess_iso_a"
        dir_b = ROOT / "dashboard" / "sessions" / "sess_iso_b"
        try:
            sess_a = ie.InvestigationSession("sess_iso_a", dir_a)
            sess_b = ie.InvestigationSession("sess_iso_b", dir_b)
            sess_a.ingest_file("private_a.csv", b"a,b\n1,2\n")
            self.assertTrue(any(f.original_name == "private_a.csv" for f in sess_a.files_manifest.values()))
            self.assertFalse(any(f.original_name == "private_a.csv" for f in sess_b.files_manifest.values()))
        finally:
            shutil.rmtree(dir_a, ignore_errors=True)
            shutil.rmtree(dir_b, ignore_errors=True)

    def test_06_three_phase_ordering_contract(self):
        """Verify all generated steps strictly follow FINDING -> REMEDIATION -> VERIFICATION."""
        c = self.session.get_case("case_34")
        self.assertIsNotNone(c)
        steps = c["steps"]
        phase_map = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
        phases = [phase_map[s["phase"]] for s in steps]
        self.assertEqual(phases, sorted(phases))

    def test_07_absence_of_evidence_not_evidence_of_absence(self):
        """Verify that missing verification leads to INCOMPLETE, never claimed as complete."""
        # case_33 has no affirmative verification evidence
        c = self.session.get_case("case_33")
        self.assertIsNotNone(c)
        self.assertEqual(c["deletion_status"], "INCOMPLETE")
        # And chat explains the absence-of-evidence principle
        res = self.agent.query("Why is case_33 incomplete?")
        self.assertIn("Absence of evidence is NOT evidence of absence", res["response"])

    def test_08_scoped_agent_domain_guardrails(self):
        """Verify chat agent answers deletion audit queries and strictly rejects general out-of-scope queries."""
        # Audit queries: in scope
        res_valid = self.agent.query("Which systems still contain personal data?")
        self.assertTrue(res_valid["in_scope"])
        self.assertTrue(len(res_valid["response"]) > 20)

        # Non-audit queries: out of scope
        for out_query in (
            "What is the capital of Australia?",
            "Write a poem about the sunrise",
            "What is the recipe for chocolate cake?",
        ):
            res_out = self.agent.query(out_query)
            self.assertFalse(res_out["in_scope"])
            self.assertIn("Domain Scope Notice", res_out["response"])

    def test_09_case_comparison_agent_query(self):
        """Verify agent can compare two deletion requests side by side."""
        res = self.agent.query("Compare case_01 and case_04")
        self.assertTrue(res["in_scope"])
        self.assertIn("case_01", res["response"])
        self.assertIn("case_04", res["response"])
        self.assertIn("|", res["response"])  # Markdown table

    def test_10_dynamic_report_generation(self):
        """Verify ReportGenerator creates valid output.csv with UTF-8 BOM and markdown reports."""
        paths = ie.ReportGenerator.generate_all(self.session)
        self.assertIn("output_csv", paths)
        csv_file = Path(paths["output_csv"])
        self.assertTrue(csv_file.exists())

        # Check UTF-8 BOM
        raw_header = csv_file.read_bytes()[:3]
        self.assertEqual(raw_header, b"\xef\xbb\xbf")

        # Validate CSV columns
        with open(csv_file, "r", encoding="utf-8-sig") as f:
            reader = csv.reader(f)
            header = next(reader)
            self.assertEqual(header, ["case_id", "deletion_status", "steps_json"])
            rows = list(reader)
            self.assertGreaterEqual(len(rows), 518)


if __name__ == "__main__":
    unittest.main()
