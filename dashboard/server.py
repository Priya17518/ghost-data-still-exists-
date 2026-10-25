import base64
import http.server
import json
import os
import socketserver
import sys
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "code"))

import investigation_engine as engine

DASHBOARD_DIR = ROOT / "dashboard"
PORT = 8080

# Shared active investigation session
active_session = engine.InvestigationSession("default")
chat_agent = engine.InvestigationChatAgent(active_session)


class DashboardHandler(http.server.SimpleHTTPRequestHandler):
    def send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def send_file_download(self, file_path: Path, filename: str, content_type: str = "text/plain"):
        if not file_path.exists():
            self.send_error(404, f"File {filename} not found")
            return
        content = file_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(content)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # Static index / data routes
        if path in ("/", "/index.html"):
            return self.serve_file(DASHBOARD_DIR / "index.html", "text/html; charset=utf-8")
        if path == "/data.json":
            return self.serve_file(DASHBOARD_DIR / "data.json", "application/json; charset=utf-8")
        if path == "/output.csv":
            return self.serve_file(ROOT / "output.csv", "text/csv; charset=utf-8")

        # API: Session info
        if path == "/api/session":
            return self.send_json({
                "session_id": active_session.session_id,
                "meta": active_session.cached_meta,
                "files_count": len(active_session.files_manifest),
                "cases_count": len(active_session.cached_cases),
            })

        # API: List uploaded & indexed files
        if path == "/api/files":
            files = [info.__dict__ for info in active_session.files_manifest.values()]
            return self.send_json({"files": files})

        # API: Cases list with filtering
        if path == "/api/cases":
            status_filter = query.get("status", [None])[0]
            ghost_filter = query.get("ghost", [None])[0]
            search_filter = query.get("search", [None])[0]

            filtered = active_session.cached_cases
            if status_filter and status_filter.upper() != "ALL":
                filtered = [c for c in filtered if c["deletion_status"] == status_filter.upper()]
            if ghost_filter == "true":
                filtered = [c for c in filtered if c["is_ghost"]]
            if search_filter:
                term = search_filter.lower()
                filtered = [
                    c for c in filtered
                    if term in c["case_id"].lower()
                    or term in c["email"].lower()
                    or term in c.get("request_text", "").lower()
                ]

            page = int(query.get("page", ["1"])[0])
            limit = int(query.get("limit", ["25"])[0])
            start = (page - 1) * limit
            end = start + limit
            paged = filtered[start:end]

            return self.send_json({
                "total": len(filtered),
                "page": page,
                "limit": limit,
                "total_pages": max(1, (len(filtered) + limit - 1) // limit),
                "cases": paged,
            })

        # API: Single case details
        if path.startswith("/api/case/"):
            case_id = path.split("/api/case/")[1].strip()
            case = active_session.get_case(case_id)
            if not case:
                return self.send_json({"error": f"Case {case_id} not found"}, status=404)
            return self.send_json({"case": case})

        # API: Download generated reports
        if path.startswith("/api/download/"):
            report_type = path.split("/api/download/")[1].strip()
            reports_dir = active_session.reports_dir
            if report_type == "output.csv":
                p = reports_dir / "output.csv"
                if not p.exists():
                    p = ROOT / "output.csv"
                return self.send_file_download(p, "output.csv", "text/csv; charset=utf-8")
            elif report_type == "investigation_report.md":
                return self.send_file_download(
                    reports_dir / "investigation_report.md", "investigation_report.md", "text/markdown; charset=utf-8"
                )
            elif report_type == "investigation_report.json":
                return self.send_file_download(
                    reports_dir / "investigation_report.json", "investigation_report.json", "application/json; charset=utf-8"
                )
            elif report_type == "evidence_limitations.md":
                return self.send_file_download(
                    reports_dir / "evidence_limitations.md", "evidence_limitations.md", "text/markdown; charset=utf-8"
                )
            return self.send_json({"error": f"Unknown report type: {report_type}"}, status=404)

        return super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        content_length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_length) if content_length > 0 else b""

        # API: File upload (supports JSON base64 or multipart/form-data)
        if path == "/api/upload":
            content_type = self.headers.get("Content-Type", "")
            if "application/json" in content_type:
                try:
                    payload = json.loads(raw_body.decode("utf-8"))
                    filename = payload.get("filename", "upload.dat")
                    b64content = payload.get("content", "")
                    content_bytes = base64.b64decode(b64content)
                    success, message, added_ids = active_session.ingest_file(filename, content_bytes)
                    return self.send_json({"success": success, "message": message, "added_ids": added_ids})
                except Exception as exc:
                    return self.send_json({"success": False, "error": str(exc)}, status=400)
            elif "multipart/form-data" in content_type:
                try:
                    # Simple boundary parsing
                    boundary = content_type.split("boundary=")[1].encode()
                    parts = raw_body.split(b"--" + boundary)
                    uploaded_count = 0
                    messages = []
                    for part in parts:
                        if b'filename="' in part:
                            header_part, file_data = part.split(b"\r\n\r\n", 1)
                            # Remove trailing \r\n
                            if file_data.endswith(b"\r\n"):
                                file_data = file_data[:-2]
                            # Extract filename
                            header_text = header_part.decode("utf-8", errors="replace")
                            fname_match = urllib.parse.unquote(
                                header_text.split('filename="')[1].split('"')[0]
                            )
                            if fname_match:
                                ok, msg, added = active_session.ingest_file(fname_match, file_data)
                                if ok:
                                    uploaded_count += len(added) if added else 1
                                messages.append(msg)
                    return self.send_json({
                        "success": uploaded_count > 0,
                        "uploaded_count": uploaded_count,
                        "message": "; ".join(messages),
                    })
                except Exception as exc:
                    return self.send_json({"success": False, "error": str(exc)}, status=400)
            else:
                return self.send_json({"success": False, "error": "Unsupported Content-Type"}, status=400)

        # API: Trigger Audit Run
        if path == "/api/audit":
            try:
                meta = active_session.rerun_audit()
                return self.send_json({"success": True, "meta": meta})
            except Exception as exc:
                return self.send_json({"success": False, "error": str(exc)}, status=500)

        # API: Chat Agent Query
        if path == "/api/chat":
            try:
                payload = json.loads(raw_body.decode("utf-8"))
                user_msg = payload.get("message", "")
                case_id = payload.get("case_id", "")
                res = chat_agent.query(user_msg, case_id)
                return self.send_json(res)
            except Exception as exc:
                return self.send_json({"error": str(exc)}, status=400)

        # API: Generate Reports
        if path == "/api/generate-reports":
            try:
                paths = engine.ReportGenerator.generate_all(active_session)
                return self.send_json({"success": True, "reports": paths})
            except Exception as exc:
                return self.send_json({"success": False, "error": str(exc)}, status=500)

        return self.send_error(404, "Endpoint not found")

    def do_DELETE(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path.startswith("/api/files/"):
            file_id = path.split("/api/files/")[1].strip()
            removed = active_session.remove_file(file_id)
            return self.send_json({"success": removed, "file_id": file_id})
        return self.send_error(404, "Endpoint not found")

    def serve_file(self, file_path: Path, content_type: str):
        if not file_path.exists():
            self.send_error(404, f"File not found: {file_path.name}")
            return
        content = file_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, format, *args):
        # Keep server log clean
        sys.stderr.write(f"[{self.log_date_time_string()}] {args[0]}\n")


def run(port=PORT):
    for p in range(port, port + 10):
        try:
            with socketserver.TCPServer(("", p), DashboardHandler) as httpd:
                print(f"Ghost Data Audit Agent Server running at: http://localhost:{p}")
                sys.stdout.flush()
                httpd.serve_forever()
        except OSError as e:
            if "Address already in use" in str(e) or e.errno == 10048:
                continue
            raise


if __name__ == "__main__":
    p = int(sys.argv[1]) if len(sys.argv) > 1 else PORT
    run(p)
