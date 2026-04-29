from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from .config import AppConfig
from .ingestion.readers import EventReader
from .processing.pipeline import ThreatDetectionPipeline


ASSET_DIR = Path(__file__).resolve().parent / "web"


def serve_dashboard(config: AppConfig, host: str = "127.0.0.1", port: int = 8000) -> None:
    pipeline = ThreatDetectionPipeline(config)
    reader = EventReader()

    class DashboardHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            route = urlparse(self.path).path
            if route == "/":
                self._serve_file(ASSET_DIR / "index.html", "text/html; charset=utf-8")
                return
            if route == "/assets/app.css":
                self._serve_file(ASSET_DIR / "app.css", "text/css; charset=utf-8")
                return
            if route == "/assets/app.js":
                self._serve_file(ASSET_DIR / "app.js", "application/javascript; charset=utf-8")
                return
            if route == "/api/report":
                self._send_json(pipeline.repository.build_report())
                return

            self.send_error(HTTPStatus.NOT_FOUND, "Not found")

        def do_POST(self) -> None:  # noqa: N802
            route = urlparse(self.path).path
            if route == "/api/simulate":
                summary = pipeline.handle_events(reader.sample_events())
                self._send_json(summary.to_dict(), status=HTTPStatus.CREATED)
                return
            if route == "/api/demo":
                decision = pipeline.handle_event(_build_demo_event())
                self._send_json(decision.to_dict(), status=HTTPStatus.CREATED)
                return
            if route == "/api/feedback":
                payload = self._read_json()
                pipeline.repository.record_feedback(
                    payload["event_id"],
                    payload["actual_label"],
                    payload.get("notes", ""),
                )
                self._send_json({"status": "recorded"})
                return
            if route == "/api/upload":
                payload = self._read_json()
                suffix = Path(payload["filename"]).suffix or ".jsonl"
                events = reader.read_text(payload["content"], suffix)
                summary = pipeline.handle_events(events)
                self._send_json(summary.to_dict(), status=HTTPStatus.CREATED)
                return

            self.send_error(HTTPStatus.NOT_FOUND, "Not found")

        def log_message(self, format: str, *args: object) -> None:
            return

        def _read_json(self) -> dict:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length).decode("utf-8") if length else "{}"
            return json.loads(body or "{}")

        def _serve_file(self, path: Path, content_type: str) -> None:
            if not path.exists():
                self.send_error(HTTPStatus.NOT_FOUND, "Missing asset")
                return
            data = path.read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _send_json(self, payload: dict, status: HTTPStatus = HTTPStatus.OK) -> None:
            data = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = ThreadingHTTPServer((host, port), DashboardHandler)
    print(f"Dashboard running at http://{host}:{port}")
    server.serve_forever()


def _build_demo_event():
    from .main import build_demo_event

    return build_demo_event()
