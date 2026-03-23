from __future__ import annotations

import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from core.pipeline import ExperimentOrchestrator
from core.schemas import ExperimentRequest, RemediationRequest

orchestrator = ExperimentOrchestrator()
DEFAULT_ORIGINS = ("http://127.0.0.1:5173", "http://localhost:5173")


def allowed_origins() -> set[str]:
    raw = os.getenv("SNSX_ALLOWED_ORIGINS", "")
    if not raw.strip():
        return set(DEFAULT_ORIGINS)
    return {x.strip() for x in raw.split(",") if x.strip()}


class Handler(BaseHTTPRequestHandler):
    def _origin_header(self) -> str:
        req_origin = self.headers.get("Origin", "").strip()
        allowed = allowed_origins()
        if req_origin and req_origin in allowed:
            return req_origin
        return sorted(allowed)[0]

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", self._origin_header())
        self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        self._send(200, {"ok": True})

    def do_GET(self) -> None:
        if self.path == "/":
            self._send(
                200,
                {
                    "service": "snsx-crs-fallback",
                    "status": "ok",
                    "endpoints": [
                        "/health",
                        "/experiments/run",
                        "/experiments/{experiment_id}",
                        "/experiments/{experiment_id}/remediate",
                    ],
                },
            )
            return

        if self.path == "/health":
            self._send(200, {"status": "ok", "service": "snsx-crs-fallback"})
            return

        m = re.fullmatch(r"/experiments/([A-Za-z0-9-]+)", self.path)
        if m:
            experiment_id = m.group(1)
            result = orchestrator.get(experiment_id)
            if not result:
                self._send(404, {"detail": "Experiment not found"})
                return
            self._send(200, result.model_dump(mode="json"))
            return

        self._send(404, {"detail": "Not found"})

    def do_POST(self) -> None:
        if self.path == "/experiments/run":
            length = int(self.headers.get("Content-Length", "0"))
            payload = self.rfile.read(length) if length > 0 else b"{}"
            try:
                data = json.loads(payload.decode("utf-8"))
                if data.get("software_path", None) is None:
                    data["software_path"] = ""
                request = ExperimentRequest(**data)
                result = orchestrator.run(request)
                self._send(200, result.model_dump(mode="json"))
                return
            except FileNotFoundError as exc:
                self._send(400, {"detail": str(exc)})
                return
            except Exception as exc:
                self._send(500, {"detail": f"Experiment failed: {exc}"})
                return

        rem = re.fullmatch(r"/experiments/([A-Za-z0-9-]+)/remediate", self.path)
        if rem:
            experiment_id = rem.group(1)
            length = int(self.headers.get("Content-Length", "0"))
            payload = self.rfile.read(length) if length > 0 else b"{}"
            try:
                data = json.loads(payload.decode("utf-8"))
                request = RemediationRequest(**data)
                result = orchestrator.remediate(experiment_id, request)
                self._send(200, result.model_dump(mode="json"))
                return
            except FileNotFoundError as exc:
                self._send(404, {"detail": str(exc)})
                return
            except Exception as exc:
                self._send(500, {"detail": f"Remediation failed: {exc}"})
                return

        if self.path != "/experiments/run":
            self._send(404, {"detail": "Not found"})
            return


def run(host: str = "127.0.0.1", port: int = 8000) -> None:
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"Fallback backend serving on http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    run(args.host, args.port)
