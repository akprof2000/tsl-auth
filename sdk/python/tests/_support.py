"""Общее для контрактных тестов: путь к src, загрузка vectors.json, заглушка JWKS."""
from __future__ import annotations

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

SDK_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(SDK_DIR, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

_VECTORS = os.environ.get("SDK_CONTRACT_VECTORS") or os.path.join(SDK_DIR, "..", "..", "tests", "sdk-contract", "vectors.json")


def load_vectors() -> dict:
    with open(_VECTORS, encoding="utf-8") as f:
        return json.load(f)


def case(vectors: dict, name: str) -> dict:
    return next(c for c in vectors["cases"] if c["name"] == name)


def free_port() -> int:
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class JwksStub:
    """Локальный JWKS: отдаёт `document`, считает обращения."""

    def __init__(self, document: dict):
        self.document = document
        self.hits = 0
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                stub.hits += 1
                body = json.dumps(stub.document).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}/jwks"
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
