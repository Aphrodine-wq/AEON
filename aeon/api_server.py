"""AEON Verification API Server.

A REST API that exposes AEON's analysis engines over HTTP.
Plug this into CI/CD pipelines, VS Code extensions, or any tool.

Usage:
    python -m aeon.api_server          # Start on port 8000
    python -m aeon.api_server --port 3000

Endpoints:
    POST /verify/python      — Verify Python code
    POST /verify/java        — Verify Java code
    POST /verify/javascript  — Verify JavaScript code
    POST /verify/typescript  — Verify TypeScript code
    POST /verify/go          — Verify Go code
    POST /verify/rust        — Verify Rust code
    POST /verify/c           — Verify C code
    POST /verify/cpp         — Verify C++ code
    POST /verify/ruby        — Verify Ruby code
    POST /verify/aeon        — Verify AEON code
    POST /verify             — Auto-detect or specify language
    GET  /health             — Health check
    GET  /analyses           — List available analyses
    GET  /languages          — List supported languages
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import traceback
from collections import defaultdict
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any, Dict, Optional
from urllib.parse import urlparse, parse_qs

# ── Security Constants ──────────────────────────────────────
MAX_BODY_SIZE = 1 * 1024 * 1024  # 1 MB max request body
MAX_SOURCE_LENGTH = 500_000       # 500K chars max source code
RATE_LIMIT_WINDOW = 60            # seconds
RATE_LIMIT_MAX = 60               # requests per window per IP
ALLOWED_ORIGINS = os.environ.get("AEON_CORS_ORIGINS", "*")

# ── Rate limiter ────────────────────────────────────────────
_rate_buckets: Dict[str, list] = defaultdict(list)

def _rate_limit_check(client_ip: str) -> bool:
    """Return True if the request should be rejected (rate exceeded)."""
    now = time.monotonic()
    bucket = _rate_buckets[client_ip]
    # Prune old entries
    _rate_buckets[client_ip] = [t for t in bucket if now - t < RATE_LIMIT_WINDOW]
    if len(_rate_buckets[client_ip]) >= RATE_LIMIT_MAX:
        return True
    _rate_buckets[client_ip].append(now)
    return False


def _verify_language(source: str, language: str, analyses: Optional[list] = None,
                     deep_verify: bool = True) -> Dict[str, Any]:
    """Run AEON verification on source code in any supported language."""
    from aeon.language_adapter import verify
    result = verify(source, language, deep_verify=deep_verify, analyses=analyses)
    return result.to_dict()


def _verify_python_code(source: str, analyses: Optional[list] = None,
                        deep_verify: bool = True) -> Dict[str, Any]:
    """Run AEON verification on Python source code."""
    return _verify_language(source, "python", analyses=analyses, deep_verify=deep_verify)


def _verify_aeon_code(source: str, deep_verify: bool = True) -> Dict[str, Any]:
    """Run AEON verification on AEON source code."""
    from aeon.parser import parse
    from aeon.pass1_prove import prove
    from aeon.errors import CompileError

    try:
        program = parse(source)
    except CompileError as e:
        return {
            "verified": False,
            "errors": [json.loads(e.to_json())],
            "warnings": [],
            "summary": f"Parse error: {e}",
        }

    errors = prove(program, deep_verify=deep_verify)

    error_list = []
    warning_list = []
    for e in errors:
        d = e.to_dict()
        if e.kind.value in ("type_error", "ownership_error"):
            error_list.append(d)
        else:
            warning_list.append(d)

    verified = len(error_list) == 0
    return {
        "verified": verified,
        "errors": error_list,
        "warnings": warning_list,
        "summary": f"{'✅ VERIFIED' if verified else f'❌ {len(error_list)} bug(s) found'}"
                   f" ({len(warning_list)} warnings)" if warning_list else
                   f"{'✅ VERIFIED' if verified else f'❌ {len(error_list)} bug(s) found'}",
    }


AVAILABLE_ANALYSES = [
    {"id": "refinement", "name": "Liquid Type Inference", "paper": "Rondon et al., PLDI 2008"},
    {"id": "abstract", "name": "Abstract Interpretation", "paper": "Cousot & Cousot, POPL 1977"},
    {"id": "termination", "name": "Size-Change Termination", "paper": "Lee et al., POPL 2001"},
    {"id": "hoare", "name": "Hoare Logic / wp-Calculus", "paper": "Dijkstra 1975, Hoare 1969"},
    {"id": "effects", "name": "Algebraic Effects", "paper": "Plotkin & Pretnar, ESOP 2009"},
    {"id": "category", "name": "Category-Theoretic Semantics", "paper": "Moggi, Info. & Comp. 1991"},
    {"id": "security", "name": "Information Flow / Noninterference", "paper": "Volpano et al., JCS 1996"},
    {"id": "dependent", "name": "Dependent Types / Curry-Howard", "paper": "Martin-Löf 1984"},
    {"id": "certified", "name": "Certified Compilation", "paper": "Leroy, CACM 2009"},
    {"id": "symbolic", "name": "Symbolic Execution", "paper": "King, CACM 1976"},
    {"id": "separation", "name": "Separation Logic", "paper": "Reynolds, LICS 2002; O'Hearn et al., CSL 2001"},
    {"id": "taint", "name": "Taint Analysis", "paper": "Schwartz et al., IEEE S&P 2010"},
    {"id": "concurrency", "name": "Concurrency Verification", "paper": "Owicki & Gries, CACM 1976; Lamport 1978"},
    {"id": "shape", "name": "Shape Analysis", "paper": "Sagiv et al., TOPLAS 2002"},
    {"id": "model", "name": "Bounded Model Checking", "paper": "Clarke et al. 1986; Biere et al., TACAS 1999"},
    {"id": "gradual", "name": "Gradual Typing Verification", "paper": "Siek & Taha 2006; Siek et al., SNAPL 2015"},
    {"id": "linear", "name": "Linear / Affine Resource Analysis", "paper": "Girard 1987; Hofmann & Jost, ESOP 2003"},
    {"id": "probabilistic", "name": "Probabilistic Program Analysis", "paper": "Kozen 1981; Gordon et al., FOSE 2014"},
    {"id": "relational", "name": "Relational Verification / 2-Safety", "paper": "Barthe et al., FM 2011; Benton, POPL 2004"},
    {"id": "session", "name": "Session Types / Protocol Verification", "paper": "Honda et al., POPL 2008; Wadler, ICFP 2012"},
    {"id": "complexity", "name": "Automatic Complexity Analysis (RAML)", "paper": "Hoffmann et al., TOPLAS 2012; Gulwani et al., POPL 2009"},
    {"id": "abstract_refinement", "name": "Abstract Refinement Types", "paper": "Vazou et al., ESOP 2013; Vazou et al., ICFP 2014"},
    {"id": "privacy", "name": "Differential Privacy Verification", "paper": "Reed & Pierce, ICFP 2010; Gaboardi et al., POPL 2013"},
    {"id": "typestate", "name": "Type-State Analysis", "paper": "Strom & Yemini 1986; DeLine & Fähndrich, ECOOP 2004"},
    {"id": "interpolation", "name": "Craig Interpolation / CEGAR", "paper": "McMillan, CAV 2003; Henzinger et al., POPL 2004"},
]


class AeonAPIHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the AEON API."""

    def do_GET(self):
        client_ip = self.client_address[0]
        if _rate_limit_check(client_ip):
            self._json_response(429, {"error": "Rate limit exceeded. Try again later."})
            return

        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/health":
            from aeon.language_adapter import supported_languages
            langs = [l["id"] for l in supported_languages()]
            self._json_response(200, {
                "status": "ok", "version": "0.5.0",
                "supported_languages": langs,
            })

        elif path == "/analyses":
            self._json_response(200, {"analyses": AVAILABLE_ANALYSES})

        elif path == "/languages":
            from aeon.language_adapter import supported_languages
            self._json_response(200, {"languages": supported_languages()})

        else:
            self._json_response(404, {"error": "Not found", "endpoints": [
                "GET  /health", "GET  /analyses", "GET  /languages",
                "POST /verify/python", "POST /verify/java",
                "POST /verify/javascript", "POST /verify/typescript",
                "POST /verify/go", "POST /verify/rust",
                "POST /verify/c", "POST /verify/cpp",
                "POST /verify/ruby", "POST /verify/swift",
                "POST /verify/kotlin", "POST /verify/php",
                "POST /verify/scala", "POST /verify/dart",
                "POST /verify/lua", "POST /verify/r",
                "POST /verify/elixir", "POST /verify/haskell",
                "POST /verify/ocaml", "POST /verify/zig",
                "POST /verify/julia",
                "POST /verify/aeon", "POST /verify (auto-detect)",
            ]})

    def do_POST(self):
        client_ip = self.client_address[0]
        if _rate_limit_check(client_ip):
            self._json_response(429, {"error": "Rate limit exceeded. Try again later."})
            return

        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        # Read body with size limit
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > MAX_BODY_SIZE:
            self._json_response(413, {"error": f"Request body too large. Maximum is {MAX_BODY_SIZE} bytes."})
            return
        body = self.rfile.read(content_length).decode("utf-8") if content_length else ""

        try:
            payload = json.loads(body) if body else {}
        except json.JSONDecodeError:
            self._json_response(400, {"error": "Invalid JSON"})
            return

        source = payload.get("source", payload.get("code", ""))
        analyses = payload.get("analyses", None)
        deep_verify = payload.get("deep_verify", True)

        if not source:
            self._json_response(400, {"error": "Missing 'source' field in request body"})
            return

        if len(source) > MAX_SOURCE_LENGTH:
            self._json_response(413, {"error": f"Source code too large. Maximum is {MAX_SOURCE_LENGTH} characters."})
            return

        try:
            if path == "/verify/python":
                result = _verify_language(source, "python", analyses=analyses, deep_verify=deep_verify)
                self._json_response(200, result)

            elif path == "/verify/java":
                result = _verify_language(source, "java", analyses=analyses, deep_verify=deep_verify)
                self._json_response(200, result)

            elif path == "/verify/javascript":
                result = _verify_language(source, "javascript", analyses=analyses, deep_verify=deep_verify)
                self._json_response(200, result)

            elif path == "/verify/typescript":
                result = _verify_language(source, "typescript", analyses=analyses, deep_verify=deep_verify)
                self._json_response(200, result)

            elif path == "/verify/go":
                result = _verify_language(source, "go", analyses=analyses, deep_verify=deep_verify)
                self._json_response(200, result)

            elif path == "/verify/rust":
                result = _verify_language(source, "rust", analyses=analyses, deep_verify=deep_verify)
                self._json_response(200, result)

            elif path == "/verify/c":
                result = _verify_language(source, "c", analyses=analyses, deep_verify=deep_verify)
                self._json_response(200, result)

            elif path == "/verify/cpp":
                result = _verify_language(source, "cpp", analyses=analyses, deep_verify=deep_verify)
                self._json_response(200, result)

            elif path == "/verify/ruby":
                result = _verify_language(source, "ruby", analyses=analyses, deep_verify=deep_verify)
                self._json_response(200, result)

            elif path == "/verify/swift":
                result = _verify_language(source, "swift", analyses=analyses, deep_verify=deep_verify)
                self._json_response(200, result)

            elif path == "/verify/kotlin":
                result = _verify_language(source, "kotlin", analyses=analyses, deep_verify=deep_verify)
                self._json_response(200, result)

            elif path == "/verify/php":
                result = _verify_language(source, "php", analyses=analyses, deep_verify=deep_verify)
                self._json_response(200, result)

            elif path == "/verify/scala":
                result = _verify_language(source, "scala", analyses=analyses, deep_verify=deep_verify)
                self._json_response(200, result)

            elif path == "/verify/dart":
                result = _verify_language(source, "dart", analyses=analyses, deep_verify=deep_verify)
                self._json_response(200, result)

            elif path == "/verify/aeon":
                result = _verify_aeon_code(source, deep_verify=deep_verify)
                self._json_response(200, result)

            elif path == "/verify":
                # Generic endpoint: auto-detect or use 'language' field
                language = payload.get("language", "python")
                if language == "aeon":
                    result = _verify_aeon_code(source, deep_verify=deep_verify)
                else:
                    result = _verify_language(source, language, analyses=analyses, deep_verify=deep_verify)
                self._json_response(200, result)

            else:
                self._json_response(404, {"error": "Not found"})

        except Exception as e:
            # Log full traceback server-side, but never expose to clients
            sys.stderr.write(f"[AEON API] Internal error: {traceback.format_exc()}\n")
            self._json_response(500, {
                "error": "Internal server error",
                "detail": "An unexpected error occurred during verification.",
            })

    def _json_response(self, status: int, data: dict):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", ALLOWED_ORIGINS)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode("utf-8"))

    def do_OPTIONS(self):
        """Handle CORS preflight."""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", ALLOWED_ORIGINS)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def log_message(self, format, *args):
        """Cleaner logging."""
        sys.stderr.write(f"[AEON API] {args[0]} {args[1]} {args[2]}\n")


def main():
    parser = argparse.ArgumentParser(description="AEON Verification API Server")
    parser.add_argument("--port", type=int, default=8000, help="Port to listen on")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    args = parser.parse_args()

    server = HTTPServer((args.host, args.port), AeonAPIHandler)
    print(f"\U0001f52c AEON Verification API running on http://{args.host}:{args.port}")
    print(f"   POST /verify/python      — Verify Python code")
    print(f"   POST /verify/java        — Verify Java code")
    print(f"   POST /verify/javascript  — Verify JavaScript code")
    print(f"   POST /verify/typescript  — Verify TypeScript code")
    print(f"   POST /verify/go          — Verify Go code")
    print(f"   POST /verify/rust        — Verify Rust code")
    print(f"   POST /verify/c           — Verify C code")
    print(f"   POST /verify/cpp         — Verify C++ code")
    print(f"   POST /verify/ruby        — Verify Ruby code")
    print(f"   POST /verify/swift       — Verify Swift code")
    print(f"   POST /verify/kotlin      — Verify Kotlin code")
    print(f"   POST /verify/php         — Verify PHP code")
    print(f"   POST /verify/scala       — Verify Scala code")
    print(f"   POST /verify/dart        — Verify Dart code")
    print(f"   POST /verify/aeon        — Verify AEON code")
    print(f"   POST /verify             — Auto-detect language")
    print(f"   GET  /languages          — List supported languages")
    print(f"   GET  /analyses           — List available analyses")
    print(f"   GET  /health             — Health check")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.server_close()


if __name__ == "__main__":
    main()
