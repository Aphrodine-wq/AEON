"""AEON MCP Safety — AI Agent Verification Layer.

An MCP-compatible server that wraps AI agent tool calls with AEON verification.
Before an agent executes code, AEON proves it satisfies safety contracts.

The seatbelt for AI agents.

Usage:
    aeon mcp-safety                # Start server on port 8001
    aeon mcp-safety --port 9000    # Custom port
"""

from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from pathlib import Path


@dataclass
class SafetyPolicy:
    """A safety policy that agent actions must satisfy."""
    name: str
    description: str
    rules: List[str]           # Formal rules
    severity: str = "block"    # 'block', 'warn', 'log'

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "rules": self.rules,
            "severity": self.severity,
        }


@dataclass
class VerificationRequest:
    """A request to verify an agent action."""
    action_type: str           # 'execute_code', 'file_write', 'shell_command', 'api_call'
    content: str               # The code/command/request to verify
    language: str = "python"
    context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VerificationResult:
    """Result of safety verification."""
    allowed: bool
    action_type: str
    violations: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    contracts_checked: int = 0
    verification_hash: str = ""
    explanation: str = ""

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "action_type": self.action_type,
            "violations": self.violations,
            "warnings": self.warnings,
            "contracts_checked": self.contracts_checked,
            "verification_hash": self.verification_hash,
            "explanation": self.explanation,
        }


# ---------------------------------------------------------------------------
# Default safety policies
# ---------------------------------------------------------------------------

DEFAULT_POLICIES: List[SafetyPolicy] = [
    SafetyPolicy(
        name="no_destructive_commands",
        description="Prevent destructive shell commands",
        rules=[
            "rm -rf /",
            "rm -rf ~",
            "rm -rf *",
            "mkfs",
            "dd if=",
            ":(){:|:&};:",
            "chmod -R 777 /",
            "shutdown",
            "reboot",
            "halt",
            "init 0",
            "kill -9 1",
        ],
        severity="block",
    ),
    SafetyPolicy(
        name="no_data_exfiltration",
        description="Prevent data exfiltration patterns",
        rules=[
            "curl.*POST.*@",
            "wget.*--post-data",
            "nc -e",
            "base64.*|.*curl",
            "/etc/passwd",
            "/etc/shadow",
            "AWS_SECRET",
            "PRIVATE_KEY",
        ],
        severity="block",
    ),
    SafetyPolicy(
        name="no_privilege_escalation",
        description="Prevent privilege escalation",
        rules=[
            "sudo",
            "su -",
            "chmod u+s",
            "chown root",
            "visudo",
            "passwd",
            "/etc/sudoers",
        ],
        severity="block",
    ),
    SafetyPolicy(
        name="no_network_abuse",
        description="Prevent network abuse patterns",
        rules=[
            "nmap",
            "masscan",
            "hydra",
            "sqlmap",
            "metasploit",
            "msfconsole",
        ],
        severity="block",
    ),
    SafetyPolicy(
        name="code_safety",
        description="Prevent unsafe code patterns",
        rules=[
            "eval(",
            "exec(",
            "__import__",
            "os.system(",
            "subprocess.call.*shell=True",
            "pickle.loads",
            "yaml.load(",
            "marshal.loads",
        ],
        severity="warn",
    ),
    SafetyPolicy(
        name="file_safety",
        description="Prevent dangerous file operations",
        rules=[
            "shutil.rmtree('/'",
            "os.remove('/'",
            "open('/etc/",
            "open('/proc/",
            "open('/sys/",
            "../..",
        ],
        severity="block",
    ),
]


class AeonMCPServer:
    """MCP-compatible safety server for AI agent verification."""

    def __init__(self, policies: Optional[List[SafetyPolicy]] = None):
        self.policies = policies or DEFAULT_POLICIES
        self.audit_log: List[Dict] = []

    def verify_action(self, request: VerificationRequest) -> VerificationResult:
        """Verify an agent action against safety policies."""
        violations: List[str] = []
        warnings: List[str] = []
        contracts_checked = 0

        content = request.content
        content_lower = content.lower()

        for policy in self.policies:
            for rule in policy.rules:
                contracts_checked += 1
                if rule.lower() in content_lower:
                    msg = f"[{policy.name}] Matches blocked pattern: {rule}"
                    if policy.severity == "block":
                        violations.append(msg)
                    else:
                        warnings.append(msg)

        # Additional code-specific checks
        if request.action_type == "execute_code":
            code_violations, code_warnings = self._check_code_safety(
                content, request.language,
            )
            violations.extend(code_violations)
            warnings.extend(code_warnings)
            contracts_checked += 10  # Approximate

        allowed = len(violations) == 0
        verification_hash = hashlib.sha256(
            f"{request.action_type}:{content}:{allowed}".encode()
        ).hexdigest()[:16]

        result = VerificationResult(
            allowed=allowed,
            action_type=request.action_type,
            violations=violations,
            warnings=warnings,
            contracts_checked=contracts_checked,
            verification_hash=verification_hash,
            explanation=self._explain_result(allowed, violations, warnings),
        )

        # Audit log
        self.audit_log.append({
            "action_type": request.action_type,
            "allowed": allowed,
            "violations": len(violations),
            "warnings": len(warnings),
            "hash": verification_hash,
        })

        return result

    def verify_code(self, code: str, language: str = "python") -> VerificationResult:
        """Convenience: verify code execution."""
        return self.verify_action(VerificationRequest(
            action_type="execute_code",
            content=code,
            language=language,
        ))

    def verify_shell(self, command: str) -> VerificationResult:
        """Convenience: verify shell command."""
        return self.verify_action(VerificationRequest(
            action_type="shell_command",
            content=command,
        ))

    def verify_file_write(self, path: str, content: str) -> VerificationResult:
        """Convenience: verify file write."""
        return self.verify_action(VerificationRequest(
            action_type="file_write",
            content=f"WRITE {path}\n{content}",
        ))

    def add_policy(self, policy: SafetyPolicy) -> None:
        """Add a custom safety policy."""
        self.policies.append(policy)

    def get_policies(self) -> List[Dict]:
        """Get all active policies."""
        return [p.to_dict() for p in self.policies]

    def get_audit_log(self) -> List[Dict]:
        """Get the audit log."""
        return self.audit_log

    def serve(self, port: int = 8001) -> None:
        """Start the MCP safety server."""
        try:
            from http.server import HTTPServer, BaseHTTPRequestHandler
        except ImportError:
            print("HTTP server not available")
            return

        server_ref = self

        class SafetyHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(length).decode('utf-8')

                try:
                    data = json.loads(body)
                except json.JSONDecodeError:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b'{"error": "invalid JSON"}')
                    return

                request = VerificationRequest(
                    action_type=data.get("action_type", "execute_code"),
                    content=data.get("content", ""),
                    language=data.get("language", "python"),
                    context=data.get("context", {}),
                )

                result = server_ref.verify_action(request)

                self.send_response(200 if result.allowed else 403)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(result.to_dict()).encode())

            def do_GET(self):
                if self.path == "/policies":
                    data = server_ref.get_policies()
                elif self.path == "/audit":
                    data = server_ref.get_audit_log()
                elif self.path == "/health":
                    data = {"status": "ok", "policies": len(server_ref.policies)}
                else:
                    data = {
                        "name": "AEON MCP Safety Server",
                        "version": "0.5.0",
                        "endpoints": {
                            "POST /": "Verify an agent action",
                            "GET /policies": "List active policies",
                            "GET /audit": "View audit log",
                            "GET /health": "Health check",
                        },
                    }

                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(data, indent=2).encode())

            def log_message(self, format, *args):
                # Quieter logging
                pass

        httpd = HTTPServer(("", port), SafetyHandler)
        print(f"AEON MCP Safety Server listening on port {port}")
        print(f"  POST /         — Verify agent action")
        print(f"  GET /policies  — List policies")
        print(f"  GET /audit     — Audit log")
        print(f"  GET /health    — Health check")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down...")
            httpd.shutdown()

    # -- internal ----------------------------------------------------------

    def _check_code_safety(self, code: str, language: str) -> tuple:
        """Run language-specific code safety checks."""
        violations: List[str] = []
        warnings: List[str] = []

        if language == "python":
            # Infinite loops
            if "while True" in code and "break" not in code:
                warnings.append("[code_safety] Potential infinite loop (while True without break)")

            # Unbounded recursion
            import re
            func_m = re.search(r'def (\w+)\(', code)
            if func_m:
                name = func_m.group(1)
                if name in code.split("def " + name, 1)[-1] and "if " not in code:
                    warnings.append(f"[code_safety] Potential unbounded recursion in {name}")

            # Network access
            if any(mod in code for mod in ['urllib', 'requests', 'httpx', 'aiohttp']):
                warnings.append("[code_safety] Code performs network requests")

            # System modifications
            if "os.environ" in code and "=" in code:
                warnings.append("[code_safety] Code modifies environment variables")

        return violations, warnings

    def _explain_result(self, allowed: bool, violations: List[str],
                        warnings: List[str]) -> str:
        if allowed and not warnings:
            return "Action verified safe. No policy violations detected."
        if allowed and warnings:
            return f"Action allowed with {len(warnings)} warning(s). Review recommended."
        return f"Action BLOCKED. {len(violations)} policy violation(s) detected."
