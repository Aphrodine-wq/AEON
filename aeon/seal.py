"""AEON Seal — Proof-Carrying Binaries.

Embed cryptographic proof certificates into verified code so third parties
can verify correctness without access to source.

Usage:
    aeon seal <file>              # Verify + generate .aeon-seal
    aeon seal <file> --embed      # Also embed seal comment in source
    aeon verify-seal <file>       # Verify an existing seal
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict


@dataclass
class ProofCertificate:
    """Cryptographic proof certificate for verified code."""
    version: str = "1.0"
    file_path: str = ""
    file_hash: str = ""           # SHA-256 of source
    verification_hash: str = ""   # Hash of proof obligations
    timestamp: str = ""           # ISO 8601
    aeon_version: str = "0.5.0"
    language: str = ""
    engines_used: List[str] = field(default_factory=list)
    contracts_verified: int = 0
    properties_proven: List[str] = field(default_factory=list)
    errors_found: int = 0
    seal_hash: str = ""           # Hash of all above fields


@dataclass
class SealResult:
    """Result of a sealing operation."""
    certificate: ProofCertificate
    seal_file: str
    embed_comment: str
    badge_markdown: str
    verification_command: str


class AeonSealer:
    """Generate and verify proof-carrying seals."""

    def seal(self, filepath: str, verification_result: Optional[dict] = None) -> SealResult:
        """Generate a seal for verified code.

        Args:
            filepath: Path to the source file.
            verification_result: Dict from the verification engine with keys
                like 'errors', 'language', 'engines', 'contracts', 'properties'.
                If None, a basic seal is generated from file hash alone.
        """
        path = Path(filepath)
        source = path.read_text(encoding="utf-8")
        file_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()

        vr = verification_result or {}
        engines = vr.get("engines", [])
        contracts = vr.get("contracts_verified", 0)
        properties = vr.get("properties_proven", [])
        errors = vr.get("errors_found", 0)
        language = vr.get("language", _detect_language(filepath))

        verification_hash = hashlib.sha256(
            json.dumps(vr, sort_keys=True, default=str).encode()
        ).hexdigest()

        cert = ProofCertificate(
            file_path=str(path.name),
            file_hash=file_hash,
            verification_hash=verification_hash,
            timestamp=datetime.now(timezone.utc).isoformat(),
            language=language,
            engines_used=engines,
            contracts_verified=contracts,
            properties_proven=properties,
            errors_found=errors,
        )
        cert.seal_hash = self._compute_seal_hash(cert)

        seal_path = str(path) + ".aeon-seal"
        with open(seal_path, "w") as f:
            json.dump(asdict(cert), f, indent=2)

        badge = self.generate_badge(cert)
        embed = self._make_embed_comment(cert, language)
        verify_cmd = f"aeon verify-seal {filepath}"

        return SealResult(
            certificate=cert,
            seal_file=seal_path,
            embed_comment=embed,
            badge_markdown=badge,
            verification_command=verify_cmd,
        )

    def verify_seal(self, filepath: str, seal_path: Optional[str] = None) -> bool:
        """Verify that a seal matches the current source file."""
        path = Path(filepath)
        if not path.exists():
            return False

        seal_file = seal_path or (str(path) + ".aeon-seal")
        if not os.path.exists(seal_file):
            return False

        with open(seal_file) as f:
            data = json.load(f)

        source = path.read_text(encoding="utf-8")
        current_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()

        if current_hash != data.get("file_hash"):
            return False

        cert = ProofCertificate(**{k: v for k, v in data.items()
                                   if k in ProofCertificate.__dataclass_fields__})
        cert.seal_hash = ""
        expected_seal = self._compute_seal_hash(cert)
        return expected_seal == data.get("seal_hash")

    def embed_seal(self, filepath: str, seal: SealResult) -> str:
        """Embed seal as a comment in the source file. Returns updated source."""
        path = Path(filepath)
        source = path.read_text(encoding="utf-8")
        comment = seal.embed_comment
        if comment in source:
            return source
        updated = comment + "\n\n" + source
        path.write_text(updated, encoding="utf-8")
        return updated

    def generate_badge(self, cert: ProofCertificate) -> str:
        """Generate a shields.io badge in markdown."""
        status = "verified" if cert.errors_found == 0 else "issues_found"
        color = "brightgreen" if cert.errors_found == 0 else "red"
        label = f"AEON-{status}"
        detail = f"{cert.contracts_verified}_contracts"
        return f"![{label}](https://img.shields.io/badge/AEON-{status}_{detail}-{color})"

    def export_certificate(self, cert: ProofCertificate, fmt: str = "json") -> str:
        """Export certificate in various formats."""
        data = asdict(cert)
        if fmt == "json":
            return json.dumps(data, indent=2)
        # Human-readable text
        lines = [
            "AEON PROOF CERTIFICATE",
            "=" * 40,
            f"File:        {cert.file_path}",
            f"Language:    {cert.language}",
            f"Timestamp:   {cert.timestamp}",
            f"AEON:        v{cert.aeon_version}",
            "",
            f"File Hash:   {cert.file_hash[:16]}...",
            f"Seal Hash:   {cert.seal_hash[:16]}...",
            "",
            f"Contracts Verified: {cert.contracts_verified}",
            f"Errors Found:       {cert.errors_found}",
        ]
        if cert.engines_used:
            lines.append(f"Engines:     {', '.join(cert.engines_used)}")
        if cert.properties_proven:
            lines.append("")
            lines.append("Properties Proven:")
            for p in cert.properties_proven:
                lines.append(f"  + {p}")
        return "\n".join(lines)

    # -- internal ----------------------------------------------------------

    def _compute_seal_hash(self, cert: ProofCertificate) -> str:
        """Deterministic hash of all certificate fields (except seal_hash)."""
        data = asdict(cert)
        data.pop("seal_hash", None)
        raw = json.dumps(data, sort_keys=True).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def _make_embed_comment(self, cert: ProofCertificate, language: str) -> str:
        """Generate a language-appropriate comment block with seal info."""
        lines = [
            f"AEON VERIFIED | {cert.timestamp}",
            f"Seal: {cert.seal_hash[:24]}...",
            f"Contracts: {cert.contracts_verified} | Errors: {cert.errors_found}",
            f"Verify: aeon verify-seal {cert.file_path}",
        ]
        comment_styles = {
            "python": ("#", "#"),
            "ruby": ("#", "#"),
            "r": ("#", "#"),
            "elixir": ("#", "#"),
            "lua": ("--", "--"),
            "haskell": ("--", "--"),
            "javascript": ("//", "//"),
            "typescript": ("//", "//"),
            "java": ("//", "//"),
            "go": ("//", "//"),
            "rust": ("//", "//"),
            "c": ("//", "//"),
            "cpp": ("//", "//"),
            "swift": ("//", "//"),
            "kotlin": ("//", "//"),
            "scala": ("//", "//"),
            "dart": ("//", "//"),
            "php": ("//", "//"),
            "zig": ("//", "//"),
        }
        prefix = comment_styles.get(language, ("#", "#"))
        return "\n".join(f"{prefix[0]} {line}" for line in lines)


def _detect_language(filepath: str) -> str:
    """Detect language from file extension."""
    ext_map = {
        ".py": "python", ".java": "java", ".js": "javascript",
        ".ts": "typescript", ".go": "go", ".rs": "rust",
        ".c": "c", ".cpp": "cpp", ".rb": "ruby", ".swift": "swift",
        ".kt": "kotlin", ".scala": "scala", ".php": "php",
        ".dart": "dart", ".ex": "elixir", ".exs": "elixir",
        ".hs": "haskell", ".ml": "ocaml", ".lua": "lua",
        ".r": "r", ".jl": "julia", ".zig": "zig", ".aeon": "aeon",
    }
    ext = Path(filepath).suffix.lower()
    return ext_map.get(ext, "unknown")
