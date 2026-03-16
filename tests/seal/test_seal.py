"""Tests for AEON proof-carrying seals."""
import json
import os
import tempfile
import pytest
from aeon.seal import AeonSealer, ProofCertificate


@pytest.fixture
def sample_file(tmp_path):
    f = tmp_path / "sample.py"
    f.write_text("def hello(): return 'world'\n")
    return str(f)


@pytest.fixture
def sealer():
    return AeonSealer()


class TestSealGeneration:
    def test_seal_creates_file(self, sealer, sample_file):
        result = sealer.seal(sample_file)
        assert os.path.exists(result.seal_file)
        assert result.seal_file.endswith(".aeon-seal")

    def test_seal_certificate_fields(self, sealer, sample_file):
        result = sealer.seal(sample_file, {"language": "python", "contracts_verified": 5})
        cert = result.certificate
        assert cert.file_hash
        assert cert.seal_hash
        assert cert.timestamp
        assert cert.aeon_version == "0.5.0"

    def test_seal_deterministic(self, sealer, sample_file):
        r1 = sealer.seal(sample_file)
        r2 = sealer.seal(sample_file)
        assert r1.certificate.file_hash == r2.certificate.file_hash


class TestSealVerification:
    def test_valid_seal_passes(self, sealer, sample_file):
        sealer.seal(sample_file)
        assert sealer.verify_seal(sample_file) is True

    def test_tampered_source_fails(self, sealer, sample_file):
        sealer.seal(sample_file)
        with open(sample_file, "a") as f:
            f.write("# tampered\n")
        assert sealer.verify_seal(sample_file) is False

    def test_missing_seal_fails(self, sealer, sample_file):
        assert sealer.verify_seal(sample_file) is False


class TestCertificateExport:
    def test_json_export(self, sealer, sample_file):
        result = sealer.seal(sample_file)
        exported = sealer.export_certificate(result.certificate, fmt="json")
        data = json.loads(exported)
        assert "file_hash" in data
        assert "seal_hash" in data

    def test_text_export(self, sealer, sample_file):
        result = sealer.seal(sample_file)
        exported = sealer.export_certificate(result.certificate, fmt="text")
        assert "AEON PROOF CERTIFICATE" in exported


class TestBadge:
    def test_badge_generation(self, sealer, sample_file):
        result = sealer.seal(sample_file, {"errors_found": 0})
        badge = result.badge_markdown
        assert "shields.io" in badge
        assert "AEON" in badge


class TestEmbed:
    def test_embed_comment(self, sealer, sample_file):
        result = sealer.seal(sample_file)
        sealer.embed_seal(sample_file, result)
        content = open(sample_file).read()
        assert "AEON VERIFIED" in content
