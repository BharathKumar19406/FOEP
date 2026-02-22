# tests/unit/test_normalize.py

import hashlib
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from foep.normalize.schema import Evidence, EntityType, ObservationType
from foep.normalize.hash_utils import compute_sha256, compute_sha256_from_file
from foep.normalize.transformer import normalize_raw_input, EvidenceNormalizer


class TestEvidenceSchema:
    """Test Evidence Pydantic model validation and constraints."""

    def test_valid_evidence_creation(self):
        """Test creating valid Evidence instances."""
        evidence = Evidence(
            evidence_id="test::123",
            entity_type=EntityType.EMAIL,
            entity_value="user@example.com",
            observation_type=ObservationType.OSINT_POST,
            source="test_source",
            metadata={"key": "value"},
            credibility_score=85,
            sha256_hash="a" * 64
        )
        assert evidence.evidence_id == "test::123"
        assert evidence.entity_type == EntityType.EMAIL
        assert evidence.credibility_score == 85

    def test_evidence_id_validation(self):
        """Test evidence_id format validation."""
        # Valid ID
        valid = Evidence(
            evidence_id="source::key",
            entity_type=EntityType.IP,
            entity_value="192.168.1.1",
            observation_type=ObservationType.LOG_ARTIFACT,
            source="test",
            credibility_score=100
        )
        assert valid.evidence_id == "source::key"

        # Invalid ID (no ::)
        with pytest.raises(ValueError, match="must be in format"):
            Evidence(
                evidence_id="invalid_id",
                entity_type=EntityType.IP,
                entity_value="192.168.1.1",
                observation_type=ObservationType.LOG_ARTIFACT,
                source="test",
                credibility_score=100
            )

    def test_entity_value_validation(self):
        """Test entity_value validation."""
        # Valid value
        valid = Evidence(
            evidence_id="test::1",
            entity_type=EntityType.USERNAME,
            entity_value="user123",
            observation_type=ObservationType.OSINT_POST,
            source="test",
            credibility_score=100
        )
        assert valid.entity_value == "user123"

        # Empty value
        with pytest.raises(ValueError, match="must not be empty"):
            Evidence(
                evidence_id="test::2",
                entity_type=EntityType.USERNAME,
                entity_value="",
                observation_type=ObservationType.OSINT_POST,
                source="test",
                credibility_score=100
            )

    def test_credibility_score_bounds(self):
        """Test credibility_score range validation."""
        # Valid scores
        Evidence(
            evidence_id="test::3",
            entity_type=EntityType.IP,
            entity_value="192.168.1.1",
            observation_type=ObservationType.LOG_ARTIFACT,
            source="test",
            credibility_score=0
        )
        Evidence(
            evidence_id="test::4",
            entity_type=EntityType.IP,
            entity_value="192.168.1.1",
            observation_type=ObservationType.LOG_ARTIFACT,
            source="test",
            credibility_score=100
        )

        # Invalid scores
        with pytest.raises(ValueError):
            Evidence(
                evidence_id="test::5",
                entity_type=EntityType.IP,
                entity_value="192.168.1.1",
                observation_type=ObservationType.LOG_ARTIFACT,
                source="test",
                credibility_score=101
            )
        with pytest.raises(ValueError):
            Evidence(
                evidence_id="test::6",
                entity_type=EntityType.IP,
                entity_value="192.168.1.1",
                observation_type=ObservationType.LOG_ARTIFACT,
                source="test",
                credibility_score=-1
            )

    def test_evidence_immutability(self):
        """Test that Evidence objects are immutable."""
        evidence = Evidence(
            evidence_id="test::7",
            entity_type=EntityType.EMAIL,
            entity_value="test@example.com",
            observation_type=ObservationType.OSINT_POST,
            source="test",
            credibility_score=80
        )
        
        # Attempt to modify should raise error
        with pytest.raises(TypeError, match="does not support item assignment"):
            evidence.entity_value = "new@example.com"

    def test_json_serialization(self):
        """Test Evidence JSON serialization."""
        evidence = Evidence(
            evidence_id="test::8",
            entity_type=EntityType.IP,
            entity_value="192.168.1.1",
            observation_type=ObservationType.LOG_ARTIFACT,
            source="test",
            metadata={"timestamp": "2024-01-01"},
            credibility_score=90,
            sha256_hash="b" * 64
        )
        
        json_str = evidence.model_dump_json()
        parsed = json.loads(json_str)
        
        assert parsed["entity_type"] == "ip"
        assert parsed["observation_type"] == "log_artifact"
        assert parsed["credibility_score"] == 90


class TestHashUtils:
    """Test hash utility functions."""

    def test_compute_sha256_bytes(self):
        """Test SHA-256 computation for bytes."""
        data = b"hello world"
        expected = hashlib.sha256(data).hexdigest()
        result = compute_sha256(data)
        assert result == expected

    def test_compute_sha256_string(self):
        """Test SHA-256 computation for strings."""
        data = "hello world"
        expected = hashlib.sha256(data.encode("utf-8")).hexdigest()
        result = compute_sha256(data)
        assert result == expected

    def test_compute_sha256_from_file(self, tmp_path):
        """Test SHA-256 computation for files."""
        test_file = tmp_path / "test.txt"
        content = "file content for hashing"
        test_file.write_text(content)
        
        expected = hashlib.sha256(content.encode("utf-8")).hexdigest()
        result = compute_sha256_from_file(str(test_file))
        assert result == expected

    def test_compute_sha256_large_file(self, tmp_path):
        """Test SHA-256 computation for large files (incremental reading)."""
        test_file = tmp_path / "large.bin"
        # Create 1MB file
        large_content = b"x" * (1024 * 1024)
        test_file.write_bytes(large_content)
        
        expected = hashlib.sha256(large_content).hexdigest()
        result = compute_sha256_from_file(str(test_file))
        assert result == expected

    def test_compute_sha256_invalid_input(self):
        """Test error handling for invalid input types."""
        with pytest.raises(TypeError, match="Input must be bytes or str"):
            compute_sha256(123)


class TestEvidenceNormalizer:
    """Test EvidenceNormalizer transformation logic."""

    def test_normalize_log_artefact(self):
        """Test normalization of log artefacts."""
        raw_input = {
            "message": "User john logged in from 192.168.1.100",
            "timestamp": "2024-01-01T12:00:00Z",
            "user": "john"
        }
        
        normalizer = EvidenceNormalizer()
        evidence_list = list(normalizer.normalize(
            raw_input,
            source="test_logger",
            observation_type=ObservationType.LOG_ARTIFACT
        ))
        
        assert len(evidence_list) == 1
        ev = evidence_list[0]
        assert ev.entity_type == EntityType.COMMAND_LINE
        assert "john logged in" in ev.entity_value
        assert ev.source == "test_logger"
        assert ev.credibility_score == 100  # Internal source

    def test_normalize_osint_post(self):
        """Test normalization of OSINT posts."""
        raw_input = {
            "username": "attacker123",
            "email": "attacker@example.com",
            "content": "Check out my new malware!",
            "platform": "twitter"
        }
        
        normalizer = EvidenceNormalizer(default_credibility=70)
        evidence_list = list(normalizer.normalize(
            raw_input,
            source="twitter",
            observation_type=ObservationType.OSINT_POST
        ))
        
        assert len(evidence_list) == 3  # username, email, post
        
        usernames = [ev for ev in evidence_list if ev.entity_type == EntityType.USERNAME]
        emails = [ev for ev in evidence_list if ev.entity_type == EntityType.EMAIL]
        posts = [ev for ev in evidence_list if ev.entity_type == EntityType.POST]
        
        assert len(usernames) == 1
        assert len(emails) == 1
        assert len(posts) == 1
        
        assert usernames[0].entity_value == "attacker123"
        assert emails[0].entity_value == "attacker@example.com"
        assert "malware" in posts[0].entity_value
        assert posts[0].credibility_score == 70

    def test_normalize_breach_data(self):
        """Test normalization of breach data."""
        raw_input = {
            "email": "victim@company.com",
            "username": "victim_user",
            "breach_name": "CompanyDB",
            "breach_date": "2023-12-01"
        }
        
        normalizer = EvidenceNormalizer(default_credibility=80)
        evidence_list = list(normalizer.normalize(
            raw_input,
            source="hibp",
            observation_type=ObservationType.OSINT_BREACH
        ))
        
        assert len(evidence_list) == 3  # email, username, breach
        
        breach_ev = next(ev for ev in evidence_list if ev.entity_type == EntityType.BREACH)
        assert breach_ev.entity_value == "CompanyDB"
        assert breach_ev.credibility_score == 80

    def test_normalize_json_string_input(self):
        """Test normalization of JSON string input."""
        raw_input = '{"message": "System alert", "severity": "high"}'
        
        normalizer = EvidenceNormalizer()
        evidence_list = list(normalizer.normalize(
            raw_input,
            source="syslog",
            observation_type=ObservationType.LOG_ARTIFACT
        ))
        
        assert len(evidence_list) == 1
        assert evidence_list[0].entity_type == EntityType.COMMAND_LINE
        assert "System alert" in evidence_list[0].entity_value

    def test_normalize_invalid_input(self):
        """Test normalization of invalid input types."""
        normalizer = EvidenceNormalizer()
        
        # Non-dict, non-string input
        evidence_list = list(normalizer.normalize(
            123,
            source="test",
            observation_type=ObservationType.LOG_ARTIFACT
        ))
        assert len(evidence_list) == 0

    def test_normalize_public_api(self):
        """Test the public normalize_raw_input function."""
        raw_input = {"username": "testuser", "email": "test@test.com"}
        
        evidence_list = normalize_raw_input(
            raw_input,
            source="test_api",
            observation_type=ObservationType.OSINT_POST
        )
        
        assert len(evidence_list) == 2
        assert all(isinstance(ev, Evidence) for ev in evidence_list)
        usernames = [ev for ev in evidence_list if ev.entity_type == EntityType.USERNAME]
        assert len(usernames) == 1
        assert usernames[0].entity_value == "testuser"


if __name__ == "__main__":
    pytest.main([__file__])
