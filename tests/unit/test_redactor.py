# tests/unit/test_redactor.py

import pytest
from unittest.mock import patch, MagicMock

from foep.report.redactor import Redactor
from foep.normalize.schema import Evidence, EntityType, ObservationType


class TestRedactorBasic:
    """Test basic redaction functionality."""

    def test_redact_email(self):
        """Test email redaction."""
        redactor = Redactor(redact_emails=True)
        
        text = "Contact admin@company.com or user@gmail.com for help"
        result = redactor.redact_text(text)
        
        # Company email should be preserved if not in blocklist
        # Gmail should be redacted
        assert "admin@company.com" in result
        assert "[REDACTED_EMAIL]" in result
        assert "user@gmail.com" not in result

    def test_redact_ip(self):
        """Test IP address redaction."""
        redactor = Redactor(redact_ips=True, preserve_internal_ips=False)
        
        text = "Server at 192.168.1.100 and external 8.8.8.8"
        result = redactor.redact_text(text)
        
        # Both IPs should be redacted when preserve_internal_ips=False
        assert "[REDACTED_IP]" in result
        assert "192.168.1.100" not in result
        assert "8.8.8.8" not in result

    def test_preserve_internal_ips(self):
        """Test internal IP preservation."""
        redactor = Redactor(redact_ips=True, preserve_internal_ips=True)
        
        text = "Internal 192.168.1.100, loopback 127.0.0.1, external 8.8.8.8"
        result = redactor.redact_text(text)
        
        # Internal IPs preserved, external redacted
        assert "192.168.1.100" in result
        assert "127.0.0.1" in result
        assert "[REDACTED_IP]" in result
        assert "8.8.8.8" not in result

    def test_redact_with_allowlist_domains(self):
        """Test email redaction with allowlist domains."""
        redactor = Redactor(
            redact_emails=True,
            allowlist_domains=["company.com", "internal.org"]
        )
        
        text = "Emails: user@company.com, admin@internal.org, hacker@gmail.com"
        result = redactor.redact_text(text)
        
        # Allowlisted domains preserved, others redacted
        assert "user@company.com" in result
        assert "admin@internal.org" in result
        assert "[REDACTED_EMAIL]" in result
        assert "hacker@gmail.com" not in result

    def test_redact_with_blocklist_domains(self):
        """Test email redaction with blocklist domains."""
        redactor = Redactor(
            redact_emails=True,
            blocklist_domains=["gmail.com", "yahoo.com"]
        )
        
        text = "Emails: user@company.com, hacker@gmail.com, spam@yahoo.com"
        result = redactor.redact_text(text)
        
        # Blocklisted domains redacted, others preserved
        assert "user@company.com" in result
        assert "[REDACTED_EMAIL]" in result
        assert "hacker@gmail.com" not in result
        assert "spam@yahoo.com" not in result


class TestRedactorEvidence:
    """Test redaction of Evidence objects."""

    def test_redact_evidence_entity_value(self):
        """Test redaction of Evidence entity_value."""
        redactor = Redactor(redact_emails=True)
        
        evidence = Evidence(
            evidence_id="test::1",
            entity_type=EntityType.EMAIL,
            entity_value="sensitive@gmail.com",
            observation_type=ObservationType.OSINT_POST,
            source="test",
            credibility_score=70
        )
        
        redacted = redactor.redact_evidence(evidence)
        
        assert redacted.entity_value == "[REDACTED_EMAIL]"
        assert redacted.evidence_id == evidence.evidence_id
        assert redacted.credibility_score == evidence.credibility_score

    def test_redact_evidence_metadata(self):
        """Test redaction of Evidence metadata."""
        redactor = Redactor(redact_emails=True, redact_ips=True)
        
        evidence = Evidence(
            evidence_id="test::2",
            entity_type=EntityType.COMMAND_LINE,
            entity_value="Log entry",
            observation_type=ObservationType.LOG_ARTIFACT,
            source="syslog",
            metadata={
                "message": "User john@gmail.com connected from 192.168.1.100",
                "original_ip": "8.8.8.8",
                "safe_field": "no_pii_here"
            },
            credibility_score=100
        )
        
        redacted = redactor.redact_evidence(evidence)
        
        # Check metadata redaction
        assert "john@gmail.com" not in redacted.metadata["message"]
        assert "[REDACTED_EMAIL]" in redacted.metadata["message"]
        assert "8.8.8.8" not in redacted.metadata["original_ip"]
        assert "[REDACTED_IP]" in redacted.metadata["original_ip"]
        assert redacted.metadata["safe_field"] == "no_pii_here"


class TestRedactorNames:
    """Test name redaction with spaCy NLP."""

    @patch('foep.report.redactor.spacy.load')
    def test_redact_names_with_spacy(self, mock_spacy_load):
        """Test name redaction using mocked spaCy."""
        # Mock spaCy NLP pipeline
        mock_nlp = MagicMock()
        mock_doc = MagicMock()
        
        # Mock entities
        mock_person_ent = MagicMock()
        mock_person_ent.label_ = "PERSON"
        mock_person_ent.text = "John Doe"
        mock_person_ent.start_char = 10
        mock_person_ent.end_char = 18
        
        mock_org_ent = MagicMock()
        mock_org_ent.label_ = "ORG"
        mock_org_ent.text = "Google"
        mock_org_ent.start_char = 25
        mock_org_ent.end_char = 31
        
        mock_doc.ents = [mock_person_ent, mock_org_ent]
        mock_nlp.return_value = mock_doc
        mock_spacy_load.return_value = mock_nlp
        
        redactor = Redactor(redact_names=True)
        
        text = "Contact John Doe at Google for assistance"
        result = redactor.redact_text(text)
        
        # Person name should be redacted, known org preserved
        assert "[REDACTED_NAME]" in result
        assert "John Doe" not in result
        assert "Google" in result  # Known org not redacted

    @patch('foep.report.redactor.spacy.load')
    def test_redact_names_spacy_not_installed(self, mock_spacy_load):
        """Test name redaction when spaCy is not available."""
        mock_spacy_load.side_effect = ImportError("spaCy not installed")
        
        # Should not raise error, just disable name redaction
        redactor = Redactor(redact_names=True)
        assert redactor.redact_names == False  # Automatically disabled
        
        text = "Contact John Doe for help"
        result = redactor.redact_text(text)
        assert result == text  # No redaction performed


class TestRedactorUsernames:
    """Test username redaction behavior."""

    def test_redact_usernames_disabled_by_default(self):
        """Test that username redaction is disabled by default."""
        redactor = Redactor()  # Default: redact_usernames=False
        
        text = "Username: attacker123 found in logs"
        result = redactor.redact_text(text)
        
        # Username should NOT be redacted by default (for attribution)
        assert "attacker123" in result
        assert "[REDACTED_USERNAME]" not in result

    def test_redact_usernames_enabled(self):
        """Test username redaction when enabled."""
        redactor = Redactor(redact_usernames=True)
        
        text = "Username: attacker123 and admin_user"
        result = redactor.redact_text(text)
        
        # Usernames should be redacted
        assert "[REDACTED_USERNAME]" in result
        assert "attacker123" not in result
        assert "admin_user" not in result

    def test_username_heuristics(self):
        """Test username redaction heuristics."""
        redactor = Redactor(redact_usernames=True)
        
        # Valid usernames should be redacted
        assert "[REDACTED_USERNAME]" in redactor.redact_text("user: john_doe123")
        
        # Invalid usernames should be preserved
        assert "12345" in redactor.redact_text("ID: 12345")  # Pure numbers
        assert "system admin" in redactor.redact_text("Role: system admin")  # Contains spaces


class TestRedactorCustomPatterns:
    """Test custom redaction patterns."""

    def test_custom_redaction_patterns(self):
        """Test custom regex patterns for redaction."""
        custom_patterns = {
            "credit_card": r"\b(?:\d{4}[-\s]?){3}\d{4}\b"
        }
        
        redactor = Redactor(custom_patterns=custom_patterns)
        
        text = "Card: 1234-5678-9012-3456 and email user@test.com"
        result = redactor.redact_text(text)
        
        # Credit card should be redacted with generic marker
        assert "[REDACTED]" in result
        assert "1234-5678-9012-3456" not in result
        assert "user@test.com" in result  # Email not redacted (default disabled)


class TestRedactorEdgeCases:
    """Test edge cases and error handling."""

    def test_redact_empty_string(self):
        """Test redaction of empty strings."""
        redactor = Redactor(redact_emails=True)
        assert redactor.redact_text("") == ""
        assert redactor.redact_text(None) is None

    def test_redact_non_string_input(self):
        """Test redaction of non-string input."""
        redactor = Redactor(redact_emails=True)
        assert redactor.redact_text(123) == 123
        assert redactor.redact_text([]) == []

    def test_redact_nested_metadata(self):
        """Test redaction of nested metadata structures."""
        redactor = Redactor(redact_emails=True)
        
        evidence = Evidence(
            evidence_id="test::3",
            entity_type=EntityType.COMMAND_LINE,
            entity_value="Log entry",
            observation_type=ObservationType.LOG_ARTIFACT,
            source="test",
            metadata={
                "nested": {
                    "deep": {
                        "email": "deep@test.com"
                    }
                },
                "list_field": ["first@test.com", "second@test.com"]
            },
            credibility_score=100
        )
        
        redacted = redactor.redact_evidence(evidence)
        
        # Nested dict redaction
        assert "deep@test.com" not in str(redacted.metadata)
        assert "[REDACTED_EMAIL]" in str(redacted.metadata)
        
        # List redaction
        list_field = redacted.metadata["list_field"]
        assert all("[REDACTED_EMAIL]" in item for item in list_field)


if __name__ == "__main__":
    pytest.main([__file__])
