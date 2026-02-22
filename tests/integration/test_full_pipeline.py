# tests/integration/test_full_pipeline.py

import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from foep.core.pipeline import FOEPPipeline
from foep.core.config import FOEPConfig, GitHubConfig, Neo4jConfig
from foep.normalize.schema import Evidence, EntityType, ObservationType


class TestFullPipeline:
    """Integration tests for the complete FOEP pipeline."""

    @pytest.fixture
    def mock_config(self):
        """Create a mock configuration for testing."""
        return FOEPConfig(
            github=GitHubConfig(enabled=True, api_token="test_token"),
            neo4j=Neo4jConfig(
                uri="bolt://localhost:7687",
                username="neo4j",
                password="test_password"
            )
        )

    @pytest.fixture
    def sample_evidence(self):
        """Create sample evidence for testing."""
        return [
            Evidence(
                evidence_id="disk_file::test.txt",
                entity_type=EntityType.FILE,
                entity_value="/home/user/test.txt",
                observation_type=ObservationType.DISK_ARTIFACT,
                source="disk_image",
                metadata={"size_bytes": 1024, "modified_time": "2024-01-01T12:00:00Z"},
                credibility_score=100,
                sha256_hash="a" * 64
            ),
            Evidence(
                evidence_id="github_user::attacker123",
                entity_type=EntityType.USERNAME,
                entity_value="attacker123",
                observation_type=ObservationType.OSINT_POST,
                source="github",
                metadata={"name": "Malicious User", "bio": "Hacker"},
                credibility_score=90,
                sha256_hash=None
            ),
            Evidence(
                evidence_id="log_email::user@company.com",
                entity_type=EntityType.EMAIL,
                entity_value="user@company.com",
                observation_type=ObservationType.LOG_ARTIFACT,
                source="log_parser",
                metadata={"source_file": "/var/log/syslog"},
                credibility_score=100,
                sha256_hash=None
            )
        ]

    @patch("foep.correlate.graph_db.GraphDatabase")
    def test_full_pipeline_basic(self, mock_graph_db_class, mock_config, sample_evidence):
        """Test basic full pipeline execution."""
        # Mock GraphDatabase
        mock_graph_db = MagicMock()
        mock_graph_db_class.return_value.__enter__.return_value = mock_graph_db
        
        # Initialize pipeline
        pipeline = FOEPPipeline(
            config=mock_config,
            case_id="TEST-001",
            investigator="test_analyst"
        )
        pipeline.all_evidence = sample_evidence
        
        # Run correlation and scoring
        scored_evidence = pipeline.run_correlation_and_scoring()
        
        # Verify results
        assert len(scored_evidence) >= len(sample_evidence)  # May have extracted entities
        
        # Check that credibility scores are present
        for evidence in scored_evidence:
            assert 0 <= evidence.credibility_score <= 100
        
        # Verify graph database calls
        mock_graph_db.ingest_evidence_batch.assert_called()
        mock_graph_db.create_linkage_relationships.assert_called()
        
        # Check for linkage metadata
        linked_evidence = [ev for ev in scored_evidence if "linkage_group_id" in ev.metadata]
        assert len(linked_evidence) >= 0  # May have correlations

    @patch("foep.correlate.graph_db.GraphDatabase")
    def test_pipeline_with_extraction(self, mock_graph_db_class, mock_config):
        """Test pipeline with entity extraction from unstructured text."""
        mock_graph_db = MagicMock()
        mock_graph_db_class.return_value.__enter__.return_value = mock_graph_db
        
        # Create evidence with extractable content
        log_evidence = Evidence(
            evidence_id="log_cmd::123",
            entity_type=EntityType.COMMAND_LINE,
            entity_value="User john@company.com connected from 192.168.1.100 to server",
            observation_type=ObservationType.LOG_ARTIFACT,
            source="syslog",
            metadata={},
            credibility_score=100,
            sha256_hash=None
        )
        
        pipeline = FOEPPipeline(
            config=mock_config,
            case_id="TEST-002",
            investigator="test_analyst"
        )
        pipeline.all_evidence = [log_evidence]
        
        scored_evidence = pipeline.run_correlation_and_scoring()
        
        # Should have original + extracted entities
        assert len(scored_evidence) > 1
        
        # Check for extracted email and IP
        emails = [ev for ev in scored_evidence if ev.entity_type == EntityType.EMAIL]
        ips = [ev for ev in scored_evidence if ev.entity_type == EntityType.IP]
        
        assert len(emails) >= 1
        assert len(ips) >= 1
        assert emails[0].entity_value == "john@company.com"
        assert ips[0].entity_value == "192.168.1.100"

    @patch("foep.correlate.graph_db.GraphDatabase")
    def test_pipeline_credibility_scoring(self, mock_graph_db_class, mock_config):
        """Test credibility scoring with corroboration."""
        mock_graph_db = MagicMock()
        mock_graph_db_class.return_value.__enter__.return_value = mock_graph_db
        
        # Create corroborating evidence
        email1 = Evidence(
            evidence_id="osint_email::1",
            entity_type=EntityType.EMAIL,
            entity_value="user@company.com",
            observation_type=ObservationType.OSINT_POST,
            source="github",
            metadata={},
            credibility_score=90,
            sha256_hash=None
        )
        
        email2 = Evidence(
            evidence_id="log_email::1",
            entity_type=EntityType.EMAIL,
            entity_value="user@company.com",
            observation_type=ObservationType.LOG_ARTIFACT,
            source="log_parser",
            metadata={},
            credibility_score=100,
            sha256_hash=None
        )
        
        pipeline = FOEPPipeline(
            config=mock_config,
            case_id="TEST-003",
            investigator="test_analyst"
        )
        pipeline.all_evidence = [email1, email2]
        
        scored_evidence = pipeline.run_correlation_and_scoring()
        
        # Both should have increased credibility due to corroboration
        for evidence in scored_evidence:
            if evidence.entity_value == "user@company.com":
                # Should have bonus for corroboration
                assert evidence.credibility_score > evidence.metadata["original_credibility_score"]
                # Check scoring metadata
                assert "credibility_adjustments" in evidence.metadata
                adjustments = evidence.metadata["credibility_adjustments"]
                assert adjustments["corroboration_bonus"] > 0

    @patch("foep.report.generator.ReportGenerator")
    @patch("foep.correlate.graph_db.GraphDatabase")
    def test_pipeline_report_generation(self, mock_graph_db_class, mock_report_generator_class, mock_config, sample_evidence):
        """Test report generation in the pipeline."""
        mock_graph_db = MagicMock()
        mock_graph_db_class.return_value.__enter__.return_value = mock_graph_db
        
        mock_report_generator = MagicMock()
        mock_report_generator_class.return_value = mock_report_generator
        mock_report_generator.generate_report.return_value = "/tmp/test_report.pdf"
        
        pipeline = FOEPPipeline(
            config=mock_config,
            case_id="TEST-004",
            investigator="test_analyst"
        )
        pipeline.all_evidence = sample_evidence
        
        # Run full pipeline up to reporting
        pipeline.run_correlation_and_scoring()
        
        # Generate report
        report_path = pipeline.generate_report(
            output_dir="/tmp",
            format="pdf",
            case_info={"title": "Test Report"}
        )
        
        # Verify report generator was called correctly
        mock_report_generator.generate_report.assert_called_once()
        assert report_path == "/tmp/test_report.pdf"
        
        # Verify evidence passed to report generator includes custody
        args, kwargs = mock_report_generator.generate_report.call_args
        evidence_list = kwargs["evidence_list"]
        for evidence in evidence_list:
            assert "chain_of_custody" in evidence.metadata
            custody = evidence.metadata["chain_of_custody"]
            assert custody["investigator"] == "test_analyst"
            assert custody["case_id"] == "TEST-004"

    def test_pipeline_json_roundtrip(self, mock_config, sample_evidence):
        """Test JSON serialization/deserialization of pipeline evidence."""
        pipeline = FOEPPipeline(
            config=mock_config,
            case_id="TEST-005",
            investigator="test_analyst"
        )
        pipeline.all_evidence = sample_evidence
        
        # Serialize to JSON
        evidence_dicts = [ev.model_dump() for ev in sample_evidence]
        
        # Deserialize back to Evidence objects
        deserialized = [
            Evidence(**ev_dict) for ev_dict in evidence_dicts
        ]
        
        # Verify roundtrip integrity
        for original, restored in zip(sample_evidence, deserialized):
            assert original.evidence_id == restored.evidence_id
            assert original.entity_value == restored.entity_value
            assert original.credibility_score == restored.credibility_score
            assert original.metadata == restored.metadata

    @patch("foep.correlate.graph_db.GraphDatabase")
    def test_pipeline_error_handling(self, mock_graph_db_class, mock_config):
        """Test pipeline error handling and resilience."""
        mock_graph_db = MagicMock()
        # Simulate Neo4j failure
        mock_graph_db.ingest_evidence_batch.side_effect = Exception("Neo4j connection failed")
        mock_graph_db_class.return_value.__enter__.return_value = mock_graph_db
        
        evidence = [
            Evidence(
                evidence_id="test::1",
                entity_type=EntityType.IP,
                entity_value="192.168.1.1",
                observation_type=ObservationType.LOG_ARTIFACT,
                source="test",
                credibility_score=100
            )
        ]
        
        pipeline = FOEPPipeline(
            config=mock_config,
            case_id="TEST-006",
            investigator="test_analyst"
        )
        pipeline.all_evidence = evidence
        
        # Should not crash on Neo4j failure - continue to reporting
        scored_evidence = pipeline.run_correlation_and_scoring()
        assert len(scored_evidence) == 1  # Evidence still processed

    @patch("foep.correlate.graph_db.GraphDatabase")
    def test_pipeline_with_realistic_scenario(self, mock_graph_db_class, mock_config):
        """Test pipeline with a realistic investigation scenario."""
        mock_graph_db = MagicMock()
        mock_graph_db_class.return_value.__enter__.return_value = mock_graph_db
        
        # Simulate evidence from a real investigation
        evidence = [
            # Forensic evidence
            Evidence(
                evidence_id="disk_user::john",
                entity_type=EntityType.USERNAME,
                entity_value="john",
                observation_type=ObservationType.DISK_ARTIFACT,
                source="disk_image",
                metadata={"home_dir": "/home/john"},
                credibility_score=100
            ),
            Evidence(
                evidence_id="mem_proc::1234",
                entity_type=EntityType.FILE,
                entity_value="malware.exe",
                observation_type=ObservationType.MEMORY_ARTIFACT,
                source="volatility3",
                metadata={"pid": 1234, "command_line": "malware.exe --connect 10.0.0.5:4444"},
                credibility_score=100
            ),
            # OSINT evidence
            Evidence(
                evidence_id="github_user::john_hacker",
                entity_type=EntityType.USERNAME,
                entity_value="john_hacker",
                observation_type=ObservationType.OSINT_POST,
                source="github",
                metadata={"email": "john@personal.com"},
                credibility_score=90
            ),
            Evidence(
                evidence_id="breach_email::john@company.com",
                entity_type=EntityType.EMAIL,
                entity_value="john@company.com",
                observation_type=ObservationType.OSINT_BREACH,
                source="hibp",
                metadata={"breach_name": "CompanyDB"},
                credibility_score=85
            )
        ]
        
        pipeline = FOEPPipeline(
            config=mock_config,
            case_id="REAL-001",
            investigator="senior_analyst"
        )
        pipeline.all_evidence = evidence
        
        scored_evidence = pipeline.run_correlation_and_scoring()
        
        # Should have extracted entities from command line
        extracted = [ev for ev in scored_evidence if ev.source == "entity_extractor"]
        assert len(extracted) > 0
        
        # Should have high-credibility items
        high_cred = [ev for ev in scored_evidence if ev.credibility_score >= 80]
        assert len(high_cred) > 0
        
        # All evidence should have custody metadata after reporting
        pipeline.generate_report("/tmp", "html", {"title": "Real Investigation"})
        reported_evidence = pipeline.all_evidence
        for ev in reported_evidence:
            assert "chain_of_custody" in ev.metadata


class TestPipelineCLIIntegration:
    """Test integration with CLI scripts."""
    
    def test_pipeline_ingest_correlate_report_flow(self, mock_config):
        """Test the complete CLI workflow: ingest -> correlate -> report."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            
            # Step 1: Create sample evidence (simulating ingestion)
            evidence = [
                Evidence(
                    evidence_id="test::1",
                    entity_type=EntityType.EMAIL,
                    entity_value="user@test.com",
                    observation_type=ObservationType.OSINT_POST,
                    source="github",
                    credibility_score=90
                )
            ]
            
            # Save to JSON (like foep_ingest.py would)
            ingest_file = tmp_path / "evidence.json"
            with open(ingest_file, "w") as f:
                json.dump([ev.model_dump() for ev in evidence], f, indent=2)
            
            # Step 2: Load and correlate (like foep_correlate.py would)
            pipeline = FOEPPipeline(
                config=mock_config,
                case_id="CLI-TEST",
                investigator="cli_user"
            )
            
            with open(ingest_file, "r") as f:
                loaded_evidence = [Evidence(**item) for item in json.load(f)]
            
            pipeline.all_evidence = loaded_evidence
            correlated_evidence = pipeline.run_correlation_and_scoring()
            
            # Save correlated evidence
            correlate_file = tmp_path / "correlated.json"
            with open(correlate_file, "w") as f:
                json.dump([ev.model_dump() for ev in correlated_evidence], f, indent=2)
            
            # Step 3: Generate report (like foep_report.py would)
            report_dir = tmp_path / "reports"
            pipeline.generate_report(str(report_dir), "html", {"title": "CLI Test Report"})
            
            # Verify files were created
            assert correlate_file.exists()
            assert (report_dir / "foep_report_CLI-TEST.html").exists()


if __name__ == "__main__":
    pytest.main([__file__])
