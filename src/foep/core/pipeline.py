# src/foep/core/pipeline.py

import logging
import time
from pathlib import Path
from typing import List, Dict, Any, Optional, Union

from foep.core.config import FOEPConfig
from foep.ingest.forensic import (
    ingest_disk_image,
    ingest_memory_dump,
    ingest_log_file,
    ingest_logs_directory,
)
from foep.ingest.osint.social import collect_social_osint
from foep.ingest.osint.breaches import collect_breach_osint
from foep.ingest.osint.code_repos import collect_code_repo_osint
from foep.normalize.schema import Evidence, ObservationType
from foep.correlate.extractor import extract_identifiers
from foep.correlate.linker import link_entities
from foep.correlate.graph_db import GraphDatabase
from foep.credibility.scorer import CredibilityScorer
from foep.report.redactor import Redactor
from foep.report.custody import ChainOfCustody
from foep.report.generator import ReportGenerator

logger = logging.getLogger(__name__)


class FOEPPipeline:
    """
    End-to-end pipeline for the Forensic OSINT-to-Evidence Pipeline (FOEP).

    Orchestrates ingestion, correlation, scoring, and reporting in a forensically sound manner.
    """

    def __init__(self, config: FOEPConfig, case_id: str, investigator: str):
        """
        Initialize FOEP pipeline.

        Args:
            config: Validated FOEP configuration
            case_id: Unique case identifier
            investigator: Name of the investigating analyst
        """
        self.config = config
        self.case_id = case_id
        self.investigator = investigator
        self.custody = ChainOfCustody(
            investigator=investigator,
            case_id=case_id,
            organization=config.case_defaults.get("organization", "Unknown Org"),
        )
        self.all_evidence: List[Evidence] = []

    def run_forensic_ingestion(
        self,
        disk_images: Optional[List[str]] = None,
        memory_dumps: Optional[List[str]] = None,
        log_files: Optional[List[str]] = None,
        log_directories: Optional[List[str]] = None,
    ) -> List[Evidence]:
        """
        Ingest forensic artefacts from disk, memory, and logs.

        Args:
            disk_images: List of disk image paths (E01, RAW, etc.)
            memory_dumps: List of memory dump paths
            log_files: List of individual log files
            log_directories: List of directories containing logs

        Returns:
            List of ingested Evidence objects.
        """
        evidence = []
        input_sources = []

        # Disk images
        if disk_images:
            for img_path in disk_images:
                logger.info(f"Ingesting disk image: {img_path}")
                input_sources.append(img_path)
                try:
                    evidence.extend(ingest_disk_image(img_path))
                except Exception as e:
                    logger.error(f"Failed to ingest disk image {img_path}: {e}")

        # Memory dumps
        if memory_dumps:
            for mem_path in memory_dumps:
                logger.info(f"Ingesting memory dump: {mem_path}")
                input_sources.append(mem_path)
                try:
                    evidence.extend(ingest_memory_dump(mem_path))
                except Exception as e:
                    logger.error(f"Failed to ingest memory dump {mem_path}: {e}")

        # Log files
        if log_files:
            for log_path in log_files:
                logger.info(f"Ingesting log file: {log_path}")
                input_sources.append(log_path)
                try:
                    evidence.extend(ingest_log_file(log_path))
                except Exception as e:
                    logger.error(f"Failed to ingest log file {log_path}: {e}")

        # Log directories
        if log_directories:
            for log_dir in log_directories:
                logger.info(f"Ingesting log directory: {log_dir}")
                input_sources.append(log_dir)
                try:
                    evidence.extend(ingest_logs_directory(log_dir))
                except Exception as e:
                    logger.error(f"Failed to ingest log directory {log_dir}: {e}")

        logger.info(
            f"Forensic ingestion complete. Collected {len(evidence)} artefacts."
        )
        self.all_evidence.extend(evidence)
        return evidence

    def run_osint_collection(
        self,
        social_queries: Optional[List[Dict[str, str]]] = None,
        breach_queries: Optional[List[Dict[str, str]]] = None,
        code_queries: Optional[List[str]] = None,
    ) -> List[Evidence]:
        """
        Collect OSINT from social media, breach databases, and code repositories.

        Args:
            social_queries: List of {"platform": "...", "identifier": "..."}
            breach_queries: List of {"query": "...", "type": "email|username|domain"}
            code_queries: List of search terms for code repositories

        Returns:
            List of collected OSINT Evidence objects.
        """
        evidence = []

        # Social media
        if social_queries:
            for query in social_queries:
                platform = query.get("platform", "").lower()
                identifier = query.get("identifier", "")
                if not platform or not identifier:
                    continue
                logger.info(f"Collecting {platform} OSINT for: {identifier}")
                try:
                    evidence.extend(
                        collect_social_osint(
                            platform, identifier, self.config.model_dump()
                        )
                    )
                except Exception as e:
                    logger.error(f"Failed to collect {platform} OSINT: {e}")

        # Breach data
        if breach_queries:
            for query in breach_queries:
                q = query.get("query", "")
                q_type = query.get("type", "email")
                if not q:
                    continue
                logger.info(f"Searching breaches for {q_type}: {q}")
                try:
                    evidence.extend(
                        collect_breach_osint(q, q_type, self.config.model_dump())
                    )
                except Exception as e:
                    logger.error(f"Failed to collect breach  {e}")

        # Code repositories
        if code_queries:
            for query in code_queries:
                logger.info(f"Searching code repos for: {query}")
                try:
                    evidence.extend(
                        collect_code_repo_osint(query, self.config.model_dump())
                    )
                except Exception as e:
                    logger.error(f"Failed to collect code repo  {e}")

        logger.info(f"OSINT collection complete. Collected {len(evidence)} items.")
        self.all_evidence.extend(evidence)
        return evidence

    def run_correlation_and_scoring(self) -> List[Evidence]:
        """
        Perform entity extraction, linking, graph persistence, and credibility scoring.

        Returns:
            List of scored and linked Evidence objects.
        """
        if not self.all_evidence:
            logger.warning("No evidence to correlate")
            return []

        logger.info("Starting correlation and scoring pipeline...")

        # Step 1: Extract identifiers from all evidence
        logger.info("Extracting identifiers from evidence...")
        extracted_evidence = []
        for ev in self.all_evidence:
            try:
                extracted_evidence.extend(extract_identifiers(ev))
            except Exception as e:
                logger.debug(f"Failed to extract from {ev.evidence_id}: {e}")
        all_with_extracted = self.all_evidence + extracted_evidence
        logger.info(f"Extracted {len(extracted_evidence)} additional entities")

        # Step 2: Link related entities
        logger.info("Linking related entities...")
        linked_evidence = link_entities(all_with_extracted)
        logger.info(f"Created linkage groups for {len(linked_evidence)} evidence items")

        # Step 3: Score evidence credibility
        logger.info("Scoring evidence credibility...")
        scorer = CredibilityScorer(
            max_corroboration_bonus=self.config.credibility.max_corroboration_bonus,
            age_penalty_per_day=self.config.credibility.age_penalty_per_day,
            max_age_penalty=self.config.credibility.max_age_penalty,
            conflict_penalty=self.config.credibility.conflict_penalty,
            min_credibility=self.config.credibility.min_credibility,
        )
        scored_evidence = scorer.score_evidence_batch(linked_evidence)
        logger.info("Credibility scoring complete")

        # Step 4: Persist to graph database
        logger.info("Persisting to graph database...")
        try:
            with GraphDatabase(
                uri=self.config.neo4j.uri,
                username=self.config.neo4j.username,
                password=self.config.neo4j.password.get_secret_value(),
                database=self.config.neo4j.database,
            ) as gdb:
                # Ingest evidence
                gdb.ingest_evidence_batch(scored_evidence)
                # Create linkage relationships
                gdb.create_linkage_relationships(scored_evidence)
        except Exception as e:
            logger.error(f"Failed to persist to Neo4j: {e}")
            # Continue without graph persistence (reporting still works)

        self.all_evidence = scored_evidence
        return scored_evidence

    def generate_report(
        self,
        output_dir: Union[str, Path],
        format: str = "pdf",
        case_info: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Generate a court-admissible forensic report.

        Args:
            output_dir: Directory to save report
            format: "pdf" or "html"
            case_info: Additional case metadata

        Returns:
            Path to generated report file.
        """
        if not self.all_evidence:
            raise ValueError("No evidence to report on")

        # Prepare case info
        default_info = {
            "title": f"FOEP Investigation Report - {self.case_id}",
            "description": self.config.case_defaults.get(
                "description", "Forensic OSINT investigation"
            ),
            "investigator": self.investigator,
            "case_id": self.case_id,
        }
        if case_info:
            default_info.update(case_info)

        # Create redactor
        redactor = Redactor(
            redact_emails=self.config.redaction.redact_emails,
            redact_ips=self.config.redaction.redact_ips,
            redact_names=self.config.redaction.redact_names,
            redact_usernames=self.config.redaction.redact_usernames,
            preserve_internal_ips=self.config.redaction.preserve_internal_ips,
            allowlist_domains=self.config.redaction.allowlist_domains,
            blocklist_domains=self.config.redaction.blocklist_domains,
        )

        # Add chain of custody to evidence
        evidence_with_custody = self.custody.add_custody_to_evidence(
            self.all_evidence,
            input_sources=[],  # Input sources should be passed during ingestion
        )

        # Generate report
        generator = ReportGenerator(
            redactor=redactor,
            neo4j_uri=self.config.neo4j.uri,
        )

        output_path = Path(output_dir) / f"foep_report_{self.case_id}.{format}"
        report_path = generator.generate_report(
            evidence_list=evidence_with_custody,
            output_path=output_path,
            case_info=default_info,
            custody=self.custody,
            format=format,
        )

        # Generate standalone custody log
        custody_log = self.custody.generate_custody_log(
            evidence_with_custody, Path(output_dir) / f"custody_{self.case_id}.json"
        )

        logger.info(f"Report generated: {report_path}")
        logger.info(f"Custody log: {custody_log}")
        return report_path

    def run_full_pipeline(
        self,
        disk_images: Optional[List[str]] = None,
        memory_dumps: Optional[List[str]] = None,
        log_files: Optional[List[str]] = None,
        log_directories: Optional[List[str]] = None,
        social_queries: Optional[List[Dict[str, str]]] = None,
        breach_queries: Optional[List[Dict[str, str]]] = None,
        code_queries: Optional[List[str]] = None,
        output_dir: Union[str, Path] = "reports",
        report_format: str = "pdf",
        case_info: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Execute the complete FOEP pipeline from ingestion to reporting.

        Returns:
            Path to generated report.
        """
        start_time = time.time()
        logger.info(f"Starting FOEP full pipeline for case: {self.case_id}")

        # Ingest forensic data
        self.run_forensic_ingestion(
            disk_images=disk_images,
            memory_dumps=memory_dumps,
            log_files=log_files,
            log_directories=log_directories,
        )

        # Collect OSINT
        self.run_osint_collection(
            social_queries=social_queries,
            breach_queries=breach_queries,
            code_queries=code_queries,
        )

        # Correlate and score
        self.run_correlation_and_scoring()

        # Generate report
        report_path = self.generate_report(
            output_dir=output_dir,
            format=report_format,
            case_info=case_info,
        )

        elapsed = time.time() - start_time
        logger.info(f"FOEP pipeline completed in {elapsed:.2f} seconds")
        return report_path
