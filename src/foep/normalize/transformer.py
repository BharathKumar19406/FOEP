# src/foep/normalize/transformer.py

import hashlib
import json
import logging
from typing import Any, Dict, List, Union, Generator, Optional
from datetime import datetime

from foep.normalize.schema import Evidence, EntityType, ObservationType
from foep.normalize.hash_utils import compute_sha256

logger = logging.getLogger(__name__)


class EvidenceNormalizer:
    """
    Normalizes raw artefacts into FOEP Evidence objects.

    Handles diverse input formats (dict, JSON string, log line) and maps them
    to standardized entity types with credibility scoring.
    """

    def __init__(self, default_credibility: int = 70):
        self.default_credibility = default_credibility

    def normalize(
        self,
        raw_input: Union[Dict[str, Any], str],
        source: str,
        observation_type: ObservationType,
        credibility_score: Optional[int] = None,
    ) -> Generator[Evidence, None, None]:
        """
        Normalize raw input into one or more Evidence objects.

        Args:
            raw_input: Dict or JSON string containing artefact data
            source: Origin tool/platform (e.g., "custom_parser", "sysmon")
            observation_type: Category of evidence
            credibility_score: Optional override; defaults to internal logic

        Yields:
            Validated Evidence objects.
        """
        # Parse if string
        if isinstance(raw_input, str):
            try:
                data = json.loads(raw_input)
            except json.JSONDecodeError:
                # Treat as raw log line
                data = {"raw_message": raw_input}
        else:
            data = raw_input

        if not isinstance(data, dict):
            logger.warning(f"Skipping non-dict input from {source}")
            return

        # Determine credibility
        score = (
            credibility_score
            if credibility_score is not None
            else self._infer_credibility(source)
        )

        # Extract entities based on observation type
        if observation_type == ObservationType.LOG_ARTIFACT:
            yield from self._normalize_log_artefact(data, source, score)
        elif observation_type == ObservationType.OSINT_POST:
            yield from self._normalize_osint_post(data, source, score)
        elif observation_type == ObservationType.OSINT_BREACH:
            yield from self._normalize_breach_data(data, source, score)
        elif observation_type == ObservationType.OSINT_CODE:
            yield from self._normalize_code_snippet(data, source, score)
        else:
            # Generic fallback: treat top-level string values as COMMAND_LINE
            yield from self._normalize_generic(data, source, score)

    def _infer_credibility(self, source: str) -> int:
        """Map source to credibility score."""
        internal_sources = {
            "volatility3",
            "disk_image",
            "log_parser",
            "sysmon",
            "plaso",
        }
        if source in internal_sources:
            return 100
        # OSINT sources handled by credibility/scorer.py later
        return self.default_credibility

    def _normalize_log_artefact(
        self, data: Dict[str, Any], source: str, score: int
    ) -> Generator[Evidence, None, None]:
        message = data.get("message") or data.get("raw_message") or str(data)
        evidence_id = f"log_norm::{source}::{hash(message) & 0xFFFFFFFF}"

        yield Evidence(
            evidence_id=evidence_id,
            entity_type=EntityType.COMMAND_LINE,
            entity_value=message,
            observation_type=ObservationType.LOG_ARTIFACT,
            source=source,
            metadata=data,
            credibility_score=score,
            sha256_hash=compute_sha256(message),
        )

    def _normalize_osint_post(
        self, data: Dict[str, Any], source: str, score: int
    ) -> Generator[Evidence, None, None]:
        # Try to extract structured entities
        username = data.get("username") or data.get("user")
        email = data.get("email")
        content = (
            data.get("content") or data.get("text") or data.get("bio") or str(data)
        )

        if username:
            yield Evidence(
                evidence_id=f"osint_user::{source}::{username}",
                entity_type=EntityType.USERNAME,
                entity_value=username,
                observation_type=ObservationType.OSINT_POST,
                source=source,
                metadata=data,
                credibility_score=score,
                sha256_hash=None,
            )
        if email:
            yield Evidence(
                evidence_id=f"osint_email::{source}::{email}",
                entity_type=EntityType.EMAIL,
                entity_value=email,
                observation_type=ObservationType.OSINT_POST,
                source=source,
                metadata=data,
                credibility_score=score,
                sha256_hash=None,
            )
        if content:
            yield Evidence(
                evidence_id=f"osint_post::{source}::{hash(content) & 0xFFFFFFFF}",
                entity_type=EntityType.POST,
                entity_value=content,
                observation_type=ObservationType.OSINT_POST,
                source=source,
                metadata=data,
                credibility_score=score,
                sha256_hash=compute_sha256(content),
            )

    def _normalize_breach_data(
        self, data: Dict[str, Any], source: str, score: int
    ) -> Generator[Evidence, None, None]:
        email = data.get("email")
        username = data.get("username")
        breach_name = data.get("breach_name") or data.get("database_name")

        if email:
            yield Evidence(
                evidence_id=f"breach_email::{source}::{email}",
                entity_type=EntityType.EMAIL,
                entity_value=email,
                observation_type=ObservationType.OSINT_BREACH,
                source=source,
                metadata=data,
                credibility_score=score,
                sha256_hash=None,
            )
        if username:
            yield Evidence(
                evidence_id=f"breach_user::{source}::{username}",
                entity_type=EntityType.USERNAME,
                entity_value=username,
                observation_type=ObservationType.OSINT_BREACH,
                source=source,
                metadata=data,
                credibility_score=score,
                sha256_hash=None,
            )
        if breach_name:
            yield Evidence(
                evidence_id=f"breach_record::{source}::{breach_name}",
                entity_type=EntityType.BREACH,
                entity_value=breach_name,
                observation_type=ObservationType.OSINT_BREACH,
                source=source,
                metadata=data,
                credibility_score=score,
                sha256_hash=None,
            )

    def _normalize_code_snippet(
        self, data: Dict[str, Any], source: str, score: int
    ) -> Generator[Evidence, None, None]:
        snippet = data.get("snippet") or data.get("code") or str(data)
        repo = data.get("repository") or data.get("repo")

        if snippet:
            yield Evidence(
                evidence_id=f"code_snippet::{source}::{hash(snippet) & 0xFFFFFFFF}",
                entity_type=EntityType.CODE_SNIPPET,
                entity_value=snippet,
                observation_type=ObservationType.OSINT_CODE,
                source=source,
                metadata=data,
                credibility_score=score,
                sha256_hash=compute_sha256(snippet),
            )
        if repo:
            yield Evidence(
                evidence_id=f"code_repo::{source}::{repo}",
                entity_type=EntityType.REPO,
                entity_value=repo,
                observation_type=ObservationType.OSINT_CODE,
                source=source,
                metadata=data,
                credibility_score=score,
                sha256_hash=None,
            )

    def _normalize_generic(
        self, data: Dict[str, Any], source: str, score: int
    ) -> Generator[Evidence, None, None]:
        # Emit each string value as COMMAND_LINE
        for key, value in data.items():
            if isinstance(value, str) and value.strip():
                yield Evidence(
                    evidence_id=f"generic::{source}::{key}::{hash(value) & 0xFFFFFFFF}",
                    entity_type=EntityType.COMMAND_LINE,
                    entity_value=value,
                    observation_type=ObservationType.LOG_ARTIFACT,
                    source=source,
                    metadata={"original_key": key, **data},
                    credibility_score=score,
                    sha256_hash=compute_sha256(value),
                )


# --- PUBLIC INTERFACE ---
def normalize_raw_input(
    raw_input: Union[Dict[str, Any], str],
    source: str,
    observation_type: ObservationType,
    credibility_score: Optional[int] = None,
) -> List[Evidence]:
    """
    Normalize raw input into a list of Evidence objects.

    This is the primary public API for external integrations.

    Args:
        raw_input: Raw artefact (dict or JSON string)
        source: Origin identifier
        observation_type: Evidence category
        credibility_score: Optional override

    Returns:
        List of validated Evidence objects.
    """
    normalizer = EvidenceNormalizer()
    return list(
        normalizer.normalize(raw_input, source, observation_type, credibility_score)
    )
