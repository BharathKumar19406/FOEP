# src/foep/correlate/extractor.py

import ipaddress
import logging
import re
from typing import Generator, Set, Dict, Any, List
from urllib.parse import urlparse

from foep.normalize.schema import Evidence, EntityType

logger = logging.getLogger(__name__)


class EntityExtractor:
    """
    Extracts structured entities from Evidence objects for graph correlation.

    Operates on Evidence.entity_value and Evidence.metadata to find correlatable identifiers.
    """

    def __init__(self):
        # Precompile regex patterns for performance
        self.patterns = {
            EntityType.IP: re.compile(
                r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
            ),
            EntityType.EMAIL: re.compile(
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
            ),
            EntityType.DOMAIN: re.compile(
                r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b"
            ),
            EntityType.HASH: re.compile(
                r"\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}|[a-fA-F0-9]{128})\b"
            ),
            EntityType.URL: re.compile(r"https?://[^\s<>\"]+|www\.[^\s<>\"]+"),
        }

        # Common false positive filters
        self.false_positive_domains = {
            "localhost",
            "example.com",
            "test.com",
            "local",
            "broadcasthost",
        }
        self.false_positive_ips = {"0.0.0.0", "255.255.255.255", "127.0.0.1", "::1"}

    def extract_from_evidence(
        self, evidence: Evidence
    ) -> Generator[Evidence, None, None]:
        """
        Extract all identifiable entities from an Evidence object.

        Yields new Evidence objects representing extracted entities,
        linked to the original via metadata.
        """
        if not isinstance(evidence, Evidence):
            logger.warning("Non-Evidence object passed to extractor")
            return

        # Extract from entity_value
        yield from self._extract_from_text(
            evidence.entity_value, evidence, evidence.entity_type
        )

        # Extract from metadata (recursively)
        yield from self._extract_from_metadata(evidence.metadata, evidence)

    def _extract_from_text(
        self,
        text: str,
        source_evidence: Evidence,
        original_type: EntityType,
    ) -> Generator[Evidence, None, None]:
        """Extract entities from a text string."""
        if not isinstance(text, str) or not text.strip():
            return

        extracted: Set[str] = set()  # Deduplicate within this text

        # IP addresses
        for match in self.patterns[EntityType.IP].finditer(text):
            ip_str = match.group()
            if self._is_valid_ip(ip_str) and ip_str not in self.false_positive_ips:
                if ip_str not in extracted:
                    extracted.add(ip_str)
                    yield self._create_extracted_evidence(
                        ip_str, EntityType.IP, source_evidence
                    )

        # Emails
        for match in self.patterns[EntityType.EMAIL].finditer(text):
            email = match.group().lower()
            if email not in extracted:
                extracted.add(email)
                yield self._create_extracted_evidence(
                    email, EntityType.EMAIL, source_evidence
                )

        # Domains (from URLs or standalone)
        for match in self.patterns[EntityType.URL].finditer(text):
            url = match.group()
            domain = self._extract_domain_from_url(url)
            if domain and self._is_valid_domain(domain):
                if (
                    domain not in extracted
                    and domain not in self.false_positive_domains
                ):
                    extracted.add(domain)
                    yield self._create_extracted_evidence(
                        domain, EntityType.DOMAIN, source_evidence
                    )

        # Standalone domains
        for match in self.patterns[EntityType.DOMAIN].finditer(text):
            domain = match.group().lower()
            if (
                self._is_valid_domain(domain)
                and domain not in extracted
                and domain not in self.false_positive_domains
            ):
                extracted.add(domain)
                yield self._create_extracted_evidence(
                    domain, EntityType.DOMAIN, source_evidence
                )

        # Hashes
        for match in self.patterns[EntityType.HASH].finditer(text):
            hash_val = match.group().lower()
            if hash_val not in extracted:
                extracted.add(hash_val)
                hash_type = self._infer_hash_type(hash_val)
                yield self._create_extracted_evidence(
                    hash_val, EntityType.HASH, source_evidence, {"hash_type": hash_type}
                )

    def _extract_from_metadata(
        self, metadata: Dict[str, Any], source_evidence: Evidence
    ) -> Generator[Evidence, None, None]:
        """Recursively extract from metadata dictionary."""
        if not isinstance(metadata, dict):
            return

        for key, value in metadata.items():
            if isinstance(value, str):
                yield from self._extract_from_text(
                    value, source_evidence, EntityType.COMMAND_LINE
                )
            elif isinstance(value, (list, tuple)):
                for item in value:
                    if isinstance(item, str):
                        yield from self._extract_from_text(
                            item, source_evidence, EntityType.COMMAND_LINE
                        )
            elif isinstance(value, dict):
                yield from self._extract_from_metadata(value, source_evidence)

    def _is_valid_ip(self, ip_str: str) -> bool:
        """Validate IP and exclude private/reserved ranges if needed."""
        try:
            ip = ipaddress.ip_address(ip_str)
            # Keep all IPs (including private) — let investigator decide relevance
            return True
        except ValueError:
            return False

    def _is_valid_domain(self, domain: str) -> bool:
        """Basic domain validation."""
        if len(domain) > 253:
            return False
        if domain.startswith("-") or domain.endswith("-"):
            return False
        if ".." in domain:
            return False
        labels = domain.split(".")
        if len(labels) < 2:
            return False
        for label in labels:
            if len(label) == 0 or len(label) > 63:
                return False
            if label.startswith("-") or label.endswith("-"):
                return False
            if not re.match(r"^[a-zA-Z0-9\-]+$", label):
                return False
        return True

    def _extract_domain_from_url(self, url: str) -> str:
        """Safely extract domain from URL."""
        try:
            if not url.startswith(("http://", "https://")):
                url = "http://" + url
            parsed = urlparse(url)
            return parsed.netloc.lower()
        except Exception:
            return ""

    def _infer_hash_type(self, hash_val: str) -> str:
        """Infer hash algorithm from length."""
        length = len(hash_val)
        if length == 32:
            return "md5"
        elif length == 40:
            return "sha1"
        elif length == 64:
            return "sha256"
        elif length == 128:
            return "sha512"
        else:
            return "unknown"

    def _create_extracted_evidence(
        self,
        value: str,
        entity_type: EntityType,
        source_evidence: Evidence,
        extra_meta: Dict[str, Any] = None,
    ) -> Evidence:
        """Create a new Evidence object for the extracted entity."""
        metadata = {
            "extracted_from_evidence_id": source_evidence.evidence_id,
            "original_entity_type": source_evidence.entity_type.value,
            "original_observation_type": source_evidence.observation_type.value,
            "original_source": source_evidence.source,
        }
        if extra_meta:
            metadata.update(extra_metadata)

        # Inherit credibility (or slightly reduce for extracted entities)
        credibility = max(source_evidence.credibility_score - 5, 0)

        return Evidence(
            evidence_id=f"extracted::{entity_type.value}::{value}",
            entity_type=entity_type,
            entity_value=value,
            observation_type=source_evidence.observation_type,
            source="entity_extractor",
            metadata=metadata,
            credibility_score=credibility,
            sha256_hash=None,
        )


# --- PUBLIC INTERFACE ---
def extract_identifiers(evidence: Evidence) -> List[Evidence]:
    """
    Public API to extract all identifiers from an Evidence object.

    Args:
        evidence: Input Evidence object

    Returns:
        List of new Evidence objects representing extracted entities.
    """
    extractor = EntityExtractor()
    return list(extractor.extract_from_evidence(evidence))
