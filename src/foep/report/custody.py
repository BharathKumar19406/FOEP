# src/foep/report/custody.py

import getpass
import hashlib
import logging
import os
import platform
import socket
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union
from pathlib import Path

from foep.normalize.hash_utils import compute_sha256_from_file

logger = logging.getLogger(__name__)


class ChainOfCustody:
    """
    Manages chain-of-custody metadata for forensic evidence.

    Embeds provenance data into Evidence metadata for legal compliance.
    """

    def __init__(
        self,
        investigator: Optional[str] = None,
        case_id: Optional[str] = None,
        organization: Optional[str] = None,
    ):
        """
        Initialize chain-of-custody context.

        Args:
            investigator: Name of investigator (defaults to OS user)
            case_id: Case reference number
            organization: Investigating organization
        """
        self.investigator = investigator or getpass.getuser()
        self.case_id = case_id or "DEFAULT_CASE"
        self.organization = organization or socket.getfqdn()
        self.tool_name = "FOEP"
        self.tool_version = self._get_tool_version()
        self.system_info = {
            "hostname": socket.gethostname(),
            "os": platform.platform(),
            "python_version": platform.python_version(),
        }

    def _get_tool_version(self) -> str:
        """Get FOEP version from package metadata."""
        try:
            from foep import __version__

            return __version__
        except ImportError:
            return "unknown"

    def add_custody_to_evidence(
        self,
        evidence_list: List["Evidence"],
        input_sources: Optional[List[Union[str, Path]]] = None,
    ) -> List["Evidence"]:
        """
        Add chain-of-custody metadata to a list of Evidence objects.

        Args:
            evidence_list: List of Evidence objects to enrich
            input_sources: Paths to original input files (for hash verification)

        Returns:
            List of Evidence objects with custody metadata.
        """
        from foep.normalize.schema import Evidence  # Late import to avoid circularity

        # Compute input hashes if sources provided
        input_hashes = {}
        if input_sources:
            for src in input_sources:
                src_path = Path(src)
                if src_path.exists() and src_path.is_file():
                    try:
                        hash_val = compute_sha256_from_file(str(src_path))
                        input_hashes[str(src_path)] = hash_val
                    except Exception as e:
                        logger.warning(f"Failed to hash input {src}: {e}")

        custody_record = {
            "investigator": self.investigator,
            "case_id": self.case_id,
            "organization": self.organization,
            "tool": {
                "name": self.tool_name,
                "version": self.tool_version,
                "system_info": self.system_info,
            },
            "custody_timestamp": self._get_timestamp(),
            "input_hashes": input_hashes,
        }

        enriched_evidence = []
        for evidence in evidence_list:
            metadata = dict(evidence.metadata)
            metadata["chain_of_custody"] = custody_record

            enriched_evidence.append(
                Evidence(
                    evidence_id=evidence.evidence_id,
                    entity_type=evidence.entity_type,
                    entity_value=evidence.entity_value,
                    observation_type=evidence.observation_type,
                    source=evidence.source,
                    metadata=metadata,
                    credibility_score=evidence.credibility_score,
                    sha256_hash=evidence.sha256_hash,
                )
            )

        return enriched_evidence

    def generate_custody_log(
        self,
        evidence_list: List["Evidence"],
        output_path: Union[str, Path],
    ) -> str:
        """
        Generate a standalone chain-of-custody log file.

        Args:
            evidence_list: List of Evidence objects
            output_path: Path to save custody log (JSON format)

        Returns:
            Absolute path to custody log file.
        """
        import json

        output_path = Path(output_path).resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Build custody manifest
        manifest = {
            "custody_header": {
                "investigator": self.investigator,
                "case_id": self.case_id,
                "organization": self.organization,
                "generated_at": self._get_timestamp(),
                "tool": f"{self.tool_name} v{self.tool_version}",
            },
            "evidence_summary": {
                "total_items": len(evidence_list),
                "sources": sorted(set(ev.source for ev in evidence_list)),
                "entity_types": sorted(
                    set(ev.entity_type.value for ev in evidence_list)
                ),
            },
            "evidence_items": [
                {
                    "evidence_id": ev.evidence_id,
                    "entity_type": ev.entity_type.value,
                    "source": ev.source,
                    "credibility_score": ev.credibility_score,
                    "sha256_hash": ev.sha256_hash,
                }
                for ev in evidence_list
            ],
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        logger.info(f"Chain-of-custody log saved to: {output_path}")
        return str(output_path)

    def _get_timestamp(self) -> str:
        """Get ISO 8601 UTC timestamp with timezone."""
        return datetime.now(timezone.utc).isoformat()
