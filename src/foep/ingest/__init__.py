# src/foep/ingest/__init__.py

"""
Top-level ingestion package for FOEP.
Exposes forensic and OSINT ingestion interfaces.
"""

# Forensic subpackage is imported via its own __init__.py
from . import forensic
from .osint.virustotal import VirusTotalCollector
from .osint.shodan import ShodanCollector
from .osint.ipgeolocation import IPGeolocationCollector
from .osint.whois_history import WHOISHistoryCollector
from .osint.archiveorg import ArchiveOrgCollector
from .threat_utils import (
    ThreatDetectionIngest,
    enrich_evidence_with_threat_intel,
    filter_evidence_by_threat_level,
    get_high_priority_evidence,
    create_threat_summary,
)

# OSINT subpackage will be added when implemented
# from . import osint

__all__ = [
    "forensic",
    "VirusTotalCollector",
    "ShodanCollector",
    "IPGeolocationCollector",
    "WHOISHistoryCollector",
    "ArchiveOrgCollector",
    "ThreatDetectionIngest",
    "enrich_evidence_with_threat_intel",
    "filter_evidence_by_threat_level",
    "get_high_priority_evidence",
    "create_threat_summary",
    # "osint",  # Uncomment when osint modules are ready
]
