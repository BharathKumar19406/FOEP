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

# OSINT subpackage will be added when implemented
# from . import osint

__all__ = [
    "forensic",
    "VirusTotalCollector",
    "ShodanCollector",
    "IPGeolocationCollector",
    "WHOISHistoryCollector",
    "ArchiveOrgCollector"
    # "osint",  # Uncomment when osint modules are ready
]
