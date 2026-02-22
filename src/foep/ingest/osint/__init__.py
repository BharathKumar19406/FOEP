# src/foep/ingest/osint/__init__.py

"""
OSINT ingestion module for FOEP.
Exposes social media, breach, and code repository collectors.
"""

from . import social
from . import breaches
from . import code_repos
from . import domains
from . import virustotal

__all__ = [
    "social",
    "breaches",
    "code_repos",
    "domains",
    "virtustotal",
]
