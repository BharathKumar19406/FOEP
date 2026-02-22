# src/foep/correlate/__init__.py

"""
Correlation engine for FOEP.
Links entities across forensic and OSINT datasets using graph-based modeling.
"""

from .extractor import extract_identifiers
from .linker import link_entities
from .graph_db import GraphDatabase

__all__ = [
    "extract_identifiers",
    "link_entities",
    "GraphDatabase",
]
