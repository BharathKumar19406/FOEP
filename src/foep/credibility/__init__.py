# src/foep/credibility/__init__.py

"""
Credibility scoring system for FOEP.
Assigns trust scores to evidence based on source, context, and corroboration.
"""

from .scorer import CredibilityScorer
from .sources import SOURCE_REPUTATION_REGISTRY

__all__ = [
    "CredibilityScorer",
    "SOURCE_REPUTATION_REGISTRY",
]
