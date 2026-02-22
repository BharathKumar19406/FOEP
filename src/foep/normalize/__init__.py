# src/foep/normalize/__init__.py

"""
Normalization layer for FOEP.
Converts raw artefacts into structured, schema-compliant evidence objects.
"""

from .schema import Evidence, EntityType, ObservationType
from .hash_utils import compute_sha256
from .transformer import normalize_raw_input

__all__ = [
    "Evidence",
    "EntityType",
    "ObservationType",
    "compute_sha256",
    "normalize_raw_input",
]
