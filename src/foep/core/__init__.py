# src/foep/core/__init__.py

"""
Core orchestration for FOEP.
Manages configuration and end-to-end pipeline execution.
"""

from .config import load_config
from .pipeline import FOEPPipeline

__all__ = [
    "load_config",
    "FOEPPipeline",
]
