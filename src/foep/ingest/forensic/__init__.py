# src/foep/ingest/forensic/__init__.py

"""
Forensic artefact ingestion module for FOEP.
Provides unified interfaces to parse disk images, memory dumps, and log files.
"""

from .disk import ingest_disk_image
from .memory import ingest_memory_dump
from .logs import ingest_log_file, ingest_logs_directory

__all__ = [
    "ingest_disk_image",
    "ingest_memory_dump",
    "ingest_log_file",
    "ingest_logs_directory",
]
