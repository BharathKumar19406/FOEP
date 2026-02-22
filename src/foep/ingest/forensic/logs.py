# src/foep/ingest/forensic/logs.py

import hashlib
import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Generator, Dict, Any, Optional, Union
from xml.etree import ElementTree as ET


try:
    from Evtx import Evtx
except ImportError:
    try:
        from Evtx import evtx as Evtx
    except ImportError:
        # Fallback: skip EVTX processing
        Evtx = None
# python-evtx

from foep.normalize.schema import Evidence, EntityType, ObservationType
from foep.normalize.hash_utils import compute_sha256

logger = logging.getLogger(__name__)


# --- Windows EVTX PARSING ---
def _parse_evtx_file(file_path: Path) -> Generator[Dict[str, Any], None, None]:
    """Parse EVTX and yield structured events."""
    if Evtx is None:
        logger.warning("EVTX parsing not available")
        return
    # ... rest of
    try:
        with Evtx.Evtx(str(file_path)) as evtx_file:
            for record in evtx_file.records():
                try:
                    xml_str = record.xml()
                    root = ET.fromstring(xml_str)

                    # Extract system fields
                    system = root.find("System", {})
                    event_data = root.find("EventData", {})

                    event_id = None
                    if system is not None:
                        event_id_elem = system.find("EventID", {})
                        event_id = (
                            int(event_id_elem.text)
                            if event_id_elem is not None
                            and event_id_elem.text.isdigit()
                            else None
                        )

                    # Build flat dict
                    event = {
                        "timestamp": None,
                        "event_id": event_id,
                        "computer": None,
                        "user": None,
                        "process_id": None,
                        "thread_id": None,
                        "channel": None,
                        "message": "",
                        "raw_xml": xml_str,
                    }

                    if system is not None:
                        time_created = system.find("TimeCreated", {})
                        if time_created is not None:
                            ts_str = time_created.get("SystemTime")
                            if ts_str:
                                try:
                                    event["timestamp"] = datetime.fromisoformat(
                                        ts_str.replace("Z", "+00:00")
                                    ).isoformat()
                                except ValueError:
                                    pass

                        event["computer"] = (system.find("Computer", {}) or {}).text
                        event["channel"] = (system.find("Channel", {}) or {}).text

                        user_id = system.find("Security", {})
                        if user_id is not None:
                            event["user"] = user_id.get("UserID")

                        pid = system.find("Execution", {})
                        if pid is not None:
                            event["process_id"] = pid.get("ProcessID")
                            event["thread_id"] = pid.get("ThreadID")

                    # Extract event data fields
                    if event_data is not None:
                        data_fields = {}
                        for data in event_data.findall("Data", {}):
                            name = data.get("Name")
                            value = data.text or ""
                            if name:
                                data_fields[name] = value
                            event["message"] += f"{name}: {value} "

                    yield event

                except Exception as e:
                    logger.warning(f"Failed to parse EVTX record: {e}")
                    continue

    except Exception as e:
        logger.error(f"Failed to open EVTX file {file_path}: {e}")
        return


# --- SYSLOG PARSING (RFC 5424 & 3164) ---
_SYSLOG_RFC5424_PATTERN = re.compile(
    r"<(?P<pri>\d{1,3})>"
    r"(?P<version>\d) "
    r"(?P<timestamp>\S+) "
    r"(?P<hostname>\S+) "
    r"(?P<app_name>\S+) "
    r"(?P<proc_id>\S+) "
    r"(?P<msg_id>\S+) "
    r"(?P<structured_data>\S+) "
    r"(?P<message>.*)"
)

_SYSLOG_RFC3164_PATTERN = re.compile(
    r"<(?P<pri>\d{1,3})>"
    r"(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<tag>\S+):\s+"
    r"(?P<message>.*)"
)


def _parse_syslog_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse a single syslog line (RFC 5424 or 3164)."""
    line = line.strip()
    if not line:
        return None

    # Try RFC 5424 first
    match = _SYSLOG_RFC5424_PATTERN.match(line)
    if match:
        groups = match.groupdict()
        return {
            "timestamp": groups["timestamp"],
            "hostname": groups["hostname"],
            "app_name": groups["app_name"],
            "proc_id": groups["proc_id"],
            "message": groups["message"],
            "raw": line,
        }

    # Fall back to RFC 3164
    match = _SYSLOG_RFC3164_PATTERN.match(line)
    if match:
        groups = match.groupdict()
        return {
            "timestamp": groups["timestamp"],
            "hostname": groups["hostname"],
            "app_name": groups["tag"].split("[")[0] if groups["tag"] else None,
            "proc_id": (
                groups["tag"].split("[")[1].rstrip("]")
                if "[" in groups["tag"]
                else None
            ),
            "message": groups["message"],
            "raw": line,
        }

    return None


# --- JSON LOG PARSING ---
def _parse_json_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse a single JSON log line."""
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return None


def _emit_evidence_from_log_entry(
    log_entry: Dict[str, Any],
    log_hash: str,
    source_file: str,
    log_type: str,
) -> Generator[Evidence, None, None]:
    """Convert a parsed log entry into one or more Evidence objects."""
    metadata = {
        "source_file": source_file,
        "log_type": log_type,
        **{
            k: v for k, v in log_entry.items() if k not in ("message", "raw", "raw_xml")
        },
    }

    message = log_entry.get("message") or log_entry.get("raw") or ""

    # Emit the full log line as COMMAND_LINE (generic container for log content)
    yield Evidence(
        evidence_id=f"log::{log_hash}::{hash(message) & 0xFFFFFFFF}",
        entity_type=EntityType.COMMAND_LINE,
        entity_value=message,
        observation_type=ObservationType.LOG_ARTIFACT,
        source="log_parser",
        metadata=metadata,
        credibility_score=100,
        sha256_hash=None,
    )

    # Extract user
    user = log_entry.get("user") or log_entry.get("UserID")
    if user and isinstance(user, str):
        yield Evidence(
            evidence_id=f"log_user::{log_hash}::{user}",
            entity_type=EntityType.USERNAME,
            entity_value=user,
            observation_type=ObservationType.LOG_ARTIFACT,
            source="log_parser",
            metadata=metadata,
            credibility_score=100,
            sha256_hash=None,
        )

    # Extract hostname as IP or domain
    host = log_entry.get("hostname") or log_entry.get("computer")
    if host and isinstance(host, str):
        # Basic IP/domain detection (full extraction in correlate/extractor.py)
        yield Evidence(
            evidence_id=f"log_host::{log_hash}::{host}",
            entity_type=EntityType.DOMAIN if "." in host else EntityType.IP,
            entity_value=host,
            observation_type=ObservationType.LOG_ARTIFACT,
            source="log_parser",
            metadata=metadata,
            credibility_score=100,
            sha256_hash=None,
        )

    # Extract process
    proc = log_entry.get("app_name") or log_entry.get("process_id")
    if proc and isinstance(proc, str):
        yield Evidence(
            evidence_id=f"log_proc::{log_hash}::{proc}",
            entity_type=EntityType.FILE,
            entity_value=proc,
            observation_type=ObservationType.LOG_ARTIFACT,
            source="log_parser",
            metadata=metadata,
            credibility_score=100,
            sha256_hash=None,
        )


def ingest_log_file(
    log_path: Union[str, Path],
    max_entries: int = 10000,
) -> Generator[Evidence, None, None]:
    """
    Ingest a single log file (EVTX, syslog, or JSON) and yield Evidence objects.

    Args:
        log_path: Path to log file
        max_entries: Maximum number of log entries to process

    Yields:
        Evidence objects.
    """
    log_path = Path(log_path).resolve()
    if not log_path.exists():
        raise FileNotFoundError(f"Log file not found: {log_path}")

    logger.info(f"Ingesting log file: {log_path}")

    # Compute file hash
    with open(log_path, "rb") as f:
        log_hash = compute_sha256(f.read())

    suffix = log_path.suffix.lower()
    entry_count = 0

    try:
        if suffix == ".evtx":
            for event in _parse_evtx_file(log_path):
                if entry_count >= max_entries:
                    logger.warning("Max log entries reached")
                    return
                yield from _emit_evidence_from_log_entry(
                    event, log_hash, str(log_path), "evtx"
                )
                entry_count += 1

        else:
            # Text-based logs: syslog, JSON, generic
            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if entry_count >= max_entries:
                        break

                    parsed = None
                    stripped = line.strip()
                    if not stripped:
                        continue

                    # Try JSON first
                    if stripped.startswith("{"):
                        parsed = _parse_json_line(stripped)
                        if parsed is not None:
                            yield from _emit_evidence_from_log_entry(
                                parsed, log_hash, str(log_path), "json"
                            )
                            entry_count += 1
                            continue

                    # Try syslog
                    parsed = _parse_syslog_line(stripped)
                    if parsed is not None:
                        yield from _emit_evidence_from_log_entry(
                            parsed, log_hash, str(log_path), "syslog"
                        )
                        entry_count += 1
                        continue

                    # Fallback: treat as raw message
                    yield Evidence(
                        evidence_id=f"log_raw::{log_hash}::{hash(stripped) & 0xFFFFFFFF}",
                        entity_type=EntityType.COMMAND_LINE,
                        entity_value=stripped,
                        observation_type=ObservationType.LOG_ARTIFACT,
                        source="log_parser",
                        metadata={"source_file": str(log_path), "log_type": "raw"},
                        credibility_score=100,
                        sha256_hash=None,
                    )
                    entry_count += 1

    except Exception as e:
        logger.error(f"Error processing log file {log_path}: {e}")
        return


def ingest_logs_directory(
    dir_path: Union[str, Path],
    recursive: bool = True,
    max_entries_per_file: int = 10000,
) -> Generator[Evidence, None, None]:
    """Ingest all log files in a directory."""
    dir_path = Path(dir_path)
    if not dir_path.is_dir():
        raise ValueError(f"Path is not a directory: {dir_path}")

    pattern = "**/*" if recursive else "*"
    for file_path in dir_path.glob(pattern):
        if file_path.is_file() and file_path.suffix.lower() in [
            ".log",
            ".txt",
            ".evtx",
            ".json",
        ]:
            yield from ingest_log_file(file_path, max_entries=max_entries_per_file)
