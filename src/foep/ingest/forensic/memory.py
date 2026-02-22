# src/foep/ingest/forensic/memory.py

import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Generator, Any, Dict, List, Optional

from volatility3 import framework
from volatility3.framework import contexts, automagic, interfaces, plugins
from volatility3.framework.configuration import requirements

try:
    from volatility3.plugins.windows.pslist import PsList
    from volatility3.plugins.windows.netscan import NetScan
    from volatility3.plugins.windows.dlllist import DllList
    from volatility3.plugins.linux.pslist import PsList as LinuxPsList
    from volatility3.plugins.linux.netfilter import NetFilter
    from volatility3.plugins.linux.sockstat import Sockstat
except ImportError:
    # Fallback for older versions
    from volatility3.plugins import windows, linux

from foep.normalize.schema import Evidence, EntityType, ObservationType
from foep.normalize.hash_utils import compute_sha256

logger = logging.getLogger(__name__)


def _setup_volatility_context(
    memory_path: str,
) -> tuple[interfaces.context.ContextInterface, str]:
    """Initialize Volatility 3 context and auto-detect OS."""
    # Register plugins
    framework.require_interface_version(2, 0, 0)
    automagics = automagic.available(contexts.Context())

    # Create context
    context = contexts.Context()

    # Add the memory layer
    layer_name = "memory_layer"
    context.config["automagic.LayerStacker.single_location"] = f"file:{memory_path}"
    context.config["automagic.LayerStacker.stackers"] = [
        "LinuxIntel32Stacker",
        "LinuxIntel64Stacker",
        "WindowsIntel32Stacker",
        "WindowsIntel64Stacker",
    ]

    # Run automagic to detect OS and build layers
    constructed = None
    for amagic in automagics:
        try:
            constructed = amagic(context, automagics, None, None)
            if constructed:
                break
        except Exception as e:
            logger.debug(f"Automagic {amagic.__class__.__name__} failed: {e}")
            continue

    if not constructed:
        raise RuntimeError("Failed to auto-detect OS or construct memory context")

    # Determine OS from available symbol tables
    os_name = "unknown"
    for requirement in constructed.requirements:
        if isinstance(requirement, requirements.SymbolTableRequirement):
            if "windows" in requirement.value.lower():
                os_name = "windows"
            elif "linux" in requirement.value.lower():
                os_name = "linux"
            break

    return context, os_name


def _run_plugin(
    context: interfaces.context.ContextInterface,
    plugin_cls: type,
    layer_name: str,
    symbol_table: str,
) -> List[Dict[str, Any]]:
    """Run a Volatility plugin and return structured results."""
    try:
        plugin = plugin_cls(context)
        if hasattr(plugin, "build_configuration"):
            plugin.build_configuration()
        # Set required config
        plugin.config["primary"] = layer_name
        if hasattr(plugin, "config") and "nt_symbols" in plugin.config:
            plugin.config["nt_symbols"] = symbol_table

        results = []
        for row in plugin.run():
            if hasattr(row, "_fields"):
                # Volatility uses named tuples or tree grids
                row_dict = {}
                for field in row._fields:
                    val = getattr(row, field)
                    # Convert non-serializable types
                    if isinstance(val, (bytes, bytearray)):
                        try:
                            row_dict[field] = val.decode("utf-8", errors="replace")
                        except Exception:
                            row_dict[field] = str(val)
                    elif hasattr(val, "__dict__"):
                        row_dict[field] = str(val)
                    else:
                        row_dict[field] = val
                results.append(row_dict)
            else:
                results.append({"raw": str(row)})
        return results
    except Exception as e:
        logger.error(f"Plugin {plugin_cls.__name__} failed: {e}")
        return []


def _emit_evidence_from_processes(
    processes: List[Dict], memory_hash: str
) -> Generator[Evidence, None, None]:
    for proc in processes:
        pid = proc.get("PID") or proc.get("Pid")
        name = proc.get("ImageFileName") or proc.get("Name") or "unknown"
        cmdline = proc.get("CommandLine") or ""

        metadata = {
            "pid": pid,
            "process_name": name,
            "command_line": cmdline,
            "offset": proc.get("Offset") or proc.get("VAD"),
        }

        # Emit process as FILE entity (executable path)
        yield Evidence(
            evidence_id=f"mem_proc::{memory_hash}::{pid}",
            entity_type=EntityType.FILE,
            entity_value=name,
            observation_type=ObservationType.MEMORY_ARTIFACT,
            source="volatility3",
            metadata=metadata,
            credibility_score=100,
            sha256_hash=None,
        )

        # Extract potential IPs/ports from cmdline (basic)
        # Full extraction done later in correlate/extractor.py
        if cmdline:
            yield Evidence(
                evidence_id=f"mem_cmdline::{memory_hash}::{pid}",
                entity_type=EntityType.COMMAND_LINE,
                entity_value=cmdline,
                observation_type=ObservationType.MEMORY_ARTIFACT,
                source="volatility3",
                metadata={"pid": pid, "process": name},
                credibility_score=100,
                sha256_hash=None,
            )


def _emit_evidence_from_network(
    conns: List[Dict], memory_hash: str, os_name: str
) -> Generator[Evidence, None, None]:
    for conn in conns:
        if os_name == "windows":
            local_addr = (
                f"{conn.get('LocalAddr', '0.0.0.0')}:{conn.get('LocalPort', 0)}"
            )
            remote_addr = (
                f"{conn.get('RemoteAddr', '0.0.0.0')}:{conn.get('RemotePort', 0)}"
            )
            pid = conn.get("PID")
        else:  # linux
            local_addr = f"{conn.get('LocalAddr', '0.0.0.0')}:{conn.get('LPort', 0)}"
            remote_addr = f"{conn.get('RemoteAddr', '0.0.0.0')}:{conn.get('RPort', 0)}"
            pid = conn.get("Pid")

        metadata = {"pid": pid, "protocol": conn.get("Proto", "TCP")}

        if local_addr != "0.0.0.0:0":
            yield Evidence(
                evidence_id=f"mem_net_local::{memory_hash}::{local_addr}",
                entity_type=EntityType.IP_PORT,
                entity_value=local_addr,
                observation_type=ObservationType.MEMORY_ARTIFACT,
                source="volatility3",
                metadata=metadata,
                credibility_score=100,
                sha256_hash=None,
            )
        if remote_addr != "0.0.0.0:0" and remote_addr != "127.0.0.1:0":
            yield Evidence(
                evidence_id=f"mem_net_remote::{memory_hash}::{remote_addr}",
                entity_type=EntityType.IP_PORT,
                entity_value=remote_addr,
                observation_type=ObservationType.MEMORY_ARTIFACT,
                source="volatility3",
                metadata=metadata,
                credibility_score=100,
                sha256_hash=None,
            )


def ingest_memory_dump(
    memory_path: str,
    max_evidence_count: int = 10000,
) -> Generator[Evidence, None, None]:
    """
    Ingest a memory dump using Volatility 3 and yield normalized Evidence objects.

    Args:
        memory_path: Path to memory dump (raw, ELF, etc.)
        max_evidence_count: Safety limit to prevent runaway output

    Yields:
        Evidence objects from memory analysis.
    """
    memory_path = Path(memory_path).resolve()
    if not memory_path.exists():
        raise FileNotFoundError(f"Memory dump not found: {memory_path}")

    logger.info(f"Ingesting memory dump: {memory_path}")

    # Compute hash for chain-of-custody
    with open(memory_path, "rb") as f:
        memory_hash = compute_sha256(
            f.read(1024 * 1024)
        )  # First 1MB for speed; full hash in custody.py later

    # Setup Volatility
    context, os_name = _setup_volatility_context(str(memory_path))
    logger.info(f"Detected OS: {os_name}")

    evidence_count = 0

    # --- Processes ---
    if os_name == "windows":
        processes = _run_plugin(context, PsList, "memory_layer", "nt_symbols")
    else:
        processes = _run_plugin(
            context, linux.pslist.PsList, "memory_layer", "linux_symbols"
        )

    for ev in _emit_evidence_from_processes(processes, memory_hash):
        if evidence_count >= max_evidence_count:
            logger.warning("Max evidence count reached in memory ingestion")
            return
        yield ev
        evidence_count += 1

    # --- Network connections ---
    if os_name == "windows":
        nets = _run_plugin(
            context, windows.netscan.NetScan, "memory_layer", "nt_symbols"
        )
    else:
        nets = _run_plugin(
            context, linux.netfilter.NetFilter, "memory_layer", "linux_symbols"
        )
        if not nets:  # fallback
            nets = _run_plugin(
                context, linux.sockstat.Sockstat, "memory_layer", "linux_symbols"
            )

    for ev in _emit_evidence_from_network(nets, memory_hash, os_name):
        if evidence_count >= max_evidence_count:
            return
        yield ev
        evidence_count += 1

    # --- DLLs (Windows only) ---
    if os_name == "windows":
        dlls = _run_plugin(
            context, windows.dlllist.DllList, "memory_layer", "nt_symbols"
        )
        for dll in dlls:
            pid = dll.get("PID")
            dll_path = dll.get("Path") or dll.get("Name")
            if dll_path and pid:
                if evidence_count >= max_evidence_count:
                    return
                yield Evidence(
                    evidence_id=f"mem_dll::{memory_hash}::{pid}::{dll_path}",
                    entity_type=EntityType.FILE,
                    entity_value=dll_path,
                    observation_type=ObservationType.MEMORY_ARTIFACT,
                    source="volatility3",
                    metadata={"pid": pid},
                    credibility_score=100,
                    sha256_hash=None,
                )
                evidence_count += 1

    logger.info(
        f"Memory ingestion complete. Generated {evidence_count} evidence items."
    )
