# src/foep/ingest/forensic/disk.py

import hashlib
import logging
import os
from pathlib import Path
from typing import Generator, Optional, List

from dfvfs.analyzer import analyzer
from dfvfs.lib import definitions, errors
from dfvfs.path import factory as path_spec_factory
from dfvfs.resolver import resolver
from dfvfs.volume import tsk_volume_system
from dfvfs.file_io import file_io
from dfvfs.vfs import file_entry

from foep.normalize.schema import Evidence, EntityType, ObservationType
from foep.normalize.hash_utils import compute_sha256

logger = logging.getLogger(__name__)


def _get_volume_system_path_specs(path_spec):
    """Retrieve volume system path specs (e.g., NTFS partitions in E01)."""
    try:
        type_indicators = analyzer.Analyzer.GetStorageMediaImageTypeIndicators(
            path_spec
        )
        if not type_indicators:
            # Not a storage media image; treat as single volume
            return [path_spec]

        volume_system_path_specs = []
        for type_indicator in type_indicators:
            volume_system_path_spec = path_spec_factory.Factory.NewPathSpec(
                type_indicator, parent=path_spec
            )
            volume_system = resolver.Resolver.OpenFileSystem(volume_system_path_spec)
            if isinstance(volume_system, tsk_volume_system.TSKVolumeSystem):
                volume_identifiers = volume_system.GetVolumeIdentifiers()
                for volume_id in volume_identifiers:
                    volume_location = f"/{volume_id}"
                    sub_path_spec = path_spec_factory.Factory.NewPathSpec(
                        definitions.TYPE_INDICATOR_TSK_PARTITION,
                        location=volume_location,
                        parent=volume_system_path_spec,
                    )
                    volume_system_path_specs.append(sub_path_spec)
            else:
                # Non-partitioned image (e.g., dd of a filesystem)
                volume_system_path_specs.append(volume_system_path_spec)
        return volume_system_path_specs
    except Exception as e:
        logger.warning(f"Failed to parse volume system: {e}")
        return [path_spec]


def _traverse_file_entry(
    file_entry: file_entry.FileEntry,
    base_path: str = "",
    max_file_size: int = 100 * 1024 * 1024,  # Skip files >100MB by default
) -> Generator[Evidence, None, None]:
    """Recursively traverse file entries and yield Evidence objects."""
    try:
        full_path = os.path.join(base_path, file_entry.name or "")
        is_directory = file_entry.IsDirectory()

        # Skip special files
        if file_entry.IsDevice() or file_entry.IsSocket() or file_entry.IsLink():
            return

        stat_object = file_entry.GetStat()
        size = getattr(stat_object, "size", 0) if stat_object else 0

        # Prepare metadata
        metadata = {
            "file_path": full_path,
            "is_directory": is_directory,
            "size_bytes": size,
        }

        if hasattr(stat_object, "crtime"):
            metadata["created_time"] = stat_object.crtime
        if hasattr(stat_object, "atime"):
            metadata["accessed_time"] = stat_object.atime
        if hasattr(stat_object, "mtime"):
            metadata["modified_time"] = stat_object.mtime
        if hasattr(stat_object, "ctime"):
            metadata["changed_time"] = stat_object.ctime

        # For directories, emit without content hash
        if is_directory:
            yield Evidence(
                evidence_id=f"disk_dir::{full_path}",
                entity_type=EntityType.FILE,
                entity_value=full_path,
                observation_type=ObservationType.DISK_ARTIFACT,
                source="disk_image",
                metadata=metadata,
                credibility_score=100,  # Internal artefact = high trust
                sha256_hash=None,
            )
        else:
            # Skip excessively large files to avoid memory issues
            if size > max_file_size:
                logger.info(f"Skipping large file: {full_path} ({size} bytes)")
                # Emit placeholder without content
                yield Evidence(
                    evidence_id=f"disk_file::{full_path}",
                    entity_type=EntityType.FILE,
                    entity_value=full_path,
                    observation_type=ObservationType.DISK_ARTIFACT,
                    source="disk_image",
                    metadata=metadata,
                    credibility_score=100,
                    sha256_hash=None,
                )
                return

            # Read content and compute hash
            try:
                file_object = file_entry.GetFileObject()
                if file_object:
                    content = file_object.read()
                    sha256 = compute_sha256(content)
                    metadata["content_preview"] = content[:200].decode(
                        "utf-8", errors="replace"
                    )
                    file_object.close()

                    yield Evidence(
                        evidence_id=f"disk_file::{sha256}",
                        entity_type=EntityType.FILE,
                        entity_value=full_path,
                        observation_type=ObservationType.DISK_ARTIFACT,
                        source="disk_image",
                        metadata=metadata,
                        credibility_score=100,
                        sha256_hash=sha256,
                    )
                else:
                    # File exists but no content (e.g., deleted)
                    yield Evidence(
                        evidence_id=f"disk_file::{full_path}",
                        entity_type=EntityType.FILE,
                        entity_value=full_path,
                        observation_type=ObservationType.DISK_ARTIFACT,
                        source="disk_image",
                        metadata=metadata,
                        credibility_score=100,
                        sha256_hash=None,
                    )
            except Exception as e:
                logger.error(f"Error reading file {full_path}: {e}")
                yield Evidence(
                    evidence_id=f"disk_file::{full_path}",
                    entity_type=EntityType.FILE,
                    entity_value=full_path,
                    observation_type=ObservationType.DISK_ARTIFACT,
                    source="disk_image",
                    metadata=metadata,
                    credibility_score=100,
                    sha256_hash=None,
                )

        # Recurse into directories
        if is_directory:
            for sub_entry in file_entry.sub_file_entries:
                yield from _traverse_file_entry(sub_entry, full_path, max_file_size)

    except Exception as e:
        logger.error(f"Error traversing {file_entry.name}: {e}")


def ingest_disk_image(
    image_path: str,
    max_file_size: int = 100 * 1024 * 1024,
    volume_index: Optional[int] = None,
) -> Generator[Evidence, None, None]:
    """
    Ingest a forensic disk image and yield normalized Evidence objects.

    Args:
        image_path: Path to disk image (RAW, E01, etc.)
        max_file_size: Skip files larger than this (bytes)
        volume_index: If multi-volume, specify 0-based index; else auto-detect

    Yields:
        Evidence objects representing files/directories.
    """
    image_path = Path(image_path).resolve()
    if not image_path.exists():
        raise FileNotFoundError(f"Disk image not found: {image_path}")

    logger.info(f"Ingesting disk image: {image_path}")

    # Step 1: Create OS path spec
    os_path_spec = path_spec_factory.Factory.NewPathSpec(
        definitions.TYPE_INDICATOR_OS, location=str(image_path)
    )

    # Step 2: Detect and resolve storage media type
    try:
        analyzer.Analyzer.GetStorageMediaImageTypeIndicators(os_path_spec)
    except errors.ScannerError:
        # Not a recognized image; treat as raw filesystem
        pass

    # Step 3: Get top-level path specs (volumes or single FS)
    volume_path_specs = _get_volume_system_path_specs(os_path_spec)

    if volume_index is not None:
        if volume_index >= len(volume_path_specs):
            raise ValueError(
                f"Volume index {volume_index} out of range (max: {len(volume_path_specs)-1})"
            )
        selected_specs = [volume_path_specs[volume_index]]
    else:
        selected_specs = volume_path_specs

    for path_spec in selected_specs:
        try:
            file_system = resolver.Resolver.OpenFileSystem(path_spec)
            root_entry = file_system.GetRootFileEntry()
            if root_entry:
                yield from _traverse_file_entry(root_entry, "/", max_file_size)
        except Exception as e:
            logger.error(f"Failed to process volume {path_spec}: {e}")
            continue
