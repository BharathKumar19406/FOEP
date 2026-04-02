import logging
import requests
from typing import Generator, Dict, Any
from foep.normalize.schema import Evidence, EntityType, ObservationType

logger = logging.getLogger(__name__)

class ArchiveOrgCollector:
    BASE_URL = "http://web.archive.org/cdx/search/cdx"

    def __init__(self, config):
        self.enabled = getattr(config.archiveorg, 'enabled', True) if hasattr(config, 'archiveorg') else True

    def check_domain(self, domain: str) -> Generator[Evidence, None, None]:
        if not self.enabled:
            return

        url = f"{self.BASE_URL}?url={domain}/*&output=json&limit=1000"
        
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if len(data) > 1:  # First row is header
                    snapshot_count = len(data) - 1
                    first_seen = data[1][1] if snapshot_count > 0 else "Unknown"
                    last_seen = data[-1][1] if snapshot_count > 0 else "Unknown"
                    
                    yield Evidence(
                        evidence_id=f"archive_domain::{domain}",
                        entity_type=EntityType.DOMAIN,
                        entity_value=domain,
                        observation_type=ObservationType.OSINT_HISTORICAL,
                        source="archiveorg",
                        metadata={
                            "snapshot_count": snapshot_count,
                            "first_seen": first_seen,
                            "last_seen": last_seen
                        },
                        credibility_score=65,
                        sha256_hash=None
                    )
            else:
                logger.warning(f"Archive.org error for {domain}: {response.status_code}")
        except Exception as e:
            logger.error(f"Archive.org API error: {e}")

    def check_url(self, url: str) -> Generator[Evidence, None, None]:
        """Check URL in Wayback Machine."""
        if not self.enabled:
            return

        api_url = f"{self.BASE_URL}?url={url}&output=json&limit=100"
        
        try:
            response = requests.get(api_url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if len(data) > 1:  # First row is header
                    snapshot_count = len(data) - 1
                    
                    yield Evidence(
                        evidence_id=f"archive_url::{url}",
                        entity_type=EntityType.URL,
                        entity_value=url,
                        observation_type=ObservationType.OSINT_HISTORICAL,
                        source="archiveorg",
                        metadata={
                            "snapshot_count": snapshot_count,
                            "first_snapshot": data[1][1] if snapshot_count > 0 else "Unknown",
                            "last_snapshot": data[-1][1] if snapshot_count > 0 else "Unknown",
                        },
                        credibility_score=65,
                        sha256_hash=None
                    )
        except Exception as e:
            logger.error(f"Archive.org URL check error: {e}")


def collect_wayback_data(
    url: str,
    config: Dict[str, Any]
) -> Generator[Evidence, None, None]:
    """
    Collect historical URL data from Archive.org Wayback Machine.
    
    Args:
        url: URL to search in Wayback Machine
        config: Configuration dictionary
    
    Yields:
        Evidence objects
    """
    collector = ArchiveOrgCollector(config)
    
    # Try as URL first
    yield from collector.check_url(url)
    
    # Also try as domain
    if "://" not in url:
        yield from collector.check_domain(url)
