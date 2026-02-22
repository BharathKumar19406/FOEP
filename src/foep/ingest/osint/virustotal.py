# src/foep/ingest/osint/virustotal.py
import logging
import requests
from typing import Generator, Dict, Any
from foep.normalize.schema import Evidence, EntityType, ObservationType

logger = logging.getLogger(__name__)

class VirusTotalCollector:
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, config):
        self.enabled = getattr(config.virustotal, 'enabled', False)
        self.api_key = getattr(config.virustotal, 'api_key', "")

    def check_domain(self, domain: str) -> Generator[Evidence, None, None]:
        if not self.enabled or not self.api_key:
            return

        url = f"{self.BASE_URL}/domains/{domain}"
        headers = {"x-apikey": self.api_key}
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]
                malicious = stats.get("malicious", 0)
                total = sum(stats.values())
                
                yield Evidence(
                    evidence_id=f"vt_domain::{domain}",
                    entity_type=EntityType.DOMAIN,
                    entity_value=domain,
                    observation_type=ObservationType.OSINT_REPUTATION,
                    source="virustotal",
                    metadata={
                        "malicious_engines": malicious,
                        "total_engines": total,
                        "reputation": "clean" if malicious == 0 else "suspicious"
                    },
                    credibility_score=85 if malicious == 0 else 40,
                    sha256_hash=None
                )
            elif response.status_code == 404:
                logger.info(f"Domain {domain} not found in VirusTotal")
            else:
                logger.warning(f"VirusTotal error for {domain}: {response.status_code}")
        except Exception as e:
            logger.error(f"VirusTotal API error: {e}")


def collect_vt_hash(
    sha256: str, config: Dict[str, Any]
) -> Generator[Evidence, None, None]:
    """Check file hash on VirusTotal."""
    api_key = config.get("virustotal", {}).get("api_key")
    if not api_key:
        return

    headers = {"x-apikey": api_key}
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            yield Evidence(
                evidence_id=f"vt_file::{sha256}",
                entity_type=EntityType.HASH,
                entity_value=sha256,
                observation_type=ObservationType.OSINT_BREACH,
                source="virustotal",
                metadata={
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "first_seen": attributes.get("first_submission_date"),
                    "names": attributes.get("names", [])[:5],
                },
                credibility_score=85,
                sha256_hash=sha256,
            )
    except Exception as e:
        logger.error(f"VT hash check failed for {sha256}: {e}")
