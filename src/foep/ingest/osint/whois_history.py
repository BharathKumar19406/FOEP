import logging
import requests
from typing import Generator, Dict, Any
from foep.normalize.schema import Evidence, EntityType, ObservationType

logger = logging.getLogger(__name__)

class WHOISHistoryCollector:
    BASE_URL = "https://api.securitytrails.com/v1/history"

    def __init__(self, config):
        self.enabled = getattr(config.whois_history, 'enabled', False)
        self.api_key = getattr(config.whois_history, 'api_key', "")

    def check_domain(self, domain: str) -> Generator[Evidence, None, None]:
        if not self.enabled or not self.api_key:
            return

        url = f"{self.BASE_URL}/{domain}/whois"
        headers = {"APIKEY": self.api_key}
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                records = data.get("records", [])
                if records:
                    latest = records[0]
                    registrar = latest.get("registrar", "Unknown")
                    created = latest.get("created", "Unknown")
                    
                    yield Evidence(
                        evidence_id=f"whois_domain::{domain}",
                        entity_type=EntityType.DOMAIN,
                        entity_value=domain,
                        observation_type=ObservationType.OSINT_REGISTRATION,
                        source="whois_history",
                        metadata={
                            "registrar": registrar,
                            "created_date": created,
                            "record_count": len(records)
                        },
                        credibility_score=70,
                        sha256_hash=None
                    )
            elif response.status_code == 404:
                logger.info(f"Domain {domain} not found in WHOIS history")
            else:
                logger.warning(f"WHOIS History error for {domain}: {response.status_code}")
        except Exception as e:
            logger.error(f"WHOIS History API error: {e}")
