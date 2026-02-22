import logging
import requests
from typing import Generator, Dict, Any
from foep.normalize.schema import Evidence, EntityType, ObservationType

logger = logging.getLogger(__name__)

class ShodanCollector:
    BASE_URL = "https://api.shodan.io"

    def __init__(self, config):
        self.enabled = getattr(config.shodan, 'enabled', False)
        self.api_key = getattr(config.shodan, 'api_key', "")

    def check_ip(self, ip: str) -> Generator[Evidence, None, None]:
        if not self.enabled or not self.api_key:
            return

        url = f"{self.BASE_URL}/shodan/host/{ip}?key={self.api_key}"
        
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                ports = data.get("ports", [])
                os = data.get("os", "Unknown")
                isp = data.get("isp", "Unknown")
                
                yield Evidence(
                    evidence_id=f"shodan_ip::{ip}",
                    entity_type=EntityType.IP_ADDRESS,
                    entity_value=ip,
                    observation_type=ObservationType.OSINT_EXPOSURE,
                    source="shodan",
                    metadata={
                        "open_ports": ports,
                        "operating_system": os,
                        "isp": isp
                    },
                    credibility_score=80,
                    sha256_hash=None
                )
            elif response.status_code == 404:
                logger.info(f"IP {ip} not found in Shodan")
            else:
                logger.warning(f"Shodan error for {ip}: {response.status_code}")
        except Exception as e:
            logger.error(f"Shodan API error: {e}")
