import logging
import requests
from typing import Generator, Dict, Any
from foep.normalize.schema import Evidence, EntityType, ObservationType

logger = logging.getLogger(__name__)

class IPGeolocationCollector:
    BASE_URL = "http://ip-api.com/json"

    def __init__(self, config):
        self.enabled = getattr(config.ipgeolocation, 'enabled', True)

    def check_ip(self, ip: str) -> Generator[Evidence, None, None]:
        if not self.enabled:
            return

        url = f"{self.BASE_URL}/{ip}"
        
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    country = data.get("country", "Unknown")
                    isp = data.get("isp", "Unknown")
                    lat = data.get("lat")
                    lon = data.get("lon")
                    
                    yield Evidence(
                        evidence_id=f"geo_ip::{ip}",
                        entity_type=EntityType.IP_ADDRESS,
                        entity_value=ip,
                        observation_type=ObservationType.OSINT_GEO,
                        source="ipgeolocation",
                        metadata={
                            "country": country,
                            "isp": isp,
                            "latitude": lat,
                            "longitude": lon
                        },
                        credibility_score=75,
                        sha256_hash=None
                    )
            else:
                logger.warning(f"IP Geolocation error for {ip}: {response.status_code}")
        except Exception as e:
            logger.error(f"IP Geolocation API error: {e}")
