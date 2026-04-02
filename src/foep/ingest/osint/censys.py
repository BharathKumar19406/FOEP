"""
Censys integration for FOEP.
Provides internet host data, certificates, and infrastructure intelligence.
"""

import logging
import requests
from typing import Generator, Dict, Any
from foep.normalize.schema import Evidence, EntityType, ObservationType

logger = logging.getLogger(__name__)


class CensysCollector:
    """Queries Censys for infrastructure and certificate data."""
    
    BASE_URL = "https://api.censys.io/v1"
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize Censys collector with config dict."""
        self.config = config if isinstance(config, dict) else config.model_dump() if hasattr(config, 'model_dump') else {}
        censys_config = self.config.get('censys', {})
        self.user_id = censys_config.get('user_id', "")
        self.api_secret = censys_config.get('api_secret', "")
        self.enabled = censys_config.get('enabled', True)
        self.auth = (self.user_id, self.api_secret) if self.user_id and self.api_secret else None
    
    def search_ip(self, ip: str) -> Generator[Evidence, None, None]:
        """Search Censys for IP host information."""
        if not self.enabled or not self.auth:
            logger.warning("Censys not configured")
            return
        
        url = f"{self.BASE_URL}/view/ipv4/{ip}"
        
        try:
            response = requests.get(url, auth=self.auth, timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                services = []
                protocols = data.get("protocols", [])
                for protocol in protocols:
                    proto_port = protocol.split("/")
                    if len(proto_port) == 2:
                        services.append(proto_port[1].split("/")[0])
                
                yield Evidence(
                    evidence_id=f"censys_ip::{ip}",
                    entity_type=EntityType.IP_ADDRESS,
                    entity_value=ip,
                    observation_type=ObservationType.OSINT_EXPOSURE,
                    source="censys",
                    metadata={
                        "open_services": services,
                        "protocols": protocols,
                        "location_country": data.get("location", {}).get("country_code", "unknown"),
                        "autonomous_system": data.get("autonomous_system", {}).get("asn", "unknown"),
                        "last_updated": data.get("last_updated_at", "unknown"),
                    },
                    credibility_score=75,
                    sha256_hash=None
                )
            elif response.status_code == 404:
                logger.debug(f"IP {ip} not found in Censys")
            elif response.status_code == 401:
                logger.error("Censys authentication failed")
        except Exception as e:
            logger.error(f"Censys API error for IP {ip}: {e}")
    
    def search_certificate(self, serial: str) -> Generator[Evidence, None, None]:
        """Search Censys for SSL certificate information."""
        if not self.enabled or not self.auth:
            return
        
        url = f"{self.BASE_URL}/view/certificates/{serial}"
        
        try:
            response = requests.get(url, auth=self.auth, timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                yield Evidence(
                    evidence_id=f"censys_cert::{serial}",
                    entity_type=EntityType.HASH,  # Certificate serial is hash-like
                    entity_value=serial,
                    observation_type=ObservationType.OSINT_REPUTATION,
                    source="censys",
                    metadata={
                        "subject_cn": data.get("subject", {}).get("common_name", "unknown"),
                        "issuer_cn": data.get("issuer", {}).get("common_name", "unknown"),
                        "validity_start": data.get("validity", {}).get("start", "unknown"),
                        "validity_end": data.get("validity", {}).get("end", "unknown"),
                        "public_key_type": data.get("public_key", {}).get("key_algorithm", "unknown"),
                    },
                    credibility_score=70,
                    sha256_hash=None
                )
            elif response.status_code == 404:
                logger.debug(f"Certificate {serial} not found in Censys")
        except Exception as e:
            logger.error(f"Censys API error for certificate {serial}: {e}")


def collect_censys_data(
    query_value: str,
    query_type: str,  # 'ip', 'certificate'
    config: Dict[str, Any]
) -> Generator[Evidence, None, None]:
    """
    Collect infrastructure data from Censys.
    
    Args:
        query_value: IP address or certificate serial
        query_type: Type of query ('ip', 'certificate')
        config: Configuration dictionary
    
    Yields:
        Evidence objects
    """
    collector = CensysCollector(config)
    
    if query_type.lower() == 'ip':
        yield from collector.search_ip(query_value)
    elif query_type.lower() == 'certificate':
        yield from collector.search_certificate(query_value)
    else:
        logger.warning(f"Unsupported Censys query type: {query_type}")
