"""
AlienVault OTX (Open Threat Exchange) integration for FOEP.
Provides threat intelligence on IPs, domains, URLs, hashes, and files.
"""

import logging
import requests
from typing import Generator, Dict, Any, Optional
from foep.normalize.schema import Evidence, EntityType, ObservationType

logger = logging.getLogger(__name__)


class OTXCollector:
    """Queries AlienVault OTX for threat intelligence."""
    
    BASE_URL = "https://otx.alienvault.com/api/v1"
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize OTX collector with config dict."""
        self.config = config if isinstance(config, dict) else config.model_dump() if hasattr(config, 'model_dump') else {}
        otx_config = self.config.get('otx', {})
        self.api_key = otx_config.get('api_key', "")
        self.enabled = otx_config.get('enabled', True)
    
    def search_ip(self, ip: str) -> Generator[Evidence, None, None]:
        """Search OTX for IP reputation."""
        if not self.enabled:
            return
        
        url = f"{self.BASE_URL}/indicators/IPv4/{ip}/general"
        headers = {"X-OTX-API-KEY": self.api_key} if self.api_key else {}
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                pulse_count = len(data.get("pulse_info", {}).get("pulses", []))
                reputation = "suspicious" if pulse_count > 0 else "benign"
                
                yield Evidence(
                    evidence_id=f"otx_ip::{ip}",
                    entity_type=EntityType.IP_ADDRESS,
                    entity_value=ip,
                    observation_type=ObservationType.OSINT_REPUTATION,
                    source="otx",
                    metadata={
                        "reputation": reputation,
                        "pulse_count": pulse_count,
                        "threat_indicators": data.get("pulse_info", {}).get("count", 0),
                        "whitelisted": data.get("whitelisted", False),
                    },
                    credibility_score=75 if pulse_count > 0 else 60,
                    sha256_hash=None
                )
            elif response.status_code == 404:
                logger.debug(f"IP {ip} not found in OTX")
        except Exception as e:
            logger.error(f"OTX API error for IP {ip}: {e}")
    
    def search_domain(self, domain: str) -> Generator[Evidence, None, None]:
        """Search OTX for domain reputation."""
        if not self.enabled:
            return
        
        url = f"{self.BASE_URL}/indicators/domain/{domain}/general"
        headers = {"X-OTX-API-KEY": self.api_key} if self.api_key else {}
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                pulse_count = len(data.get("pulse_info", {}).get("pulses", []))
                reputation = "malicious" if pulse_count > 5 else "suspicious" if pulse_count > 0 else "benign"
                
                yield Evidence(
                    evidence_id=f"otx_domain::{domain}",
                    entity_type=EntityType.DOMAIN,
                    entity_value=domain,
                    observation_type=ObservationType.OSINT_REPUTATION,
                    source="otx",
                    metadata={
                        "reputation": reputation,
                        "pulse_count": pulse_count,
                        "threat_indicators": data.get("pulse_info", {}).get("count", 0),
                        "whitelisted": data.get("whitelisted", False),
                    },
                    credibility_score=80 if pulse_count > 5 else 65,
                    sha256_hash=None
                )
            elif response.status_code == 404:
                logger.debug(f"Domain {domain} not found in OTX")
        except Exception as e:
            logger.error(f"OTX API error for domain {domain}: {e}")
    
    def search_hash(self, hash_value: str) -> Generator[Evidence, None, None]:
        """Search OTX for hash reputation."""
        if not self.enabled:
            return
        
        # Determine hash type
        hash_type = "file"
        if len(hash_value) == 32:
            hash_type = "md5"
        elif len(hash_value) == 40:
            hash_type = "sha1"
        elif len(hash_value) == 64:
            hash_type = "sha256"
        
        url = f"{self.BASE_URL}/indicators/{hash_type}/{hash_value}/general"
        headers = {"X-OTX-API-KEY": self.api_key} if self.api_key else {}
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                pulse_count = len(data.get("pulse_info", {}).get("pulses", []))
                reputation = "malicious" if pulse_count > 0 else "benign"
                
                yield Evidence(
                    evidence_id=f"otx_hash::{hash_value}",
                    entity_type=EntityType.HASH,
                    entity_value=hash_value,
                    observation_type=ObservationType.OSINT_REPUTATION,
                    source="otx",
                    metadata={
                        "reputation": reputation,
                        "pulse_count": pulse_count,
                        "file_type": data.get("type", "unknown"),
                        "threat_indicators": data.get("pulse_info", {}).get("count", 0),
                    },
                    credibility_score=85 if pulse_count > 0 else 50,
                    sha256_hash=hash_value if hash_type == "sha256" else None
                )
            elif response.status_code == 404:
                logger.debug(f"Hash {hash_value} not found in OTX")
        except Exception as e:
            logger.error(f"OTX API error for hash {hash_value}: {e}")


def collect_otx_intelligence(
    query: str,
    query_type: str,  # 'ip', 'domain', 'hash'
    config: Dict[str, Any]
) -> Generator[Evidence, None, None]:
    """
    Collect threat intelligence from AlienVault OTX.
    
    Args:
        query: The value to search
        query_type: Type of indicator ('ip', 'domain', 'hash')
        config: Configuration dictionary
    
    Yields:
        Evidence objects
    """
    collector = OTXCollector(config)
    
    if query_type.lower() == 'ip':
        yield from collector.search_ip(query)
    elif query_type.lower() == 'domain':
        yield from collector.search_domain(query)
    elif query_type.lower() == 'hash':
        yield from collector.search_hash(query)
    else:
        logger.warning(f"Unsupported OTX query type: {query_type}")
