"""
AbuseIPDB integration for FOEP.
Provides IP reputation and abuse reporting data.
"""

import logging
import requests
from typing import Generator, Dict, Any
from foep.normalize.schema import Evidence, EntityType, ObservationType

logger = logging.getLogger(__name__)


class AbuseIPDBCollector:
    """Queries AbuseIPDB for IP reputation and abuse reports."""
    
    BASE_URL = "https://api.abuseipdb.com/api/v2"
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize AbuseIPDB collector with config dict."""
        self.config = config if isinstance(config, dict) else config.model_dump() if hasattr(config, 'model_dump') else {}
        abuseip_config = self.config.get('abuseipdb', {})
        self.api_key = abuseip_config.get('api_key', "")
        self.enabled = abuseip_config.get('enabled', True)
    
    def check_ip(self, ip: str) -> Generator[Evidence, None, None]:
        """Check IP reputation on AbuseIPDB."""
        if not self.enabled:
            return
        
        if not self.api_key:
            logger.warning("AbuseIPDB API key not configured")
            return
        
        url = f"{self.BASE_URL}/check"
        headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": ""
        }
        
        try:
            response = requests.get(url, headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                abuse_data = data.get("data", {})
                
                confidence_score = abuse_data.get("abuseConfidenceScore", 0)
                total_reports = abuse_data.get("totalReports", 0)
                is_whitelisted = abuse_data.get("isWhitelisted", False)
                
                # Determine threat level
                if is_whitelisted:
                    threat_level = "benign"
                elif confidence_score >= 75:
                    threat_level = "critical"
                elif confidence_score >= 50:
                    threat_level = "high"
                elif confidence_score >= 25:
                    threat_level = "medium"
                elif total_reports > 0:
                    threat_level = "low"
                else:
                    threat_level = "unknown"
                
                yield Evidence(
                    evidence_id=f"abuseipdb_ip::{ip}",
                    entity_type=EntityType.IP_ADDRESS,
                    entity_value=ip,
                    observation_type=ObservationType.OSINT_REPUTATION,
                    source="abuseipdb",
                    metadata={
                        "confidence_score": confidence_score,
                        "total_reports": total_reports,
                        "is_whitelisted": is_whitelisted,
                        "threat_level": threat_level,
                        "isp": abuse_data.get("isp", "unknown"),
                        "domain": abuse_data.get("domain", "unknown"),
                        "country_code": abuse_data.get("countryCode", "unknown"),
                        "usage_type": abuse_data.get("usageType", "unknown"),
                    },
                    credibility_score=int(min(100, max(50, confidence_score + 50))),
                    sha256_hash=None
                )
            elif response.status_code == 429:
                logger.warning("AbuseIPDB rate limit exceeded")
            else:
                logger.warning(f"AbuseIPDB error: {response.status_code}")
        except Exception as e:
            logger.error(f"AbuseIPDB API error: {e}")


def collect_abuseipdb_intelligence(
    ip: str,
    config: Dict[str, Any]
) -> Generator[Evidence, None, None]:
    """
    Collect IP reputation from AbuseIPDB.
    
    Args:
        ip: IP address to check
        config: Configuration dictionary
    
    Yields:
        Evidence objects
    """
    collector = AbuseIPDBCollector(config)
    yield from collector.check_ip(ip)
