"""
URLScan integration for FOEP.
Provides URL scanning and web infrastructure intelligence.
"""

import logging
import requests
from typing import Generator, Dict, Any
import time
from foep.normalize.schema import Evidence, EntityType, ObservationType

logger = logging.getLogger(__name__)


class URLScanCollector:
    """Queries URLScan for URL and domain reputation."""
    
    BASE_URL = "https://urlscan.io/api/v1"
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize URLScan collector with config dict."""
        self.config = config if isinstance(config, dict) else config.model_dump() if hasattr(config, 'model_dump') else {}
        urlscan_config = self.config.get('urlscan', {})
        self.api_key = urlscan_config.get('api_key', "")
        self.enabled = urlscan_config.get('enabled', True)
    
    def scan_url(self, url: str) -> Generator[Evidence, None, None]:
        """Submit and retrieve URL scan results."""
        if not self.enabled:
            return
        
        # Submit for scanning
        submit_url = f"{self.BASE_URL}/scan/"
        headers = {
            "API-Key": self.api_key,
            "Content-Type": "application/json"
        } if self.api_key else {"Content-Type": "application/json"}
        
        data = {
            "url": url,
            "public": False
        }
        
        try:
            # Submit the URL
            response = requests.post(submit_url, json=data, headers=headers, timeout=10)
            
            if response.status_code in [200, 201]:
                scan_data = response.json()
                scan_id = scan_data.get("uuid")
                
                if not scan_id:
                    logger.warning(f"No scan ID returned for {url}")
                    return
                
                # Wait and retrieve results
                time.sleep(2)
                result_url = f"{self.BASE_URL}/result/{scan_id}/"
                result_response = requests.get(result_url, headers=headers, timeout=10)
                
                if result_response.status_code == 200:
                    result_data = result_response.json()
                    page = result_data.get("page", {})
                    
                    yield Evidence(
                        evidence_id=f"urlscan_scan::{scan_id}",
                        entity_type=EntityType.URL,
                        entity_value=url,
                        observation_type=ObservationType.OSINT_REPUTATION,
                        source="urlscan",
                        metadata={
                            "scan_id": scan_id,
                            "country": page.get("country", "unknown"),
                            "server": page.get("server", "unknown"),
                            "status_code": page.get("status", "unknown"),
                            "title": page.get("title", ""),
                            "domain": page.get("domain", ""),
                            "ip": page.get("ip", ""),
                        },
                        credibility_score=70,
                        sha256_hash=None
                    )
            elif response.status_code == 429:
                logger.warning("URLScan rate limit exceeded")
            else:
                logger.warning(f"URLScan submit error: {response.status_code}")
        except Exception as e:
            logger.error(f"URLScan API error: {e}")
    
    def query_domain(self, domain: str) -> Generator[Evidence, None, None]:
        """Query URLScan for recent scans of a domain."""
        if not self.enabled:
            return
        
        search_url = f"{self.BASE_URL}/search/?q=domain:{domain}"
        headers = {
            "API-Key": self.api_key
        } if self.api_key else {}
        
        try:
            response = requests.get(search_url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                results = data.get("results", [])
                
                if results:
                    # Get the most recent scan
                    latest = results[0]
                    
                    yield Evidence(
                        evidence_id=f"urlscan_domain::{domain}",
                        entity_type=EntityType.DOMAIN,
                        entity_value=domain,
                        observation_type=ObservationType.OSINT_REPUTATION,
                        source="urlscan",
                        metadata={
                            "latest_scan_id": latest.get("_id", ""),
                            "latest_scan_time": latest.get("result", ""),
                            "page_title": latest.get("title", ""),
                            "page_ip": latest.get("page", {}).get("ip", ""),
                            "total_scans": len(results),
                        },
                        credibility_score=65,
                        sha256_hash=None
                    )
        except Exception as e:
            logger.error(f"URLScan search error: {e}")


def collect_urlscan_data(
    query_value: str,
    query_type: str,  # 'url', 'domain'
    config: Dict[str, Any]
) -> Generator[Evidence, None, None]:
    """
    Collect URL and domain data from URLScan.
    
    Args:
        query_value: URL or domain to scan
        query_type: Type of query ('url', 'domain')
        config: Configuration dictionary
    
    Yields:
        Evidence objects
    """
    collector = URLScanCollector(config)
    
    if query_type.lower() == 'url':
        yield from collector.scan_url(query_value)
    elif query_type.lower() == 'domain':
        yield from collector.query_domain(query_value)
    else:
        logger.warning(f"Unsupported URLScan query type: {query_type}")
