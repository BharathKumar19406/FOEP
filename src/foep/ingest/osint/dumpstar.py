"""
DumpStar integration for FOEP.
Provides access to leaked data and dark web databases.
"""

import logging
import requests
from typing import Generator, Dict, Any
from foep.normalize.schema import Evidence, EntityType, ObservationType

logger = logging.getLogger(__name__)


class DumpStarCollector:
    """Queries DumpStar for leaked data and dark web intelligence."""
    
    BASE_URL = "https://api.dumpstar.com/api/v1"
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize DumpStar collector with config dict."""
        self.config = config if isinstance(config, dict) else config.model_dump() if hasattr(config, 'model_dump') else {}
        dumpstar_config = self.config.get('dumpstar', {})
        self.api_key = dumpstar_config.get('api_key', "")
        self.enabled = dumpstar_config.get('enabled', True)
    
    def search_email(self, email: str) -> Generator[Evidence, None, None]:
        """Search DumpStar for email in leaked databases."""
        if not self.enabled:
            logger.warning("DumpStar not enabled")
            return
        
        if not self.api_key:
            logger.warning("DumpStar API key not configured")
            return
        
        url = f"{self.BASE_URL}/query"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        data = {
            "query": email,
            "type": "email"
        }
        
        try:
            response = requests.post(url, json=data, headers=headers, timeout=10)
            
            if response.status_code == 200:
                results = response.json()
                total_leaks = len(results.get("leaks", []))
                
                for leak in results.get("leaks", []):
                    yield Evidence(
                        evidence_id=f"dumpstar_leak::{email}_{leak.get('id')}",
                        entity_type=EntityType.EMAIL,
                        entity_value=email,
                        observation_type=ObservationType.OSINT_BREACH,
                        source="dumpstar",
                        metadata={
                            "leak_name": leak.get("name", "unknown"),
                            "leak_date": leak.get("date", "unknown"),
                            "records_count": leak.get("size", 0),
                            "data_types": leak.get("fields", []),
                            "severity": leak.get("severity", "medium"),
                        },
                        credibility_score=80,
                        sha256_hash=None
                    )
            elif response.status_code == 401:
                logger.error("DumpStar authentication failed")
            elif response.status_code == 404:
                logger.debug(f"Email {email} not found in DumpStar")
        except Exception as e:
            logger.error(f"DumpStar API error: {e}")
    
    def search_username(self, username: str) -> Generator[Evidence, None, None]:
        """Search DumpStar for username in leaked databases."""
        if not self.enabled or not self.api_key:
            return
        
        url = f"{self.BASE_URL}/query"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        data = {
            "query": username,
            "type": "username"
        }
        
        try:
            response = requests.post(url, json=data, headers=headers, timeout=10)
            
            if response.status_code == 200:
                results = response.json()
                
                for leak in results.get("leaks", []):
                    yield Evidence(
                        evidence_id=f"dumpstar_username::{username}_{leak.get('id')}",
                        entity_type=EntityType.USERNAME,
                        entity_value=username,
                        observation_type=ObservationType.OSINT_BREACH,
                        source="dumpstar",
                        metadata={
                            "leak_name": leak.get("name", "unknown"),
                            "leak_date": leak.get("date", "unknown"),
                            "data_types": leak.get("fields", []),
                            "severity": leak.get("severity", "medium"),
                        },
                        credibility_score=75,
                        sha256_hash=None
                    )
        except Exception as e:
            logger.error(f"DumpStar API error for username {username}: {e}")
    
    def search_phone(self, phone: str) -> Generator[Evidence, None, None]:
        """Search DumpStar for phone number in leaked databases."""
        if not self.enabled or not self.api_key:
            return
        
        url = f"{self.BASE_URL}/query"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        data = {
            "query": phone,
            "type": "phone"
        }
        
        try:
            response = requests.post(url, json=data, headers=headers, timeout=10)
            
            if response.status_code == 200:
                results = response.json()
                
                for leak in results.get("leaks", []):
                    yield Evidence(
                        evidence_id=f"dumpstar_phone::{phone}_{leak.get('id')}",
                        entity_type=EntityType.USERNAME,  # Using USERNAME as placeholder
                        entity_value=phone,
                        observation_type=ObservationType.OSINT_BREACH,
                        source="dumpstar",
                        metadata={
                            "leak_name": leak.get("name", "unknown"),
                            "leak_date": leak.get("date", "unknown"),
                            "data_types": leak.get("fields", []),
                        },
                        credibility_score=75,
                        sha256_hash=None
                    )
        except Exception as e:
            logger.error(f"DumpStar API error for phone {phone}: {e}")


def collect_dumpstar_leaks(
    query_value: str,
    query_type: str,  # 'email', 'username', 'phone'
    config: Dict[str, Any]
) -> Generator[Evidence, None, None]:
    """
    Collect leaked data from DumpStar.
    
    Args:
        query_value: Email, username, or phone number
        query_type: Type of query ('email', 'username', 'phone')
        config: Configuration dictionary
    
    Yields:
        Evidence objects
    """
    collector = DumpStarCollector(config)
    
    if query_type.lower() == 'email':
        yield from collector.search_email(query_value)
    elif query_type.lower() == 'username':
        yield from collector.search_username(query_value)
    elif query_type.lower() == 'phone':
        yield from collector.search_phone(query_value)
    else:
        logger.warning(f"Unsupported DumpStar query type: {query_type}")
