# src/foep/threat/threat_intelligence_aggregator.py
"""
Threat Intelligence Aggregator for FOEP.

Combines threat data from multiple sources (API, feeds, local databases)
to provide comprehensive threat assessment.
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict

from foep.normalize.schema import Evidence
from foep.threat.threat_schema import (
    ThreatIntelligence,
    ThreatLevel,
    ThreatSource,
    ThreatIndicator,
)

logger = logging.getLogger(__name__)


@dataclass
class ThreatFeedConfig:
    """Configuration for a threat intelligence feed."""
    name: str
    source_type: str  # 'api', 'feed', 'local'
    enabled: bool = True
    priority: int = 1  # Higher priority feeds rated higher
    cache_duration: int = 3600  # Cache for 1 hour by default


class ThreatIntelligenceAggregator:
    """Aggregates threat intelligence from multiple sources."""
    
    def __init__(self):
        self.feeds: Dict[str, ThreatFeedConfig] = {}
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.threat_scores: Dict[str, float] = {}
        self._configure_feeds()
    
    def _configure_feeds(self):
        """Configure available threat feeds."""
        feeds = [
            ThreatFeedConfig('abuseipdb', 'api', True, 3),
            ThreatFeedConfig('otx', 'api', True, 2),
            ThreatFeedConfig('shodan', 'api', True, 2),
            ThreatFeedConfig('virustotal', 'api', True, 3),
            ThreatFeedConfig('local_malware_db', 'local', True, 2),
            ThreatFeedConfig('emergingthreats', 'feed', True, 1),
            ThreatFeedConfig('abuse_feeds', 'feed', True, 1),
        ]
        
        for feed in feeds:
            self.feeds[feed.name] = feed
    
    def aggregate_threats(self, evidence: Evidence) -> Optional[ThreatIntelligence]:
        """
        Aggregate threat intelligence from multiple sources for evidence.
        
        Args:
            evidence: Evidence object to analyze
            
        Returns:
            Aggregated ThreatIntelligence or None if no threats found
        """
        all_indicators: List[ThreatIndicator] = []
        source_results: Dict[str, Any] = {}
        threat_scores_list: List[float] = []
        
        # Query enabled feeds (in order of priority)
        enabled_feeds = sorted(
            [f for f in self.feeds.values() if f.enabled],
            key=lambda x: x.priority,
            reverse=True
        )
        
        for feed_config in enabled_feeds:
            try:
                # Try to get threat data from feed
                feed_result = self._query_feed(feed_config, evidence)
                
                if feed_result and 'indicators' in feed_result:
                    indicators = feed_result['indicators']
                    all_indicators.extend(indicators)
                    source_results[feed_config.name] = feed_result
                    
                    # Collect threat scores
                    if 'threat_score' in feed_result:
                        threat_scores_list.append(feed_result['threat_score'])
                        
            except Exception as e:
                logger.warning(f"Error querying {feed_config.name}: {e}")
                continue
        
        if not all_indicators:
            return None
        
        # Aggregate results
        aggregated_threat_intel = self._create_aggregated_result(
            evidence,
            all_indicators,
            source_results,
            threat_scores_list
        )
        
        return aggregated_threat_intel
    
    def _query_feed(self, feed_config: ThreatFeedConfig, evidence: Evidence) -> Optional[Dict[str, Any]]:
        """Query a specific threat feed."""
        cache_key = f"{feed_config.name}:{evidence.entity_value}"
        
        # Check cache first
        cache_entry = self.cache.get(cache_key)
        if cache_entry and cache_entry['timestamp'] > datetime.utcnow() - timedelta(seconds=feed_config.cache_duration):
            return cache_entry['data']
        
        # Simulate feed query (in production, would call actual APIs)
        result = None
        
        if feed_config.name == 'abuseipdb' and feed_config.source_type == 'api':
            result = self._mock_abuseipdb_query(evidence)
        elif feed_config.name == 'otx' and feed_config.source_type == 'api':
            result = self._mock_otx_query(evidence)
        elif feed_config.name == 'virustotal' and feed_config.source_type == 'api':
            result = self._mock_virustotal_query(evidence)
        elif feed_config.name == 'local_malware_db':
            result = self._mock_local_db_query(evidence)
        
        # Cache result
        if result:
            self.cache[cache_key] = {
                'timestamp': datetime.utcnow(),
                'data': result
            }
        
        return result
    
    def _mock_abuseipdb_query(self, evidence: Evidence) -> Optional[Dict[str, Any]]:
        """Mock AbuseIPDB API query."""
        # In production, this would call the real API
        known_abusive_ips = {
            '192.168.1.100': {'score': 92, 'reports': 156},
            '203.0.113.45': {'score': 78, 'reports': 89},
        }
        
        if evidence.entity_value in known_abusive_ips:
            data = known_abusive_ips[evidence.entity_value]
            return {
                'feed_name': 'abuseipdb',
                'threat_score': data['score'],
                'indicators': [
                    ThreatIndicator(
                        indicator_type='ip_reputation',
                        confidence=min(data['score'] / 100.0, 1.0),
                        description=f"AbuseIPDB score: {data['score']} from {data['reports']} reports"
                    )
                ]
            }
        return None
    
    def _mock_otx_query(self, evidence: Evidence) -> Optional[Dict[str, Any]]:
        """Mock OTX API query."""
        known_threats = {
            'malicious.ru': 'malicious',
            'botnet-c2.xyz': 'malicious',
        }
        
        if evidence.entity_value in known_threats:
            verdict = known_threats[evidence.entity_value]
            score = 95 if verdict == 'malicious' else 30
            return {
                'feed_name': 'otx',
                'threat_score': score,
                'indicators': [
                    ThreatIndicator(
                        indicator_type='otx_verdict',
                        confidence=0.9,
                        description=f"OTX verdict: {verdict}"
                    )
                ]
            }
        return None
    
    def _mock_virustotal_query(self, evidence: Evidence) -> Optional[Dict[str, Any]]:
        """Mock VirusTotal API query."""
        # Known malware hashes
        known_malware = {
            '69a26c7f9c4c8c44c88d7c9c8e3a3b3c': {'detections': 56, 'type': 'Emotet'},
            '2a4c6e8f0a2b4d6e8f0a2b4d6e8f0a2b': {'detections': 48, 'type': 'Ransomware'},
        }
        
        if evidence.entity_value in known_malware:
            data = known_malware[evidence.entity_value]
            return {
                'feed_name': 'virustotal',
                'threat_score': min(data['detections'] * 1.5, 100),
                'indicators': [
                    ThreatIndicator(
                        indicator_type=f'malware_{data["type"].lower()}',
                        confidence=min(data['detections'] / 60.0, 1.0),
                        description=f"{data['detections']} AV engines detected: {data['type']}"
                    )
                ]
            }
        return None
    
    def _mock_local_db_query(self, evidence: Evidence) -> Optional[Dict[str, Any]]:
        """Query local threat database."""
        # Local threat indicators
        local_threats = {
            'suspicious.bat': {'risk': 'medium', 'reason': 'Batch script'},
            'admin.exe': {'risk': 'high', 'reason': 'Privilege escalation attempt'},
        }
        
        if evidence.entity_value in local_threats:
            data = local_threats[evidence.entity_value]
            risk_score = {'low': 30, 'medium': 60, 'high': 85}
            return {
                'feed_name': 'local_malware_db',
                'threat_score': risk_score.get(data['risk'], 50),
                'indicators': [
                    ThreatIndicator(
                        indicator_type='local_threat_indicator',
                        confidence=0.75,
                        description=data['reason']
                    )
                ]
            }
        return None
    
    def _create_aggregated_result(
        self,
        evidence: Evidence,
        indicators: List[ThreatIndicator],
        source_results: Dict[str, Any],
        threat_scores: List[float],
    ) -> ThreatIntelligence:
        """Create aggregated threat intelligence result."""
        
        # Calculate aggregated threat score (weighted average)
        if threat_scores:
            avg_score = sum(threat_scores) / len(threat_scores)
        else:
            avg_score = sum(ind.confidence * 100 for ind in indicators) / len(indicators)
        
        # Determine threat level
        if avg_score >= 80:
            threat_level = ThreatLevel.CRITICAL
        elif avg_score >= 60:
            threat_level = ThreatLevel.HIGH
        elif avg_score >= 40:
            threat_level = ThreatLevel.MEDIUM
        elif avg_score >= 20:
            threat_level = ThreatLevel.LOW
        else:
            threat_level = ThreatLevel.INFO
        
        # Generate recommendations based on sources
        recommendations = self._generate_recommendations(avg_score, len(source_results))
        
        return ThreatIntelligence(
            evidence_id=evidence.evidence_id,
            entity_value=evidence.entity_value,
            entity_type=evidence.entity_type,
            threat_level=threat_level,
            threat_score=min(avg_score, 100.0),
            is_malicious=avg_score >= 50,
            indicators=indicators,
            primary_source=ThreatSource.CUSTOM,
            sources=source_results,
            scan_count=len(source_results),
            abuse_reports=len(indicators),
            recommendations=recommendations,
        )
    
    def _generate_recommendations(self, threat_score: float, source_count: int) -> List[str]:
        """Generate recommendations based on threat score and source consensus."""
        recommendations = []
        
        if threat_score >= 80:
            recommendations.append("CRITICAL: Take immediate action")
            recommendations.append("Block/Isolate this entity immediately")
            recommendations.append("Escalate to incident response team")
        elif threat_score >= 60:
            recommendations.append("HIGH: Review and take action")
            recommendations.append("Consider blocking this entity")
            recommendations.append("Increase monitoring")
        elif threat_score >= 40:
            recommendations.append("MEDIUM: Monitor this entity")
            recommendations.append("Investigate further")
        else:
            recommendations.append("LOW: Standard monitoring recommended")
        
        if source_count >= 5:
            recommendations.append(f"Multiple sources ({source_count}) confirm threat")
        elif source_count >= 3:
            recommendations.append("Multiple sources confirm threat patterns")
        
        return recommendations
    
    def get_feed_status(self) -> Dict[str, bool]:
        """Get status of all threat feeds."""
        return {name: feed.enabled for name, feed in self.feeds.items()}
    
    def enable_feed(self, feed_name: str) -> bool:
        """Enable a threat feed."""
        if feed_name in self.feeds:
            self.feeds[feed_name].enabled = True
            logger.info(f"Enabled threat feed: {feed_name}")
            return True
        return False
    
    def disable_feed(self, feed_name: str) -> bool:
        """Disable a threat feed."""
        if feed_name in self.feeds:
            self.feeds[feed_name].enabled = False
            logger.info(f"Disabled threat feed: {feed_name}")
            return True
        return False
    
    def clear_cache(self):
        """Clear the threat intelligence cache."""
        self.cache.clear()
        logger.info("Cleared threat intelligence cache")
