# src/foep/ingest/threat_utils.py
"""
Utility functions for threat detection during evidence ingestion.

Provides threat detection integration for forensic and OSINT collectors.
"""

import logging
from typing import List, Optional, Dict, Any

from foep.normalize.schema import Evidence, EntityType
from foep.threat import ThreatDetectionEngine, ThreatIntelligenceAggregator, ThreatIntelligence

logger = logging.getLogger(__name__)


class ThreatDetectionIngest:
    """Manages threat detection during ingestion process."""
    
    _instance = None
    _detector = None
    _aggregator = None
    
    def __new__(cls):
        """Singleton pattern."""
        if cls._instance is None:
            cls._instance = super(ThreatDetectionIngest, cls).__new__(cls)
            cls._instance._detector = ThreatDetectionEngine()
            cls._instance._aggregator = ThreatIntelligenceAggregator()
        return cls._instance
    
    @classmethod
    def get_detector(cls) -> ThreatDetectionEngine:
        """Get threat detection engine."""
        instance = cls()
        return instance._detector
    
    @classmethod
    def get_aggregator(cls) -> ThreatIntelligenceAggregator:
        """Get threat intelligence aggregator."""
        instance = cls()
        return instance._aggregator
    
    @classmethod
    def analyze_evidence(cls, evidence: Evidence) -> Optional[ThreatIntelligence]:
        """
        Analyze single evidence item for threats.
        
        Uses both local detection and aggregated threat intelligence.
        
        Args:
            evidence: Evidence object to analyze
            
        Returns:
            ThreatIntelligence if detected, None otherwise
        """
        detector = cls.get_detector()
        aggregator = cls.get_aggregator()
        
        # First try local detection
        local_threat = detector.detect_threats(evidence)
        if local_threat:
            return local_threat
        
        # Then try aggregated threat intelligence
        aggregated_threat = aggregator.aggregate_threats(evidence)
        return aggregated_threat
    
    @classmethod
    def analyze_batch(cls, evidence_list: List[Evidence]) -> Dict[str, List[ThreatIntelligence]]:
        """
        Batch analyze multiple evidence items.
        
        Args:
            evidence_list: List of evidence objects
            
        Returns:
            Dictionary with 'detected' and 'clean' lists
        """
        threats_detected = []
        clean_evidence = []
        
        for evidence in evidence_list:
            threat = cls.analyze_evidence(evidence)
            if threat:
                threats_detected.append(threat)
            else:
                clean_evidence.append(evidence)
        
        return {
            'detected': threats_detected,
            'clean': clean_evidence,
            'threat_count': len(threats_detected),
            'total_count': len(evidence_list),
        }
    
    @classmethod
    def get_threat_statistics(cls) -> Dict[str, Any]:
        """Get threat detection statistics."""
        detector = cls.get_detector()
        aggregator = cls.get_aggregator()
        
        return {
            'cache_size': len(detector.threat_cache),
            'feeds_status': aggregator.get_feed_status(),
            'active_feeds': sum(1 for v in aggregator.get_feed_status().values() if v),
        }


def enrich_evidence_with_threat_intel(evidence: Evidence) -> Evidence:
    """
    Enrich evidence object with threat intelligence.
    
    Args:
        evidence: Evidence object to enrich
        
    Returns:
        Enriched evidence with threat metadata
    """
    threat_intel = ThreatDetectionIngest.analyze_evidence(evidence)
    
    if threat_intel:
        # Add threat info to metadata
        if evidence.metadata is None:
            evidence.metadata = {}
        
        evidence.metadata['threat_intel'] = {
            'threat_level': threat_intel.threat_level.value,
            'threat_score': threat_intel.threat_score,
            'is_malicious': threat_intel.is_malicious,
            'indicator_count': len(threat_intel.indicators),
            'primary_source': threat_intel.primary_source.value,
            'recommendations': threat_intel.recommendations,
        }
        
        # Adjust credibility score based on threat level
        if threat_intel.is_malicious:
            evidence.credibility_score = max(evidence.credibility_score - 20, 0)
    
    return evidence


def filter_evidence_by_threat_level(
    evidence_list: List[Evidence],
    threat_level_threshold: str = 'high'
) -> Dict[str, List[Evidence]]:
    """
    Filter evidence by threat level.
    
    Args:
        evidence_list: List of evidence to filter
        threat_level_threshold: Minimum threat level ('critical', 'high', 'medium', 'low', 'info')
        
    Returns:
        Dictionary with categorized evidence
    """
    threat_levels = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
    threshold_value = threat_levels.get(threat_level_threshold.lower(), 1)
    
    critical = []
    high = []
    medium = []
    low = []
    clean = []
    
    for evidence in evidence_list:
        threat = ThreatDetectionIngest.analyze_evidence(evidence)
        
        if not threat:
            clean.append(evidence)
        elif threat.threat_level.value == 'critical':
            critical.append(evidence)
        elif threat.threat_level.value == 'high':
            high.append(evidence)
        elif threat.threat_level.value == 'medium':
            medium.append(evidence)
        elif threat.threat_level.value == 'low':
            low.append(evidence)
        else:
            clean.append(evidence)
    
    return {
        'critical': critical,
        'high': high,
        'medium': medium,
        'low': low,
        'clean': clean,
    }


def get_high_priority_evidence(
    evidence_list: List[Evidence],
    priority_threshold: float = 0.7  # 70% threat score
) -> List[Evidence]:
    """
    Get high-priority evidence for immediate review.
    
    Args:
        evidence_list: List of evidence
        priority_threshold: Threat score threshold (0-1)
        
    Returns:
        List of high-priority evidence sorted by threat score
    """
    high_priority = []
    
    for evidence in evidence_list:
        threat = ThreatDetectionIngest.analyze_evidence(evidence)
        
        if threat and threat.threat_score / 100 >= priority_threshold:
            high_priority.append((evidence, threat.threat_score))
    
    # Sort by threat score (descending)
    high_priority.sort(key=lambda x: x[1], reverse=True)
    
    return [evidence for evidence, _ in high_priority]


def create_threat_summary(evidence_list: List[Evidence]) -> Dict[str, Any]:
    """
    Create a summary of threats found in evidence list.
    
    Args:
        evidence_list: List of evidence to analyze
        
    Returns:
        Summary dictionary with threat statistics
    """
    threats = []
    indicators_by_type = {}
    threat_sources = set()
    
    for evidence in evidence_list:
        threat = ThreatDetectionIngest.analyze_evidence(evidence)
        
        if threat:
            threats.append(threat)
            threat_sources.add(threat.primary_source.value)
            
            for indicator in threat.indicators:
                indicator_type = indicator.indicator_type
                if indicator_type not in indicators_by_type:
                    indicators_by_type[indicator_type] = 0
                indicators_by_type[indicator_type] += 1
    
    # Calculate statistics
    threat_levels = {}
    for threat in threats:
        level = threat.threat_level.value
        threat_levels[level] = threat_levels.get(level, 0) + 1
    
    avg_threat_score = sum(t.threat_score for t in threats) / len(threats) if threats else 0
    
    return {
        'total_threats': len(threats),
        'clean_items': len(evidence_list) - len(threats),
        'threat_levels': threat_levels,
        'average_threat_score': avg_threat_score,
        'top_indicators': dict(sorted(indicators_by_type.items(), key=lambda x: x[1], reverse=True)[:5]),
        'threat_sources': list(threat_sources),
        'critical_count': threat_levels.get('critical', 0),
        'high_count': threat_levels.get('high', 0),
    }
