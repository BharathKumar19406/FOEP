# src/foep/threat/threat_detector.py
"""
Advanced threat detection engine for FOEP.

Integrates multiple threat intelligence sources and detection methods
to identify malicious activity during evidence ingestion.
"""

import logging
import re
from abc import ABC, abstractmethod
from hashlib import sha256
from typing import Dict, Any, List, Optional, Set
from datetime import datetime
from collections import defaultdict

from foep.normalize.schema import Evidence, EntityType, ObservationType
from foep.threat.threat_schema import (
    ThreatIntelligence,
    ThreatLevel,
    ThreatSource,
    ThreatIndicator,
)

logger = logging.getLogger(__name__)


class ThreatDetectionEngine:
    """Main threat detection engine that coordinates multiple detectors."""
    
    def __init__(self):
        self.detectors: Dict[str, 'BaseThreatDetector'] = {}
        self.threat_cache: Dict[str, ThreatIntelligence] = {}
        self._register_detectors()
    
    def _register_detectors(self):
        """Register all threat detection modules."""
        self.detectors['hash'] = MalwareHashDetector()
        self.detectors['domain'] = MaliciousDomainDetector()
        self.detectors['ip'] = MaliciousIPDetector()
        self.detectors['url'] = MaliciousURLDetector()
        self.detectors['behavioral'] = BehavioralThreatDetector()
        self.detectors['network'] = NetworkThreatDetector()
        self.detectors['command_line'] = ProcessThreatDetector()
    
    def detect_threats(self, evidence: Evidence) -> Optional[ThreatIntelligence]:
        """
        Detect threats in evidence using appropriate detectors.
        
        Args:
            evidence: Evidence object to analyze
            
        Returns:
            ThreatIntelligence object if threats detected, None otherwise
        """
        cache_key = f"{evidence.entity_type.value}:{evidence.entity_value}"
        
        # Check cache first
        if cache_key in self.threat_cache:
            return self.threat_cache[cache_key]
        
        # Route to appropriate detector based on entity type
        threat_intel = None
        
        if evidence.entity_type == EntityType.HASH:
            threat_intel = self.detectors['hash'].detect(evidence)
        elif evidence.entity_type == EntityType.DOMAIN:
            threat_intel = self.detectors['domain'].detect(evidence)
        elif evidence.entity_type == EntityType.IP_ADDRESS:
            threat_intel = self.detectors['ip'].detect(evidence)
        elif evidence.entity_type == EntityType.URL:
            threat_intel = self.detectors['url'].detect(evidence)
        elif evidence.entity_type == EntityType.FILE:
            threat_intel = self.detectors['behavioral'].detect(evidence)
        elif evidence.entity_type == EntityType.COMMAND_LINE:
            threat_intel = self.detectors['command_line'].detect(evidence)
        
        # Cache result
        if threat_intel:
            self.threat_cache[cache_key] = threat_intel
        
        return threat_intel
    
    def detect_batch(self, evidence_list: List[Evidence]) -> List[ThreatIntelligence]:
        """
        Batch process multiple evidence items.
        
        Args:
            evidence_list: List of evidence objects
            
        Returns:
            List of detected threat intelligence
        """
        threats = []
        for evidence in evidence_list:
            threat = self.detect_threats(evidence)
            if threat:
                threats.append(threat)
        return threats


class BaseThreatDetector(ABC):
    """Base class for all threat detectors."""
    
    @abstractmethod
    def detect(self, evidence: Evidence) -> Optional[ThreatIntelligence]:
        """Detect threats in evidence."""
        pass
    
    def _create_threat_intel(
        self,
        evidence: Evidence,
        threat_level: ThreatLevel,
        indicators: List[ThreatIndicator],
        source: ThreatSource = ThreatSource.CUSTOM,
    ) -> ThreatIntelligence:
        """Helper to create ThreatIntelligence object."""
        threat_score = self._calculate_threat_score(indicators)
        
        return ThreatIntelligence(
            evidence_id=evidence.evidence_id,
            entity_value=evidence.entity_value,
            entity_type=evidence.entity_type,
            threat_level=threat_level,
            threat_score=threat_score,
            is_malicious=threat_score >= 50,
            indicators=indicators,
            primary_source=source,
            sources={source.value: self._get_source_details(evidence)},
        )
    
    def _calculate_threat_score(self, indicators: List[ThreatIndicator]) -> float:
        """Calculate threat score from indicators."""
        if not indicators:
            return 0.0
        
        # Weighted average of confidence scores
        total = sum(ind.confidence * 100 for ind in indicators)
        return min(100.0, total / len(indicators))
    
    def _get_source_details(self, evidence: Evidence) -> Dict[str, Any]:
        """Get source-specific details."""
        return {
            "entity_type": evidence.entity_type.value,
            "observation_type": evidence.observation_type.value,
            "detected_at": datetime.utcnow().isoformat(),
        }


class MalwareHashDetector(BaseThreatDetector):
    """Detect malicious file hashes using known malware databases."""
    
    # Known malware hash indicators (sha256)
    KNOWN_MALWARE = {
        # Emotet variants
        '69a26c7f9c4c8c44c88d7c9c8e3a3b3c': ('emotet', 0.95, 'Known Emotet malware variant'),
        # Ransomware samples
        '2a4c6e8f0a2b4d6e8f0a2b4d6e8f0a2b': ('ransomware', 0.90, 'Known ransomware sample'),
        # Trojan samples
        '1b3d5f7a9c1e3f5b7d9f1a3b5c7d9e1f': ('trojan', 0.88, 'Known trojan sample'),
    }
    
    # Suspicious hash patterns (entropy, size, etc.)
    SUSPICIOUS_PATTERNS = {
        'high_entropy': lambda h: len(set(h)) > 30,  # Many unique chars = compressed/encrypted
        'double_extension': lambda h: h.count('.') > 1,  # Like .exe.txt
    }
    
    def detect(self, evidence: Evidence) -> Optional[ThreatIntelligence]:
        """Detect malicious file hashes."""
        if evidence.entity_type != EntityType.HASH:
            return None
        
        hash_value = evidence.entity_value.lower()
        indicators = []
        
        # Check against known malware database
        if hash_value in self.KNOWN_MALWARE:
            malware_type, confidence, description = self.KNOWN_MALWARE[hash_value]
            indicators.append(ThreatIndicator(
                indicator_type=f"malware_{malware_type}",
                confidence=confidence,
                description=description,
            ))
        
        # Check suspicious patterns
        metadata = evidence.metadata or {}
        filename = metadata.get('filename', '')
        
        if filename and filename.count('.') > 1:
            indicators.append(ThreatIndicator(
                indicator_type="suspicious_filename",
                confidence=0.6,
                description=f"Suspicious double extension: {filename}",
            ))
        
        if not indicators:
            return None
        
        threat_score = self._calculate_threat_score(indicators)
        
        return ThreatIntelligence(
            evidence_id=evidence.evidence_id,
            entity_value=evidence.entity_value,
            entity_type=evidence.entity_type,
            threat_level=ThreatLevel.CRITICAL if threat_score >= 80 else ThreatLevel.HIGH,
            threat_score=threat_score,
            is_malicious=True,
            indicators=indicators,
            primary_source=ThreatSource.CUSTOM,
            sources={'malware_db': {'hash_type': metadata.get('hash_type', 'unknown')}},
            recommendations=[
                "BLOCK immediately - Known malware detected",
                "Isolate affected system",
                "Perform full system scan",
                "Check for persistence mechanisms",
            ],
        )


class MaliciousDomainDetector(BaseThreatDetector):
    """Detect malicious domains using pattern recognition and threat feeds."""
    
    # Known malicious domains
    KNOWN_MALICIOUS_DOMAINS = {
        'malicious.ru': ('command_and_control', 0.98),
        'botnet-c2.xyz': ('command_and_control', 0.95),
        'phishing-service.net': ('phishing_infrastructure', 0.92),
        'malware-distribution.com': ('malware_distribution', 0.96),
    }
    
    # Suspicious domain patterns
    SUSPICIOUS_PATTERNS = [
        r'.*-[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}\..*',  # IP-like domains
        r'.*\.bit$',  # Tor exit node domain TLD
        r'.*\.onion$',  # Tor network
        r'.*[a-z]{10,}[0-9]{5,}\..*',  # Random char+number pattern
    ]
    
    def detect(self, evidence: Evidence) -> Optional[ThreatIntelligence]:
        """Detect malicious domains."""
        if evidence.entity_type != EntityType.DOMAIN:
            return None
        
        domain = evidence.entity_value.lower()
        indicators = []
        
        # Check against known malicious domains
        if domain in self.KNOWN_MALICIOUS_DOMAINS:
            threat_type, confidence = self.KNOWN_MALICIOUS_DOMAINS[domain]
            indicators.append(ThreatIndicator(
                indicator_type=threat_type,
                confidence=confidence,
                description=f"Known {threat_type} domain",
            ))
        
        # Check suspicious patterns
        for pattern in self.SUSPICIOUS_PATTERNS:
            if re.match(pattern, domain):
                indicators.append(ThreatIndicator(
                    indicator_type="suspicious_domain_pattern",
                    confidence=0.7,
                    description=f"Matches suspicious pattern: {pattern}",
                ))
                break
        
        if not indicators:
            return None
        
        threat_score = self._calculate_threat_score(indicators)
        
        return ThreatIntelligence(
            evidence_id=evidence.evidence_id,
            entity_value=evidence.entity_value,
            entity_type=evidence.entity_type,
            threat_level=ThreatLevel.CRITICAL if threat_score >= 80 else ThreatLevel.HIGH,
            threat_score=threat_score,
            is_malicious=True,
            indicators=indicators,
            primary_source=ThreatSource.CUSTOM,
            sources={'domain_intel': {'domain_age': evidence.metadata.get('registration_date')}},
            recommendations=[
                "Block domain at firewall/DNS level",
                "Monitor DNS queries to this domain",
                "Identify all affected systems",
                "Check for data exfiltration",
            ],
        )


class MaliciousIPDetector(BaseThreatDetector):
    """Detect malicious IPs using geolocation, reputation, and threat feeds."""
    
    # Known malicious IPs (C2 servers, etc.)
    KNOWN_MALICIOUS_IPS = {
        '192.168.1.100': ('scanner', 0.75),
        '203.0.113.45': ('botnet_c2', 0.92),
        '198.51.100.10': ('malware_distribution', 0.88),
    }
    
    # Suspicious geolocation
    SUSPICIOUS_COUNTRIES = {'KP', 'IR', 'SY'}  # North Korea, Iran, Syria
    
    # Private/reserved ranges to flag
    RESERVED_RANGES = [
        (0, 16777215),           # 0.0.0.0/8
        (167772160, 184549375),  # 10.0.0.0/8
        (2886729728, 2887778303),  # 172.16.0.0/12
        (3232235520, 3232301055),  # 192.168.0.0/16
    ]
    
    def detect(self, evidence: Evidence) -> Optional[ThreatIntelligence]:
        """Detect malicious IPs."""
        if evidence.entity_type != EntityType.IP_ADDRESS:
            return None
        
        ip = evidence.entity_value
        indicators = []
        
        # Check against known malicious IPs
        if ip in self.KNOWN_MALICIOUS_IPS:
            threat_type, confidence = self.KNOWN_MALICIOUS_IPS[ip]
            indicators.append(ThreatIndicator(
                indicator_type=threat_type,
                confidence=confidence,
                description=f"Known {threat_type} IP",
            ))
        
        # Check for suspicious geolocation
        metadata = evidence.metadata or {}
        country_code = metadata.get('country_code', '')
        if country_code in self.SUSPICIOUS_COUNTRIES:
            indicators.append(ThreatIndicator(
                indicator_type="suspicious_geolocation",
                confidence=0.7,
                description=f"IP located in {country_code}",
            ))
        
        # Check for abnormal ports in metadata
        open_ports = metadata.get('open_ports', [])
        risky_ports = [23, 445, 3389]  # Telnet, SMB, RDP
        if any(p in open_ports for p in risky_ports):
            indicators.append(ThreatIndicator(
                indicator_type="risky_ports_exposed",
                confidence=0.8,
                description=f"Risky ports detected: {set(open_ports) & set(risky_ports)}",
            ))
        
        if not indicators:
            return None
        
        threat_score = self._calculate_threat_score(indicators)
        
        return ThreatIntelligence(
            evidence_id=evidence.evidence_id,
            entity_value=evidence.entity_value,
            entity_type=evidence.entity_type,
            threat_level=ThreatLevel.CRITICAL if threat_score >= 80 else ThreatLevel.HIGH,
            threat_score=threat_score,
            is_malicious=True,
            indicators=indicators,
            primary_source=ThreatSource.CUSTOM,
            sources={'ip_intel': {'geolocation': country_code}},
            recommendations=[
                "Block IP at firewall",
                "Monitor all connections from/to this IP",
                "Review firewall logs",
                "Check for data exfiltration",
            ],
        )


class MaliciousURLDetector(BaseThreatDetector):
    """Detect malicious URLs."""
    
    KNOWN_MALICIOUS_URLS = {
        'http://malicious.ru/payload.exe': ('malware_distribution', 0.98),
        'https://phishing-site.xyz/login': ('phishing', 0.95),
    }
    
    SUSPICIOUS_PATTERNS = [
        r'.*payload.*',
        r'.*dropper.*',
        r'.*agent.*',
        r'.*c2.*',
    ]
    
    def detect(self, evidence: Evidence) -> Optional[ThreatIntelligence]:
        """Detect malicious URLs."""
        if evidence.entity_type != EntityType.URL:
            return None
        
        url = evidence.entity_value.lower()
        indicators = []
        
        # Check known malicious URLs
        if url in self.KNOWN_MALICIOUS_URLS:
            threat_type, confidence = self.KNOWN_MALICIOUS_URLS[url]
            indicators.append(ThreatIndicator(
                indicator_type=threat_type,
                confidence=confidence,
                description=f"Known {threat_type} URL",
            ))
        
        # Check suspicious patterns
        for pattern in self.SUSPICIOUS_PATTERNS:
            if re.search(pattern, url):
                indicators.append(ThreatIndicator(
                    indicator_type="suspicious_url_pattern",
                    confidence=0.75,
                    description=f"URL contains suspicious keywords: {pattern}",
                ))
                break
        
        if not indicators:
            return None
        
        threat_score = self._calculate_threat_score(indicators)
        
        return ThreatIntelligence(
            evidence_id=evidence.evidence_id,
            entity_value=evidence.entity_value,
            entity_type=evidence.entity_type,
            threat_level=ThreatLevel.CRITICAL if threat_score >= 80 else ThreatLevel.HIGH,
            threat_score=threat_score,
            is_malicious=True,
            indicators=indicators,
            primary_source=ThreatSource.CUSTOM,
            sources={'url_intel': {'url_category': 'malicious_url'}},
            recommendations=[
                "Block URL at HTTP proxy/firewall",
                "Alert users attempting to access this URL",
                "Analyze page content for exploits",
            ],
        )


class BehavioralThreatDetector(BaseThreatDetector):
    """Detect behavioral threats (registry, file activity, etc.)."""
    
    SUSPICIOUS_REGISTRY_KEYS = [
        r'.*\\Run$',  # Autorun locations
        r'.*\\RunOnce$',
        r'.*CurrentVersion\\Run.*',
        r'.*Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Run.*',
        r'.*Shell\\Open\\Command.*',  # Shell associations
    ]
    
    def detect(self, evidence: Evidence) -> Optional[ThreatIntelligence]:
        """Detect behavioral threats."""
        if evidence.entity_type != EntityType.FILE:
            return None
        
        file_path = evidence.entity_value
        indicators = []
        
        # Check for suspicious file paths/names
        for pattern in self.SUSPICIOUS_REGISTRY_KEYS:
            if re.search(pattern, file_path, re.IGNORECASE):
                indicators.append(ThreatIndicator(
                    indicator_type="suspicious_file_path",
                    confidence=0.85,
                    description=f"File path indicates potential persistence: {file_path}",
                ))
                break
        
        if not indicators:
            return None
        
        threat_score = self._calculate_threat_score(indicators)
        
        return ThreatIntelligence(
            evidence_id=evidence.evidence_id,
            entity_value=evidence.entity_value,
            entity_type=evidence.entity_type,
            threat_level=ThreatLevel.HIGH,
            threat_score=threat_score,
            is_malicious=True,
            indicators=indicators,
            primary_source=ThreatSource.CUSTOM,
            sources={'registry_intel': {'key_type': 'persistence_mechanism'}},
            recommendations=[
                "Investigate registry modification time",
                "Identify files referenced in key values",
                "Check for malware associations",
            ],
        )


class NetworkThreatDetector(BaseThreatDetector):
    """Detect network-based threats."""
    
    SUSPICIOUS_PORTS = {
        23: 'telnet_unencrypted',
        445: 'smb_exposed',
        3389: 'rdp_exposed',
        5900: 'vnc_exposed',
    }
    
    def detect(self, evidence: Evidence) -> Optional[ThreatIntelligence]:
        """Detect network threats."""
        # This detector handles custom entity processing if needed
        return None


class ProcessThreatDetector(BaseThreatDetector):
    """Detect malicious processes."""
    
    SUSPICIOUS_PROCESS_NAMES = [
        'rundll32.exe',
        'regsvcs.exe',
        'regasm.exe',
        'InstallUtil.exe',
        'mshta.exe',
        'powershell.exe',
    ]
    
    def detect(self, evidence: Evidence) -> Optional[ThreatIntelligence]:
        """Detect malicious processes."""
        if evidence.entity_type != EntityType.COMMAND_LINE:
            return None
        
        command_line = evidence.entity_value.lower()
        indicators = []
        
        # Check for suspicious process names (use for living-off-the-land attacks)
        for susp_process in self.SUSPICIOUS_PROCESS_NAMES:
            if susp_process.lower() in command_line:
                indicators.append(ThreatIndicator(
                    indicator_type="living_off_the_land_attack",
                    confidence=0.8,
                    description=f"Suspicious LOLBin process: {command_line}",
                ))
                break
        
        if not indicators:
            return None
        
        threat_score = self._calculate_threat_score(indicators)
        
        return ThreatIntelligence(
            evidence_id=evidence.evidence_id,
            entity_value=evidence.entity_value,
            entity_type=evidence.entity_type,
            threat_level=ThreatLevel.HIGH,
            threat_score=threat_score,
            is_malicious=True,
            indicators=indicators,
            primary_source=ThreatSource.CUSTOM,
            sources={'process_intel': {'process_type': 'livingoftheland_binary'}},
            recommendations=[
                "Identify parent process and command line",
                "Check for code injection",
                "Monitor for malicious behavior",
            ],
        )
