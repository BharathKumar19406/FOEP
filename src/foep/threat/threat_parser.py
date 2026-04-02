# src/foep/threat/threat_parser.py
"""Threat intelligence parsers for AbuseIPDB, OTX, and Shodan."""

import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from datetime import datetime

from foep.threat.threat_schema import (
    ThreatIntelligence,
    ThreatLevel,
    ThreatSource,
    ThreatIndicator,
)
from foep.normalize.schema import Evidence, EntityType

logger = logging.getLogger(__name__)


class ThreatParser(ABC):
    """Base class for threat intelligence parsers."""
    
    @abstractmethod
    def parse(self, evidence: Evidence, raw_data: Dict[str, Any]) -> Optional[ThreatIntelligence]:
        """Parse threat data and return ThreatIntelligence object."""
        pass
    
    def _calculate_threat_score(self, indicators: List[ThreatIndicator]) -> float:
        """Calculate threat score from indicators."""
        if not indicators:
            return 0.0
        
        # Weighted scoring: confidence * impact
        total_score = sum(ind.confidence * 100 for ind in indicators)
        return min(100.0, total_score / len(indicators))
    
    def _determine_threat_level(self, score: float) -> ThreatLevel:
        """Map threat score to threat level."""
        if score >= 80:
            return ThreatLevel.CRITICAL
        elif score >= 60:
            return ThreatLevel.HIGH
        elif score >= 40:
            return ThreatLevel.MEDIUM
        elif score >= 20:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.INFO


class AbuseIPDBParser(ThreatParser):
    """Parser for AbuseIPDB threat data."""
    
    SOURCE = ThreatSource.ABUSEIPDB
    
    # Threat type mappings
    THREAT_MAPPINGS = {
        "phishing": ("phishing", 0.9),
        "proxy": ("proxy_service", 0.7),
        "spam": ("spam", 0.6),
        "malware": ("malware", 0.95),
        "open_proxy": ("open_proxy", 0.8),
        "web_spam": ("web_spam", 0.65),
        "email_spam": ("email_spam", 0.5),
        "ssh": ("ssh_brute_force", 0.85),
        "ftp": ("ftp_brute_force", 0.80),
    }
    
    def parse(self, evidence: Evidence, raw_data: Dict[str, Any]) -> Optional[ThreatIntelligence]:
        """Parse AbuseIPDB response data."""
        
        if evidence.entity_type != EntityType.IP_ADDRESS:
            return None  # AbuseIPDB only processes IPs
        
        # Extract key fields
        abuseipdb_score = raw_data.get("abuseConfidenceScore", 0)
        report_count = raw_data.get("totalReports", 0)
        reports = raw_data.get("reports", [])
        is_whitelisted = raw_data.get("isWhitelisted", False)
        
        # Build indicators from reports
        indicators = []
        threat_actor_categories = set()
        
        for report in reports[:10]:  # Top 10 reports
            categories = report.get("categories", [])
            for category in categories:
                if category in self.THREAT_MAPPINGS:
                    threat_type, confidence = self.THREAT_MAPPINGS[category]
                    indicators.append(ThreatIndicator(
                        indicator_type=threat_type,
                        confidence=confidence,
                        last_seen=self._parse_datetime(report.get("reportedAt")),
                        description=f"Reported by {report.get('reporterCountryName', 'Unknown')}"
                    ))
                    threat_actor_categories.add(threat_type)
        
        # Determine if malicious
        is_malicious = (abuseipdb_score > 50 or report_count > 5) and not is_whitelisted
        
        # Calculate threat score
        threat_score = min(abuseipdb_score * 1.0, 100.0)  # Use AbuseIPDB score directly
        
        # Build recommendations
        recommendations = []
        if threat_score >= 75:
            recommendations.append("BLOCK immediately - High confidence malicious activity")
            recommendations.append("Monitor connections from this IP")
        elif threat_score >= 50:
            recommendations.append("QUARANTINE - Possible malicious activity")
        elif threat_score >= 25:
            recommendations.append("MONITOR - Suspicious activity detected")
        
        return ThreatIntelligence(
            evidence_id=evidence.evidence_id,
            entity_value=evidence.entity_value,
            entity_type=evidence.entity_type,
            threat_level=self._determine_threat_level(threat_score),
            threat_score=threat_score,
            is_malicious=is_malicious,
            indicators=indicators,
            primary_source=self.SOURCE,
            sources={
                "abuseipdb": {
                    "confidence_score": abuseipdb_score,
                    "report_count": report_count,
                    "is_whitelisted": is_whitelisted,
                }
            },
            scan_count=report_count,
            abuse_reports=report_count,
            recommendations=recommendations,
        )
    
    @staticmethod
    def _parse_datetime(date_str: Optional[str]) -> Optional[datetime]:
        """Parse ISO datetime string."""
        if not date_str:
            return None
        try:
            return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        except Exception:
            return None


class OTXParser(ThreatParser):
    """Parser for OTX (Open Threat Exchange) threat data."""
    
    SOURCE = ThreatSource.OTX
    
    # OTX verdict to threat level mapping
    VERDICT_MAPPING = {
        "malicious": (ThreatLevel.CRITICAL, 95),
        "suspicious": (ThreatLevel.HIGH, 70),
        "benign": (ThreatLevel.BENIGN, 5),
        "unknown": (ThreatLevel.INFO, 20),
    }
    
    def parse(self, evidence: Evidence, raw_data: Dict[str, Any]) -> Optional[ThreatIntelligence]:
        """Parse OTX response data."""
        
        # OTX can process various entity types
        if evidence.entity_type not in [EntityType.IP_ADDRESS, EntityType.DOMAIN, EntityType.URL]:
            return None
        
        # Extract verdict and pulses
        verdict = raw_data.get("verdict", "unknown").lower()
        pulses = raw_data.get("pulses", [])
        sections = raw_data.get("sections", {})
        
        threat_level, threat_score = self.VERDICT_MAPPING.get(verdict, (ThreatLevel.INFO, 20))
        
        # Build indicators from pulses (threat campaigns)
        indicators = []
        campaigns = []
        
        for pulse in pulses[:10]:
            campaign_name = pulse.get("name", "Unknown Campaign")
            campaigns.append(campaign_name)
            
            indicators.append(ThreatIndicator(
                indicator_type="threat_campaign",
                confidence=0.8,
                last_seen=self._parse_datetime(pulse.get("modified")),
                description=f"Part of campaign: {campaign_name}"
            ))
        
        # Analyze sections for specific threat indicators
        for section_name, section_data in sections.items():
            if section_name == "analysis":
                for analysis in section_data.get("analysis", []):
                    indicators.append(ThreatIndicator(
                        indicator_type="behavioral_analysis",
                        confidence=0.75,
                        description=f"{analysis}: {section_data.get(analysis, {}).get('type', '')}"
                    ))
        
        # Build recommendations
        recommendations = []
        if threat_level == ThreatLevel.CRITICAL:
            recommendations.append("BLOCK - Known malicious by OTX consensus")
        elif threat_level == ThreatLevel.HIGH:
            recommendations.append("QUARANTINE - Suspected malicious activity")
        
        if campaigns:
            recommendations.append(f"Track campaigns: {', '.join(campaigns[:3])}")
        
        return ThreatIntelligence(
            evidence_id=evidence.evidence_id,
            entity_value=evidence.entity_value,
            entity_type=evidence.entity_type,
            threat_level=threat_level,
            threat_score=threat_score,
            is_malicious=threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH],
            indicators=indicators,
            primary_source=self.SOURCE,
            sources={
                "otx": {
                    "verdict": verdict,
                    "pulse_count": len(pulses),
                    "campaigns": campaigns,
                }
            },
            scan_count=len(pulses),
            recommendations=recommendations,
            related_incidents=campaigns,
        )
    
    @staticmethod
    def _parse_datetime(date_str: Optional[str]) -> Optional[datetime]:
        """Parse ISO datetime string."""
        if not date_str:
            return None
        try:
            return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        except Exception:
            return None


class ShodanParser(ThreatParser):
    """Parser for Shodan threat exposure data."""
    
    SOURCE = ThreatSource.SHODAN
    
    # Risk scoring for open services
    SERVICE_RISK = {
        "ssh": 0.4,           # Often brute-forced
        "telnet": 0.9,        # Insecure protocol
        "ftp": 0.8,           # Insecure protocol
        "http": 0.3,          # Common but risky if misconfigured
        "https": 0.2,         # Encrypted
        "rdp": 0.7,           # Remote desktop attacks
        "smb": 0.85,          # Ransomware vector
        "dns": 0.3,           # Can be abused
        "ntp": 0.5,           # DDoS amplification
        "snmp": 0.7,          # Information disclosure
    }
    
    def parse(self, evidence: Evidence, raw_data: Dict[str, Any]) -> Optional[ThreatIntelligence]:
        """Parse Shodan exposure data."""
        
        if evidence.entity_type != EntityType.IP_ADDRESS:
            return None  # Shodan primarily for IPs
        
        # Extract exposure data
        open_ports = raw_data.get("ports", [])
        hostnames = raw_data.get("hostnames", [])
        organization = raw_data.get("org", "Unknown")
        services = raw_data.get("data", [])
        
        # Assess exposure risk
        high_risk_services = []
        indicators = []
        total_risk = 0.0
        
        for service_data in services[:20]:  # Analyze top 20 services
            port = service_data.get("port")
            product = service_data.get("product", "").lower()
            http = service_data.get("http", {})
            
            # Determine service type
            service_type = self._identify_service(port, product)
            risk = self.SERVICE_RISK.get(service_type, 0.5)
            
            if risk > 0.6:
                high_risk_services.append(f"{service_type}:{port}")
            
            total_risk += risk
            
            # Check for known vulnerabilities
            title = http.get("title", "")
            if any(keyword in title.lower() for keyword in ["vulnerable", "deprecated", "unsupported"]):
                risk *= 1.3  # Increase risk for known vulnerable products
            
            indicators.append(ThreatIndicator(
                indicator_type=f"exposed_{service_type}",
                confidence=min(risk, 1.0),
                description=f"Port {port}: {product} exposed to internet"
            ))
        
        # Calculate threat score
        avg_risk = (total_risk / len(services)) * 100 if services else 0
        exposure_score = min(avg_risk + (len(high_risk_services) * 15), 100)
        
        # Build recommendations
        recommendations = []
        if high_risk_services:
            recommendations.append(f"CLOSE or FIREWALL risky services: {', '.join(high_risk_services[:3])}")
        if len(open_ports) > 10:
            recommendations.append(f"Excessive open ports ({len(open_ports)}) - Apply principle of least privilege")
        recommendations.append("Enable firewall rules to restrict internet access")
        
        return ThreatIntelligence(
            evidence_id=evidence.evidence_id,
            entity_value=evidence.entity_value,
            entity_type=evidence.entity_type,
            threat_level=self._determine_threat_level(exposure_score),
            threat_score=exposure_score,
            is_malicious=exposure_score > 70,  # High exposure = potential attack surface
            indicators=indicators,
            primary_source=self.SOURCE,
            sources={
                "shodan": {
                    "open_ports": len(open_ports),
                    "services_identified": len(services),
                    "high_risk_services": high_risk_services,
                    "organization": organization,
                    "hostnames": hostnames,
                }
            },
            scan_count=len(services),
            recommendations=recommendations,
        )
    
    @staticmethod
    def _identify_service(port: int, product: str) -> str:
        """Identify service type from port and product."""
        service_map = {
            22: "ssh", 23: "telnet", 21: "ftp", 80: "http", 443: "https",
            3306: "mysql", 5432: "postgres", 6379: "redis", 27017: "mongodb",
            3389: "rdp", 445: "smb", 53: "dns", 123: "ntp", 161: "snmp",
        }
        
        # Try port-based identification first
        if port in service_map:
            return service_map[port]
        
        # Try product-based identification
        product_lower = product.lower()
        for keyword, service in [
            ("ssh", "ssh"), ("telnet", "telnet"), ("ftp", "ftp"),
            ("http", "http"), ("https", "https"), ("rdp", "rdp"),
            ("mysql", "mysql"), ("postgres", "postgres"), ("mongodb", "mongodb"),
            ("redis", "redis"),
        ]:
            if keyword in product_lower:
                return service
        
        return "unknown"
