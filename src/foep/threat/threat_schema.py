# src/foep/threat/threat_schema.py
"""Threat intelligence schema for FOEP."""

from enum import Enum
from typing import Any, Dict, Optional, List
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict

from foep.normalize.schema import Evidence, EntityType


class ThreatLevel(str, Enum):
    """Threat level classification."""
    CRITICAL = "critical"      # Immediate action required
    HIGH = "high"              # Significant risk
    MEDIUM = "medium"          # Moderate concern
    LOW = "low"                # Minor concern
    INFO = "info"              # Informational only
    BENIGN = "benign"          # Not a threat


class ThreatSource(str, Enum):
    """Threat intelligence sources."""
    ABUSEIPDB = "abuseipdb"
    OTX = "otx"
    SHODAN = "shodan"
    VIRUSTOTAL = "virustotal"
    IPREPUTATION = "ipreputation"
    CUSTOM = "custom"


class ThreatIndicator(BaseModel):
    """Single threat indicator/signal."""
    indicator_type: str = Field(..., description="Type: malware, phishing, botnet, scanner, etc.")
    confidence: float = Field(..., ge=0, le=1, description="Confidence level (0-1)")
    last_seen: Optional[datetime] = Field(None, description="Last time indicator was active")
    description: str = Field("", description="Human-readable description")


class ThreatIntelligence(BaseModel):
    """Comprehensive threat intelligence for an entity."""
    model_config = ConfigDict(frozen=False)
    
    evidence_id: str = Field(..., description="Reference to original Evidence")
    entity_value: str = Field(..., description="The entity being analyzed")
    entity_type: EntityType = Field(..., description="Type of entity")
    
    # Threat Assessment
    threat_level: ThreatLevel = Field(default=ThreatLevel.INFO)
    threat_score: float = Field(default=0.0, ge=0, le=100, description="Overall threat score (0-100)")
    is_malicious: bool = Field(default=False, description="Binary malicious classification")
    
    # Indicators
    indicators: List[ThreatIndicator] = Field(default_factory=list)
    
    # Source information
    primary_source: ThreatSource = Field(default=ThreatSource.CUSTOM)
    sources: Dict[str, Any] = Field(default_factory=dict, description="Data from each threat source")
    
    # Metadata
    last_updated: datetime = Field(default_factory=datetime.utcnow)
    scan_count: int = Field(default=0, description="Number of scans/detections")
    abuse_reports: int = Field(default=0, description="Number of abuse reports")
    
    # Additional context
    recommendations: List[str] = Field(default_factory=list)
    related_incidents: List[str] = Field(default_factory=list, description="Related incident IDs")


class IncidentNode(BaseModel):
    """Neo4j Incident node for correlated threat."""
    model_config = ConfigDict(frozen=False)
    
    incident_id: str = Field(..., description="Unique incident identifier")
    case_id: str = Field(..., description="Investigation case ID")
    
    # Classification
    incident_type: str = Field(..., description="e.g., malware_distribution, phishing, intrusion")
    threat_level: ThreatLevel = Field(...)
    severity_score: float = Field(..., ge=0, le=100)
    
    # Timeline
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    
    # Details
    description: str = Field(..., description="Incident description")
    affected_entities: List[str] = Field(default_factory=list, description="Entity IDs involved")
    threat_actors: List[str] = Field(default_factory=list, description="Identified threat actors")
    
    # Evidence linking
    evidence_count: int = Field(default=0)
    evidence_ids: List[str] = Field(default_factory=list)
    
    # Status
    status: str = Field(default="open", description="open, investigating, contained, resolved")
    confidence: float = Field(default=0.0, ge=0, le=1)
    
    # Response
    recommended_actions: List[str] = Field(default_factory=list)
    mitigations_applied: List[str] = Field(default_factory=list)


class ForensicVerdict(BaseModel):
    """Final forensic verdict based on threat analysis."""
    model_config = ConfigDict(frozen=False)
    
    case_id: str = Field(..., description="Investigation case ID")
    verdict_timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    # Overall Assessment
    verdict: str = Field(..., description="MALICIOUS, SUSPICIOUS, BENIGN, INCONCLUSIVE")
    confidence_level: float = Field(..., ge=0, le=1, description="Verdict confidence")
    threat_level: ThreatLevel = Field(...)
    
    # Supporting Evidence
    threat_evidences: List[str] = Field(default_factory=list, description="Flagged evidence IDs")
    threat_count: int = Field(default=0)
    incident_count: int = Field(default=0)
    
    # Analysis Details
    primary_threat_indicators: List[str] = Field(default_factory=list)
    credibility_index: float = Field(default=0.0, ge=0, le=1)
    
    # Recommendations
    conclusions: str = Field(..., description="Summary of findings")
    recommendations: List[str] = Field(default_factory=list)
    
    # Chain of Custody
    analyst: str = Field(default="FOEP_AUTOMATED")
    signature_hash: Optional[str] = Field(None, description="Report integrity hash")
