# src/foep/threat/threat_correlation.py
"""Neo4j graph correlation for threat incidents."""

import logging
import hashlib
from typing import List, Optional, Dict, Any
from datetime import datetime

from foep.threat.threat_schema import ThreatIntelligence, IncidentNode, ThreatLevel
from foep.normalize.schema import Evidence

logger = logging.getLogger(__name__)


class ThreatCorrelationEngine:
    """Correlates threat intelligence and creates incident nodes."""
    
    def __init__(self, graph_db=None):
        """Initialize correlation engine with optional graph DB connection."""
        self.graph_db = graph_db
    
    def create_incident_from_threat(
        self,
        threat_intel: ThreatIntelligence,
        case_id: str,
        related_evidence: List[Evidence] = None,
    ) -> Optional[IncidentNode]:
        """Create an Incident node from threat intelligence."""
        
        if not threat_intel.is_malicious:
            return None  # Only create incidents for malicious threats
        
        related_evidence = related_evidence or []
        
        # Generate incident ID
        incident_id = self._generate_incident_id(threat_intel, case_id)
        
        # Determine incident type based on threat indicators
        incident_type = self._classify_incident_type(threat_intel)
        
        # Collect affected entities
        affected_entities = [threat_intel.evidence_id]
        affected_entities.extend(threat_intel.related_incidents)
        
        # Build threat actor profile if multiple related incidents
        threat_actors = []
        if len(threat_intel.sources) > 2:
            threat_actors.append(f"THREAT_ACTOR_{incident_id[:8]}")
        
        return IncidentNode(
            incident_id=incident_id,
            case_id=case_id,
            incident_type=incident_type,
            threat_level=threat_intel.threat_level,
            severity_score=threat_intel.threat_score,
            description=self._build_incident_description(threat_intel),
            affected_entities=affected_entities,
            threat_actors=threat_actors,
            evidence_count=len([threat_intel.evidence_id] + related_evidence),
            evidence_ids=[threat_intel.evidence_id] + [e.evidence_id for e in related_evidence],
            confidence=min(0.5 + (threat_intel.threat_score / 200), 1.0),  # Score-based confidence
            recommended_actions=threat_intel.recommendations,
        )
    
    def correlate_incidents(self, incidents: List[IncidentNode]) -> Dict[str, Any]:
        """Correlate multiple incidents and identify patterns."""
        
        if not incidents:
            return {"correlation_count": 0, "patterns": []}
        
        correlation = {
            "correlation_count": 0,
            "patterns": [],
            "threat_actor_clusters": [],
            "attack_chains": [],
        }
        
        # Group by incident type
        type_groups = {}
        for incident in incidents:
            if incident.incident_type not in type_groups:
                type_groups[incident.incident_type] = []
            type_groups[incident.incident_type].append(incident)
        
        # Identify patterns
        for incident_type, grouped_incidents in type_groups.items():
            if len(grouped_incidents) > 1:
                correlation["patterns"].append({
                    "type": incident_type,
                    "count": len(grouped_incidents),
                    "severity": max(i.severity_score for i in grouped_incidents),
                    "incident_ids": [i.incident_id for i in grouped_incidents],
                })
                correlation["correlation_count"] += 1
        
        # Identify threat actor clusters
        threat_actor_map = {}
        for incident in incidents:
            for actor in incident.threat_actors:
                if actor not in threat_actor_map:
                    threat_actor_map[actor] = []
                threat_actor_map[actor].append(incident.incident_id)
        
        for actor, incident_ids in threat_actor_map.items():
            if len(incident_ids) > 1:
                correlation["threat_actor_clusters"].append({
                    "actor": actor,
                    "incident_count": len(incident_ids),
                    "incident_ids": incident_ids,
                })
        
        return correlation
    
    def link_incident_to_graph(self, incident: IncidentNode, session=None) -> bool:
        """Create Incident node and links in Neo4j."""
        
        if not self.graph_db or not session:
            logger.warning("Graph DB not configured, skipping Neo4j persistence")
            return False
        
        try:
            # Create Incident node
            query = """
                MERGE (incident:Incident {incident_id: $incident_id})
                SET incident.case_id = $case_id,
                    incident.incident_type = $incident_type,
                    incident.threat_level = $threat_level,
                    incident.severity_score = $severity_score,
                    incident.status = $status,
                    incident.detected_at = $detected_at,
                    incident.description = $description,
                    incident.evidence_count = $evidence_count,
                    incident.confidence = $confidence
                RETURN incident
            """
            
            session.run(query, {
                "incident_id": incident.incident_id,
                "case_id": incident.case_id,
                "incident_type": incident.incident_type,
                "threat_level": incident.threat_level.value,
                "severity_score": incident.severity_score,
                "status": incident.status,
                "detected_at": incident.detected_at.isoformat(),
                "description": incident.description,
                "evidence_count": incident.evidence_count,
                "confidence": incident.confidence,
            })
            
            # Link to Evidence nodes
            for evidence_id in incident.evidence_ids:
                link_query = """
                    MATCH (incident:Incident {incident_id: $incident_id})
                    MATCH (evidence:Evidence {evidence_id: $evidence_id})
                    MERGE (incident)-[rel:INVOLVES]->(evidence)
                    SET rel.created_at = $timestamp
                    RETURN rel
                """
                
                session.run(link_query, {
                    "incident_id": incident.incident_id,
                    "evidence_id": evidence_id,
                    "timestamp": datetime.utcnow().isoformat(),
                })
            
            # Link threat actors
            for actor in incident.threat_actors:
                actor_query = """
                    MERGE (ta:ThreatActor {name: $actor_name})
                    MATCH (incident:Incident {incident_id: $incident_id})
                    MERGE (ta)-[rel:PERPETRATED]->(incident)
                    RETURN rel
                """
                
                session.run(actor_query, {
                    "actor_name": actor,
                    "incident_id": incident.incident_id,
                })
            
            logger.info(f"Created incident node: {incident.incident_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error linking incident to graph: {e}")
            return False
    
    def build_incident_graph_query(self, incident: IncidentNode) -> str:
        """Generate Cypher query for incident graph creation."""
        
        cypher_parts = []
        
        # Create Incident node
        cypher_parts.append(f"""
        // Create Incident Node
        CREATE (incident:Incident {{
            incident_id: '{incident.incident_id}',
            case_id: '{incident.case_id}',
            incident_type: '{incident.incident_type}',
            threat_level: '{incident.threat_level.value}',
            severity_score: {incident.severity_score},
            status: '{incident.status}',
            confidence: {incident.confidence},
            detected_at: '{incident.detected_at.isoformat()}',
            description: '{self._escape_cypher_string(incident.description)}',
            evidence_count: {incident.evidence_count}
        }})
        """)
        
        # Link to Evidence nodes
        for evidence_id in incident.evidence_ids[:5]:  # Limit to top 5
            cypher_parts.append(f"""
            // Link to Evidence
            MATCH (is_evidence:Evidence {{evidence_id: '{evidence_id}'}})
            MATCH (is_incident:Incident {{incident_id: '{incident.incident_id}'}})
            CREATE (is_incident)-[:INVOLVES {{confidence: 0.95}}]->(is_evidence)
            """)
        
        # Link threat actors
        for actor in incident.threat_actors:
            cypher_parts.append(f"""
            // Create Threat Actor and Link
            MERGE (ta:ThreatActor {{name: '{actor}'}})
            MATCH (ta_incident:Incident {{incident_id: '{incident.incident_id}'}})
            CREATE (ta)-[:PERPETRATED]->(ta_incident)
            """)
        
        # Create Incident cluster relationships
        if len(incident.affected_entities) > 1:
            for i, entity_id in enumerate(incident.affected_entities[1:]):
                cypher_parts.append(f"""
                // Link affected entities
                MATCH (entity_{i}:Evidence {{evidence_id: '{entity_id}'}})
                MATCH (main_entity:Evidence {{evidence_id: '{incident.affected_entities[0]}'}})
                CREATE (main_entity)-[:CORRELATED_WITH {{confidence: 0.8}}]->(entity_{i})
                """)
        
        return "\n".join(cypher_parts)
    
    @staticmethod
    def _generate_incident_id(threat_intel: ThreatIntelligence, case_id: str) -> str:
        """Generate unique incident ID."""
        base = f"{case_id}_{threat_intel.entity_value}_{threat_intel.primary_source.value}"
        hash_suffix = hashlib.md5(base.encode()).hexdigest()[:8].upper()
        return f"INC_{case_id}_{hash_suffix}"
    
    @staticmethod
    def _classify_incident_type(threat_intel: ThreatIntelligence) -> str:
        """Classify incident type from threat indicators."""
        
        indicators_lower = [ind.indicator_type.lower() for ind in threat_intel.indicators]
        
        if any("malware" in ind for ind in indicators_lower):
            return "malware_infection"
        elif any("phishing" in ind for ind in indicators_lower):
            return "phishing_campaign"
        elif any("bot" in ind or "c2" in ind for ind in indicators_lower):
            return "botnet_activity"
        elif any("brute" in ind or "ssh" in ind for ind in indicators_lower):
            return "brute_force_attack"
        elif any("exposure" in ind or "open" in ind for ind in indicators_lower):
            return "infrastructure_exposure"
        else:
            return "suspicious_activity"
    
    @staticmethod
    def _build_incident_description(threat_intel: ThreatIntelligence) -> str:
        """Build incident description from threat intelligence."""
        
        indicators_str = ", ".join([ind.indicator_type for ind in threat_intel.indicators[:3]])
        sources_str = ", ".join([str(s) for s in threat_intel.sources.keys()])
        
        return (
            f"Incident detected for {threat_intel.entity_type.value} '{threat_intel.entity_value}'. "
            f"Threat level: {threat_intel.threat_level.value}. "
            f"Key indicators: {indicators_str}. "
            f"Detected via: {sources_str}. "
            f"Score: {threat_intel.threat_score:.1f}/100"
        )
    
    @staticmethod
    def _escape_cypher_string(text: str) -> str:
        """Escape string for Cypher query."""
        return text.replace("'", "\\'").replace('"', '\\"')[:200]  # Limit length
