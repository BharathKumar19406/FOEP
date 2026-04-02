#!/usr/bin/env python3
# scripts/threat_detection_demo.py
"""
Comprehensive demonstration of FOEP threat detection pipeline.

Shows:
1. Threat intelligence parsing (AbuseIPDB, OTX, Shodan)
2. Neo4j incident correlation
3. Forensic verdict generation
"""

import sys
import json
from pathlib import Path
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from foep.normalize.schema import Evidence, EntityType, ObservationType
from foep.threat import (
    AbuseIPDBParser,
    OTXParser,
    ShodanParser,
    ThreatLevel,
    ThreatIndicator,
)
from foep.threat.threat_correlation import ThreatCorrelationEngine
from foep.threat.forensic_verdict_template import ForensicVerdictGenerator
from foep.threat.threat_schema import ForensicVerdict


def create_sample_evidence():
    """Create sample evidence items for threat detection."""
    return [
        Evidence(
            evidence_id="abuseipdb::ip::192.168.1.100",
            entity_type=EntityType.IP_ADDRESS,
            entity_value="192.168.1.100",
            observation_type=ObservationType.OSINT_REPUTATION,
            source="abuseipdb",
            metadata={"scan_source": "network_monitoring"},
            credibility_score=85,
        ),
        Evidence(
            evidence_id="otx::domain::malicious.ru",
            entity_type=EntityType.DOMAIN,
            entity_value="malicious.ru",
            observation_type=ObservationType.OSINT_REPUTATION,
            source="otx",
            metadata={"scan_source": "dns_lookup"},
            credibility_score=90,
        ),
        Evidence(
            evidence_id="shodan::ip::203.0.113.45",
            entity_type=EntityType.IP_ADDRESS,
            entity_value="203.0.113.45",
            observation_type=ObservationType.OSINT_GEO,
            source="shodan",
            metadata={"scan_source": "port_scan"},
            credibility_score=80,
        ),
    ]


def create_sample_threat_data():
    """Create sample threat intelligence data."""
    return {
        "abuseipdb": {
            "192.168.1.100": {
                "abuseConfidenceScore": 92,
                "totalReports": 156,
                "isWhitelisted": False,
                "reports": [
                    {
                        "categories": ["malware", "phishing"],
                        "reportedAt": "2024-04-02T10:30:00Z",
                        "reporterCountryName": "US",
                    },
                    {
                        "categories": ["ssh"],
                        "reportedAt": "2024-04-02T09:15:00Z",
                        "reporterCountryName": "UK",
                    },
                ],
            }
        },
        "otx": {
            "malicious.ru": {
                "verdict": "malicious",
                "pulses": [
                    {
                        "name": "Emotet Command & Control",
                        "modified": "2024-04-01T18:45:00Z",
                    },
                    {
                        "name": "Russian APT Botnet",
                        "modified": "2024-03-31T12:00:00Z",
                    },
                ],
                "sections": {
                    "analysis": {
                        "analysis": {
                            "dns_requests": {"type": "C2_communication"},
                            "file_analysis": {"type": "malware_sample"},
                        }
                    }
                },
            }
        },
        "shodan": {
            "203.0.113.45": {
                "ports": [21, 22, 23, 3306, 5432, 6379, 8080],
                "org": "TechCorp ISP",
                "hostnames": ["exposed-server.corp.internal"],
                "data": [
                    {
                        "port": 23,
                        "product": "TelnetD",
                        "http": {"title": "Telnet Server (Deprecated)"},
                    },
                    {
                        "port": 3306,
                        "product": "MySQL 5.5",
                        "http": {"title": "MySQL vulnerable to known exploits"},
                    },
                    {
                        "port": 6379,
                        "product": "Redis",
                        "http": {"title": "Redis no auth"},
                    },
                    {"port": 22, "product": "OpenSSH 7.4", "http": {}},
                    {"port": 80, "product": "Apache httpd", "http": {}},
                ],
            }
        },
    }


def demonstrate_threat_parsing():
    """Demonstrate threat intelligence parsing."""
    print("\n" + "=" * 80)
    print("🚨 THREAT DETECTION PIPELINE DEMONSTRATION")
    print("=" * 80)
    
    # Create evidence and threat data
    evidence_items = create_sample_evidence()
    threat_data = create_sample_threat_data()
    
    # Initialize parsers
    abuseipdb_parser = AbuseIPDBParser()
    otx_parser = OTXParser()
    shodan_parser = ShodanParser()
    
    all_threats = []
    
    # ========== STAGE 1: PARSE THREATS ==========
    print("\n" + "─" * 80)
    print("STAGE 1️⃣  : THREAT INTELLIGENCE PARSING")
    print("─" * 80)
    
    # Parse AbuseIPDB
    print("\n📥 Processing AbuseIPDB data for IP 192.168.1.100...")
    abuse_threat = abuseipdb_parser.parse(
        evidence_items[0],
        threat_data["abuseipdb"]["192.168.1.100"]
    )
    if abuse_threat:
        all_threats.append(abuse_threat)
        print(f"   ✅ Threat Level: {abuse_threat.threat_level.value.upper()}")
        print(f"   ✅ Threat Score: {abuse_threat.threat_score:.1f}/100")
        print(f"   ✅ Is Malicious: {abuse_threat.is_malicious}")
        print(f"   ✅ Indicators: {len(abuse_threat.indicators)}")
        for ind in abuse_threat.indicators[:3]:
            print(f"      - {ind.indicator_type}: {ind.confidence:.0%}")
    
    # Parse OTX
    print("\n📥 Processing OTX data for domain malicious.ru...")
    otx_threat = otx_parser.parse(
        evidence_items[1],
        threat_data["otx"]["malicious.ru"]
    )
    if otx_threat:
        all_threats.append(otx_threat)
        print(f"   ✅ Threat Level: {otx_threat.threat_level.value.upper()}")
        print(f"   ✅ Threat Score: {otx_threat.threat_score:.1f}/100")
        print(f"   ✅ Is Malicious: {otx_threat.is_malicious}")
        print(f"   ✅ Campaign Indicators: {len(otx_threat.related_incidents)}")
        for campaign in otx_threat.related_incidents:
            print(f"      - {campaign}")
    
    # Parse Shodan
    print("\n📥 Processing Shodan data for IP 203.0.113.45...")
    shodan_threat = shodan_parser.parse(
        evidence_items[2],
        threat_data["shodan"]["203.0.113.45"]
    )
    if shodan_threat:
        all_threats.append(shodan_threat)
        print(f"   ✅ Threat Level: {shodan_threat.threat_level.value.upper()}")
        print(f"   ✅ Threat Score: {shodan_threat.threat_score:.1f}/100")
        print(f"   ✅ Is Malicious: {shodan_threat.is_malicious}")
        print(f"   ✅ Open Services: {shodan_threat.scan_count}")
        print(f"   ✅ Recommendations:")
        for rec in shodan_threat.recommendations[:2]:
            print(f"      → {rec}")
    
    # ========== STAGE 2: CORRELATE THREATS ==========
    print("\n" + "─" * 80)
    print("STAGE 2️⃣  : NEO4J INCIDENT CORRELATION")
    print("─" * 80)
    
    correlation_engine = ThreatCorrelationEngine()
    incidents = []
    
    for threat in all_threats:
        if threat.is_malicious:
            incident = correlation_engine.create_incident_from_threat(
                threat,
                case_id="FORENSIC-2024-001",
                related_evidence=[]
            )
            if incident:
                incidents.append(incident)
                print(f"\n🔗 Created Incident: {incident.incident_id}")
                print(f"   Type: {incident.incident_type}")
                print(f"   Severity: {incident.severity_score:.1f}/100")
                print(f"   Status: {incident.status}")
                print(f"   Evidence linked: {incident.evidence_count}")
    
    # Correlate incidents
    correlation_results = correlation_engine.correlate_incidents(incidents)
    print(f"\n📊 Correlation Results:")
    print(f"   Total Correlations: {correlation_results['correlation_count']}")
    print(f"   Patterns Detected: {len(correlation_results['patterns'])}")
    for pattern in correlation_results['patterns']:
        print(f"      - {pattern['type']}: {pattern['count']} incidents")
    
    # ========== STAGE 3: GENERATE VERDICT ==========
    print("\n" + "─" * 80)
    print("STAGE 3️⃣  : FORENSIC VERDICT GENERATION")
    print("─" * 80)
    
    # Build comprehensive verdict
    malicious_count = sum(1 for t in all_threats if t.is_malicious)
    avg_threat_score = sum(t.threat_score for t in all_threats) / len(all_threats)
    
    verdict = ForensicVerdict(
        case_id="FORENSIC-2024-001",
        verdict="MALICIOUS" if malicious_count >= 2 else "SUSPICIOUS",
        confidence_level=0.92,
        threat_level=ThreatLevel.CRITICAL if avg_threat_score >= 80 else ThreatLevel.HIGH,
        threat_evidences=[t.evidence_id for t in all_threats if t.is_malicious],
        threat_count=len(all_threats),
        incident_count=len(incidents),
        primary_threat_indicators=[
            f"Detected {len(all_threats)} entities with malicious behavior",
            f"Average threat score: {avg_threat_score:.1f}/100",
            "Multiple threat sources confirming malicious activity",
            f"Correlated into {len(incidents)} incident cluster(s)",
        ],
        credibility_index=0.88,
        conclusions=(
            f"Investigation of case FORENSIC-2024-001 identified {malicious_count} "
            f"malicious entities across {len(all_threats)} evidence items. "
            f"Threat intelligence from multiple sources (AbuseIPDB, OTX, Shodan) "
            f"confirms active malicious activity with high confidence. "
            f"Automated correlation identified {len(incidents)} distinct incident(s) "
            f"requiring immediate investigation and remediation."
        ),
        recommendations=[
            f"Block all {malicious_count} identified malicious IP addresses immediately",
            "Initiate incident response protocol for each correlated incident",
            "Conduct forensic analysis of affected systems",
            "Monitor for lateral movement and exfiltration attempts",
            "Implement additional detection rules for identified threat patterns",
            "Coordinate with threat intelligence sharing groups",
        ],
        analyst="FOEP_AUTOMATED_V1",
    )
    
    # ========== OUTPUT REPORTS ==========
    print("\n📄 Generating Forensic Reports...\n")
    
    generator = ForensicVerdictGenerator()
    
    # Text report
    text_report = generator.generate_text_report(verdict)
    print(text_report)
    
    # HTML report
    html_report = generator.generate_html_report(verdict)
    
    # JSON report
    json_report = generator.generate_json_report(verdict)
    
    # Save reports
    output_dir = Path("/workspaces/FOEP/threat_detection_results")
    output_dir.mkdir(exist_ok=True)
    
    # Save text report
    with open(output_dir / "verdict_textreport.txt", "w") as f:
        f.write(text_report)
    print(f"✅ Text report saved: {output_dir / 'verdict_text_report.txt'}")
    
    # Save HTML report
    with open(output_dir / "verdict_report.html", "w") as f:
        f.write(html_report)
    print(f"✅ HTML report saved: {output_dir / 'verdict_report.html'}")
    
    # Save JSON report
    with open(output_dir / "verdict_report.json", "w") as f:
        json.dump(json_report, f, indent=2)
    print(f"✅ JSON report saved: {output_dir / 'verdict_report.json'}")
    
    # Save threat intelligence data
    threats_json = {
        "threats": [
            {
                "evidence_id": t.evidence_id,
                "entity_value": t.entity_value,
                "entity_type": t.entity_type.value,
                "threat_level": t.threat_level.value,
                "threat_score": t.threat_score,
                "is_malicious": t.is_malicious,
                "indicators": [
                    {
                        "type": ind.indicator_type,
                        "confidence": ind.confidence,
                        "description": ind.description,
                    }
                    for ind in t.indicators
                ],
            }
            for t in all_threats
        ]
    }
    
    with open(output_dir / "threat_intelligence.json", "w") as f:
        json.dump(threats_json, f, indent=2)
    print(f"✅ Threat intelligence saved: {output_dir / 'threat_intelligence.json'}")
    
    # Save incidents
    incidents_json = {
        "incidents": [
            {
                "incident_id": inc.incident_id,
                "case_id": inc.case_id,
                "incident_type": inc.incident_type,
                "threat_level": inc.threat_level.value,
                "severity_score": inc.severity_score,
                "description": inc.description,
                "affected_entities": inc.affected_entities,
                "evidence_ids": inc.evidence_ids,
                "recommended_actions": inc.recommended_actions,
            }
            for inc in incidents
        ],
        "correlation": correlation_results,
    }
    
    with open(output_dir / "incidents_correlation.json", "w") as f:
        json.dump(incidents_json, f, indent=2)
    print(f"✅ Incidents saved: {output_dir / 'incidents_correlation.json'}")
    
    # Save Neo4j Cypher queries
    cypher_queries = "\n\n".join(
        correlation_engine.build_incident_graph_query(inc)
        for inc in incidents
    )
    
    with open(output_dir / "neo4j_queries.cypher", "w") as f:
        f.write("// Threat Incident Neo4j Graph Queries\n")
        f.write("// Execute these queries in Neo4j to create incident graph\n\n")
        f.write(cypher_queries)
    print(f"✅ Neo4j queries saved: {output_dir / 'neo4j_queries.cypher'}")
    
    print("\n" + "=" * 80)
    print("🎉 THREAT DETECTION PIPELINE COMPLETED SUCCESSFULLY")
    print("=" * 80)
    
    return all_threats, incidents, verdict


if __name__ == "__main__":
    demonstrate_threat_parsing()
