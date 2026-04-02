#!/usr/bin/env python3
# scripts/threat_detection_demo.py
"""
Comprehensive demonstration of FOEP threat detection pipeline.

Shows:
1. Local threat detection (malware hashes, domains, IPs, URLs, behavioral)
2. Threat intelligence aggregation from multiple sources
3. Evidence enrichment with threat metadata
4. Threat analysis and reporting
5. Neo4j incident correlation
6. Forensic verdict generation
"""

import sys
import json
from pathlib import Path
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from foep.normalize.schema import Evidence, EntityType, ObservationType
from foep.threat import (
    ThreatDetectionEngine,
    ThreatIntelligenceAggregator,
    AbuseIPDBParser,
    OTXParser,
    ShodanParser,
    ThreatLevel,
)
from foep.threat.threat_correlation import ThreatCorrelationEngine
from foep.threat.forensic_verdict_template import ForensicVerdictGenerator
from foep.threat.threat_schema import ForensicVerdict
from foep.ingest.threat_utils import (
    ThreatDetectionIngest,
    filter_evidence_by_threat_level,
    create_threat_summary,
)


def create_sample_evidence():
    """Create comprehensive sample evidence for threat detection."""
    return [
        # Malware hash evidence
        Evidence(
            evidence_id="forensic::file_hash::emotet",
            entity_type=EntityType.HASH,
            entity_value="69a26c7f9c4c8c44c88d7c9c8e3a3b3c",
            observation_type=ObservationType.DISK_ARTIFACT,
            source="forensic_disk",
            metadata={
                "filename": "payload.exe.txt",
                "hash_type": "sha256",
                "file_path": "C:\\Users\\Admin\\Downloads\\",
            },
            credibility_score=90,
        ),
        # Malicious domain
        Evidence(
            evidence_id="osint::domain::c2",
            entity_type=EntityType.DOMAIN,
            entity_value="malicious.ru",
            observation_type=ObservationType.OSINT_REPUTATION,
            source="dns_logs",
            metadata={"dns_queries": 156, "first_seen": "2024-02-15"},
            credibility_score=85,
        ),
        # Malicious IP
        Evidence(
            evidence_id="osint::ip::botnet",
            entity_type=EntityType.IP_ADDRESS,
            entity_value="203.0.113.45",
            observation_type=ObservationType.OSINT_GEO,
            source="network_logs",
            metadata={
                "outbound_connections": 245,
                "country_code": "RU",
                "open_ports": [443, 8080, 3389],
            },
            credibility_score=88,
        ),
        # Malicious URL
        Evidence(
            evidence_id="osint::url::payload",
            entity_type=EntityType.URL,
            entity_value="http://malicious.ru/payload.exe",
            observation_type=ObservationType.OSINT_REPUTATION,
            source="proxy_logs",
            metadata={"http_requests": 23, "user_agents": ["WinHttp"]},
            credibility_score=82,
        ),
        # Suspicious file (persistence mechanism)
        Evidence(
            evidence_id="forensic::file::persistence",
            entity_type=EntityType.FILE,
            entity_value="C:\\malware.exe",
            observation_type=ObservationType.DISK_ARTIFACT,
            source="forensic_registry",
            metadata={"value": "c:\\malware.exe", "modified_time": "2024-03-01T14:23:00Z"},
            credibility_score=95,
        ),
        # Suspicious command line
        Evidence(
            evidence_id="forensic::cmdline::lolbin",
            entity_type=EntityType.COMMAND_LINE,
            entity_value="powershell.exe -e <base64_encoded>",
            observation_type=ObservationType.MEMORY_ARTIFACT,
            source="memory_dump",
            metadata={
                "parent_process": "explorer.exe",
                "command_line": "powershell.exe -e <base64_encoded>",
            },
            credibility_score=80,
        ),
        # Clean evidence (for comparison)
        Evidence(
            evidence_id="osint::domain::legitimate",
            entity_type=EntityType.DOMAIN,
            entity_value="microsoft.com",
            observation_type=ObservationType.OSINT_REPUTATION,
            source="dns_logs",
            metadata={"reputation": "trusted", "whois_registrant": "Microsoft Corp"},
            credibility_score=95,
        ),
    ]


def demo_local_threat_detection():
    """Demonstrate local threat detection capabilities."""
    print("\n" + "="*80)
    print("1. LOCAL THREAT DETECTION DEMO")
    print("="*80 + "\n")
    
    evidence_list = create_sample_evidence()
    detector = ThreatDetectionEngine()
    
    print("Analyzing evidence with local threat detectors...\n")
    
    threats_found = []
    for evidence in evidence_list:
        threat = detector.detect_threats(evidence)
        
        if threat:
            threats_found.append(threat)
            
            # Display threat info
            print(f"⚠️  THREAT DETECTED: {evidence.entity_value}")
            print(f"  Type: {evidence.entity_type.value}")
            print(f"  Threat Level: {threat.threat_level.value.upper()}")
            print(f"  Threat Score: {threat.threat_score:.1f}%")
            print(f"  Malicious: {'Yes' if threat.is_malicious else 'No'}")
            print(f"  Indicators: {len(threat.indicators)}")
            
            for indicator in threat.indicators[:3]:
                print(f"    - {indicator.indicator_type}: {indicator.description}")
            
            if threat.recommendations:
                print(f"  Recommendations:")
                for rec in threat.recommendations[:2]:
                    print(f"    • {rec}")
            print()
        else:
            print(f"✓ {evidence.entity_value} - No threats detected\n")
    
    # Summary
    print("Local Threat Detection Summary:")
    print("-" * 40)
    threat_counts = {}
    for threat in threats_found:
        level = threat.threat_level.value
        threat_counts[level] = threat_counts.get(level, 0) + 1
    
    for level in ['critical', 'high', 'medium', 'low', 'info']:
        if level in threat_counts:
            print(f"  {level.upper()}: {threat_counts[level]}")


def demo_threat_intelligence_aggregation():
    """Demonstrate threat intelligence aggregation from multiple sources."""
    print("\n" + "="*80)
    print("2. THREAT INTELLIGENCE AGGREGATION DEMO")
    print("="*80 + "\n")
    
    aggregator = ThreatIntelligenceAggregator()
    
    # Show available feeds
    print("Available Threat Intelligence Feeds:")
    print("-" * 40)
    for feed_name, feed_config in aggregator.feeds.items():
        status = "Enabled" if feed_config.enabled else "Disabled"
        print(f"  • {feed_name:25} [{feed_config.source_type:6}] {status}")
    print()
    
    # Test aggregation on sample evidence
    test_evidence = [
        Evidence(
            evidence_id="network::test_ip_1",
            entity_type=EntityType.IP_ADDRESS,
            entity_value="192.168.1.100",
            observation_type=ObservationType.OSINT_REPUTATION,
            source="network",
            metadata={},
            credibility_score=80,
        ),
        Evidence(
            evidence_id="dns::test_domain_1",
            entity_type=EntityType.DOMAIN,
            entity_value="malicious.ru",
            observation_type=ObservationType.OSINT_REPUTATION,
            source="dns",
            metadata={},
            credibility_score=85,
        ),
    ]
    
    print("Aggregating threat intelligence for test evidence...\n")
    
    for evidence in test_evidence:
        threat = aggregator.aggregate_threats(evidence)
        if threat:
            print(f"{evidence.entity_value}")
            print(f"  Threat Score: {threat.threat_score:.1f}%")
            print(f"  Sources: {', '.join(threat.sources.keys())}")
            print(f"  Threat Level: {threat.threat_level.value.upper()}")
            print()


def demo_evidence_enrichment():
    """Demonstrate evidence enrichment with threat metadata."""
    print("\n" + "="*80)
    print("3. EVIDENCE ENRICHMENT DEMO")
    print("="*80 + "\n")
    
    evidence_list = create_sample_evidence()
    
    print("Enriching evidence with threat intelligence...\n")
    
    malicious_count = 0
    for evidence in evidence_list:
        threat = ThreatDetectionIngest.analyze_evidence(evidence)
        
        if threat and threat.is_malicious:
            malicious_count += 1
            print(f"✗ {evidence.entity_value}")
            print(f"  Threat: {threat.threat_level.value} ({threat.threat_score:.0f}%)")
            indicators = ', '.join(ind.indicator_type for ind in threat.indicators[:2])
            print(f"  Flagged for: {indicators}")
            print()
    
    print(f"Summary: {malicious_count} malicious items detected")


def demo_threat_filtering():
    """Demonstrate filtering evidence by threat level."""
    print("\n" + "="*80)
    print("4. THREAT-BASED EVIDENCE FILTERING")
    print("="*80 + "\n")
    
    evidence_list = create_sample_evidence()
    
    print("Filtering evidence by threat level...\n")
    
    filtered = filter_evidence_by_threat_level(evidence_list)
    
    print("Evidence Distribution by Threat Level:")
    print("-" * 40)
    for level in ['critical', 'high', 'medium', 'low', 'clean']:
        count = len(filtered[level]) if level in filtered else 0
        print(f"  {level.upper():10}: {count}")
    print()
    
    # Show prioritized items
    if filtered['critical']:
        print("CRITICAL THREATS (Immediate Action Required):")
        for evidence in filtered['critical']:
            print(f"  • {evidence.entity_value} ({evidence.entity_type.value})")


def demo_threat_summary():
    """Demonstrate threat summary generation."""
    print("\n" + "="*80)
    print("5. THREAT ANALYSIS SUMMARY")
    print("="*80 + "\n")
    
    evidence_list = create_sample_evidence()
    
    print("Generating comprehensive threat summary...\n")
    
    summary = create_threat_summary(evidence_list)
    
    print("Threat Intelligence Summary:")
    print("-" * 40)
    print(f"  Total Threats Detected: {summary['total_threats']}")
    print(f"  Clean Items:            {summary['clean_items']}")
    print(f"  Critical Threats:       {summary['critical_count']}")
    print(f"  High Threats:           {summary['high_count']}")
    print(f"  Average Threat Score:   {summary['average_threat_score']:.1f}%")
    print(f"  Threat Sources:         {', '.join(summary['threat_sources'])}")
    print()
    
    # Top indicators
    if summary['top_indicators']:
        print("Top Threat Indicators:")
        for indicator_type, count in list(summary['top_indicators'].items())[:5]:
            print(f"  • {indicator_type}: {count} occurrences")


def main():
    """Run all threat detection demos."""
    print("\n" + "="*80)
    print("FOEP ADVANCED THREAT DETECTION DEMONSTRATION")
    print("="*80 + "\n")
    
    try:
        # Run demonstrations
        demo_local_threat_detection()
        demo_threat_intelligence_aggregation()
        demo_evidence_enrichment()
        demo_threat_filtering()
        demo_threat_summary()
        
        # Final summary
        print("\n" + "="*80)
        print("✓ THREAT DETECTION DEMONSTRATION COMPLETE")
        print("="*80 + "\n")
        
        print("KEY IMPROVEMENTS:")
        print("-" * 40)
        print("• Local threat detection for hashes, domains, IPs, URLs")
        print("• Behavioral threat detection (persistence mechanisms)")
        print("• Aggregation from multiple threat intelligence sources")
        print("• Evidence enrichment with threat metadata")
        print("• Intelligent filtering and prioritization")
        print("• Comprehensive threat analysis and reporting")
        print()
        
    except Exception as e:
        print(f"Error during demonstration: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()



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
