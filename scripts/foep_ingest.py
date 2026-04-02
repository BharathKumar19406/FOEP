import argparse
import json
import logging
import sys
from pathlib import Path
from typing import List, Dict, Any

# Proper package imports (works when installed on Kali/any system)
from foep.core.config import load_config
from foep.core.pipeline import FOEPPipeline
from foep.normalize.schema import Evidence

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("foep_ingest")


def parse_social_queries(social_args: List[str]) -> List[Dict[str, str]]:
    """Parse social media queries from CLI arguments."""
    queries = []
    for arg in social_args:
        if ":" not in arg:
            logger.warning(
                f"Invalid social query format: {arg}. Expected 'platform:identifier'"
            )
            continue
        platform, identifier = arg.split(":", 1)
        queries.append({"platform": platform.strip(), "identifier": identifier.strip()})
    return queries


def parse_breach_queries(breach_args: List[str]) -> List[Dict[str, str]]:
    """Parse breach queries from CLI arguments."""
    queries = []
    for arg in breach_args:  # ✅ FIXED: was 'in_args'
        if ":" not in arg:
            # Assume email if no type specified
            queries.append({"query": arg.strip(), "type": "email"})
        else:
            query_type, value = arg.split(":", 1)
            if query_type.lower() in {"email", "username", "domain"}:
                queries.append({"query": value.strip(), "type": query_type.lower()})
            else:
                logger.warning(
                    f"Invalid breach query type: {query_type}. Using 'email'"
                )
                queries.append({"query": arg.strip(), "type": "email"})
    return queries


def evidence_to_dict(evidence: Evidence) -> Dict[str, Any]:
    """Convert Evidence object to JSON-serializable dict."""
    return {
        "evidence_id": evidence.evidence_id,
        "entity_type": evidence.entity_type.value,
        "entity_value": evidence.entity_value,
        "observation_type": evidence.observation_type.value,
        "source": evidence.source,
        "metadata": evidence.metadata,
        "credibility_score": evidence.credibility_score,
        "sha256_hash": evidence.sha256_hash,
    }


def main():
    parser = argparse.ArgumentParser(
        description="FOEP Evidence Ingestion Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Collect OSINT
  foep_ingest.py --social "github:trailofbits" --domain "microsoft.com" --breach "user@x.com" --output evidence.json

  # Combine forensic and OSINT
  foep_ingest.py --disk disk.img --social "github:attacker" --output combined.json
        """,
    )

    # Input sources
    parser.add_argument("--disk", nargs="+", help="Disk image paths (E01, RAW, etc.)")
    parser.add_argument("--memory", nargs="+", help="Memory dump paths")
    parser.add_argument("--log", nargs="+", help="Log file paths")
    parser.add_argument("--log-dir", nargs="+", help="Log directory paths")

    # OSINT sources
    parser.add_argument(
        "--social", nargs="+", help="Social media queries (format: platform:identifier, e.g., 'github:user' or 'twitter:handle')"
    )
    parser.add_argument("--twitter", nargs="+", help="Twitter username searches")
    parser.add_argument("--linkedin", nargs="+", help="LinkedIn profile searches")
    parser.add_argument(
        "--breach",
        nargs="+",
        help="Breach queries (format: [type:]value, e.g., 'email:user@x.com')"
    )
    parser.add_argument("--code", nargs="+", help="Code repository search queries")
    parser.add_argument("--domain", nargs="+", help="Domain for OSINT enrichment")
    parser.add_argument("--vt-hash", nargs="+", help="VirusTotal file hash checks")
    
    # Threat Intelligence Sources
    parser.add_argument("--otx-ip", nargs="+", help="OTX IP reputation checks")
    parser.add_argument("--otx-domain", nargs="+", help="OTX domain reputation checks")
    parser.add_argument("--otx-hash", nargs="+", help="OTX hash reputation checks")
    
    parser.add_argument("--abuseipdb", nargs="+", help="AbuseIPDB IP reputation checks")
    
    parser.add_argument("--shodan-ip", nargs="+", help="Shodan IP infrastructure checks")
    
    parser.add_argument("--censys-ip", nargs="+", help="Censys IP intelligence")
    parser.add_argument("--censys-cert", nargs="+", help="Censys certificate lookup")
    
    parser.add_argument("--urlscan-url", nargs="+", help="URLScan URL scans")
    parser.add_argument("--urlscan-domain", nargs="+", help="URLScan domain scans")
    
    parser.add_argument("--dumpstar-email", nargs="+", help="DumpStar email leak search")
    parser.add_argument("--dumpstar-username", nargs="+", help="DumpStar username leak search")
    parser.add_argument("--dumpstar-phone", nargs="+", help="DumpStar phone leak search")
    
    parser.add_argument("--archive-org", nargs="+", help="Archive.org URL history search")

    # Output and config
    parser.add_argument("--output", required=True, help="Output JSON file path")
    parser.add_argument(
        "--config",
        default="config/config.yaml",
        help="Configuration file path (default: config/config.yaml)",
    )
    parser.add_argument(
        "--case-id",
        default="DEFAULT_CASE",
        help="Case identifier",
    )
    parser.add_argument(
        "--investigator", default="unknown", help="Investigator name"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose logging"
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # ✅ VALIDATION: Include all OSINT sources
    has_forensic = any([args.disk, args.memory, args.log, args.log_dir])
    has_osint = any([
        args.social, 
        args.twitter,
        args.linkedin,
        args.breach, 
        args.code, 
        args.domain,
        args.vt_hash,
        args.otx_ip,
        args.otx_domain,
        args.otx_hash,
        args.abuseipdb,
        args.shodan_ip,
        args.censys_ip,
        args.censys_cert,
        args.urlscan_url,
        args.urlscan_domain,
        args.dumpstar_email,
        args.dumpstar_username,
        args.dumpstar_phone,
        args.archive_org,
    ])
    if not (has_forensic or has_osint):
        parser.error(
            "At least one input source required (--social, --twitter, --linkedin, --domain, --otx-ip, --shodan-ip, etc.)"
        )

    # Load configuration
    try:
        config = load_config(args.config)
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        sys.exit(1)

    # Initialize pipeline
    pipeline = FOEPPipeline(
        config=config, case_id=args.case_id, investigator=args.investigator
    )

    all_evidence = []

    # Run forensic ingestion
    if has_forensic:
        logger.info("Starting forensic ingestion...")
        forensic_evidence = pipeline.run_forensic_ingestion(
            disk_images=args.disk,
            memory_dumps=args.memory,
            log_files=args.log,
            log_directories=args.log_dir,
        )
        all_evidence.extend(forensic_evidence)
        logger.info(f"Collected {len(forensic_evidence)} forensic artefacts")

    # Run OSINT collection
    if has_osint:
        logger.info("Starting OSINT collection...")
        social_queries = parse_social_queries(args.social) if args.social else None
        breach_queries = parse_breach_queries(args.breach) if args.breach else None
        code_queries = args.code if args.code else None

        osint_evidence = pipeline.run_osint_collection(
            social_queries=social_queries,
            breach_queries=breach_queries,
            code_queries=code_queries,
        )

        # ✅ DOMAIN COLLECTION
        if args.domain:
            from foep.ingest.osint.domains import DomainCollector
            domain_collector = DomainCollector(config)
            for domain in args.domain:
                logger.info(f"Collecting domain OSINT for: {domain}")
                osint_evidence.extend(domain_collector.check_domain(domain))

        # VT hash checks
        if args.vt_hash:
            from foep.ingest.osint.virustotal import collect_vt_hash
            for h in args.vt_hash:
                osint_evidence.extend(collect_vt_hash(h, config.model_dump()))

        # ✅ TWITTER COLLECTION
        if args.twitter:
            from foep.ingest.osint.social import TwitterCollector
            twitter_collector = TwitterCollector(config)
            for username in args.twitter:
                logger.info(f"Collecting Twitter OSINT for: {username}")
                osint_evidence.extend(twitter_collector.collect_user(username))
                osint_evidence.extend(twitter_collector.collect_tweets(username, max_tweets=10))

        # ✅ LINKEDIN COLLECTION
        if args.linkedin:
            from foep.ingest.osint.social import LinkedInCollector
            linkedin_collector = LinkedInCollector(config)
            for profile in args.linkedin:
                logger.info(f"Collecting LinkedIn OSINT for: {profile}")
                osint_evidence.extend(linkedin_collector.collect_profile(profile))

        # ✅ OTX THREAT INTELLIGENCE
        if args.otx_ip:
            from foep.ingest.osint.otx import collect_otx_intelligence
            for ip in args.otx_ip:
                logger.info(f"Checking OTX for IP: {ip}")
                osint_evidence.extend(collect_otx_intelligence(ip, 'ip', config.model_dump()))

        if args.otx_domain:
            from foep.ingest.osint.otx import collect_otx_intelligence
            for domain in args.otx_domain:
                logger.info(f"Checking OTX for domain: {domain}")
                osint_evidence.extend(collect_otx_intelligence(domain, 'domain', config.model_dump()))

        if args.otx_hash:
            from foep.ingest.osint.otx import collect_otx_intelligence
            for hash_val in args.otx_hash:
                logger.info(f"Checking OTX for hash: {hash_val}")
                osint_evidence.extend(collect_otx_intelligence(hash_val, 'hash', config.model_dump()))

        # ✅ ABUSEIPDB CHECK
        if args.abuseipdb:
            from foep.ingest.osint.abuseipdb import collect_abuseipdb_intelligence
            for ip in args.abuseipdb:
                logger.info(f"Checking AbuseIPDB for: {ip}")
                osint_evidence.extend(collect_abuseipdb_intelligence(ip, config.model_dump()))

        # ✅ SHODAN CHECK
        if args.shodan_ip:
            from foep.ingest.osint.shodan import ShodanCollector
            shodan_collector = ShodanCollector(config.model_dump())
            for ip in args.shodan_ip:
                logger.info(f"Checking Shodan for IP: {ip}")
                osint_evidence.extend(shodan_collector.check_ip(ip))

        # ✅ CENSYS CHECK
        if args.censys_ip:
            from foep.ingest.osint.censys import collect_censys_data
            for ip in args.censys_ip:
                logger.info(f"Checking Censys for IP: {ip}")
                osint_evidence.extend(collect_censys_data(ip, 'ip', config.model_dump()))

        if args.censys_cert:
            from foep.ingest.osint.censys import collect_censys_data
            for cert in args.censys_cert:
                logger.info(f"Checking Censys for certificate: {cert}")
                osint_evidence.extend(collect_censys_data(cert, 'certificate', config.model_dump()))

        # ✅ URLSCAN CHECK
        if args.urlscan_url:
            from foep.ingest.osint.urlscan import collect_urlscan_data
            for url in args.urlscan_url:
                logger.info(f"Scanning URL with URLScan: {url}")
                osint_evidence.extend(collect_urlscan_data(url, 'url', config.model_dump()))

        if args.urlscan_domain:
            from foep.ingest.osint.urlscan import collect_urlscan_data
            for domain in args.urlscan_domain:
                logger.info(f"Scanning domain with URLScan: {domain}")
                osint_evidence.extend(collect_urlscan_data(domain, 'domain', config.model_dump()))

        # ✅ DUMPSTAR LEAK SEARCH
        if args.dumpstar_email:
            from foep.ingest.osint.dumpstar import collect_dumpstar_leaks
            for email in args.dumpstar_email:
                logger.info(f"Searching DumpStar for email: {email}")
                osint_evidence.extend(collect_dumpstar_leaks(email, 'email', config.model_dump()))

        if args.dumpstar_username:
            from foep.ingest.osint.dumpstar import collect_dumpstar_leaks
            for username in args.dumpstar_username:
                logger.info(f"Searching DumpStar for username: {username}")
                osint_evidence.extend(collect_dumpstar_leaks(username, 'username', config.model_dump()))

        if args.dumpstar_phone:
            from foep.ingest.osint.dumpstar import collect_dumpstar_leaks
            for phone in args.dumpstar_phone:
                logger.info(f"Searching DumpStar for phone: {phone}")
                osint_evidence.extend(collect_dumpstar_leaks(phone, 'phone', config.model_dump()))

        # ✅ ARCHIVE.ORG URL HISTORY
        if args.archive_org:
            from foep.ingest.osint.archiveorg import collect_wayback_data
            for url in args.archive_org:
                logger.info(f"Checking Archive.org for URL: {url}")
                osint_evidence.extend(collect_wayback_data(url, config.model_dump()))

        all_evidence.extend(osint_evidence)
        logger.info(f"Collected {len(osint_evidence)} OSINT items")

    # Output results
    output_path = Path(args.output).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    evidence_dicts = [evidence_to_dict(ev) for ev in all_evidence]

    with open(output_path, "w", encoding="utf-8") as f:  # ✅ FIXED: was 'output,w"'
        json.dump(evidence_dicts, f, indent=2)

    logger.info(
        f"Ingestion complete. Wrote {len(all_evidence)} evidence items to {output_path}"
    )


if __name__ == "__main__":
    main()
