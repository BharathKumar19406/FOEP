import argparse
import json
import logging
import sys
from pathlib import Path
from typing import List, Dict, Any

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

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
    for arg in breach_args:
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
  # Ingest a disk image
  foep_ingest.py --disk /evidence/disk.img --output evidence.json

  # Ingest memory and logs
  foep_ingest.py --memory /evidence/mem.raw --log /evidence/syslog --output evidence.json

  # Collect OSINT
  foep_ingest.py --social "github:attacker123" --social "twitter:user123" \\
                 --breach "user@company.com" --breach "domain:company.com" \\
                 --code "filename:.env password" --output osint.json

  # Combine forensic and OSINT
  foep_ingest.py --disk disk.img --social "github:attacker123" --output combined.json
        """,
    )

    # Input sources
    parser.add_argument("--disk", nargs="+", help="Disk image paths (E01, RAW, etc.)")
    parser.add_argument("--memory", nargs="+", help="Memory dump paths")
    parser.add_argument("--log", nargs="+", help="Log file paths")
    parser.add_argument("--log-dir", nargs="+", help="Log directory paths")

    # OSINT sources
    parser.add_argument(
        "--social", nargs="+", help="Social media queries (format: platform:identifier)"
    )
    parser.add_argument(
        "--breach",
        nargs="+",
        help="Breach queries (format: [type:]value, e.g., 'email:user@x.com' or 'user@x.com')",
    )
    parser.add_argument("--code", nargs="+", help="Code repository search queries")
    parser.add_argument("--domain", nargs="+", help="Domain for subdomain enumeration")
    parser.add_argument("--vt-hash", nargs="+", help="VirusTotal file hash checks")

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
        help="Case identifier (default: DEFAULT_CASE)",
    )
    parser.add_argument(
        "--investigator", default="unknown", help="Investigator name (default: unknown)"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose logging"
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Validate at least one input source
    has_forensic = any([args.disk, args.memory, args.log, args.log_dir])
    has_osint = any([
        args.social, 
        args.breach, 
        args.code, 
        args.domain,
        args.vt_hash
    ])
    if not (has_forensic or has_osint):
        parser.error(
            "At least one input source (--disk, --memory, --log, --social, --domain, etc.) is required"
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

        # Domain collection with enrichment
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

        all_evidence.extend(osint_evidence)
        logger.info(f"Collected {len(osint_evidence)} OSINT items")

    # Output results
    output_path = Path(args.output).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    evidence_dicts = [evidence_to_dict(ev) for ev in all_evidence]

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(evidence_dicts, f, indent=2)

    logger.info(
        f"Ingestion complete. Wrote {len(all_evidence)} evidence items to {output_path}"
    )


if __name__ == "__main__":
    main()
