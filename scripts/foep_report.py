#!/usr/bin/env python3
# scripts/foep_report.py

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
logger = logging.getLogger("foep_report")


def load_evidence_from_json(input_path: Path) -> List[Evidence]:
    """Load Evidence objects from JSON file."""
    with open(input_path, "r", encoding="utf-8") as f:
        evidence_dicts = json.load(f)

    evidence_list = []
    for ev_dict in evidence_dicts:
        try:
            evidence = Evidence(
                evidence_id=ev_dict["evidence_id"],
                entity_type=ev_dict["entity_type"],
                entity_value=ev_dict["entity_value"],
                observation_type=ev_dict["observation_type"],
                source=ev_dict["source"],
                metadata=ev_dict.get("metadata", {}),
                credibility_score=ev_dict["credibility_score"],
                sha256_hash=ev_dict.get("sha256_hash"),
            )
            evidence_list.append(evidence)
        except Exception as e:
            logger.warning(f"Failed to parse evidence item: {e}")
            continue

    logger.info(f"Loaded {len(evidence_list)} evidence items from {input_path}")
    return evidence_list


def main():
    parser = argparse.ArgumentParser(
        description="FOEP Forensic Report Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate PDF report
  foep_report.py --input correlated.json --output reports/ --case-id INC-2024-001

  # Generate HTML report with custom case info
  foep_report.py --input correlated.json --output reports/ --format html \\
                 --title "Insider Threat Analysis" --description "Employee misconduct investigation"
        """,
    )

    parser.add_argument(
        "--input", required=True, help="Input JSON file with correlated evidence items"
    )
    parser.add_argument(
        "--output", required=True, help="Output directory for report files"
    )
    parser.add_argument(
        "--format",
        choices=["pdf", "html"],
        default="pdf",
        help="Report format (default: pdf)",
    )
    parser.add_argument(
        "--config",
        default="config/config.yaml",
        help="Configuration file path (default: config/config.yaml)",
    )
    parser.add_argument("--case-id", required=True, help="Case identifier")
    parser.add_argument(
        "--investigator", default="unknown", help="Investigator name (default: unknown)"
    )
    parser.add_argument("--title", help="Report title (overrides config default)")
    parser.add_argument(
        "--description", help="Case description (overrides config default)"
    )
    parser.add_argument(
        "--organization", help="Investigating organization (overrides config default)"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose logging"
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Load configuration
    try:
        config = load_config(args.config)
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        sys.exit(1)

    # Load evidence
    input_path = Path(args.input).resolve()
    if not input_path.exists():
        logger.error(f"Input file not found: {input_path}")
        sys.exit(1)

    evidence_list = load_evidence_from_json(input_path)
    if not evidence_list:
        logger.error("No valid evidence items found in input")
        sys.exit(1)

    # Build case info
    case_info = {}
    if args.title:
        case_info["title"] = args.title
    if args.description:
        case_info["description"] = args.description
    if args.organization:
        case_info["organization"] = args.organization

    # Initialize pipeline (without re-processing)
    pipeline = FOEPPipeline(
        config=config, case_id=args.case_id, investigator=args.investigator
    )
    pipeline.all_evidence = evidence_list

    # Generate report
    try:
        report_path = pipeline.generate_report(
            output_dir=args.output, format=args.format, case_info=case_info
        )
        logger.info(f"Report successfully generated: {report_path}")
    except Exception as e:
        logger.error(f"Failed to generate report: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
