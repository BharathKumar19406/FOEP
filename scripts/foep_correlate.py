#!/usr/bin/env python3
# scripts/foep_correlate.py

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
logger = logging.getLogger("foep_correlate")


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
        description="FOEP Evidence Correlation Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Correlate evidence from ingestion
  foep_correlate.py --input evidence.json --output correlated.json

  # Append to existing investigation
  foep_correlate.py --input new_evidence.json --case-id INC-2024-001 --output updated.json
        """,
    )

    parser.add_argument(
        "--input", required=True, help="Input JSON file with evidence items"
    )
    parser.add_argument(
        "--output", required=True, help="Output JSON file for correlated evidence"
    )
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

    # Initialize pipeline (without re-ingesting)
    pipeline = FOEPPipeline(
        config=config, case_id=args.case_id, investigator=args.investigator
    )
    pipeline.all_evidence = evidence_list

    # Run correlation and scoring
    logger.info("Starting correlation and scoring...")
    correlated_evidence = pipeline.run_correlation_and_scoring()
    logger.info(f"Correlation complete. Processed {len(correlated_evidence)} items")

    # Output results
    output_path = Path(args.output).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    evidence_dicts = [evidence_to_dict(ev) for ev in correlated_evidence]

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(evidence_dicts, f, indent=2)

    logger.info(
        f"Correlation complete. Wrote {len(correlated_evidence)} items to {output_path}"
    )


if __name__ == "__main__":
    main()
