# src/foep/credibility/sources.py

from typing import Dict

# Source reputation registry: source_name -> credibility_score (0-100)
# Higher = more trustworthy
SOURCE_REPUTATION_REGISTRY: Dict[str, int] = {
    # Forensic sources (internal) - not used here but for completeness
    "disk_image": 100,
    "volatility3": 100,
    "log_parser": 100,
    "plaso": 100,
    # OSINT sources
    "github": 90,  # Official API, public data, high reliability
    "gitlab": 85,  # Public repos, slightly less curated than GitHub
    "twitter": 70,  # Public posts, but prone to misinformation
    "linkedin": 60,  # Public profiles only; limited data, ethical constraints
    "hibp": 85,  # Troy Hunt's curated breach database, verified breaches
    "dehashed": 80,  # Aggregated breach data, mostly reliable
    "pastebin": 40,  # Public pastes; high noise, low verification
    "reddit": 50,  # Public subreddits; mixed reliability
    "facebook": 30,  # Limited public data; mostly unreliable for OSINT
    "telegram": 35,  # Public channels only; high noise
    "shodan": 75,  # Internet-wide scan data; technical accuracy high
    "censys": 75,  # Similar to Shodan, well-maintained
    "virustotal": 80,  # Aggregated malware/URL intelligence
    "urlscan": 70,  # Public website scan results
    "threatfox": 85,  # Abuse.ch curated IOCs
    "openphish": 75,  # Verified phishing URLs
    "entity_extractor": 95,  # Derived from high-confidence sources; minor deduction
}


def update_source_reputation(source: str, score: int) -> None:
    """
    Update the credibility score for a source at runtime.

    Args:
        source: Source name (e.g., "github")
        score: New credibility score (0-100)

    Raises:
        ValueError: If score is out of range
    """
    if not (0 <= score <= 100):
        raise ValueError("Credibility score must be between 0 and 100")
    SOURCE_REPUTATION_REGISTRY[source] = score


def get_source_credibility(source: str, default: int = 50) -> int:
    """
    Get the credibility score for a source.

    Args:
        source: Source name
        default: Default score if source not found

    Returns:
        Credibility score (0-100)
    """
    return SOURCE_REPUTATION_REGISTRY.get(source, default)
