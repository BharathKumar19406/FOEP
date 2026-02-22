# src/foep/core/config.py

import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional, Union

import yaml
from pydantic import BaseModel, Field, SecretStr, field_validator

logger = logging.getLogger(__name__)


class GitHubConfig(BaseModel):
    enabled: bool = False
    api_token: Optional[SecretStr] = None

class TwitterConfig(BaseModel):
    enabled: bool = False
    bearer_token: SecretStr = Field(default="")
    api_key: SecretStr = Field(default="")
    api_key_secret: SecretStr = Field(default="")
    access_token: SecretStr = Field(default="")
    access_token_secret: SecretStr = Field(default="")

class LinkedInConfig(BaseModel):
    enabled: bool = False

class HIBPConfig(BaseModel):
    enabled: bool = Field(default=False)
    api_key: str = Field(default="")
    mock_mode: bool = Field(default=False)

class VirustotalConfig(BaseModel):
    enabled: bool = False
    api_key: str = ""

class ShodanConfig(BaseModel):
    enabled: bool = False
    api_key: str = ""

class IPGeolocationConfig(BaseModel):
    enabled: bool = True

class WHOISHistoryConfig(BaseModel):
    enabled: bool = False
    api_key: str = ""

class ArchiveOrgConfig(BaseModel):
    enabled: bool = True

class DeHashedConfig(BaseModel):
    enabled: bool = False
    email: Optional[str] = None
    api_key: Optional[SecretStr] = None


class GitLabConfig(BaseModel):
    enabled: bool = False


class Neo4jConfig(BaseModel):
    uri: str = "bolt://localhost:7687"
    username: str = "neo4j"
    password: SecretStr
    database: str = "neo4j"


class RedactionConfig(BaseModel):
    redact_emails: bool = True
    redact_ips: bool = True
    redact_names: bool = False
    redact_usernames: bool = False
    preserve_internal_ips: bool = True
    allowlist_domains: list[str] = Field(default_factory=list)
    blocklist_domains: list[str] = Field(default_factory=list)


class CredibilityConfig(BaseModel):
    max_corroboration_bonus: int = 20
    age_penalty_per_day: int = 2
    max_age_penalty: int = 30
    conflict_penalty: int = 15
    min_credibility: int = 10


class FOEPConfig(BaseModel):
    """
    Main configuration model for FOEP.
    """

    github: GitHubConfig = Field(default_factory=GitHubConfig)
    twitter: TwitterConfig = Field(default_factory=TwitterConfig)
    linkedin: LinkedInConfig = Field(default_factory=LinkedInConfig)
    hibp: HIBPConfig = Field(default_factory=HIBPConfig)
    dehashed: DeHashedConfig = Field(default_factory=DeHashedConfig)
    gitlab: GitLabConfig = Field(default_factory=GitLabConfig)
    neo4j: Neo4jConfig = Field(default_factory=Neo4jConfig)
    redaction: RedactionConfig = Field(default_factory=RedactionConfig)
    credibility: CredibilityConfig = Field(default_factory=CredibilityConfig)
    case_defaults: Dict[str, Any] = Field(default_factory=dict)
    virustotal: VirustotalConfig = VirustotalConfig()
    shodan: ShodanConfig = ShodanConfig()
    ipgeolocation: IPGeolocationConfig = IPGeolocationConfig()
    whois_history: WHOISHistoryConfig = WHOISHistoryConfig()
    archiveorg: ArchiveOrgConfig = ArchiveOrgConfig()

    @field_validator("github", "twitter", "hibp", "dehashed", mode="before")
    @classmethod
    def load_secrets_from_env(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        """Override config values with environment variables if present."""
        if not isinstance(v, dict):
            v = {}

        # GitHub
        if "GITHUB_API_TOKEN" in os.environ:
            v["api_token"] = os.environ["GITHUB_API_TOKEN"]
        if "GITHUB_ENABLED" in os.environ:
            v["enabled"] = os.environ["GITHUB_ENABLED"].lower() in ("true", "1", "yes")

        # Twitter
        if "TWITTER_BEARER_TOKEN" in os.environ:
            v["bearer_token"] = os.environ["TWITTER_BEARER_TOKEN"]
        if "TWITTER_ENABLED" in os.environ:
            v["enabled"] = os.environ["TWITTER_ENABLED"].lower() in ("true", "1", "yes")

        # HIBP
        if "HIBP_API_KEY" in os.environ:
            v["api_key"] = os.environ["HIBP_API_KEY"]
        if "HIBP_ENABLED" in os.environ:
            v["enabled"] = os.environ["HIBP_ENABLED"].lower() in ("true", "1", "yes")

        # DeHashed
        if "DEHASHED_EMAIL" in os.environ:
            v["email"] = os.environ["DEHASHED_EMAIL"]
        if "DEHASHED_API_KEY" in os.environ:
            v["api_key"] = os.environ["DEHASHED_API_KEY"]
        if "DEHASHED_ENABLED" in os.environ:
            v["enabled"] = os.environ["DEHASHED_ENABLED"].lower() in (
                "true",
                "1",
                "yes",
            )

        # Neo4j
        if "NEO4J_URI" in os.environ:
            v["neo4j.uri"] = os.environ["NEO4J_URI"]
        if "NEO4J_USERNAME" in os.environ:
            v["neo4j.username"] = os.environ["NEO4J_USERNAME"]
        if "NEO4J_PASSWORD" in os.environ:
            v["neo4j.password"] = os.environ["NEO4J_PASSWORD"]
        if "NEO4J_DATABASE" in os.environ:
            v["neo4j.database"] = os.environ["NEO4J_DATABASE"]

        return v

    class Config:
        # Allow population by field name (not just alias)
        populate_by_name = True
        # Prevent accidental logging of secrets
        json_encoders = {SecretStr: lambda v: v.get_secret_value() if v else None}


def load_config(config_path: Optional[Union[str, Path]] = None) -> FOEPConfig:
    """
    Load FOEP configuration from YAML file.

    Args:
        config_path: Path to config.yaml (default: ./config/config.yaml)

    Returns:
        Validated FOEPConfig instance.
    """
    if config_path is None:
        config_path = Path("config") / "config.yaml"
    else:
        config_path = Path(config_path)

    config_data = {}
    if config_path.exists():
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                config_data = yaml.safe_load(f) or {}
            logger.info(f"Loaded configuration from {config_path}")
        except Exception as e:
            logger.warning(f"Failed to load config file {config_path}: {e}")
    else:
        logger.info(f"Config file not found at {config_path}, using defaults")

    # Create config instance (env vars override file)
    config = FOEPConfig(**config_data)

    # Log non-secret settings for debugging
    logger.debug("FOEP configuration loaded with settings:")
    logger.debug(f"  GitHub enabled: {config.github.enabled}")
    logger.debug(f"  Twitter enabled: {config.twitter.enabled}")
    logger.debug(f"  HIBP enabled: {config.hibp.enabled}")
    logger.debug(f"  DeHashed enabled: {config.dehashed.enabled}")
    logger.debug(f"  Neo4j URI: {config.neo4j.uri}")
    logger.debug(
        f"  Redaction: emails={config.redaction.redact_emails}, IPs={config.redaction.redact_ips}"
    )

    return config
