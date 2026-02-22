# src/foep/normalize/schema.py
from enum import Enum
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field, field_validator


class EntityType(str, Enum):
    IP = "ip"
    IP_PORT = "ip_port"
    DOMAIN = "domain"
    IP_ADDRESS = "ip_address"
    EMAIL = "email"
    USERNAME = "username"
    FILE = "file"
    REPO = "repo"
    POST = "post"
    CODE_SNIPPET = "code_snippet"
    COMMAND_LINE = "command_line"
    BREACH = "breach"
    HASH = "hash"
    URL = "url"
    AWS_ARN = "aws_arn"  # ← NEW


class ObservationType(str, Enum):
    DISK_ARTIFACT = "disk_artifact"
    MEMORY_ARTIFACT = "memory_artifact"
    LOG_ARTIFACT = "log_artifact"
    OSINT_POST = "osint_post"
    OSINT_DNS = "osint_dns"              
    OSINT_REPUTATION = "osint_reputation"
    OSINT_EXPOSURE = "osint_exposure"    
    OSINT_GEO = "osint_geo"              
    OSINT_HISTORICAL = "osint_historical"
    OSINT_REGISTRATION = "osint_registration"
    OSINT_BREACH = "osint_breach"
    OSINT_CODE = "osint_code"


class Evidence(BaseModel):
    evidence_id: str = Field(
        ..., description="Globally unique ID (e.g., 'disk_file::a1b2c3')"
    )
    entity_type: EntityType = Field(..., description="Type of entity for correlation")
    entity_value: str = Field(..., description="Normalized value")
    observation_type: ObservationType = Field(..., description="Source category")
    source: str = Field(..., description="Tool or platform")
    metadata: Dict[str, Any] = Field(
        default_factory=dict, description="Structured context"
    )
    credibility_score: int = Field(ge=0, le=100, description="Trust score (0-100)")
    sha256_hash: Optional[str] = Field(
        None, pattern=r"^[a-fA-F0-9]{64}$", description="SHA-256 hash"
    )

    @field_validator("entity_value")
    @classmethod
    def validate_entity_value(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("entity_value must not be empty")
        return v.strip()

    @field_validator("evidence_id")
    @classmethod
    def validate_evidence_id(cls, v: str) -> str:
        if not v or "::" not in v:
            raise ValueError("evidence_id must be in format 'source::unique_key'")
        return v

    class Config:
        frozen = True
        json_encoders = {
            EntityType: lambda v: v.value,
            ObservationType: lambda v: v.value,
        }
