# src/foep/report/redactor.py

import logging
import re
from typing import Dict, Any, List, Optional, Set
from copy import deepcopy

logger = logging.getLogger(__name__)


class Redactor:
    """
    Redacts PII and sensitive data from evidence and reports.

    Uses layered approach: allowlists, blocklists, regex, and NLP.
    """

    def __init__(
        self,
        redact_emails: bool = True,
        redact_ips: bool = True,
        redact_names: bool = True,
        redact_usernames: bool = False,  # Often needed for attribution
        preserve_internal_ips: bool = True,
        allowlist_domains: Optional[List[str]] = None,
        blocklist_domains: Optional[List[str]] = None,
        custom_patterns: Optional[Dict[str, str]] = None,
    ):
        """
        Initialize redactor with configurable rules.

        Args:
            redact_emails: Redact email addresses
            redact_ips: Redact IP addresses
            redact_names: Redact personal names (via NLP)
            redact_usernames: Redact usernames (default: False for attribution)
            preserve_internal_ips: Keep RFC1918 and loopback IPs
            allowlist_domains: Domains to never redact (e.g., company.com)
            blocklist_domains: Domains to always redact (e.g., gmail.com)
            custom_patterns: Additional regex patterns {name: pattern}
        """
        self.redact_emails = redact_emails
        self.redact_ips = redact_ips
        self.redact_names = redact_names
        self.redact_usernames = redact_usernames
        self.preserve_internal_ips = preserve_internal_ips
        self.allowlist_domains = set(dom.lower() for dom in (allowlist_domains or []))
        self.blocklist_domains = set(dom.lower() for dom in (blocklist_domains or []))

        # Compile regex patterns
        self.patterns = {
            "email": re.compile(
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", re.IGNORECASE
            ),
            "ip": re.compile(
                r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
            ),
            "username": re.compile(
                r"\b[A-Za-z0-9](?:[A-Za-z0-9._-]{0,30}[A-Za-z0-9])?\b"
            ),
        }
        if custom_patterns:
            for name, pattern in custom_patterns.items():
                self.patterns[name] = re.compile(pattern, re.IGNORECASE)

        # Initialize NLP if needed
        self._nlp = None
        if self.redact_names:
            try:
                import spacy

                # Load small English model (install with: python -m spacy download en_core_web_sm)
                self._nlp = spacy.load("en_core_web_sm", disable=["parser", "tagger"])
            except OSError:
                logger.warning(
                    "spaCy model 'en_core_web_sm' not found. Name redaction disabled."
                )
                self.redact_names = False
            except ImportError:
                logger.warning("spaCy not installed. Name redaction disabled.")
                self.redact_names = False

    def redact_evidence(self, evidence: "Evidence") -> "Evidence":
        """
        Redact PII from an Evidence object.

        Only redacts entity_value and metadata values, preserving structure.
        """
        from foep.normalize.schema import Evidence  # Late import to avoid circularity

        # Redact entity_value
        redacted_value = self._redact_text(evidence.entity_value)

        # Redact metadata (deep copy to avoid mutation)
        redacted_metadata = self._redact_dict(evidence.metadata)

        # Create new evidence with redacted content
        return Evidence(
            evidence_id=evidence.evidence_id,
            entity_type=evidence.entity_type,
            entity_value=redacted_value,
            observation_type=evidence.observation_type,
            source=evidence.source,
            metadata=redacted_metadata,
            credibility_score=evidence.credibility_score,
            sha256_hash=evidence.sha256_hash,
        )

    def redact_text(self, text: str) -> str:
        """Redact PII from plain text."""
        return self._redact_text(text)

    def _redact_text(self, text: str) -> str:
        """Internal method to redact text with all rules."""
        if not isinstance(text, str):
            return text

        result = text

        # Redact emails
        if self.redact_emails:

            def email_repl(match):
                email = match.group()
                domain = email.split("@")[-1].lower()
                if domain in self.allowlist_domains:
                    return email  # Do not redact
                if domain in self.blocklist_domains or not self._is_internal_domain(
                    domain
                ):
                    return self._redact_value(email, "EMAIL")
                return email

            result = self.patterns["email"].sub(email_repl, result)

        # Redact IPs
        if self.redact_ips:

            def ip_repl(match):
                ip = match.group()
                if self.preserve_internal_ips and self._is_internal_ip(ip):
                    return ip  # Keep internal IPs
                return self._redact_value(ip, "IP")

            result = self.patterns["ip"].sub(ip_repl, result)

        # Redact names (NLP)
        if self.redact_names and self._nlp:
            doc = self._nlp(result)
            for ent in reversed(doc.ents):  # Reverse to preserve indices
                if ent.label_ in {"PERSON", "ORG"}:
                    # Avoid redacting known entities (e.g., company names)
                    if ent.label_ == "ORG" and self._is_known_org(ent.text):
                        continue
                    result = (
                        result[: ent.start_char]
                        + self._redact_value(ent.text, ent.label_)
                        + result[ent.end_char :]
                    )

        # Redact usernames (if enabled)
        if self.redact_usernames:
            # Only redact if not in allowlist or looks like a real username
            result = self.patterns["username"].sub(
                lambda m: (
                    self._redact_value(m.group(), "USERNAME")
                    if self._looks_like_username(m.group())
                    else m.group()
                ),
                result,
            )

        return result

    def _redact_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively redact values in a dictionary."""
        if not isinstance(data, dict):
            return data

        redacted = {}
        for key, value in data.items():
            if isinstance(value, str):
                redacted[key] = self._redact_text(value)
            elif isinstance(value, dict):
                redacted[key] = self._redact_dict(value)
            elif isinstance(value, list):
                redacted[key] = [
                    self._redact_text(item) if isinstance(item, str) else item
                    for item in value
                ]
            else:
                redacted[key] = value
        return redacted

    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP is internal (RFC1918 or loopback)."""
        try:
            import ipaddress

            addr = ipaddress.ip_address(ip)
            return (
                addr.is_private
                or addr.is_loopback
                or addr.is_link_local
                or str(addr).startswith("169.254.")  # Link-local
            )
        except ValueError:
            return False

    def _is_internal_domain(self, domain: str) -> bool:
        """Check if domain is internal (heuristic)."""
        internal_tlds = {".local", ".internal", ".lan", ".corp", ".home"}
        return any(domain.endswith(tld) for tld in internal_tlds)

    def _is_known_org(self, org_name: str) -> bool:
        """Check if organization is known (e.g., should not be redacted)."""
        known_orgs = {"microsoft", "google", "amazon", "facebook", "twitter", "github"}
        return org_name.lower().replace(" ", "") in known_orgs

    def _looks_like_username(self, text: str) -> bool:
        """Heuristic to avoid redacting non-usernames."""
        if len(text) < 3 or len(text) > 30:
            return False
        if text.isdigit():  # Pure numbers unlikely to be usernames
            return False
        if " " in text:  # Usernames typically don't have spaces
            return False
        return True

    def _redact_value(self, original: str, category: str) -> str:
        """Apply redaction pattern."""
        # Use consistent redaction markers for legal review
        if category == "EMAIL":
            return "[REDACTED_EMAIL]"
        elif category == "IP":
            return "[REDACTED_IP]"
        elif category == "USERNAME":
            return "[REDACTED_USERNAME]"
        elif category == "PERSON":
            return "[REDACTED_NAME]"
        elif category == "ORG":
            return "[REDACTED_ORG]"
        else:
            return "[REDACTED]"
