import logging
from typing import Generator, Dict, Any
from urllib.parse import quote

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from foep.normalize.schema import Evidence, EntityType, ObservationType
from foep.credibility.sources import SOURCE_REPUTATION_REGISTRY

logger = logging.getLogger(__name__)


class BreachCollector:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def _get_credibility_score(self, source: str) -> int:
        return SOURCE_REPUTATION_REGISTRY.get(source, 60)


# --- HAVE I BEEN PWNED (HIBP) v3 API ---
class HIBPBreachCollector(BreachCollector):
    BASE_URL = "https://haveibeenpwned.com/api/v3"  # No trailing spaces

    def check_email(self, email: str) -> Generator[Evidence, None, None]:
        if not self.config.get("hibp", {}).get("enabled", False):
            logger.warning("HIBP collection disabled in config")
            return

        hibp_config = self.config.get("hibp", {})
        api_key = hibp_config.get("api_key")
        mock_mode = hibp_config.get("mock_mode", False)

        # ✅ Priority 1: Mock mode (for academic/demo)
        if mock_mode:
            logger.info("[MOCK] Using simulated HIBP data for validation")
            yield from self._check_mock_tier(email)
            return

        # ✅ Priority 2: Real API (requires key)
        if not api_key:
            logger.error("HIBP API key missing and mock_mode=false — skipping breach check")
            return

        # ✅ v3 requires BOTH headers (per docs)
        headers = {
            "hibp-api-key": api_key,
            "User-Agent": "FOEP-OSINT/1.0",  # ✅ Required — missing = 403
        }
        url = f"{self.BASE_URL}/breachedaccount/{quote(email)}"

        try:
            response = self.session.get(url, headers=headers, timeout=10)

            if response.status_code == 404:
                logger.info(f"No breaches found for {email}")
                return
            elif response.status_code == 401:
                logger.error("HIBP: Invalid or missing API key (401)")
                return
            elif response.status_code == 403:
                logger.error("HIBP: Missing or invalid User-Agent header (403)")
                return
            elif response.status_code == 429:
                logger.warning("HIBP: Rate limit exceeded (429)")
                return
            response.raise_for_status()

            # ✅ Returns [{"Name":"Adobe"}, ...]
            breach_names = [b.get("Name", "Unknown") for b in response.json()]
            credibility = self._get_credibility_score("hibp")

            for name in breach_names:
                yield Evidence(
                    evidence_id=f"hibp_breach::{email}::{name}",
                    entity_type=EntityType.EMAIL,
                    entity_value=email,
                    observation_type=ObservationType.OSINT_BREACH,
                    source="hibp",
                    metadata={"breach_name": name},
                    credibility_score=credibility,
                    sha256_hash=None,
                )

        except requests.RequestException as e:
            logger.error(f"HIBP API error for {email}: {e}")
        except Exception as e:
            logger.error(f"Unexpected HIBP error: {e}")

    def _check_mock_tier(self, email: str) -> Generator[Evidence, None, None]:
        """Mock data for academic validation (matches HIBP test emails)."""
        # ✅ Official HIBP test cases (from docs)
        MOCK_DATA = {
            "account-exists@hibp-integration-tests.com": ["Adobe"],
            "multiple-breaches@hibp-integration-tests.com": ["Adobe", "Gawker", "Stratfor"],
            "unverified-breach@hibp-integration-tests.com": ["UnverifiedBreach"],
        }

        breaches = MOCK_DATA.get(email, [])
        for name in breaches:
            yield Evidence(
                evidence_id=f"hibp_mock::{email}::{name}",
                entity_type=EntityType.EMAIL,
                entity_value=email,
                observation_type=ObservationType.OSINT_BREACH,
                source="hibp",
                metadata={"breach_name": name, "mode": "mock"},
                credibility_score=60,
                sha256_hash=None,
            )
        if not breaches:
            logger.info(f"[MOCK] No simulated breaches for {email}")


# --- PUBLIC INTERFACE ---
def collect_breach_osint(
    query: str,
    query_type: str,
    config: Dict[str, Any],
    max_results: int = 10,
) -> Generator[Evidence, None, None]:
    if query_type == "email":
        collector = HIBPBreachCollector(config)
        yield from collector.check_email(query)
