# src/foep/ingest/osint/social.py

import logging
from bs4 import BeautifulSoup
import re
import time
import json 
from typing import Generator, Dict, Any, Optional
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from requests_oauthlib import OAuth1 
from foep.normalize.schema import Evidence, EntityType, ObservationType
from foep.credibility.sources import SOURCE_REPUTATION_REGISTRY

logger = logging.getLogger(__name__)


class OSINTCollector:
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
        return SOURCE_REPUTATION_REGISTRY.get(source, 50)


# --- GITHUB ---
class GitHubCollector(OSINTCollector):
    BASE_URL = "https://api.github.com"

    def collect_user(self, username: str) -> Generator[Evidence, None, None]:
        if not self.config.get("github", {}).get("enabled", False):
            logger.warning("GitHub collection disabled in config")
            return

        token = self.config.get("github", {}).get("api_token")
        headers = {"Accept": "application/vnd.github.v3+json"}
        if token:
            # Handle SecretStr from Pydantic config
            actual_token = (
                token.get_secret_value()
                if hasattr(token, "get_secret_value")
                else token
            )
            if actual_token.startswith("github_pat_"):
                headers["Authorization"] = f"Bearer {actual_token}"
            else:
                headers["Authorization"] = f"token {actual_token}"

        url = f"{self.BASE_URL}/users/{username}"
        try:
            response = self.session.get(url, headers=headers, timeout=10)
            if response.status_code == 404:
                logger.info(f"GitHub user not found: {username}")
                return
            response.raise_for_status()
            user_data = response.json()

            credibility = self._get_credibility_score("github")

            # User profile
            metadata = {
                "name": user_data.get("name"),
                "bio": user_data.get("bio"),
                "location": user_data.get("location"),
                "public_repos": user_data.get("public_repos"),
                "followers": user_data.get("followers"),
                "profile_url": user_data.get("html_url"),
            }

            yield Evidence(
                evidence_id=f"github_user::{username}",
                entity_type=EntityType.USERNAME,
                entity_value=username,
                observation_type=ObservationType.OSINT_POST,
                source="github",
                metadata=metadata,
                credibility_score=credibility,
                sha256_hash=None,
            )

            # Email (if public)
            email = user_data.get("email")
            if email:
                yield Evidence(
                    evidence_id=f"github_email::{email}",
                    entity_type=EntityType.EMAIL,
                    entity_value=email,
                    observation_type=ObservationType.OSINT_POST,
                    source="github",
                    metadata={"username": username},
                    credibility_score=credibility,
                    sha256_hash=None,
                )

            # Repositories
            repos_url = user_data.get("repos_url")
            if repos_url:
                repos_response = self.session.get(
                    repos_url, headers=headers, timeout=10
                )
                repos_response.raise_for_status()
                repos = repos_response.json()
                for repo in repos[:20]:  # Limit to 20 repos
                    repo_metadata = {
                        "name": repo.get("name"),
                        "description": repo.get("description"),
                        "url": repo.get("html_url"),
                        "language": repo.get("language"),
                        "created_at": repo.get("created_at"),
                    }
                    yield Evidence(
                        evidence_id=f"github_repo::{repo.get('full_name')}",
                        entity_type=EntityType.REPO,
                        entity_value=repo.get("full_name"),
                        observation_type=ObservationType.OSINT_POST,
                        source="github",
                        metadata=repo_metadata,
                        credibility_score=credibility,
                        sha256_hash=None,
                    )

        except requests.RequestException as e:
            logger.error(f"GitHub API error for user {username}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error in GitHub collection: {e}")

    def collect_search(
        self, query: str, max_results: int = 10
    ) -> Generator[Evidence, None, None]:
        if not self.config.get("github", {}).get("enabled", False):
            return

        token = self.config.get("github", {}).get("api_token")
        headers = {"Accept": "application/vnd.github.v3+json"}
        if token:
            # Handle SecretStr from Pydantic config
            actual_token = (
                token.get_secret_value()
                if hasattr(token, "get_secret_value")
                else token
            )
            if actual_token.startswith("github_pat_"):
                headers["Authorization"] = f"Bearer {actual_token}"
            else:
                headers["Authorization"] = f"token {actual_token}"

        url = f"{self.BASE_URL}/search/users"
        params = {"q": query, "per_page": min(max_results, 100)}
        try:
            response = self.session.get(url, headers=headers, params=params, timeout=10)
            response.raise_for_status()
            results = response.json()
            for item in results.get("items", [])[:max_results]:
                username = item.get("login")
                if username:
                    yield from self.collect_user(username)
                    time.sleep(0.1)  # Rate limit courtesy
        except Exception as e:
            logger.error(f"GitHub search error: {e}")


# --- TWITTER/X ---

class TwitterCollector(OSINTCollector):
    BASE_URL = "https://api.twitter.com/2"  # ← v2 API (Essential Access)

    def collect_user(self, username: str) -> Generator[Evidence, None, None]:
        twitter_config = self.config.get("twitter", {})
        if not twitter_config.get("enabled", False):
            logger.warning("Twitter collection disabled in config")
            return

        # ✅ Use Bearer Token (v2 only needs this)
        bearer_token = twitter_config.get("bearer_token")
        if not bearer_token:
            logger.error("Twitter bearer_token missing in config")
            return

        # ✅ Extract raw string from SecretStr
        token_value = bearer_token.get_secret_value() if hasattr(bearer_token, 'get_secret_value') else bearer_token

        headers = {"Authorization": f"Bearer {token_value}"}
        url = f"{self.BASE_URL}/users/by/username/{username}"
        params = {"user.fields": "name,description,location,public_metrics,verified,created_at,profile_image_url"}

        try:
            response = self.session.get(url, headers=headers, params=params, timeout=10)
            
            if response.status_code == 404:
                logger.warning(f"Twitter user not found: {username}")
                return
            elif response.status_code == 403:
                logger.error(f"Twitter API 403: Likely missing Essential Access approval")
                return
            response.raise_for_status()
            
            data = response.json()
            user = data.get("data", {})
            
            # ✅ Emit user evidence
            yield Evidence(
                evidence_id=f"twitter_user::{username}",
                entity_type=EntityType.USERNAME,
                entity_value=username,
                observation_type=ObservationType.OSINT_POST,
                source="twitter",
                metadata={
                    "display_name": user.get("name"),
                    "bio": user.get("description"),
                    "location": user.get("location"),
                    "followers": user.get("public_metrics", {}).get("followers_count", 0),
                    "following": user.get("public_metrics", {}).get("following_count", 0),
                    "tweets": user.get("public_metrics", {}).get("tweet_count", 0),
                    "verified": user.get("verified", False),
                    "created_at": user.get("created_at"),
                    "profile_image_url": user.get("profile_image_url")
                },
                credibility_score=75,
                sha256_hash=None
            )

        except requests.RequestException as e:
            logger.error(f"Twitter API error for {username}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error: {e}")

    def collect_tweets(self, username: str, max_tweets: int = 10) -> Generator[Evidence, None, None]:
        return 

# --- LINKEDIN (Public Profiles Only) ---

class LinkedInCollector(OSINTCollector):
    """
    Collects public LinkedIn profile data ethically.
    Uses direct HTML parsing (no login, no scraping of private data).
    Works for publicly visible profiles only.
    """
    
    def collect_profile(self, username: str) -> Generator[Evidence, None, None]:
        if not self.config.get("linkedin", {}).get("enabled", False):
            logger.warning("LinkedIn collection disabled in config")
            return

        # ✅ Try direct public profile fetch (most reliable method)
        html = self._fetch_direct_profile(username)
        if html:
            yield from self._parse_profile(html, username)
            return

        # Fallback: Google Cache (if direct fails)
        html = self._fetch_google_cache(username)
        if html:
            yield from self._parse_profile(html, username)

    def _fetch_direct_profile(self, username: str) -> Optional[str]:
        """Fetch LinkedIn profile with browser-like headers."""
        url = f"https://www.linkedin.com/in/{username}"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
        }

        try:
            response = self.session.get(url, headers=headers, timeout=15)
            # ✅ Verify it's a real profile (not login/404)
            if (
                response.status_code == 200
                and "profile" in response.text.lower()
                and "linkedin.com" in response.url
                and "top-card" in response.text
            ):
                return response.text
            logger.debug(f"Direct fetch failed for {username}: {response.status_code}")
        except Exception as e:
            logger.debug(f"Direct fetch error for {username}: {e}")
        return None

    def _fetch_google_cache(self, username: str) -> Optional[str]:
        """Fallback: Google Cache."""
        url = f"https://webcache.googleusercontent.com/search?q=cache:linkedin.com/in/{username}&strip=1"
        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
        }

        try:
            response = self.session.get(url, headers=headers, timeout=10)
            if response.status_code == 200 and "linkedin.com" in response.text:
                return response.text
        except Exception as e:
            logger.debug(f"Cache fetch failed: {e}")
        return None

    def _parse_profile(self, html: str, username: str) -> Generator[Evidence, None, None]:
        """Parse LinkedIn HTML robustly."""
        try:
            # ✅ Method 1: Extract from embedded JSON (most reliable)
            # Look for window.__INITIAL_STATE__ or similar
            json_match = re.search(r'({"profile":.*?})\s*</script>', html)
            if json_match:
                try:
                    data = json.loads(json_match.group(1))
                    profile = data.get("profile", {})
                    
                    first_name = profile.get("firstName", "")
                    last_name = profile.get("lastName", "")
                    headline = profile.get("headline", "")
                    location = profile.get("geoLocation", {}).get("geo", {}).get("displayName", "")
                    
                    name = f"{first_name} {last_name}".strip()
                    if not name:
                        name = username.replace("-", " ").title()

                    # Extract summary
                    summary = ""
                    try:
                        # Try to find summary in data
                        summary = data.get("summary", "")
                    except:
                        pass

                    metadata = {
                        "display_name": name,
                        "headline": headline,
                        "location": location,
                        "summary": summary[:300] if summary else "",
                        "source_method": "json_data"
                    }
                    metadata = {k: v for k, v in metadata.items() if v}

                    if name or headline:
                        yield Evidence(
                            evidence_id=f"linkedin_profile::{username}",
                            entity_type=EntityType.USERNAME,
                            entity_value=username,
                            observation_type=ObservationType.OSINT_POST,
                            source="linkedin",
                            metadata=metadata,
                            credibility_score=80,
                            sha256_hash=None
                        )
                        return
                except:
                    pass

            # ✅ Method 2: Extract from HTML title/meta
            # Title format: "Name - Headline | LinkedIn"
            title_match = re.search(r'<title>([^<]+)</title>', html)
            title = title_match.group(1) if title_match else ""
            
            if " - " in title and " | LinkedIn" in title:
                parts = title.replace(" | LinkedIn", "").split(" - ", 1)
                name = parts[0].strip()
                headline = parts[1].strip() if len(parts) > 1 else ""
            else:
                name = title.replace(" | LinkedIn", "").strip()
                headline = ""

            # Meta description
            desc_match = re.search(r'<meta name="description" content="([^"]*)"', html)
            description = desc_match.group(1) if desc_match else ""

            # Clean up Google Search titles
            if name.lower() in ["google search", "linkedin", ""]:
                return

            metadata = {
                "display_name": name,
                "headline": headline,
                "description": description[:300] if description else "",
                "source_method": "html_meta"
            }
            metadata = {k: v for k, v in metadata.items() if v}

            if name or headline:
                yield Evidence(
                    evidence_id=f"linkedin_profile::{username}",
                    entity_type=EntityType.USERNAME,
                    entity_value=username,
                    observation_type=ObservationType.OSINT_POST,
                    source="linkedin",
                    metadata=metadata,
                    credibility_score=70,
                    sha256_hash=None
                )

                # ✅ Extract emails from description
                emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", description)
                for email in set(emails):
                    if not email.endswith("linkedin.com"):
                        yield Evidence(
                            evidence_id=f"linkedin_email::{email}",
                            entity_type=EntityType.EMAIL,
                            entity_value=email,
                            observation_type=ObservationType.OSINT_POST,
                            source="linkedin",
                            metadata={"linkedin_user": username},
                            credibility_score=75,
                            sha256_hash=None
                        )

        except Exception as e:
            logger.warning(f"LinkedIn parsing failed for {username}: {e}")

# --- PUBLIC INTERFACE ---
def collect_social_osint(
    platform: str,
    identifier: str,
    config: Dict[str, Any],
    max_results: int = 10,
) -> Generator[Evidence, None, None]:
    """
    Unified interface to collect OSINT from social platforms.

    Args:
        platform: "github", "twitter", or "linkedin"
        identifier: username or search query
        config: Loaded from config.yaml
        max_results: Max items to return

    Yields:
        Evidence objects.
    """
    if platform == "github":
        collector = GitHubCollector(config)
        if "@" in identifier or " " in identifier:
            yield from collector.collect_search(identifier, max_results)
        else:
            yield from collector.collect_user(identifier)
    elif platform == "twitter":
        collector = TwitterCollector(config)
        yield from collector.collect_user(identifier)
        yield from collector.collect_tweets(identifier, max_results)
    elif platform == "linkedin":
        collector = LinkedInCollector(config)
        yield from collector.collect_profile(identifier)
    elif platform == "domain":
        # Basic DNS lookup
        import socket
        try:
            ip = socket.gethostbyname(identifier)
            yield Evidence(
                evidence_id=f"domain::{identifier}",
                entity_type=EntityType.DOMAIN,
                entity_value=identifier,
                observation_type=ObservationType.OSINT_POST,
                source="dns",
                metadata={"ip": ip},
                credibility_score=70,
                sha256_hash=None
            )
        except:
            pass
    else:
        logger.warning(f"Unsupported social platform: {platform}")
