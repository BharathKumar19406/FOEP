# src/foep/ingest/osint/code_repos.py

import base64
import logging
import re
import time
from typing import Generator, Dict, Any, Optional, List
from urllib.parse import quote

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from foep.normalize.schema import Evidence, EntityType, ObservationType
from foep.credibility.sources import SOURCE_REPUTATION_REGISTRY

logger = logging.getLogger(__name__)


# Sensitive patterns (extend as needed)
SENSITIVE_PATTERNS = {
    "api_key": re.compile(r"api[_-]?key[\"'\s]*[=:][\"'\s]*([A-Za-z0-9_\-]{20,})"),
    "password": re.compile(r"password[\"'\s]*[=:][\"'\s]*([^\"'\s]{8,})"),
    "secret": re.compile(r"secret[\"'\s]*[=:][\"'\s]*([A-Za-z0-9_\-/+]{20,})"),
    "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "private_key": re.compile(r"-----BEGIN.*PRIVATE KEY-----"),
    "internal_ip": re.compile(
        r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\b192\.168\.\d{1,3}\.\d{1,3}\b|\b172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}\b"
    ),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
}


class CodeRepoCollector:
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
        return SOURCE_REPUTATION_REGISTRY.get(source, 70)


# --- GITHUB CODE SEARCH ---
class GitHubCodeCollector(CodeRepoCollector):
    BASE_URL = "https://api.github.com"

    def search_code(
        self, query: str, max_results: int = 30
    ) -> Generator[Evidence, None, None]:
        token = self.config.get("github", {}).get("api_token")
        if not token:
            logger.error("GitHub API token missing")
            return

        token = self.config.get("github", {}).get("api_token")
        if not token:
            logger.error("GitHub API token missing for code search")
            return

        headers = {
            "Accept": "application/vnd.github.v3+json",
            "Authorization": f"token {token}",
            "User-Agent": "FOEP-OSINT/1.0",
        }

        # GitHub requires query to include qualifier (e.g., "filename:.env")
        # We assume caller provides meaningful query
        encoded_query = quote(query)
        url = f"{self.BASE_URL}/search/code?q={encoded_query}&per_page={min(max_results, 100)}"

        try:
            response = self.session.get(url, headers=headers, timeout=15)
            if response.status_code == 422:
                logger.warning(f"GitHub invalid search query: {query}")
                return
            elif response.status_code == 403:
                logger.error("GitHub API rate limit exceeded or token invalid")
                return
            response.raise_for_status()

            results = response.json()
            credibility = self._get_credibility_score("github")

            for item in results.get("items", [])[:max_results]:
                repo_full_name = item["repository"]["full_name"]
                file_path = item["path"]
                html_url = item["html_url"]

                # Fetch file content
                content_url = item["url"]
                try:
                    content_resp = self.session.get(
                        content_url, headers=headers, timeout=10
                    )
                    if content_resp.status_code != 200:
                        continue
                    content_data = content_resp.json()
                    if "content" not in content_data:
                        continue

                    # Decode base64 content
                    try:
                        content = base64.b64decode(content_data["content"]).decode(
                            "utf-8", errors="replace"
                        )
                    except Exception:
                        continue

                    # Scan for sensitive patterns
                    findings = self._scan_content(content)
                    if not findings:
                        continue

                    metadata = {
                        "repository": repo_full_name,
                        "file_path": file_path,
                        "html_url": html_url,
                        "sha": content_data.get("sha"),
                        "size_bytes": content_data.get("size"),
                    }

                    for pattern_name, matches in findings.items():
                        for match in matches[:3]:  # Limit to 3 per pattern
                            snippet = self._get_snippet_around_match(content, match)
                            yield Evidence(
                                evidence_id=f"github_code::{repo_full_name}::{file_path}::{hash(snippet) & 0xFFFFFFFF}",
                                entity_type=EntityType.CODE_SNIPPET,
                                entity_value=snippet,
                                observation_type=ObservationType.OSINT_CODE,
                                source="github",
                                metadata={
                                    **metadata,
                                    "pattern_type": pattern_name,
                                    "matched_value": match,
                                },
                                credibility_score=credibility,
                                sha256_hash=None,
                            )

                    # Also emit repository as entity
                    yield Evidence(
                        evidence_id=f"github_repo_leak::{repo_full_name}",
                        entity_type=EntityType.REPO,
                        entity_value=repo_full_name,
                        observation_type=ObservationType.OSINT_CODE,
                        source="github",
                        metadata={"leak_query": query, "file_path": file_path},
                        credibility_score=credibility,
                        sha256_hash=None,
                    )

                    time.sleep(0.5)  # Be kind to GitHub API

                except Exception as e:
                    logger.debug(f"Error fetching GitHub file content: {e}")
                    continue

        except Exception as e:
            logger.error(f"GitHub code search error: {e}")

    def _scan_content(self, content: str) -> Dict[str, List[str]]:
        findings = {}
        for name, pattern in SENSITIVE_PATTERNS.items():
            matches = pattern.findall(content)
            if matches:
                # Clean matches (avoid false positives)
                cleaned = []
                for m in matches:
                    if isinstance(m, tuple):
                        m = m[0] if m else ""
                    if len(m) > 5 and not m.startswith(("http", "www")):
                        cleaned.append(m)
                if cleaned:
                    findings[name] = cleaned[:5]  # Max 5 per pattern
        return findings

    def _get_snippet_around_match(
        self, content: str, match: str, context_lines: int = 2
    ) -> str:
        lines = content.splitlines()
        for i, line in enumerate(lines):
            if match in line:
                start = max(0, i - context_lines)
                end = min(len(lines), i + context_lines + 1)
                snippet = "\n".join(lines[start:end])
                return snippet[:500]  # Truncate to 500 chars
        return match[:500]


# --- GITLAB PUBLIC CODE SEARCH ---
class GitLabCodeCollector(CodeRepoCollector):
    BASE_URL = "https://gitlab.com/api/v4"

    def search_code(
        self, query: str, max_results: int = 30
    ) -> Generator[Evidence, None, None]:
        if not self.config.get("gitlab", {}).get("enabled", False):
            return

        # GitLab public search does not require auth for public repos
        headers = {"User-Agent": "FOEP-OSINT/1.0"}
        params = {
            "scope": "blobs",
            "search": query,
            "per_page": min(max_results, 100),
        }

        try:
            response = self.session.get(
                f"{self.BASE_URL}/projects", headers=headers, params=params, timeout=15
            )
            if response.status_code != 200:
                return

            projects = response.json()
            credibility = self._get_credibility_score("gitlab")

            for project in projects[:max_results]:
                repo_name = project.get("path_with_namespace")
                web_url = project.get("web_url")

                # GitLab API doesn't return file content in search; skip deep scan
                # Emit as potential lead
                yield Evidence(
                    evidence_id=f"gitlab_code_lead::{repo_name}::{hash(query) & 0xFFFFFFFF}",
                    entity_type=EntityType.REPO,
                    entity_value=repo_name,
                    observation_type=ObservationType.OSINT_CODE,
                    source="gitlab",
                    metadata={
                        "web_url": web_url,
                        "search_query": query,
                        "description": project.get("description", "")[:200],
                    },
                    credibility_score=credibility
                    - 10,  # Lower confidence without content scan
                    sha256_hash=None,
                )

        except Exception as e:
            logger.error(f"GitLab code search error: {e}")


# --- PUBLIC INTERFACE ---
def collect_code_repo_osint(
    query: str,
    config: Dict[str, Any],
    max_results: int = 30,
) -> Generator[Evidence, None, None]:
    """
    Unified interface to scan public code repositories for sensitive data.

    Args:
        query: Search term (e.g., "filename:.env", "password", "internal.company.com")
        config: Loaded from config.yaml
        max_results: Max findings to return

    Yields:
        Evidence objects.
    """
    github_collector = GitHubCodeCollector(config)
    yield from github_collector.search_code(query, max_results)

    gitlab_collector = GitLabCodeCollector(config)
    yield from gitlab_collector.search_code(query, max_results)
