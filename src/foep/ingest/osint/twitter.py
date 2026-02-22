# src/foep/ingest/osint/twitter.py
import logging
import requests
from requests_oauthlib import OAuth1
from typing import Generator, Dict, Any
from foep.normalize.schema import Evidence, EntityType, ObservationType

logger = logging.getLogger(__name__)

def collect_user(self, username: str) -> Generator[Evidence, None, None]:
    if not self.config.get("twitter", {}).get("enabled", False):
        logger.warning("Twitter collection disabled in config")
        return

    bearer_token = self.config.get("twitter", {}).get("bearer_token")
    if not bearer_token:
        logger.error("Twitter bearer token missing")
        return

    # Extract raw string from SecretStr
    token_value = (
        bearer_token.get_secret_value()
        if hasattr(bearer_token, 'get_secret_value')
        else bearer_token
    )

    headers = {"Authorization": f"Bearer {token_value}"}
    url = f"{self.BASE_URL}/users/by/username/{username}"
    params = {"user.fields": "name,description,location,public_metrics,created_at,verified,profile_image_url"}

    try:
        response = self.session.get(url, headers=headers, params=params, timeout=10)
        
        if response.status_code == 404:
            logger.info(f"Twitter user not found: {username}")
            return  # ✅ Return empty generator (not None!)
        elif response.status_code == 403:
            logger.warning(f"Twitter user {username} is private or suspended")
            return  # ✅ Return empty generator
        response.raise_for_status()
        user_data = response.json().get("data", {})

        credibility = self._get_credibility_score("twitter")

        metadata = {
            "display_name": user_data.get("name"),
            "bio": user_data.get("description"),
            "location": user_data.get("location"),
            "followers": user_data.get("public_metrics", {}).get("followers_count", 0),
            "following": user_data.get("public_metrics", {}).get("following_count", 0),
            "tweets": user_data.get("public_metrics", {}).get("tweet_count", 0),
            "created_at": user_data.get("created_at"),
            "verified": user_data.get("verified", False),
            "profile_image_url": user_data.get("profile_image_url")
        }

        yield Evidence(
            evidence_id=f"twitter_user::{username}",
            entity_type=EntityType.USERNAME,
            entity_value=username,
            observation_type=ObservationType.OSINT_POST,
            source="twitter",
            metadata=metadata,
            credibility_score=credibility,
            sha256_hash=None,
        )

    except requests.RequestException as e:
        logger.error(f"Twitter API error for user {username}: {e}")
    except Exception as e:
        logger.error(f"Unexpected error in Twitter collection: {e}")
