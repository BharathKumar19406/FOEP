# src/foep/correlate/linker.py

import logging
import re
from typing import List, Dict, Set, Tuple, Generator
from collections import defaultdict

from foep.normalize.schema import Evidence, EntityType

logger = logging.getLogger(__name__)


class EntityLinker:
    """
    Links related entities across evidence items to enable graph correlation.

    Uses rule-based and heuristic matching to resolve identities and relationships.
    """

    def __init__(self):
        # Precompile patterns
        self.email_username_pattern = re.compile(r"^([a-zA-Z0-9._-]+)@")
        self.github_url_pattern = re.compile(r"github\.com/([a-zA-Z0-9_-]+)")
        self.domain_pattern = re.compile(r"@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})")

    def link_entities(self, evidence_list: List[Evidence]) -> List[Evidence]:
        """
        Link related entities and return enriched evidence with linkage metadata.

        Args:
            evidence_list: List of Evidence objects (including extracted entities)

        Returns:
            List of Evidence objects with linkage metadata added.
        """
        if not evidence_list:
            return []

        # Index evidence by entity type and value
        entity_index = self._build_entity_index(evidence_list)

        # Build linkage groups
        linkage_groups = self._build_linkage_groups(entity_index)

        # Enrich evidence with linkage info
        enriched_evidence = []
        for evidence in evidence_list:
            metadata = dict(evidence.metadata)
            group_id = self._find_group_id(evidence, linkage_groups)
            if group_id:
                metadata["linkage_group_id"] = group_id
                metadata["linked_entities"] = list(linkage_groups[group_id])

            # Create new evidence with enriched metadata
            enriched_evidence.append(
                Evidence(
                    evidence_id=evidence.evidence_id,
                    entity_type=evidence.entity_type,
                    entity_value=evidence.entity_value,
                    observation_type=evidence.observation_type,
                    source=evidence.source,
                    metadata=metadata,
                    credibility_score=evidence.credibility_score,
                    sha256_hash=evidence.sha256_hash,
                )
            )

        return enriched_evidence

    def _build_entity_index(
        self, evidence_list: List[Evidence]
    ) -> Dict[EntityType, Dict[str, List[Evidence]]]:
        """Index evidence by entity type and normalized value."""
        index: Dict[EntityType, Dict[str, List[Evidence]]] = defaultdict(
            lambda: defaultdict(list)
        )

        for ev in evidence_list:
            # Normalize value for indexing
            norm_value = self._normalize_for_indexing(ev.entity_type, ev.entity_value)
            if norm_value:
                index[ev.entity_type][norm_value].append(ev)

        return index

    def _normalize_for_indexing(self, entity_type: EntityType, value: str) -> str:
        """Normalize entity value for consistent indexing."""
        if entity_type == EntityType.EMAIL:
            return value.lower()
        elif entity_type in (EntityType.USERNAME, EntityType.DOMAIN, EntityType.IP):
            return value.lower()
        elif entity_type == EntityType.HASH:
            return value.lower()
        else:
            return value

    def _build_linkage_groups(
        self, entity_index: Dict[EntityType, Dict[str, List[Evidence]]]
    ) -> Dict[str, Set[Tuple[EntityType, str]]]:
        """
        Build groups of linked entities using heuristic rules.

        Returns:
            Dict[group_id, set of (entity_type, normalized_value)]
        """
        groups: Dict[str, Set[Tuple[EntityType, str]]] = {}
        group_counter = 0

        # Rule 1: Exact matches within same entity type
        for entity_type, values in entity_index.items():
            for norm_value, evidence_items in values.items():
                if len(evidence_items) > 1:
                    group_id = f"group_{group_counter}"
                    groups[group_id] = {(entity_type, norm_value)}
                    group_counter += 1

        # Rule 2: Email username ↔ standalone username
        email_index = entity_index.get(EntityType.EMAIL, {})
        username_index = entity_index.get(EntityType.USERNAME, {})

        for email_norm, email_evs in email_index.items():
            username_match = self.email_username_pattern.match(email_norm)
            if not username_match:
                continue
            username = username_match.group(1)

            if username in username_index:
                group_id = f"group_{group_counter}"
                groups[group_id] = {
                    (EntityType.EMAIL, email_norm),
                    (EntityType.USERNAME, username),
                }
                group_counter += 1

        # Rule 3: GitHub URL ↔ username
        for entity_type_dict in entity_index.values():
            for ev_list in entity_type_dict.values():
                for ev in ev_list:
                    if (
                        ev.entity_type == EntityType.REPO
                        or ev.entity_type == EntityType.POST
                    ):
                        text = ev.entity_value
                        github_match = self.github_url_pattern.search(text)
                        if github_match:
                            gh_user = github_match.group(1).lower()
                            if gh_user in username_index:
                                group_id = f"group_{group_counter}"
                                groups[group_id] = {
                                    (EntityType.USERNAME, gh_user),
                                    # Link to the evidence that contained the URL
                                    (
                                        ev.entity_type,
                                        self._normalize_for_indexing(
                                            ev.entity_type, ev.entity_value
                                        ),
                                    ),
                                }
                                group_counter += 1

        # Rule 4: Domain from email ↔ standalone domain
        for email_norm, email_evs in email_index.items():
            domain_match = self.domain_pattern.search(email_norm)
            if domain_match:
                domain = domain_match.group(1).lower()
                domain_index = entity_index.get(EntityType.DOMAIN, {})
                if domain in domain_index:
                    group_id = f"group_{group_counter}"
                    groups[group_id] = {
                        (EntityType.EMAIL, email_norm),
                        (EntityType.DOMAIN, domain),
                    }
                    group_counter += 1

        # TODO: Add more rules (e.g., IP + username in same log = session)

        return groups

    def _find_group_id(
        self, evidence: Evidence, linkage_groups: Dict[str, Set[Tuple[EntityType, str]]]
    ) -> str:
        """Find which linkage group this evidence belongs to."""
        norm_value = self._normalize_for_indexing(
            evidence.entity_type, evidence.entity_value
        )
        key = (evidence.entity_type, norm_value)

        for group_id, members in linkage_groups.items():
            if key in members:
                return group_id
        return ""


# --- PUBLIC INTERFACE ---
def link_entities(evidence_list: List[Evidence]) -> List[Evidence]:
    """
    Public API to link related entities across evidence items.

    Args:
        evidence_list: List of Evidence objects

    Returns:
        List of Evidence objects enriched with linkage metadata.
    """
    linker = EntityLinker()
    return linker.link_entities(evidence_list)
