# src/foep/credibility/scorer.py

import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from collections import defaultdict

from foep.normalize.schema import Evidence
from foep.credibility.sources import get_source_credibility

logger = logging.getLogger(__name__)


class CredibilityScorer:
    """
    Dynamically scores evidence based on corroboration, context, and source reliability.

    Uses evidence linkage and metadata to adjust initial credibility scores.
    """

    def __init__(
        self,
        max_corroboration_bonus: int = 20,
        age_penalty_per_day: int = 2,
        max_age_penalty: int = 30,
        conflict_penalty: int = 15,
        min_credibility: int = 10,
    ):
        """
        Initialize scorer with configurable parameters.

        Args:
            max_corroboration_bonus: Max points for multi-source corroboration
            age_penalty_per_day: Points deducted per day old (for time-sensitive data)
            max_age_penalty: Maximum age penalty
            conflict_penalty: Points deducted for conflicting evidence
            min_credibility: Floor for final score
        """
        self.max_corroboration_bonus = max_corroboration_bonus
        self.age_penalty_per_day = age_penalty_per_day
        self.max_age_penalty = max_age_penalty
        self.conflict_penalty = conflict_penalty
        self.min_credibility = min_credibility

    def score_evidence_batch(self, evidence_list: List[Evidence]) -> List[Evidence]:
        """
        Score a batch of Evidence objects based on corroboration and context.

        Args:
            evidence_list: List of Evidence objects (should include linkage metadata)

        Returns:
            List of Evidence objects with updated credibility_score.
        """
        if not evidence_list:
            return []

        # Group by entity value and type for corroboration analysis
        entity_groups = self._group_by_entity(evidence_list)

        # Build source conflict map
        conflict_map = self._detect_conflicts(entity_groups)

        # Score each evidence item
        scored_evidence = []
        for evidence in evidence_list:
            new_score = self._compute_score(evidence, entity_groups, conflict_map)

            # Create new evidence with updated score and scoring metadata
            metadata = dict(evidence.metadata)
            metadata["original_credibility_score"] = evidence.credibility_score
            metadata["credibility_adjustments"] = {
                "corroboration_bonus": (
                    new_score - evidence.credibility_score
                    if new_score > evidence.credibility_score
                    else 0
                ),
                "age_penalty": (
                    evidence.credibility_score - new_score
                    if new_score < evidence.credibility_score
                    and self._has_timestamp(evidence)
                    else 0
                ),
                "conflict_penalty": (
                    self.conflict_penalty
                    if conflict_map.get(evidence.evidence_id)
                    else 0
                ),
            }

            scored_evidence.append(
                Evidence(
                    evidence_id=evidence.evidence_id,
                    entity_type=evidence.entity_type,
                    entity_value=evidence.entity_value,
                    observation_type=evidence.observation_type,
                    source=evidence.source,
                    metadata=metadata,
                    credibility_score=new_score,
                    sha256_hash=evidence.sha256_hash,
                )
            )

        return scored_evidence

    def _group_by_entity(
        self, evidence_list: List[Evidence]
    ) -> Dict[tuple, List[Evidence]]:
        """Group evidence by (entity_type, entity_value) for corroboration."""
        groups = defaultdict(list)
        for ev in evidence_list:
            key = (ev.entity_type, ev.entity_value.lower())
            groups[key].append(ev)
        return groups

    def _detect_conflicts(
        self, entity_groups: Dict[tuple, List[Evidence]]
    ) -> Dict[str, bool]:
        """
        Detect conflicting evidence (e.g., same IP marked as internal and external).

        Returns:
            Dict[evidence_id, is_conflicted]
        """
        conflicts = {}
        for key, evidence_group in entity_groups.items():
            if len(evidence_group) < 2:
                continue

            # Check for credibility score divergence > threshold
            scores = [ev.credibility_score for ev in evidence_group]
            if max(scores) - min(scores) > 40:  # Significant divergence
                for ev in evidence_group:
                    conflicts[ev.evidence_id] = True

            # Check for source-type conflicts (e.g., forensic vs OSINT with low OSINT score)
            sources = [ev.source for ev in evidence_group]
            has_forensic = any(
                src in {"disk_image", "volatility3", "log_parser"} for src in sources
            )
            has_low_osint = any(
                src not in {"disk_image", "volatility3", "log_parser"}
                and get_source_credibility(src) < 50
                for src in sources
            )
            if has_forensic and has_low_osint:
                for ev in evidence_group:
                    if ev.source not in {"disk_image", "volatility3", "log_parser"}:
                        conflicts[ev.evidence_id] = True

        return conflicts

    def _compute_score(
        self,
        evidence: Evidence,
        entity_groups: Dict[tuple, List[Evidence]],
        conflict_map: Dict[str, bool],
    ) -> int:
        """Compute final credibility score for an evidence item."""
        base_score = evidence.credibility_score
        adjustments = 0

        # Corroboration bonus
        key = (evidence.entity_type, evidence.entity_value.lower())
        group = entity_groups.get(key, [])
        if len(group) > 1:
            # Bonus scales with number of independent sources
            unique_sources = len(set(ev.source for ev in group))
            bonus = min(
                self.max_corroboration_bonus,
                (unique_sources - 1) * 5,  # 5 points per additional source
            )
            adjustments += bonus

        # Age penalty (for time-sensitive data)
        if self._has_timestamp(evidence):
            age_days = self._get_age_in_days(evidence)
            if age_days is not None:
                penalty = min(self.max_age_penalty, age_days * self.age_penalty_per_day)
                adjustments -= penalty

        # Conflict penalty
        if conflict_map.get(evidence.evidence_id):
            adjustments -= self.conflict_penalty

        final_score = max(self.min_credibility, base_score + adjustments)
        return min(100, final_score)  # Cap at 100

    def _has_timestamp(self, evidence: Evidence) -> bool:
        """Check if evidence has a timestamp in metadata."""
        ts_fields = {
            "timestamp",
            "created_time",
            "modified_time",
            "breach_date",
            "created_at",
        }
        return any(field in evidence.metadata for field in ts_fields)

    def _get_age_in_days(self, evidence: Evidence) -> Optional[int]:
        """Calculate age in days from evidence timestamp."""
        ts_fields = [
            "timestamp",
            "created_time",
            "modified_time",
            "breach_date",
            "created_at",
        ]

        for field in ts_fields:
            if field in evidence.metadata:
                ts_val = evidence.metadata[field]
                if not ts_val:
                    continue

                try:
                    if isinstance(ts_val, str):
                        # Handle ISO 8601 and common formats
                        if "T" in ts_val:
                            dt = datetime.fromisoformat(ts_val.replace("Z", "+00:00"))
                        else:
                            # Try common date formats
                            from dateutil import parser

                            dt = parser.parse(ts_val)
                    elif isinstance(ts_val, (int, float)):
                        # Assume Unix timestamp
                        dt = datetime.utcfromtimestamp(ts_val)
                    else:
                        continue

                    age = datetime.utcnow() - dt
                    return age.days
                except Exception:
                    continue

        return None
