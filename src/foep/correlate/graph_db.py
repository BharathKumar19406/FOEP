# src/foep/correlate/graph_db.py

import logging
import json 
from typing import List, Dict, Any, Optional
from neo4j import GraphDatabase as Neo4jGraphDatabase
from neo4j import Driver, Session, Transaction
from neo4j.exceptions import ServiceUnavailable, AuthError

from foep.normalize.schema import Evidence

logger = logging.getLogger(__name__)


class GraphDatabase:
    """
    Neo4j graph database interface for FOEP evidence correlation.

    Manages nodes (Evidence) and relationships (links, correlations).
    """

    def __init__(self, uri: str, username: str, password: str, database: str = "neo4j"):
        """
        Initialize Neo4j connection.

        Args:
            uri: Neo4j URI (e.g., "bolt://localhost:7687")
            username: Database username
            password: Database password
            database: Database name (default: "neo4j")
        """
        self.uri = uri
        self.username = username
        self.password = password
        self.database = database
        self._driver: Optional[Driver] = None
        self._ensure_connection()

    def _ensure_connection(self):
        """Establish and validate Neo4j connection."""
        if self._driver is None:
            try:
                self._driver = Neo4jGraphDatabase.driver(
                    self.uri,
                    auth=(self.username, self.password),
                    database=self.database,
                    encrypted=False,  # Set to True in production with TLS
                )
                self._driver.verify_connectivity()
                logger.info(f"Connected to Neo4j at {self.uri}")
            except (ServiceUnavailable, AuthError) as e:
                logger.error(f"Failed to connect to Neo4j: {e}")
                raise

    def close(self):
        """Close Neo4j driver connection."""
        if self._driver:
            self._driver.close()
            self._driver = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def _flatten_dict(
        self, d: Dict[str, Any], parent_key: str = "", sep: str = "_"
    ) -> Dict[str, Any]:
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            elif isinstance(v, list):
                try:
                    items.append((new_key, json.dumps(v)))
                except TypeError:
                    items.append((new_key, str(v)))
            else:
                items.append((new_key, v))
        return dict(items)

    def _evidence_to_node_props(self, evidence: Evidence) -> Dict[str, Any]:
        """Convert Evidence object to Neo4j node properties (flattened for compatibility)."""
        props = {
            "evidence_id": evidence.evidence_id,
            "entity_type": evidence.entity_type.value,
            "entity_value": evidence.entity_value,
            "observation_type": evidence.observation_type.value,
            "source": evidence.source,
            "credibility_score": evidence.credibility_score,
            "sha256_hash": evidence.sha256_hash,
            "created_at": self._get_timestamp(),
        }

        # Flatten metadata to avoid nested dicts
        if evidence.metadata:
            flattened_meta = self._flatten_dict(evidence.metadata)
            props.update(flattened_meta)

        return props

    def _get_timestamp(self) -> str:
        """Get ISO 8601 timestamp."""
        from datetime import datetime

        return datetime.utcnow().isoformat() + "Z"

    def ingest_evidence_batch(
        self, evidence_list: List[Evidence], batch_size: int = 1000
    ) -> int:
        """
        Ingest a batch of Evidence objects into Neo4j.

        Uses MERGE to avoid duplicates based on evidence_id.
        Creates indexes for performance.

        Args:
            evidence_list: List of Evidence objects
            batch_size: Number of records per transaction

        Returns:
            Number of evidence items ingested.
        """
        if not evidence_list:
            return 0

        self._ensure_connection()
        self._create_constraints_and_indexes()

        total_ingested = 0
        for i in range(0, len(evidence_list), batch_size):
            batch = evidence_list[i : i + batch_size]
            try:
                with self._driver.session(database=self.database) as session:
                    count = session.execute_write(self._ingest_batch_tx, batch)
                    total_ingested += count
                    logger.debug(f"Ingested batch of {count} evidence items")
            except Exception as e:
                logger.error(f"Failed to ingest batch: {e}")
                raise

        return total_ingested

    def _create_constraints_and_indexes(self):
        """Create constraints and indexes for performance."""
        with self._driver.session(database=self.database) as session:
            # Unique constraint on evidence_id
            session.run(
                "CREATE CONSTRAINT evidence_id_unique IF NOT EXISTS "
                "FOR (e:Evidence) REQUIRE e.evidence_id IS UNIQUE"
            )
            # Indexes for common queries
            session.run(
                "CREATE INDEX evidence_entity_value IF NOT EXISTS "
                "FOR (e:Evidence) ON (e.entity_value)"
            )
            session.run(
                "CREATE INDEX evidence_entity_type IF NOT EXISTS "
                "FOR (e:Evidence) ON (e.entity_type)"
            )
            session.run(
                "CREATE INDEX evidence_credibility IF NOT EXISTS "
                "FOR (e:Evidence) ON (e.credibility_score)"
            )

    def _ingest_batch_tx(self, tx: Transaction, evidence_batch: List[Evidence]) -> int:
        """Transaction function to ingest a batch of evidence."""
        query = """
        UNWIND $evidence_list AS ev
        MERGE (e:Evidence {evidence_id: ev.evidence_id})
        ON CREATE SET 
            e.entity_type = ev.entity_type,
            e.entity_value = ev.entity_value,
            e.observation_type = ev.observation_type,
            e.source = ev.source,
            e.credibility_score = ev.credibility_score,
            e.sha256_hash = ev.sha256_hash,
            e.metadata = ev.metadata,
            e.created_at = ev.created_at
        ON MATCH SET
            e.metadata = ev.metadata,  // Update metadata if changed
            e.credibility_score = ev.credibility_score
        RETURN count(e) AS count
        """
        params = {
            "evidence_list": [self._evidence_to_node_props(ev) for ev in evidence_batch]
        }
        result = tx.run(query, params)
        record = result.single()
        return record["count"] if record else 0

    def create_linkage_relationships(self, evidence_list: List[Evidence]) -> int:
        """
        Create :LINKED_TO relationships between evidence in the same linkage group.

        Args:
            evidence_list: List of Evidence objects (must have linkage metadata)

        Returns:
            Number of relationships created.
        """
        if not evidence_list:
            return 0

        self._ensure_connection()
        total_created = 0

        # Group evidence by linkage_group_id
        groups: Dict[str, List[Evidence]] = {}
        for ev in evidence_list:
            group_id = ev.metadata.get("linkage_group_id")
            if group_id:
                if group_id not in groups:
                    groups[group_id] = []
                groups[group_id].append(ev)

        for group_id, group_evidence in groups.items():
            if len(group_evidence) < 2:
                continue

            try:
                with self._driver.session(database=self.database) as session:
                    count = session.execute_write(
                        self._create_linkage_tx, group_id, group_evidence
                    )
                    total_created += count
            except Exception as e:
                logger.error(f"Failed to create linkages for group {group_id}: {e}")
                continue

        return total_created

    def _create_linkage_tx(
        self, tx: Transaction, group_id: str, evidence_list: List[Evidence]
    ) -> int:
        """Transaction to create all pairwise :LINKED_TO relationships in a group."""
        # Get all evidence_id in this group
        evidence_ids = [ev.evidence_id for ev in evidence_list]
        if len(evidence_ids) < 2:
            return 0

        # Create all pairwise relationships (undirected)
        query = """
        UNWIND $evidence_ids AS id1
        UNWIND $evidence_ids AS id2
        WITH id1, id2 WHERE id1 < id2
        MATCH (e1:Evidence {evidence_id: id1})
        MATCH (e2:Evidence {evidence_id: id2})
        MERGE (e1)-[r:LINKED_TO {group_id: $group_id}]->(e2)
        RETURN count(r) AS count
        """
        params = {"evidence_ids": evidence_ids, "group_id": group_id}
        result = tx.run(query, params)
        record = result.single()
        return record["count"] if record else 0

    def run_correlation_query(
        self, cypher_query: str, params: Optional[Dict] = None
    ) -> List[Dict]:
        """
        Run a custom Cypher query for investigation.

        Args:
            cypher_query: Valid Cypher query string
            params: Query parameters

        Returns:
            List of result records as dictionaries.
        """
        self._ensure_connection()
        try:
            with self._driver.session(database=self.database) as session:
                result = session.run(cypher_query, params or {})
                return [record.data() for record in result]
        except Exception as e:
            logger.error(f"Query failed: {e}")
            raise

    def get_evidence_by_id(self, evidence_id: str) -> Optional[Dict]:
        """Retrieve a single Evidence node by ID."""
        query = "MATCH (e:Evidence {evidence_id: $evidence_id}) RETURN e"
        results = self.run_correlation_query(query, {"evidence_id": evidence_id})
        return results[0] if results else None

    def find_paths_between_entities(
        self, start_value: str, end_value: str, max_depth: int = 5
    ) -> List[Dict]:
        """
        Find paths between two entity values.

        Args:
            start_value: Starting entity_value
            end_value: Ending entity_value
            max_depth: Maximum path length

        Returns:
            List of path records.
        """
        query = """
        MATCH path = shortestPath(
            (start:Evidence {entity_value: $start_value})-[*..$max_depth]-(end:Evidence {entity_value: $end_value})
        )
        WHERE start.evidence_id <> end.evidence_id
        RETURN path, nodes(path) AS nodes, relationships(path) AS rels
        """
        return self.run_correlation_query(
            query,
            {
                "start_value": start_value,
                "end_value": end_value,
                "max_depth": max_depth,
            },
        )
