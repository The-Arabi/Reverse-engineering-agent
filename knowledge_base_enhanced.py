"""
Enhanced Knowledge Base System
Multi-backend storage: SQLite, PostgreSQL+pgvector, Neo4j, Redis
"""

import json
import sqlite3
import hashlib
from typing import Dict, Any, List, Optional, Tuple, Union
from datetime import datetime
import uuid
import logging
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
import os

# Optional imports
try:
    import psycopg2
    import numpy as np
    POSTGRES_AVAILABLE = True
except ImportError:
    POSTGRES_AVAILABLE = False

try:
    from neo4j import GraphDatabase
    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False


class KnowledgeType(Enum):
    """Types of knowledge stored in the system"""
    FACT = "fact"
    HYPOTHESIS = "hypothesis"
    EXPERIMENT = "experiment"
    FINDING = "finding"
    CORRELATION = "correlation"
    FAILED_ATTEMPT = "failed_attempt"


class ConfidenceLevel(Enum):
    """Confidence levels for knowledge items"""
    VERY_LOW = 0.1
    LOW = 0.3
    MEDIUM = 0.5
    HIGH = 0.7
    VERY_HIGH = 0.9


@dataclass
class KnowledgeItem:
    """Base class for all knowledge items"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    type: KnowledgeType = KnowledgeType.FACT
    title: str = ""
    description: str = ""
    confidence: float = 0.5  # 0.0 to 1.0
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    tags: List[str] = field(default_factory=list)
    source_agent: Optional[str] = None
    related_items: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Fact(KnowledgeItem):
    """Verified piece of information"""
    evidence: List[str] = field(default_factory=list)
    source_references: List[str] = field(default_factory=list)

    def __post_init__(self):
        self.type = KnowledgeType.FACT


@dataclass
class Hypothesis(KnowledgeItem):
    """Testable proposition"""
    basis: str = ""
    testable: bool = False
    prediction: str = ""
    falsification_condition: str = ""

    def __post_init__(self):
        self.type = KnowledgeType.HYPOTHESIS


@dataclass
class Experiment(KnowledgeItem):
    """Record of an experiment performed"""
    hypothesis_id: str = ""
    setup: str = ""
    procedure: str = ""
    results: str = ""
    conclusion: str = ""
    replicated: bool = False
    replication_count: int = 0

    def __post_init__(self):
        self.type = KnowledgeType.EXPERIMENT


@dataclass
class Finding(KnowledgeItem):
    """Discovered information from analysis"""
    location: str = ""
    evidence_strength: float = 0.0  # 0.0 to 1.0
    reproducibility: float = 0.0  # How consistently it can be observed

    def __post_init__(self):
        self.type = KnowledgeType.FINDING


@dataclass
class Correlation(KnowledgeItem):
    """Relationship between two or more pieces of knowledge"""
    item_ids: List[str] = field(default_factory=list)
    correlation_type: str = ""  # e.g., "causes", "correlates_with", "contradicts"
    strength: float = 0.0  # 0.0 to 1.0
    evidence: List[str] = field(default_factory=list)

    def __post_init__(self):
        self.type = KnowledgeType.CORRELATION


@dataclass
class FailedAttempt(KnowledgeItem):
    """Record of something that was tried and didn't work"""
    attempt_type: str = ""  # What was attempted
    expected_result: str = ""
    actual_result: str = ""
    lessons_learned: str = ""

    def __post_init__(self):
        self.type = KnowledgeType.FAILED_ATTEMPT


class EnhancedKnowledgeBase:
    """Enhanced knowledge base with multiple backend support"""

    def __init__(self,
                 sqlite_path: str = "knowledge_base.db",
                 postgres_config: dict = None,
                 neo4j_config: dict = None,
                 redis_config: dict = None,
                 enable_caching: bool = True,
                 enable_vector_search: bool = False):
        """
        Initialize the enhanced knowledge base

        Args:
            sqlite_path: Path to SQLite database (fallback)
            postgres_config: PostgreSQL connection config {host, port, dbname, user, password}
            neo4j_config: Neo4j connection config {uri, user, password}
            redis_config: Redis connection config {host, port, password, db}
            enable_caching: Whether to use Redis caching
            enable_vector_search: Whether to enable vector similarity search
        """
        self.logger = logging.getLogger("enhanced_knowledge_base")
        self.sqlite_path = Path(sqlite_path)
        self.postgres_config = postgres_config
        self.neo4j_config = neo4j_config
        self.redis_config = redis_config
        self.enable_caching = enable_caching and REDIS_AVAILABLE
        self.enable_vector_search = enable_vector_search and POSTGRES_AVAILABLE

        # Initialize backends
        self._init_sqlite()
        self._init_postgres()
        self._init_neo4j()
        self._init_redis()

    def _init_sqlite(self):
        """Initialize SQLite database (always available as fallback)"""
        self.sqlite_path.parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(self.sqlite_path) as conn:
            cursor = conn.cursor()

            # Main knowledge items table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS knowledge_items (
                    id TEXT PRIMARY KEY,
                    type TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    confidence REAL,
                    created_at TEXT,
                    updated_at TEXT,
                    tags TEXT,
                    source_agent TEXT,
                    related_items TEXT,
                    metadata TEXT
                )
            """)

            # Type-specific tables
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS facts (
                    id TEXT PRIMARY KEY,
                    evidence TEXT,
                    source_references TEXT,
                    FOREIGN KEY (id) REFERENCES knowledge_items (id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS hypotheses (
                    id TEXT PRIMARY KEY,
                    basis TEXT,
                    testable BOOLEAN,
                    prediction TEXT,
                    falsification_condition TEXT,
                    FOREIGN KEY (id) REFERENCES knowledge_items (id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS experiments (
                    id TEXT PRIMARY KEY,
                    hypothesis_id TEXT,
                    setup TEXT,
                    procedure TEXT,
                    results TEXT,
                    conclusion TEXT,
                    replicated BOOLEAN,
                    replication_count INTEGER,
                    FOREIGN KEY (id) REFERENCES knowledge_items (id),
                    FOREIGN KEY (hypothesis_id) REFERENCES hypotheses (id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    location TEXT,
                    evidence_strength REAL,
                    reproducibility REAL,
                    FOREIGN KEY (id) REFERENCES knowledge_items (id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS correlations (
                    id TEXT PRIMARY KEY,
                    item_ids TEXT,
                    correlation_type TEXT,
                    strength REAL,
                    evidence TEXT,
                    FOREIGN KEY (id) REFERENCES knowledge_items (id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS failed_attempts (
                    id TEXT PRIMARY KEY,
                    attempt_type TEXT,
                    expected_result TEXT,
                    actual_result TEXT,
                    lessons_learned TEXT
                )
            """)

        # Indexes (additional types
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_type ON knowledge_items (type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS tags_idx ON knowledge_items (tags)")
        cursor.execute("CREATE INDEX IF NOT EXISTS created_at_idx ON knowledge_items (created_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS confidence_idx ON knowledge_items (confidence)")

        conn.commit()

        self.logger.info(f"SQLite knowledge base initialized at {self.sqlite_path}")

    def _init_postgres(self):
        """Initialize PostgreSQL connection"""
        if not self.postgres_config or not POSTGRES_AVAILABLE:
            self.postgres_conn = None
            self.pgvector_available = False
            return

        try:
            self.postgres_conn = psycopg2.connect(
                host=self.postgres_config.get('host', 'localhost'),
                port=self.postgres_config.get('port', 5432),
                database=self.postgres_config.get('dbname', 'knowledge_base'),
                user=self.postgres_config.get('user', 'postgres'),
                password=self.postgres_config.get('password', '')
            )

            # Enable pgvector extension if available
            with self.postgres_conn.cursor() as cursor:
                try:
                    cursor.execute("CREATE EXTENSION IF NOT EXISTS vector")
                    self.postgres_conn.commit()
                    self.pgvector_available = True
                    self.logger.info("PostgreSQL with pgvector extension initialized")

                    # Create table with vector support if not exists
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS knowledge_items_vector (
                            id TEXT PRIMARY KEY,
                            content_text TEXT,
                            embedding VECTOR(384),
                            metadata JSONB,
                            created_at TIMESTAMP,
                            FOREIGN KEY (id) REFERENCES knowledge_items (id)
                        )
                    """)
                    self.postgres_conn.commit()

                except Exception as e:
                    self.logger.warning(f"Could not enable pgvector: {e}")
                    self.pgvector_available = False

        except Exception as e:
            self.logger.error(f"Failed to connect to PostgreSQL: {e}")
            self.postgres_conn = None
            self.pgvector_available = False

    def _init_neo4j(self):
        """Initialize Neo4j connection for graph relationships"""
        if not self.neo4j_config or not NEO4J_AVAILABLE:
            self.neo4j_driver = None
            return

        try:
            self.neo4j_driver = GraphDatabase.driver(
                self.neo4j_config.get('uri', 'bolt://localhost:7687'),
                auth=(self.neo4j_config.get('user', 'neo4j'),
                      self.neo4j_config.get('password', 'password'))
            )

            # Test connection
            with self.neo4j_driver.session() as session:
                result = session.run("RETURN 1")
                result.single()

            self.logger.info("Neo4j connection established")

        except Exception as e:
            self.logger.error(f"Failed to connect to Neo4j: {e}")
            self.neo4j_driver = None

    def _init_redis(self):
        """Initialize Redis connection for caching"""
        if not self.redis_config or not REDIS_AVAILABLE or not self.enable_caching:
            self.redis_client = None
            return

        try:
            self.redis_client = redis.Redis(
                host=self.redis_config.get('host', 'localhost'),
                port=self.redis_config.get('port', 6379),
                password=self.redis_config.get('password', None),
                db=self.redis_config.get('db', 0),
                decode_responses=True
            )

            # Test connection
            self.redis_client.ping()
            self.logger.info("Redis connection established for caching")

        except Exception as e:
            self.logger.error(f"Failed to connect to Redis: {e}")
            self.redis_client = None

    def _get_from_cache(self, key: str) -> Optional[Any]:
        """Get item from Redis cache"""
        if not self.redis_client:
            return None

        try:
            cached = self.redis_client.get(f"kb:{key}")
            if cached:
                return json.loads(cached)
        except Exception as e:
            self.logger.warning(f"Cache read error: {e}")
        return None

    def _set_in_cache(self, key: str, value: Any, expire: int = 3600):
        """Set item in Redis cache"""
        if not self.redis_client:
            return

        try:
            self.redis_client.setex(
                f"kb:{key}",
                expire,
                json.dumps(value, default=str)
            )
        except Exception as e:
            self.logger.warning(f"Cache write error: {e}")

    def add_knowledge_item(self, item: KnowledgeItem) -> str:
        """Add a knowledge item to all configured backends"""
        if not item.id:
            item.id = str(uuid.uuid4())

        now = datetime.now().isoformat()
        if not item.created_at:
            created_at = now
        else:
            created_at = item.created_at
        updated_at = now

        self.logger.info(f"Adding {item.type.value}: {item.title}")

        # Store in all available backends
        self._add_to_sqlite(item, created_at, updated_at)
        self._add_to_postgres(item, created_at, updated_at)
        self._add_to_neo4j(item, created_at, updated_at)

        # Invalidate related cache entries
        self._invalidate_related_cache(item.id)

        return item.id

    def _add_to_sqlite(self, item: KnowledgeItem, created_at: str, updated_at: str):
        """Add item to SQLite database"""
        with sqlite3.connect(self.sqlite_path) as conn:
            cursor = conn.cursor()

            # Insert into main table
            cursor.execute("""
                INSERT OR REPLACE INTO knowledge_items
                (id, type, title, description, confidence, created_at, updated_at,
                 tags, source_agent, related_items, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                item.id,
                item.type.value,
                item.title,
                item.description,
                item.confidence,
                created_at,
                updated_at,
                json.dumps(item.tags),
                item.source_agent,
                json.dumps(item.related_items),
                json.dumps(item.metadata)
            ))

            # Insert into type-specific table
            if isinstance(item, Fact):
                cursor.execute("""
                    INSERT OR REPLACE INTO facts
                    (id, evidence, source_references)
                    VALUES (?, ?, ?)
                """, (
                    item.id,
                    json.dumps(item.evidence),
                    json.dumps(item.source_references)
                ))
            elif isinstance(item, Hypothesis):
                cursor.execute("""
                    INSERT OR REPLACE INTO hypotheses
                    (id, basis, testable, prediction, falsification_condition)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    item.id,
                    item.basis,
                    item.testable,
                    item.prediction,
                    item.falsification_condition
                ))
            elif isinstance(item, Experiment):
                cursor.execute("""
                    INSERT OR REPLACE INTO experiments
                    (id, hypothesis_id, setup, procedure, results, conclusion, replicated, replication_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    item.id,
                    item.hypothesis_id,
                    item.setup,
                    item.procedure,
                    item.results,
                    item.conclusion,
                    item.replicated,
                    item.replication_count
                ))
            elif isinstance(item, Finding):
                cursor.execute("""
                    INSERT OR REPLACE INTO findings
                    (id, location, evidence_strength, reproducibility)
                    VALUES (?, ?, ?, ?)
                """, (
                    item.id,
                    item.location,
                    item.evidence_strength,
                    item.reproducibility
                ))
            elif isinstance(item, Correlation):
                cursor.execute("""
                    INSERT OR REPLACE INTO correlations
                    (id, item_ids, correlation_type, strength, evidence)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    item.id,
                    json.dumps(item.item_ids),
                    item.correlation_type,
                    item.strength,
                    json.dumps(item.evidence)
                ))
            elif isinstance(item, FailedAttempt):
                cursor.execute("""
                    INSERT OR REPLACE INTO failed_attempts
                    (id, attempt_type, expected_result, actual_result, lessons_learned)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    item.id,
                    item.attempt_type,
                    item.expected_result,
                    item.actual_result,
                    item.lessons_learned
                ))

            conn.commit()

    def _add_to_postgres(self, item: KnowledgeItem, created_at: str, updated_at: str):
        """Add item to PostgreSQL database with vector embeddings if enabled"""
        if not self.postgres_conn:
            return

        try:
            with self.postgres_conn.cursor() as cursor:
                # Insert into main table (similar structure to SQLite)
                # For brevity, we'll use a simplified approach
                # In practice, you'd mirror the SQLite structure

                # Store in knowledge_items table
                cursor.execute("""
                    INSERT INTO knowledge_items
                    (id, type, title, description, confidence, created_at, updated_at,
                     tags, source_agent, related_items, metadata)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (id) DO UPDATE SET
                    title = EXCLUDED.title,
                    description = EXCLUDED.description,
                    confidence = EXCLUDED.confidence,
                    updated_at = EXCLUDED.updated_at,
                    tags = EXCLUDED.tags,
                    source_agent = EXCLUDED.source_agent,
                    related_items = EXCLUDED.related_items,
                    metadata = EXCLUDED.metadata
                """, (
                    item.id,
                    item.type.value,
                    item.title,
                    item.description,
                    item.confidence,
                    created_at,
                    updated_at,
                    json.dumps(item.tags),
                    item.source_agent,
                    json.dumps(item.related_items),
                    json.dumps(item.metadata)
                ))

                # If vector storage is enabled, generate and store embedding
                if self.pgvector_available:
                    # Generate text embedding for similarity search
                    text_for_embedding = f"{item.title} {item.description}"
                    embedding = self._generate_embedding(text_for_embedding)

                    # Store embedding in vector table
                    cursor.execute("""
                        INSERT INTO knowledge_items_vector
                        (id, content_text, embedding, metadata, created_at)
                        VALUES (%s, %s, %s::vector, %s, %s)
                        ON CONFLICT (id) DO UPDATE SET
                        content_text = EXCLUDED.content_text,
                        embedding = EXCLUDED.embedding,
                        metadata = EXCLUDED.metadata,
                        created_at = EXCLUDED.created_at
                    """, (
                        item.id,
                        f"{item.title} {item.description}",
                        embedding,
                        json.dumps(item.metadata),
                        created_at
                    ))

                self.postgres_conn.commit()
        except Exception as e:
            self.logger.error(f"PostgreSQL insert error: {e}")
            self.postgres_conn.rollback()

    def _add_to_neo4j(self, item: KnowledgeItem, created_at: str, updated_at: str):
        """Add item to Neo4j graph database"""
        if not self.neo4j_driver:
            return

        try:
            with self.neo4j_driver.session() as session:
                # Create node for the knowledge item
                query = """
                CREATE (k:KnowledgeItem {
                    id: $id,
                    type: $type,
                    title: $title,
                    description: $description,
                    confidence: $confidence,
                    created_at: $created_at,
                    updated_at: $updated_at,
                    tags: $tags,
                    source_agent: $source_agent,
                    metadata: $metadata
                })
                """

                params = {
                    'id': item.id,
                    'type': item.type.value,
                    'title': item.title,
                    'description': item.description,
                    'confidence': item.confidence,
                    'created_at': created_at,
                    'updated_at': updated_at,
                    'tags': item.tags,
                    'source_agent': item.source_agent,
                    'metadata': json.dumps(item.metadata)
                }

                session.run(query, params)

                # Create relationships for related items
                for related_id in item.related_items:
                    rel_query = """
                    MATCH (a:KnowledgeItem {id: $source_id})
                    MATCH (b:KnowledgeItem {id: $target_id})
                    MERGE (a)-[r:RELATED_TO]->(b)
                    SET r.created_at = $timestamp
                    """
                    session.run(rel_query, {
                        'source_id': item.id,
                        'target_id': related_id,
                        'timestamp': datetime.now().isoformat()
                    })

                # Also add type-specific properties
                if isinstance(item, Fact):
                    self._add_fact_properties_to_neo4j(session, item, created_at, updated_at)
                elif isinstance(item, Hypothesis):
                    self._add_hypothesis_properties_to_neo4j(session, item, created_at, updated_at)
                elif isinstance(item, Experiment):
                    self._add_experiment_properties_to_neo4j(session, item, created_at, updated_at)
                # ... add other type-specific methods as needed

        except Exception as e:
            self.logger.error(f"Neo4j insert error: {e}")

    def _add_fact_properties_to_neo4j(self, session, item: Fact, created_at: str, updated_at: str):
        """Add fact-specific properties to Neo4j"""
        query = """
        MATCH (k:KnowledgeItem {id: $id})
        SET k.evidence = $evidence,
            k.source_references = $source_references
        """
        session.run(query, {
            'id': item.id,
            'evidence': json.dumps(item.evidence),
            'source_references': json.dumps(item.source_references)
        })

    def _add_hypothesis_properties_to_neo4j(self, session, item: Hypothesis, created_at: str, updated_at: str):
        """Add hypothesis-specific properties to Neo4j"""
        query = """
        MATCH (k:KnowledgeItem {id: $id})
        SET k.basis = $basis,
            k.testable = $testable,
            k.prediction = $prediction,
            k.falsification_condition = $falsification_condition
        """
        session.run(query, {
            'id': item.id,
            'basis': item.basis,
            'testable': item.testable,
            'prediction': item.prediction,
            'falsification_condition': item.falsification_condition
        })

    def _add_experiment_properties_to_neo4j(self, session, item: Experiment, created_at: str, updated_at: str):
        """Add experiment-specific properties to Neo4j"""
        query = """
        MATCH (k:KnowledgeItem {id: $id})
        SET k.hypothesis_id = $hypothesis_id,
            k.setup = $setup,
            k.procedure = $procedure,
            k.results = $results,
            k.conclusion = $conclusion,
            k.replicated = $replicated,
            k.replication_count = $replication_count
        """
        # Also create relationship to hypothesis
        if item.hypothesis_id:
            rel_query = """
            MATCH (h:KnowledgeItem {id: $hypothesis_id})
            MATCH (e:KnowledgeItem {id: $item_id})
            MERGE (h)-[r:TESTED_BY]->(e)
            SET r.created_at = $timestamp
            """
            session.run(rel_query, {
                'hypothesis_id': item.hypothesis_id,
                'item_id': item.id,
                'timestamp': datetime.now().isoformat()
            })

        session.run(query, {
            'id': item.id,
            'hypothesis_id': item.hypothesis_id,
            'setup': item.setup,
            'procedure': item.procedure,
            'results': item.results,
            'conclusion': item.conclusion,
            'replicated': item.replicated,
            'replication_count': item.replication_count
        })

    def _invalidate_related_cache(self, item_id: str):
        """Invalidate cache entries related to an item"""
        if not self.redis_client:
            return

        try:
            # Delete specific item cache
            self.redis_client.delete(f"kb:item:{item_id}")

            # In a real implementation, you'd use cache tagging or more sophisticated invalidation
            # For now, we'll clear search-related caches with a simple pattern
            # Note: This is a simplification - production would use better cache invalidation
        except Exception as e:
            self.logger.warning(f"Cache invalidation error: {e}")

    def _generate_embedding(self, text: str) -> List[float]:
        """Generate embeddings for text (placeholder - would use actual embedding model)"""
        # This is a placeholder - in reality you would use something like:
        # from sentence_transformers import SentenceTransformer
        # model = SentenceTransformer('all-MiniLM-L6-v2')
        # return model.encode(text).tolist()

        # For now, return a deterministic pseudo-vector based on hash
        # This ensures similar texts have similar vectors (very simplified)
        hash_obj = hashlib.md5(text.encode())
        hash_int = int(hash_obj.hexdigest(), 16)

        # Generate a 384-dimensional vector (standard for many embedding models)
        random_seed = hash_int % (2**32)
        import random
        random.seed(random_seed)
        return [random.uniform(-1, 1) for _ in range(384)]

    def get_knowledge_item(self, item_id: str) -> Optional[KnowledgeItem]:
        """Retrieve a knowledge item by ID (try cache first)"""
        # Try cache first
        cached = self._get_from_cache(f"item:{item_id}")
        if cached:
            # Deserialize cached item
            if cached['related_items'] is None:
                cached['related_items'] = []
            if cached['metadata'] is None:
                cached['metadata'] = {}
            return self._dict_to_knowledge_item(cached)

        # Fall back to database (prefer PostgreSQL, then SQLite)
        item = None
        if self.postgres_conn:
            item = self._get_from_postgres(item_id)

        if not item and self.sqlite_path.exists():
            item = self._get_from_sqlite(item_id)

        # Cache the result
        if item:
            self._set_in_cache(f"item:{item_id}", self._knowledge_item_to_dict(item))

        return item

    def _get_from_sqlite(self, item_id: str) -> Optional[KnowledgeItem]:
        """Get item from SQLite database"""
        with sqlite3.connect(self.sqlite_path) as conn:
            cursor = conn.cursor()
            # Simplified retrieval - in practice, you'd join type-specific tables
            cursor.execute("""
                SELECT id, type, title, description, confidence, created_at, updated_at,
                       tags, source_agent, related_items, metadata
                FROM knowledge_items
                WHERE id = ?
            """, (item_id,))

            row = cursor.fetchone()
            if row:
                return self._sqlite_row_to_knowledge_item(row)
        return None

    def _get_from_postgres(self, item_id: str) -> Optional[KnowledgeItem]:
        """Get item from PostgreSQL database"""
        if not self.postgres_conn:
            return None

        try:
            with self.postgres_conn.cursor() as cursor:
                cursor.execute("""
                    SELECT id, type, title, description, confidence, created_at, updated_at,
                           tags, source_agent, related_items, metadata
                    FROM knowledge_items
                    WHERE id = %s
                """, (item_id,))

                row = cursor.fetchone()
                if row:
                    return self._postgres_row_to_knowledge_item(row)
        except Exception as e:
            self.logger.error(f"PostgreSQL query error: {e}")
        return None

    # Helper methods to convert database rows to KnowledgeItem objects
    def _sqlite_row_to_knowledge_item(self, row: tuple) -> KnowledgeItem:
        """Convert SQLite row to KnowledgeItem"""
        (item_id, type_str, title, description, confidence,
         created_at, updated_at, tags_json, source_agent,
         related_items_json, metadata_json) = row

        item_type = KnowledgeType(type_str)
        tags = json.loads(tags_json) if tags_json else []
        related_items = json.loads(related_items_json) if related_items_json else []
        metadata = json.loads(metadata_json) if metadata_json else {}

        base_item = KnowledgeItem(
            id=item_id,
            type=item_type,
            title=title,
            description=description,
            confidence=confidence,
            created_at=created_at,
            updated_at=updated_at,
            tags=tags,
            source_agent=source_agent,
            related_items=related_items,
            metadata=metadata
        )

        # Fetch type-specific data
        return self._populate_type_specific_sqlite(base_item, item_type, item_id)

    def _populate_type_specific_sqlite(self, base_item: KnowledgeItem, item_type: KnowledgeType, item_id: str) -> KnowledgeItem:
        """Populate type-specific fields from SQLite"""
        with sqlite3.connect(self.sqlite_path) as conn:
            cursor = conn.cursor()

            if item_type == KnowledgeType.FACT:
                cursor.execute("SELECT evidence, source_references FROM facts WHERE id = ?", (item_id,))
                row = cursor.fetchone()
                if row:
                    return Fact(
                        id=base_item.id,
                        type=base_item.type,
                        title=base_item.title,
                        description=base_item.description,
                        confidence=base_item.confidence,
                        created_at=base_item.created_at,
                        updated_at=base_item.updated_at,
                        tags=base_item.tags,
                        source_agent=base_item.source_agent,
                        related_items=base_item.related_items,
                        metadata=base_item.metadata,
                        evidence=json.loads(row[0]) if row[0] else [],
                        source_references=json.loads(row[1]) if row[1] else []
                    )
            elif item_type == KnowledgeType.HYPOTHESIS:
                cursor.execute("SELECT basis, testable, prediction, falsification_condition FROM hypotheses WHERE id = ?", (item_id,))
                row = cursor.fetchone()
                if row:
                    return Hypothesis(
                        id=base_item.id,
                        type=base_item.type,
                        title=base_item.title,
                        description=base_item.description,
                        confidence=base_item.confidence,
                        created_at=base_item.created_at,
                        updated_at=base_item.updated_at,
                        tags=base_item.tags,
                        source_agent=base_item.source_agent,
                        related_items=base_item.related_items,
                        metadata=base_item.metadata,
                        basis=row[0] if row[0] else '',
                        testable=bool(row[1]) if row[1] is not None else False,
                        prediction=row[2] if row[2] else '',
                        falsification_condition=row[3] if row[3] else ''
                    )
            elif item_type == KnowledgeType.EXPERIMENT:
                cursor.execute("SELECT hypothesis_id, setup, procedure, results, conclusion, replicated, replication_count FROM experiments WHERE id = ?", (item_id,))
                row = cursor.fetchone()
                if row:
                    return Experiment(
                        id=base_item.id,
                        type=base_item.type,
                        title=base_item.title,
                        description=base_item.description,
                        confidence=base_item.confidence,
                        created_at=base_item.created_at,
                        updated_at=base_item.updated_at,
                        tags=base_item.tags,
                        source_agent=base_item.source_agent,
                        related_items=base_item.related_items,
                        metadata=base_item.metadata,
                        hypothesis_id=row[0] if row[0] else '',
                        setup=row[1] if row[1] else '',
                        procedure=row[2] if row[2] else '',
                        results=row[3] if row[3] else '',
                        conclusion=row[4] if row[4] else '',
                        replicated=bool(row[5]) if row[5] is not None else False,
                        replication_count=int(row[6]) if row[6] is not None else 0
                    )
            elif item_type == KnowledgeType.FINDING:
                cursor.execute("SELECT location, evidence_strength, reproducibility FROM findings WHERE id = ?", (item_id,))
                row = cursor.fetchone()
                if row:
                    return Finding(
                        id=base_item.id,
                        type=base_item.type,
                        title=base_item.title,
                        description=base_item.description,
                        confidence=base_item.confidence,
                        created_at=base_item.created_at,
                        updated_at=base_item.updated_at,
                        tags=base_item.tags,
                        source_agent=base_item.source_agent,
                        related_items=base_item.related_items,
                        metadata=base_item.metadata,
                        location=row[0] if row[0] else '',
                        evidence_strength=float(row[1]) if row[1] is not None else 0.0,
                        reproducibility=float(row[2]) if row[2] is not None else 0.0
                    )
            elif item_type == KnowledgeType.CORRELATION:
                cursor.execute("SELECT item_ids, correlation_type, strength, evidence FROM correlations WHERE id = ?", (item_id,))
                row = cursor.fetchone()
                if row:
                    return Correlation(
                        id=base_item.id,
                        type=base_item.type,
                        title=base_item.title,
                        description=base_item.description,
                        confidence=base_item.confidence,
                        created_at=base_item.created_at,
                        updated_at=base_item.updated_at,
                        tags=base_item.tags,
                        source_agent=base_item.source_agent,
                        related_items=base_item.related_items,
                        metadata=base_item.metadata,
                        item_ids=json.loads(row[0]) if row[0] else [],
                        correlation_type=row[1] if row[1] else '',
                        strength=float(row[2]) if row[2] is not None else 0.0,
                        evidence=json.loads(row[3]) if row[3] else []
                    )
            elif item_type == KnowledgeType.FAILED_ATTEMPT:
                cursor.execute("SELECT attempt_type, expected_result, actual_result, lessons_learned FROM failed_attempts WHERE id = ?", (item_id,))
                row = cursor.fetchone()
                if row:
                    return FailedAttempt(
                        id=base_item.id,
                        type=base_item.type,
                        title=base_item.title,
                        description=base_item.description,
                        confidence=base_item.confidence,
                        created_at=base_item.created_at,
                        updated_at=base_item.updated_at,
                        tags=base_item.tags,
                        source_agent=base_item.source_agent,
                        related_items=base_item.related_items,
                        metadata=base_item.metadata,
                        attempt_type=row[0] if row[0] else '',
                        expected_result=row[1] if row[1] else '',
                        actual_result=row[2] if row[2] else '',
                        lessons_learned=row[3] if row[3] else ''
                    )
            # For unknown types, return the base item
            return base_item

    def _postgres_row_to_knowledge_item(self, row: tuple) -> KnowledgeItem:
        """Convert PostgreSQL row to KnowledgeItem"""
        # Similar to SQLite implementation
        (item_id, type_str, title, description, confidence,
         created_at, updated_at, tags_json, source_agent,
         related_items_json, metadata_json) = row

        item_type = KnowledgeType(type_str)
        tags = json.loads(tags_json) if tags_json else []
        related_items = json.loads(related_items_json) if related_items_json else []
        metadata = json.loads(metadata_json) if metadata_json else {}

        base_item = KnowledgeItem(
            id=item_id,
            type=item_type,
            title=title,
            description=description,
            confidence=confidence,
            created_at=created_at,
            updated_at=updated_at,
            tags=tags,
            source_agent=source_agent,
            related_items=related_items,
            metadata=metadata
        )

        # In full implementation, would populate type-specific fields
        return base_item

    def _knowledge_item_to_dict(self, item: KnowledgeItem) -> Dict[str, Any]:
        """Convert KnowledgeItem to dictionary for caching"""
        return {
            'id': item.id,
            'type': item.type.value,
            'title': item.title,
            'description': item.description,
            'confidence': item.confidence,
            'created_at': item.created_at,
            'updated_at': item.updated_at,
            'tags': item.tags,
            'source_agent': item.source_agent,
            'related_items': item.related_items,
            'metadata': item.metadata
        }

    def _dict_to_knowledge_item(self, data: Dict[str, Any]) -> KnowledgeItem:
        """Convert dictionary to KnowledgeItem"""
        item_type = KnowledgeType(data['type'])
        base_item = KnowledgeItem(
            id=data['id'],
            type=item_type,
            title=data['title'],
            description=data['description'],
            confidence=data['confidence'],
            created_at=data['created_at'],
            updated_at=data['updated_at'],
            tags=data['data']['tags'] if 'data' in data and 'tags' in data['data'] else data.get('tags', []),
            source_agent=data.get('source_agent'),
            related_items=data['data']['related_items'] if 'data' in data and 'related_items' in data['data'] else data.get('related_items', []),
            metadata=data['data']['metadata'] if 'data' in data and 'metadata' in data['data'] else data.get('metadata', {})
        )

        # In practice, would populate type-specific fields from data
        return base_item

    # Additional methods like search_knowledge, get_related_items, etc.
    # would be implemented with similar multi-backend approach

    def search_knowledge_light(self, query: str = None, limit: int = 10) -> List[KnowledgeItem]:
        """Simplified search for demonstration"""
        # Check cache first
        cache_key = f"search:{query or ''}:{limit}"
        cached = self._get_from_cache(cache_key)
        if cached:
            return [self._dict_to_knowledge_item(item) for item in cached]

        # Search in SQLite (fallback)
        results = []
        with sqlite3.connect(self.sqlite_path) as conn:
            cursor = conn.cursor()

            if query:
                cursor.execute("""
                    SELECT id, type, title, description, confidence, created_at, updated_at,
                           tags, source_agent, related_items, metadata
                    FROM knowledge_items
                    WHERE title LIKE ? OR description LIKE ?
                    ORDER BY confidence DESC
                    LIMIT ?
                """, (f"%{query}%", f"%{query}%", limit))
            else:
                cursor.execute("""
                    SELECT id, type, title, description, confidence, created_at, updated_at,
                           tags, source_agent, related_items, metadata
                    FROM knowledge_items
                    ORDER BY created_at DESC
                    LIMIT ?
                """, (limit,))

            rows = cursor.fetchall()
            for row in rows:
                results.append(self._sqlite_row_to_knowledge_item(row))

        # Cache results
        self._set_in_cache(cache_key, [self._knowledge_item_to_dict(item) for item in results])
        return results

    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about the knowledge base"""
        stats = {'backends': {}}

        # SQLite stats
        if self.sqlite_path.exists():
            try:
                with sqlite3.connect(self.sqlite_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT COUNT(*) FROM knowledge_items")
                    count = cursor.fetchone()[0]
                    stats['backends']['sqlite'] = {'count': count, 'path': str(self.sqlite_path)}
            except Exception as e:
                stats['backends']['sqlite'] = {'error': str(e)}

        # PostgreSQL stats
        if self.postgres_conn:
            try:
                with self.postgres_conn.cursor() as cursor:
                    cursor.execute("SELECT COUNT(*) FROM knowledge_items")
                    count = cursor.fetchone()[0]
                    stats['backends']['postgresql'] = {
                        'count': count,
                        'vector_enabled': getattr(self, 'pgvector_available', False)
                    }
            except Exception as e:
                stats['backends']['postgresql'] = {'error': str(e)}

        # Neo4j stats
        if self.neo4j_driver:
            try:
                with self.neo4j_driver.session() as session:
                    result = session.run("MATCH (n:KnowledgeItem) RETURN count(n) as count")
                    count = result.single()['count']
                    stats['backends']['neo4j'] = {'count': count}
            except Exception as e:
                stats['backends']['neo4j'] = {'error': str(e)}

        # Redis stats
        if self.redis_client:
            try:
                info = self.redis_client.info()
                stats['backends']['redis'] = {
                    'connected': True,
                    'used_memory': info.get('used_memory_human', 'N/A'),
                    'keyspace_hits': info.get('keyspace_hits', 0),
                    'keyspace_misses': info.get('keyspace_misses', 0)
                }
            except Exception as e:
                stats['backends']['redis'] = {'error': str(e)}

        return stats


# Global enhanced knowledge base instance
enhanced_kb = EnhancedKnowledgeBase(
    sqlite_path="knowledge_base.db",
    postgres_config={
        'host': os.getenv('POSTGRES_HOST', 'localhost'),
        'port': int(os.getenv('POSTGRES_PORT', 5432)),
        'dbname': os.getenv('POSTGRES_DB', 'knowledge_base'),
        'user': os.getenv('POSTGRES_USER', 'postgres'),
        'password': os.getenv('POSTGRES_PASSWORD', '')
    } if os.getenv('POSTGRES_HOST') else None,
    neo4j_config={
        'uri': os.getenv('NEO4J_URI', 'bolt://localhost:7687'),
        'user': os.getenv('NEO4J_USER', 'neo4j'),
        'password': os.getenv('NEO4J_PASSWORD', 'password')
    } if os.getenv('NEO4J_URI') else None,
    redis_config={
        'host': os.getenv('REDIS_HOST', 'localhost'),
        'port': int(os.getenv('REDIS_PORT', 6379)),
        'password': os.getenv('REDIS_PASSWORD', None),
        'db': int(os.getenv('REDIS_DB', 0))
    } if os.getenv('REDIS_HOST') else None,
    enable_caching=True,
    enable_vector_search=True
)

# Convenience functions that use the enhanced knowledge base
def add_fact(title: str, description: str, confidence: float,
             evidence: List[str] = None, source_references: List[str] = None,
             tags: List[str] = None, source_agent: str = None) -> str:
    """Convenience function to add a fact"""
    fact = Fact(
        id="",
        type=KnowledgeType.FACT,
        title=title,
        description=description,
        confidence=confidence,
        created_at="",
        updated_at="",
        tags=tags or [],
        source_agent=source_agent,
        related_items=[],
        evidence=evidence or [],
        source_references=source_references or []
    )
    return enhanced_kb.add_knowledge_item(fact)

def add_hypothesis(title: str, description: str, confidence: float,
                   basis: str, testable: bool, prediction: str,
                   falsification_condition: str, tags: List[str] = None,
                   source_agent: str = None) -> str:
    """Convenience function to add a hypothesis"""
    hypothesis = Hypothesis(
        id="",
        type=KnowledgeType.HYPOTHESIS,
        title=title,
        description=description,
        confidence=confidence,
        created_at="",
        updated_at="",
        tags=tags or [],
        source_agent=source_agent,
        related_items=[],
        basis=basis,
        testable=testable,
        prediction=prediction,
        falsification_condition=falsification_condition
    )
    return enhanced_kb.add_knowledge_item(hypothesis)

def add_experiment(title: str, description: str, confidence: float,
                   hypothesis_id: str, setup: str, procedure: str,
                   results: str = "", conclusion: str = "",
                   tags: List[str] = None, source_agent: str = None) -> str:
    """Convenience function to add an experiment"""
    experiment = Experiment(
        id="",
        type=KnowledgeType.EXPERIMENT,
        title=title,
        description=description,
        confidence=confidence,
        created_at="",
        updated_at="",
        tags=tags or [],
        source_agent=source_agent,
        related_items=[],
        hypothesis_id=hypothesis_id,
        setup=setup,
        procedure=procedure,
        results=results,
        conclusion=conclusion,
        replicated=False,
        replication_count=0
    )
    return enhanced_kb.add_knowledge_item(experiment)