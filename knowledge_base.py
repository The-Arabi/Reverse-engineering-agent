"""
Knowledge Base System for the Reverse Engineering Lab
Implements persistent storage for findings, hypotheses, experiments, and cross-references
"""

import json
import sqlite3
import hashlib
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
import uuid
import logging
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path


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
    id: str
    type: KnowledgeType
    title: str
    description: str
    confidence: float  # 0.0 to 1.0
    created_at: str
    updated_at: str
    tags: List[str]
    source_agent: Optional[str] = None
    related_items: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None

    def __post_init__(self):
        if self.related_items is None:
            self.related_items = []
        if self.metadata is None:
            self.metadata = {}


@dataclass
class Fact(KnowledgeItem):
    """Verified piece of information"""
    evidence: Optional[List[str]] = None
    source_references: Optional[List[str]] = None

    def __post_init__(self):
        super().__post_init__()
        self.type = KnowledgeType.FACT
        if self.evidence is None:
            self.evidence = []
        if self.source_references is None:
            self.source_references = []


@dataclass
class Hypothesis(KnowledgeItem):
    """Testable proposition"""
    basis: str = ""
    testable: bool = True
    prediction: str = ""
    falsification_condition: str = ""

    def __post_init__(self):
        super().__post_init__()
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
        super().__post_init__()
        self.type = KnowledgeType.EXPERIMENT


@dataclass
class Finding(KnowledgeItem):
    """Discovered information from analysis"""
    location: str = ""
    evidence_strength: float = 0.0
    reproducibility: float = 0.0

    def __post_init__(self):
        super().__post_init__()
        self.type = KnowledgeType.FINDING


@dataclass
class Correlation(KnowledgeItem):
    """Relationship between two or more pieces of knowledge"""
    item_ids: Optional[List[str]] = None
    correlation_type: str = ""
    strength: float = 0.0
    evidence: Optional[List[str]] = None

    def __post_init__(self):
        super().__post_init__()
        self.type = KnowledgeType.CORRELATION
        if self.item_ids is None:
            self.item_ids = []
        if self.evidence is None:
            self.evidence = []


@dataclass
class FailedAttempt(KnowledgeItem):
    """Record of something that was tried and didn't work"""
    attempt_type: str = ""
    expected_result: str = ""
    actual_result: str = ""
    lessons_learned: str = ""

    def __post_init__(self):
        super().__post_init__()
        self.type = KnowledgeType.FAILED_ATTEMPT


class KnowledgeBase:
    """Main knowledge base class for persistent storage"""

    def __init__(self, db_path: str = "knowledge_base.db"):
        self.db_path = Path(db_path)
        self.logger = logging.getLogger("knowledge_base")
        self._init_database()

    def _init_database(self):
        """Initialize the database schema"""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(self.db_path) as conn:
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
                    tags TEXT,  -- JSON array
                    source_agent TEXT,
                    related_items TEXT,  -- JSON array
                    metadata TEXT  -- JSON object
                )
            """)

            # Type-specific tables
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS facts (
                    id TEXT PRIMARY KEY,
                    evidence TEXT,  -- JSON array
                    source_references TEXT,  -- JSON array
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
                    item_ids TEXT,  -- JSON array
                    correlation_type TEXT,
                    strength REAL,
                    evidence TEXT,  -- JSON array
                    FOREIGN KEY (id) REFERENCES knowledge_items (id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS failed_attempts (
                    id TEXT PRIMARY KEY,
                    attempt_type TEXT,
                    expected_result TEXT,
                    actual_result TEXT,
                    lessons_learned TEXT,
                    FOREIGN KEY (id) REFERENCES knowledge_items (id)
                )
            """)

            # Indexes for better performance
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_type ON knowledge_items (type)")
            cursor.execute("CREATE INDEX IF NOT EXISTS tags_idx ON knowledge_items (tags)")
            cursor.execute("CREATE INDEX IF NOT EXISTS created_at_idx ON knowledge_items (created_at)")
            cursor.execute("CREATE INDEX IF NOT EXISTS confidence_idx ON knowledge_items (confidence)")

            conn.commit()

        self.logger.info(f"Knowledge base initialized at {self.db_path}")

    def _serialize_for_storage(self, obj: Any) -> str:
        """Serialize object for database storage"""
        if isinstance(obj, (list, dict)):
            return json.dumps(obj)
        return str(obj)

    def _deserialize_from_storage(self, data: str, expected_type: type = None) -> Any:
        """Deserialize object from database storage"""
        if not data:
            return [] if expected_type == list else {} if expected_type == dict else None

        try:
            return json.loads(data)
        except (json.JSONDecodeError, TypeError):
            return data

    def _row_to_knowledge_item(self, row: tuple, type_specific_data: dict) -> KnowledgeItem:
        """Convert database row to knowledge item"""
        # Row contains ki.* (11 cols) + joined columns; only unpack the 11 base columns
        (
            item_id, type_str, title, description, confidence,
            created_at, updated_at, tags_json, source_agent,
            related_items_json, metadata_json
        ) = row[:11]

        item_type = KnowledgeType(type_str)
        tags = self._deserialize_from_storage(tags_json, list)
        related_items = self._deserialize_from_storage(related_items_json, list)
        metadata = self._deserialize_from_storage(metadata_json, dict)

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

        # Return type-specific object
        base_dict = asdict(base_item)
        if item_type == KnowledgeType.FACT:
            return Fact(
                **base_dict,
                evidence=self._deserialize_from_storage(type_specific_data.get('evidence', '[]'), list),
                source_references=self._deserialize_from_storage(type_specific_data.get('source_references', '[]'), list)
            )
        elif item_type == KnowledgeType.HYPOTHESIS:
            return Hypothesis(
                **base_dict,
                basis=type_specific_data.get('basis', ''),
                testable=bool(type_specific_data.get('testable', False)),
                prediction=type_specific_data.get('prediction', ''),
                falsification_condition=type_specific_data.get('falsification_condition', '')
            )
        elif item_type == KnowledgeType.EXPERIMENT:
            return Experiment(
                **base_dict,
                hypothesis_id=type_specific_data.get('hypothesis_id', ''),
                setup=type_specific_data.get('setup', ''),
                procedure=type_specific_data.get('procedure', ''),
                results=type_specific_data.get('results', ''),
                conclusion=type_specific_data.get('conclusion', ''),
                replicated=bool(type_specific_data.get('replicated', False)),
                replication_count=int(type_specific_data.get('replication_count', 0))
            )
        elif item_type == KnowledgeType.FINDING:
            return Finding(
                **base_dict,
                location=type_specific_data.get('location', ''),
                evidence_strength=float(type_specific_data.get('evidence_strength', 0.0)),
                reproducibility=float(type_specific_data.get('reproducibility', 0.0))
            )
        elif item_type == KnowledgeType.CORRELATION:
            return Correlation(
                **base_dict,
                item_ids=self._deserialize_from_storage(type_specific_data.get('item_ids', '[]'), list),
                correlation_type=type_specific_data.get('correlation_type', ''),
                strength=float(type_specific_data.get('strength', 0.0)),
                evidence=self._deserialize_from_storage(type_specific_data.get('evidence', '[]'), list)
            )
        elif item_type == KnowledgeType.FAILED_ATTEMPT:
            return FailedAttempt(
                **base_dict,
                attempt_type=type_specific_data.get('attempt_type', ''),
                expected_result=type_specific_data.get('expected_result', ''),
                actual_result=type_specific_data.get('actual_result', ''),
                lessons_learned=type_specific_data.get('lessons_learned', '')
            )
        else:
            return base_item

    def add_knowledge_item(self, item: KnowledgeItem) -> str:
        """Add a knowledge item to the database"""
        if not item.id:
            item.id = str(uuid.uuid4())

        now = datetime.now().isoformat()
        if not item.created_at:
            item.created_at = now
        item.updated_at = now

        self.logger.info(f"Adding {item.type.value}: {item.title}")

        with sqlite3.connect(self.db_path) as conn:
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
                item.created_at,
                item.updated_at,
                self._serialize_for_storage(item.tags),
                item.source_agent,
                self._serialize_for_storage(item.related_items),
                self._serialize_for_storage(item.metadata)
            ))

            # Insert into type-specific table
            if isinstance(item, Fact):
                cursor.execute("""
                    INSERT OR REPLACE INTO facts
                    (id, evidence, source_references)
                    VALUES (?, ?, ?)
                """, (
                    item.id,
                    self._serialize_for_storage(item.evidence),
                    self._serialize_for_storage(item.source_references)
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
                    self._serialize_for_storage(item.item_ids),
                    item.correlation_type,
                    item.strength,
                    self._serialize_for_storage(item.evidence)
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

        return item.id

    def get_knowledge_item(self, item_id: str) -> Optional[KnowledgeItem]:
        """Retrieve a knowledge item by ID"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT ki.*,
                       f.evidence, f.source_references,
                       h.basis, h.testable, h.prediction, h.falsification_condition,
                       e.hypothesis_id, e.setup, e.procedure, e.results, e.conclusion, e.replicated, e.replication_count,
                       fi.location, fi.evidence_strength, fi.reproducibility,
                       c.item_ids, c.correlation_type, c.strength, c.evidence,
                       fa.attempt_type, fa.expected_result, fa.actual_result, fa.lessons_learned
                FROM knowledge_items ki
                LEFT JOIN facts f ON ki.id = f.id
                LEFT JOIN hypotheses h ON ki.id = h.id
                LEFT JOIN experiments e ON ki.id = e.id
                LEFT JOIN findings fi ON ki.id = fi.id
                LEFT JOIN correlations c ON ki.id = c.id
                LEFT JOIN failed_attempts fa ON ki.id = fa.id
                WHERE ki.id = ?
            """, (item_id,))

            row = cursor.fetchone()
            if row:
                # ki.* produces 11 columns (indices 0-10):
                # 0:id, 1:type, 2:title, 3:description, 4:confidence,
                # 5:created_at, 6:updated_at, 7:tags, 8:source_agent,
                # 9:related_items, 10:metadata
                # Joined columns start at index 11:
                type_specific = {}
                if row[11] is not None:  # f.evidence
                    type_specific.update({
                        'evidence': row[11],
                        'source_references': row[12]
                    })
                elif row[13] is not None:  # h.basis
                    type_specific.update({
                        'basis': row[13],
                        'testable': bool(row[14]),
                        'prediction': row[15],
                        'falsification_condition': row[16]
                    })
                elif row[17] is not None:  # e.hypothesis_id
                    type_specific.update({
                        'hypothesis_id': row[17],
                        'setup': row[18],
                        'procedure': row[19],
                        'results': row[20],
                        'conclusion': row[21],
                        'replicated': bool(row[22]),
                        'replication_count': row[23]
                    })
                elif row[24] is not None:  # fi.location
                    type_specific.update({
                        'location': row[24],
                        'evidence_strength': float(row[25]),
                        'reproducibility': float(row[26])
                    })
                elif row[27] is not None:  # c.item_ids
                    type_specific.update({
                        'item_ids': row[27],
                        'correlation_type': row[28],
                        'strength': float(row[29]),
                        'evidence': row[30]
                    })
                elif row[31] is not None:  # fa.attempt_type
                    type_specific.update({
                        'attempt_type': row[31],
                        'expected_result': row[32],
                        'actual_result': row[33],
                        'lessons_learned': row[34]
                    })

                return self._row_to_knowledge_item(row, type_specific)

        return None

    def search_knowledge(self,
                        query: str = None,
                        ktype: KnowledgeType = None,
                        tags: List[str] = None,
                        min_confidence: float = None,
                        limit: int = 100) -> List[KnowledgeItem]:
        """Search for knowledge items"""
        conditions = []
        params = []

        if query:
            conditions.append("(title LIKE ? OR description LIKE ?)")
            search_term = f"%{query}%"
            params.extend([search_term, search_term])

        if ktype:
            conditions.append("type = ?")
            params.append(ktype.value)

        if tags:
            # Check if any of the tags match
            tag_conditions = []
            for tag in tags:
                tag_conditions.append("tags LIKE ?")
                params.append(f"%{tag}%")
            conditions.append(f"({' OR '.join(tag_conditions)})")

        if min_confidence is not None:
            conditions.append("confidence >= ?")
            params.append(min_confidence)

        where_clause = " AND ".join(conditions) if conditions else "1=1"

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute(f"""
                SELECT ki.*,
                       f.evidence, f.source_references,
                       h.basis, h.testable, h.prediction, h.falsification_condition,
                       e.hypothesis_id, e.setup, e.procedure, e.results, e.conclusion, e.replicated, e.replication_count,
                       fi.location, fi.evidence_strength, fi.reproducibility,
                       c.item_ids, c.correlation_type, c.strength, c.evidence,
                       fa.attempt_type, fa.expected_result, fa.actual_result, fa.lessons_learned
                FROM knowledge_items ki
                LEFT JOIN facts f ON ki.id = f.id
                LEFT JOIN hypotheses h ON ki.id = h.id
                LEFT JOIN experiments e ON ki.id = e.id
                LEFT JOIN findings fi ON ki.id = fi.id
                LEFT JOIN correlations c ON ki.id = c.id
                LEFT JOIN failed_attempts fa ON ki.id = fa.id
                WHERE {where_clause}
                ORDER BY ki.confidence DESC, ki.updated_at DESC
                LIMIT ?
            """, (*params, limit))

            rows = cursor.fetchall()
            results = []

            for row in rows:
                # ki.* produces 11 columns (indices 0-10)
                type_specific = {}
                if row[11] is not None:  # f.evidence
                    type_specific.update({
                        'evidence': row[11],
                        'source_references': row[12]
                    })
                elif row[13] is not None:  # h.basis
                    type_specific.update({
                        'basis': row[13],
                        'testable': bool(row[14]),
                        'prediction': row[15],
                        'falsification_condition': row[16]
                    })
                elif row[17] is not None:  # e.hypothesis_id
                    type_specific.update({
                        'hypothesis_id': row[17],
                        'setup': row[18],
                        'procedure': row[19],
                        'results': row[20],
                        'conclusion': row[21],
                        'replicated': bool(row[22]),
                        'replication_count': row[23]
                    })
                elif row[24] is not None:  # fi.location
                    type_specific.update({
                        'location': row[24],
                        'evidence_strength': float(row[25]),
                        'reproducibility': float(row[26])
                    })
                elif row[27] is not None:  # c.item_ids
                    type_specific.update({
                        'item_ids': row[27],
                        'correlation_type': row[28],
                        'strength': float(row[29]),
                        'evidence': row[30]
                    })
                elif row[31] is not None:  # fa.attempt_type
                    type_specific.update({
                        'attempt_type': row[31],
                        'expected_result': row[32],
                        'actual_result': row[33],
                        'lessons_learned': row[34]
                    })

                item = self._row_to_knowledge_item(row, type_specific)
                if item:
                    results.append(item)

            return results

    def get_related_items(self, item_id: str, max_depth: int = 2) -> List[KnowledgeItem]:
        """Get items related to the given item (recursively up to max_depth)"""
        visited = set()
        to_visit = [item_id]
        results = []

        for depth in range(max_depth):
            if not to_visit:
                break

            next_level = []
            for current_id in to_visit:
                if current_id in visited:
                    continue
                visited.add(current_id)

                item = self.get_knowledge_item(current_id)
                if item:
                    results.append(item)
                    # Add related items to next level
                    for related_id in item.related_items:
                        if related_id not in visited:
                            next_level.append(related_id)

            to_visit = next_level

        return results

    def update_confidence(self, item_id: str, new_confidence: float, evidence_note: str = None):
        """Update the confidence of a knowledge item"""
        item = self.get_knowledge_item(item_id)
        if not item:
            raise ValueError(f"Item {item_id} not found")

        old_confidence = item.confidence
        item.confidence = max(0.0, min(1.0, new_confidence))  # Clamp to [0,1]
        item.updated_at = datetime.now().isoformat()

        if evidence_note:
            if 'evidence_notes' not in item.metadata:
                item.metadata['evidence_notes'] = []
            item.metadata['evidence_notes'].append({
                'timestamp': item.updated_at,
                'note': evidence_note,
                'old_confidence': old_confidence,
                'new_confidence': item.confidence
            })

        # Update in database
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE knowledge_items
                SET confidence = ?, updated_at = ?, metadata = ?
                WHERE id = ?
            """, (
                item.confidence,
                item.updated_at,
                self._serialize_for_storage(item.metadata),
                item_id
            ))
            conn.commit()

        self.logger.info(f"Updated confidence for {item_id}: {old_confidence} -> {item.confidence}")

    def link_items(self, item_id1: str, item_id2: str, relationship: str = "related"):
        """Create a bidirectional link between two items"""
        item1 = self.get_knowledge_item(item_id1)
        item2 = self.get_knowledge_item(item_id2)

        if not item1 or not item2:
            raise ValueError("One or both items not found")

        # Add to each other's related items if not already present
        if item_id2 not in item1.related_items:
            item1.related_items.append(item_id2)
            item1.updated_at = datetime.now().isoformat()

        if item_id1 not in item2.related_items:
            item2.related_items.append(item_id1)
            item2.updated_at = datetime.now().isoformat()

        # Update both in database
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE knowledge_items
                SET related_items = ?, updated_at = ?
                WHERE id = ?
            """, (
                self._serialize_for_storage(item1.related_items),
                item1.updated_at,
                item_id1
            ))
            cursor.execute("""
                UPDATE knowledge_items
                SET related_items = ?, updated_at = ?
                WHERE id = ?
            """, (
                self._serialize_for_storage(item2.related_items),
                item2.updated_at,
                item_id2
            ))
            conn.commit()

        self.logger.info(f"Linked items {item_id1} and {item_id2} with relationship '{relationship}'")

    def update_knowledge_item(self, item: KnowledgeItem):
        """Update an existing knowledge item in the database."""
        item.updated_at = datetime.now().isoformat()
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE knowledge_items
                SET title = ?, description = ?, confidence = ?, updated_at = ?,
                    tags = ?, source_agent = ?, metadata = ?
                WHERE id = ?
            """, (
                item.title,
                item.description,
                item.confidence,
                item.updated_at,
                self._serialize_for_storage(item.tags),
                item.source_agent,
                self._serialize_for_storage(item.metadata),
                item.id,
            ))
            conn.commit()
        self.logger.info(f"Updated knowledge item {item.id}: {item.title}")

    def delete_knowledge_item(self, item_id: str):
        """Delete a knowledge item and its type-specific record."""
        item = self.get_knowledge_item(item_id)
        if not item:
            raise ValueError(f"Item {item_id} not found")
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            type_table_map = {
                "fact": "facts",
                "hypothesis": "hypotheses",
                "experiment": "experiments",
                "finding": "findings",
                "correlation": "correlations",
                "failed_attempt": "failed_attempts",
            }
            table = type_table_map.get(item.type.value)
            if table:
                cursor.execute(f"DELETE FROM {table} WHERE id = ?", (item_id,))
            cursor.execute("DELETE FROM knowledge_items WHERE id = ?", (item_id,))
            conn.commit()
        self.logger.info(f"Deleted knowledge item {item_id}: {item.title}")

    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about the knowledge base"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Count by type
            cursor.execute("""
                SELECT type, COUNT(*)
                FROM knowledge_items
                GROUP BY type
            """)
            type_counts = dict(cursor.fetchall())

            # Total count
            cursor.execute("SELECT COUNT(*) FROM knowledge_items")
            total_count = cursor.fetchone()[0]

            # Average confidence
            cursor.execute("SELECT AVG(confidence) FROM knowledge_items")
            avg_confidence = cursor.fetchone()[0] or 0.0

            # Recent additions (last 24 hours)
            cursor.execute("""
                SELECT COUNT(*)
                FROM knowledge_items
                WHERE datetime(created_at) > datetime('now', '-1 day')
            """)
            recent_count = cursor.fetchone()[0]

            return {
                "total_items": total_count,
                "type_breakdown": type_counts,
                "average_confidence": round(avg_confidence, 3),
                "recent_24h": recent_count
            }

    def export_to_json(self, filepath: str):
        """Export knowledge base to JSON file"""
        items = self.search_knowledge(limit=10000)  # Get all items
        data = {
            "exported_at": datetime.now().isoformat(),
            "total_items": len(items),
            "items": [asdict(item) for item in items]
        }

        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, default=str)

        self.logger.info(f"Exported {len(items)} items to {filepath}")

    def import_from_json(self, filepath: str):
        """Import knowledge base from JSON file"""
        with open(filepath, 'r') as f:
            data = json.load(f)

        imported_count = 0
        for item_data in data.get("items", []):
            # Convert string dates back to proper format if needed
            try:
                item_type = KnowledgeType(item_data["type"])
                item_data["type"] = item_type

                # Create appropriate object
                if item_type == KnowledgeType.FACT:
                    item = Fact(**item_data)
                elif item_type == KnowledgeType.HYPOTHESIS:
                    item = Hypothesis(**item_data)
                elif item_type == KnowledgeType.EXPERIMENT:
                    item = Experiment(**item_data)
                elif item_type == KnowledgeType.FINDING:
                    item = Finding(**item_data)
                elif item_type == KnowledgeType.CORRELATION:
                    item = Correlation(**item_data)
                elif item_type == KnowledgeType.FAILED_ATTEMPT:
                    item = FailedAttempt(**item_data)
                else:
                    item = KnowledgeItem(**item_data)

                self.add_knowledge_item(item)
                imported_count += 1

            except Exception as e:
                self.logger.error(f"Failed to import item {item_data.get('id', 'unknown')}: {e}")

        self.logger.info(f"Imported {imported_count} items from {filepath}")


# Global knowledge base instance
kb = KnowledgeBase()


# Convenience functions for easy access
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
        evidence=evidence or [],
        source_references=source_references or []
    )
    return kb.add_knowledge_item(fact)


def add_hypothesis(title: str, description: str, confidence: float,
                   basis: str, testable: bool = True,
                   prediction: str = "", falsification_condition: str = "",
                   tags: List[str] = None, source_agent: str = None) -> str:
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
    return kb.add_knowledge_item(hypothesis)


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
    return kb.add_knowledge_item(experiment)


if __name__ == "__main__":
    # Example usage
    import asyncio
    import logging

    logging.basicConfig(level=logging.INFO)

    def main():
        # Add some sample knowledge
        fact_id = add_fact(
            title="GPU register 0x5000 controls command submission",
            description="Based on 17 experiments, register 0x5000 at offset 0x1000 in the GPU MMU controls command submission to the graphics pipeline.",
            confidence=0.95,
            evidence=["exp_001", "exp_002", "exp_003"],
            source_references=["gpu_manual_v2.pdf", "reverse_engineering_notes.txt"],
            tags=["gpu", "register", "command_submission", "hardware"],
            source_agent="hardware_behavior_agent"
        )

        hyp_id = add_hypothesis(
            title="Register 0x5000 also controls DMA transfers",
            description="Based on similar bit patterns in register 0x5000 and known DMA controllers, this register might also control DMA operations.",
            confidence=0.4,
            basis="Bit pattern analysis showing similarities with DMA controller registers",
            prediction="Writing specific values to register 0x5000 will initiate DMA transfers",
            falsification_condition="Writing test values to register 0x5000 produces no DMA activity",
            tags=["gpu", "register", "dma", "hypothesis"],
            source_agent="hardware_behavior_agent"
        )

        # Link the hypothesis to the fact
        kb.link_items(fact_id, hyp_id, "contradicts_evidence")

        # Add an experiment to test the hypothesis
        exp_id = add_experiment(
            title="Test DMA functionality of GPU register 0x5000",
            description="Write test patterns to register 0x5000 and monitor for DMA activity using logic analyzer.",
            confidence=0.8,
            hypothesis_id=hyp_id,
            setup="GPU connected to logic analyzer monitoring known DMA signals",
            procedure="1. Write 0x00000001 to register 0x5000\n2. Monitor DMA request/acknowledge lines\n3. Write 0x00000000 to register 0x5000\n4. Repeat with different values",
            results="",
            conclusion="",
            tags=["gpu", "dma", "experiment", "register_0x5000"],
            source_agent="experiment_design_agent"
        )

        # Link experiment to hypothesis
        kb.link_items(hyp_id, exp_id, "tests")

        # Show statistics
        stats = kb.get_statistics()
        print(f"Knowledge Base Statistics: {json.dumps(stats, indent=2)}")

        # Search for GPU-related items
        gpu_items = kb.search_knowledge(query="gpu", min_confidence=0.5)
        print(f"\nFound {len(gpu_items)} GPU-related items with confidence >= 0.5:")
        for item in gpu_items:
            print(f"  - [{item.type.value}] {item.title} (confidence: {item.confidence})")

    # Run example
    main()