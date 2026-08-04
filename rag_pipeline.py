"""
RAG (Retrieval-Augmented Generation) Pipeline for the Reverse Engineering Lab.
Provides semantic search, context building, and knowledge storage with embeddings.
"""

import json
import logging
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from embeddings import EmbeddingManager, EmbeddingResult, cosine_similarity
from knowledge_base import (
    Finding, KnowledgeBase, KnowledgeItem, KnowledgeType,
    add_fact, add_hypothesis, kb,
)

logger = logging.getLogger("rag_pipeline")


class RAGPipeline:
    """Retrieval-Augmented Generation pipeline.

    Stores analysis results with embeddings and provides semantic search
    for building LLM context from past analyses.
    """

    def __init__(
        self,
        knowledge_base: Optional[KnowledgeBase] = None,
        embedding_manager: Optional[EmbeddingManager] = None,
    ):
        self.kb = knowledge_base or kb
        self.embedding_manager = embedding_manager or EmbeddingManager.from_settings()
        self.db_path = self.kb.db_path
        self._init_embeddings_table()

    def _init_embeddings_table(self):
        """Create embeddings table if it doesn't exist."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS embeddings (
                    id TEXT PRIMARY KEY,
                    item_id TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    embedding BLOB NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (item_id) REFERENCES knowledge_items (id)
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_embeddings_item_id
                ON embeddings (item_id)
            """)
            conn.commit()

    def _store_embedding(
        self, item_id: str, embedding: List[float], provider: str
    ) -> str:
        """Store an embedding vector in the database."""
        emb_id = str(uuid.uuid4())
        now = datetime.now().isoformat()
        emb_blob = json.dumps(embedding).encode("utf-8")
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO embeddings (id, item_id, provider, embedding, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (emb_id, item_id, provider, emb_blob, now),
            )
            conn.commit()
        return emb_id

    def _load_all_embeddings(self) -> List[Tuple[str, str, List[float], str]]:
        """Load all embeddings from the database.

        Returns list of (item_id, provider, embedding_list, created_at).
        """
        results = []
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT item_id, provider, embedding, created_at FROM embeddings"
            )
            for row in cursor.fetchall():
                item_id, provider, emb_blob, created_at = row
                embedding = json.loads(emb_blob.decode("utf-8"))
                results.append((item_id, provider, embedding, created_at))
        return results

    def _summarize_item_for_embedding(self, item: KnowledgeItem) -> str:
        """Create a text summary of a knowledge item for embedding."""
        parts = [
            f"Type: {item.type.value}",
            f"Title: {item.title}",
            f"Description: {item.description}",
            f"Confidence: {item.confidence}",
        ]
        if item.tags:
            parts.append(f"Tags: {', '.join(item.tags)}")
        if isinstance(item, Finding):
            if item.location:
                parts.append(f"Location: {item.location}")
        return " | ".join(parts)

    async def store_analysis_result(
        self,
        agent_id: str,
        analysis_type: str,
        result_dict: Dict[str, Any],
        tags: Optional[List[str]] = None,
        summary_text: Optional[str] = None,
    ) -> str:
        """Store an analysis result as a Finding with embedding.

        Returns the KB item ID.
        """
        # Build summary text for embedding
        if not summary_text:
            summary_parts = []
            if "summary" in result_dict and isinstance(result_dict["summary"], dict):
                for k, v in result_dict["summary"].items():
                    summary_parts.append(f"{k}: {v}")
            elif "file_path" in result_dict:
                summary_parts.append(f"file: {result_dict['file_path']}")
            summary_parts.append(f"analysis_type: {analysis_type}")
            summary_text = " | ".join(summary_parts) if summary_parts else f"{analysis_type} analysis"

        # Truncate for embedding
        summary_text = summary_text[:2000]

        # Store in knowledge base
        finding = Finding(
            id="",
            type=KnowledgeType.FINDING,
            title=f"{analysis_type} analysis result",
            description=summary_text[:500],
            confidence=0.7,
            created_at="",
            updated_at="",
            tags=tags or [analysis_type, "automated_analysis"],
            source_agent=agent_id,
            location=result_dict.get("file_path", ""),
            evidence_strength=0.7,
        )
        item_id = self.kb.add_knowledge_item(finding)

        # Generate and store embedding
        try:
            emb_result = await self.embedding_manager.embed(summary_text)
            self._store_embedding(item_id, emb_result.embedding, emb_result.provider_name)
        except Exception as e:
            logger.warning(f"Failed to store embedding for {item_id}: {e}")

        logger.info(f"Stored analysis result in KB (id={item_id})")
        return item_id

    async def retrieve_similar(
        self,
        query: str,
        top_k: int = 5,
        min_confidence: float = 0.0,
    ) -> List[Dict[str, Any]]:
        """Find knowledge items similar to the query text using cosine similarity.

        Returns list of dicts with keys: item_id, score, item (KnowledgeItem).
        """
        # Embed the query
        try:
            query_emb = await self.embedding_manager.embed(query)
        except Exception as e:
            logger.error(f"Failed to embed query: {e}")
            return []

        # Load all stored embeddings
        all_embeddings = self._load_all_embeddings()
        if not all_embeddings:
            return []

        # Compute similarities
        scored: List[Tuple[float, str, str]] = []
        for item_id, provider, stored_emb, created_at in all_embeddings:
            score = cosine_similarity(query_emb.embedding, stored_emb)
            scored.append((score, item_id, provider))

        # Sort by score descending
        scored.sort(key=lambda x: x[0], reverse=True)

        # Fetch full items and filter by confidence
        results: List[Dict[str, Any]] = []
        for score, item_id, provider in scored[:top_k * 2]:  # fetch extra for filtering
            item = self.kb.get_knowledge_item(item_id)
            if item is None:
                continue
            if item.confidence < min_confidence:
                continue
            results.append({
                "item_id": item_id,
                "score": round(score, 4),
                "item": item,
                "embedding_provider": provider,
            })
            if len(results) >= top_k:
                break

        return results

    async def build_context_for_analysis(
        self,
        query: str,
        max_tokens: int = 3000,
    ) -> str:
        """Build a context string from similar KB items for LLM prompt injection.

        Returns a formatted string suitable for inclusion in an LLM system prompt.
        """
        similar = await self.retrieve_similar(query, top_k=10)
        if not similar:
            return "No relevant prior knowledge found in the knowledge base."

        context_parts = ["## Relevant Prior Knowledge\n"]
        estimated_tokens = 50  # overhead

        for entry in similar:
            item = entry["item"]
            block = (
                f"- [{item.type.value.upper()}] {item.title} "
                f"(confidence: {item.confidence}, score: {entry['score']})\n"
                f"  {item.description[:300]}\n"
            )
            block_tokens = len(block) // 4
            if estimated_tokens + block_tokens > max_tokens:
                break
            context_parts.append(block)
            estimated_tokens += block_tokens

        return "\n".join(context_parts)

    async def store_hypothesis_from_analysis(
        self,
        agent_id: str,
        title: str,
        description: str,
        basis: str,
        confidence: float = 0.5,
        tags: Optional[List[str]] = None,
    ) -> str:
        """Store a hypothesis generated by an agent's LLM analysis."""
        hyp_id = add_hypothesis(
            title=title,
            description=description,
            confidence=confidence,
            basis=basis,
            testable=True,
            prediction="To be determined through experimentation",
            falsification_condition="Contradictory evidence from tool analysis",
            tags=tags or ["hypothesis", "llm_generated"],
            source_agent=agent_id,
        )

        # Store embedding of hypothesis
        text = f"Hypothesis: {title}. {description}. Basis: {basis}"
        try:
            emb_result = await self.embedding_manager.embed(text)
            self._store_embedding(hyp_id, emb_result.embedding, emb_result.provider_name)
        except Exception as e:
            logger.warning(f"Failed to store hypothesis embedding: {e}")

        logger.info(f"Stored hypothesis from {agent_id}: {title} (id={hyp_id})")
        return hyp_id
