"""
Knowledge Extraction from LLM Analysis Responses.
Automatically extracts facts, hypotheses, and correlations from
agent analysis results using LLM structured output.
"""

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from knowledge_base import (
    add_fact, add_hypothesis, kb,
)

logger = logging.getLogger("knowledge_extraction")


@dataclass
class ExtractionResult:
    """Result of knowledge extraction from an analysis."""
    facts_stored: List[str] = field(default_factory=list)
    hypotheses_stored: List[str] = field(default_factory=list)
    correlations_found: List[str] = field(default_factory=list)
    key_insights: List[str] = field(default_factory=list)
    confidence_assessment: float = 0.5

    def to_dict(self) -> Dict[str, Any]:
        return {
            "facts_stored": self.facts_stored,
            "hypotheses_stored": self.hypotheses_stored,
            "correlations_found": self.correlations_found,
            "key_insights": self.key_insights,
            "confidence_assessment": self.confidence_assessment,
        }


EXTRACTION_PROMPT = """You are a knowledge extraction system for reverse engineering analysis.

Given the following analysis results from a {agent_type} agent, extract:
1. Key FACTS (verified findings with evidence)
2. Testable HYPOTHESES (things that could be further investigated)
3. Key INSIGHTS (important observations)

Tool output summary:
{tool_summary}

Agent analysis result:
{analysis_result}

Return JSON with this exact structure:
{{
    "facts": [
        {{
            "title": "short fact title",
            "description": "detailed description",
            "confidence": 0.0-1.0,
            "evidence": ["evidence1", "evidence2"],
            "tags": ["tag1", "tag2"]
        }}
    ],
    "hypotheses": [
        {{
            "title": "short hypothesis title",
            "description": "detailed description",
            "basis": "why this hypothesis is reasonable",
            "confidence": 0.0-1.0,
            "tags": ["tag1"]
        }}
    ],
    "key_insights": ["insight1", "insight2"],
    "confidence_assessment": 0.0-1.0
}}

Rules:
- Extract 2-5 facts and 1-3 hypotheses
- Facts should be concrete, evidence-based findings
- Hypotheses should be testable with concrete tools or experiments
- Keep titles under 100 chars
- Confidence scores should reflect actual certainty from the evidence
- Tags should include the agent type and relevant domain tags
"""


class KnowledgeExtractor:
    """Extracts structured knowledge from LLM analysis responses."""

    def __init__(self, llm_client=None):
        self._llm_client = llm_client

    def _get_llm_client(self):
        """Get or create LLM client."""
        if self._llm_client is not None:
            return self._llm_client
        from llm_client import get_llm_client
        self._llm_client = get_llm_client()
        return self._llm_client

    async def extract_findings(
        self,
        agent_id: str,
        agent_type: str,
        tool_results: Dict[str, Any],
        llm_analysis: Dict[str, Any],
    ) -> ExtractionResult:
        """Extract facts, hypotheses, and insights from analysis results.

        Uses LLM to parse and structure the knowledge, then stores it in KB.
        """
        llm = self._get_llm_client()

        tool_summary = json.dumps(tool_results, default=str)[:2000]
        analysis_str = json.dumps(llm_analysis, default=str)[:3000]

        prompt = EXTRACTION_PROMPT.format(
            agent_type=agent_type,
            tool_summary=tool_summary,
            analysis_result=analysis_str,
        )

        messages = [
            {"role": "system", "content": "You are a knowledge extraction system. Always respond with valid JSON only."},
            {"role": "user", "content": prompt},
        ]

        try:
            response = await llm.chat_completion_json(messages, temperature=0.3)
        except Exception as e:
            logger.error(f"Knowledge extraction LLM call failed: {e}")
            return ExtractionResult(key_insights=["LLM extraction failed"], confidence_assessment=0.3)

        result = ExtractionResult(
            key_insights=response.get("key_insights", []),
            confidence_assessment=float(response.get("confidence_assessment", 0.5)),
        )

        # Store extracted facts
        for fact_data in response.get("facts", []):
            try:
                fact_id = add_fact(
                    title=fact_data.get("title", "Untitled fact")[:200],
                    description=fact_data.get("description", "")[:500],
                    confidence=float(fact_data.get("confidence", 0.5)),
                    evidence=fact_data.get("evidence", []),
                    tags=fact_data.get("tags", []) + [agent_type, "extracted"],
                    source_agent=agent_id,
                )
                result.facts_stored.append(fact_id)
            except Exception as e:
                logger.warning(f"Failed to store extracted fact: {e}")

        # Store extracted hypotheses
        for hyp_data in response.get("hypotheses", []):
            try:
                hyp_id = add_hypothesis(
                    title=hyp_data.get("title", "Untitled hypothesis")[:200],
                    description=hyp_data.get("description", "")[:500],
                    confidence=float(hyp_data.get("confidence", 0.4)),
                    basis=hyp_data.get("basis", ""),
                    testable=True,
                    tags=hyp_data.get("tags", []) + [agent_type, "extracted"],
                    source_agent=agent_id,
                )
                result.hypotheses_stored.append(hyp_id)
            except Exception as e:
                logger.warning(f"Failed to store extracted hypothesis: {e}")

        logger.info(
            f"Knowledge extraction complete: {len(result.facts_stored)} facts, "
            f"{len(result.hypotheses_stored)} hypotheses, "
            f"{len(result.key_insights)} insights"
        )
        return result

    async def extract_hypotheses(
        self,
        agent_id: str,
        context: str,
        tool_results: Dict[str, Any],
        agent_type: str = "general",
    ) -> List[Dict[str, str]]:
        """Extract hypotheses from analysis context.

        Returns list of hypothesis dicts with title, description, basis.
        """
        llm = self._get_llm_client()

        prompt = f"""Based on this reverse engineering context, generate 2-4 testable hypotheses.

Context: {context[:2000]}
Tool output: {json.dumps(tool_results, default=str)[:1500]}

Return JSON:
{{
    "hypotheses": [
        {{
            "title": "short title",
            "description": "what we think might be true",
            "basis": "evidence or reasoning supporting this",
            "confidence": 0.0-1.0,
            "how_to_test": "concrete way to verify or falsify"
        }}
    ]
}}"""

        messages = [
            {"role": "system", "content": "You are a reverse engineering researcher. Generate testable hypotheses."},
            {"role": "user", "content": prompt},
        ]

        try:
            response = await llm.chat_completion_json(messages, temperature=0.5)
            return response.get("hypotheses", [])
        except Exception as e:
            logger.warning(f"Hypothesis extraction failed: {e}")
            return []
