"""
LLM-Powered Self-Critique for the Reverse Engineering Lab.
Evaluates analysis quality, detects issues, and generates improvement suggestions.
"""

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("self_critique")


@dataclass
class CritiqueResult:
    """Result of an LLM-powered self-critique evaluation."""
    score: float  # 0.0 - 1.0 overall quality
    completeness_score: float  # 0.0 - 1.0
    accuracy_score: float  # 0.0 - 1.0
    consistency_score: float  # 0.0 - 1.0
    issues_found: List[str] = field(default_factory=list)
    improvement_suggestions: List[str] = field(default_factory=list)
    missing_areas: List[str] = field(default_factory=list)
    raw_llm_response: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "completeness_score": self.completeness_score,
            "accuracy_score": self.accuracy_score,
            "consistency_score": self.consistency_score,
            "issues_found": self.issues_found,
            "improvement_suggestions": self.improvement_suggestions,
            "missing_areas": self.missing_areas,
        }


# Default critique prompts by agent type
AGENT_CRITIQUE_PROMPTS = {
    "binary_analysis": """You are a senior reverse engineer evaluating the quality of a binary analysis.

Tool output summary:
{tool_summary}

Agent's analysis result:
{analysis_result}

Evaluate this analysis on:
1. Completeness (0.0-1.0): Did it cover all important aspects? Missing sections, imports, strings, functions?
2. Accuracy (0.0-1.0): Are the findings supported by the tool output? Any contradictions?
3. Consistency (0.0-1.0): Are the findings internally consistent? No conflicting conclusions?

Return JSON:
{{
    "completeness_score": 0.0-1.0,
    "accuracy_score": 0.0-1.0,
    "consistency_score": 0.0-1.0,
    "issues_found": ["issue1", "issue2"],
    "improvement_suggestions": ["suggestion1", "suggestion2"],
    "missing_areas": ["area1", "area2"]
}}""",

    "firmware_analysis": """You are a firmware security expert evaluating analysis quality.

Tool output summary:
{tool_summary}

Agent's analysis result:
{analysis_result}

Evaluate completeness, accuracy, and consistency of the firmware analysis.
Did it adequately cover: filesystem structure, embedded strings, architecture detection,
security indicators, hardcoded credentials, debug interfaces?

Return JSON:
{{
    "completeness_score": 0.0-1.0,
    "accuracy_score": 0.0-1.0,
    "consistency_score": 0.0-1.0,
    "issues_found": ["issue1"],
    "improvement_suggestions": ["suggestion1"],
    "missing_areas": ["area1"]
}}""",

    "networking": """You are a network security analyst evaluating traffic analysis quality.

Tool output summary:
{tool_summary}

Agent's analysis result:
{analysis_result}

Evaluate the network analysis: protocol identification, traffic patterns,
security indicators, suspicious connections, DNS analysis, TLS inspection.

Return JSON:
{{
    "completeness_score": 0.0-1.0,
    "accuracy_score": 0.0-1.0,
    "consistency_score": 0.0-1.0,
    "issues_found": ["issue1"],
    "improvement_suggestions": ["suggestion1"],
    "missing_areas": ["area1"]
}}""",

    "cpu_analysis": """You are a CPU architecture expert evaluating disassembly analysis quality.

Tool output summary:
{tool_summary}

Agent's analysis result:
{analysis_result}

Evaluate: instruction classification accuracy, function boundary detection,
control flow analysis, architecture identification, algorithm detection.

Return JSON:
{{
    "completeness_score": 0.0-1.0,
    "accuracy_score": 0.0-1.0,
    "consistency_score": 0.0-1.0,
    "issues_found": ["issue1"],
    "improvement_suggestions": ["suggestion1"],
    "missing_areas": ["area1"]
}}""",

    "os_kernel": """You are a kernel security expert evaluating OS/kernel analysis quality.

Tool output summary:
{tool_summary}

Agent's analysis result:
{analysis_result}

Evaluate: kernel version/config identification, syscall analysis,
security mitigation detection, module analysis, vulnerability assessment.

Return JSON:
{{
    "completeness_score": 0.0-1.0,
    "accuracy_score": 0.0-1.0,
    "consistency_score": 0.0-1.0,
    "issues_found": ["issue1"],
    "improvement_suggestions": ["suggestion1"],
    "missing_areas": ["area1"]
}}""",
}

DEFAULT_CRITIQUE_PROMPT = """You are an expert reverse engineering analyst evaluating analysis quality.

Tool output summary:
{tool_summary}

Agent's analysis result:
{analysis_result}

Evaluate completeness, accuracy, and consistency.
Return JSON:
{{
    "completeness_score": 0.0-1.0,
    "accuracy_score": 0.0-1.0,
    "consistency_score": 0.0-1.0,
    "issues_found": ["issue1"],
    "improvement_suggestions": ["suggestion1"],
    "missing_areas": ["area1"]
}}"""


class SelfCritique:
    """LLM-powered self-critique system."""

    def __init__(self, llm_client=None):
        self._llm_client = llm_client

    def _get_llm_client(self):
        """Get or create LLM client."""
        if self._llm_client is not None:
            return self._llm_client
        from llm_client import get_llm_client
        self._llm_client = get_llm_client()
        return self._llm_client

    async def evaluate_analysis(
        self,
        agent_type: str,
        tool_output_summary: str,
        analysis_result: Dict[str, Any],
    ) -> CritiqueResult:
        """Evaluate an agent's analysis using LLM self-critique.

        Args:
            agent_type: The agent type (e.g., 'binary_analysis', 'firmware_analysis')
            tool_output_summary: Summary of raw tool outputs
            analysis_result: The agent's structured analysis result dict

        Returns:
            CritiqueResult with scores and suggestions
        """
        llm = self._get_llm_client()

        prompt_template = AGENT_CRITIQUE_PROMPTS.get(
            agent_type, DEFAULT_CRITIQUE_PROMPT
        )

        # Truncate for token budget
        tool_summary = str(tool_output_summary)[:2000]
        analysis_str = json.dumps(analysis_result, indent=2, default=str)[:3000]

        prompt = prompt_template.format(
            tool_summary=tool_summary,
            analysis_result=analysis_str,
        )

        messages = [
            {"role": "system", "content": "You are an expert analyst. Always respond with valid JSON only."},
            {"role": "user", "content": prompt},
        ]

        try:
            response = await llm.chat_completion_json(messages, temperature=0.3)
        except Exception as e:
            logger.error(f"Self-critique LLM call failed: {e}")
            return self._heuristic_fallback(tool_output_summary, analysis_result)

        return CritiqueResult(
            score=self._avg_score(response),
            completeness_score=float(response.get("completeness_score", 0.5)),
            accuracy_score=float(response.get("accuracy_score", 0.5)),
            consistency_score=float(response.get("consistency_score", 0.5)),
            issues_found=response.get("issues_found", []),
            improvement_suggestions=response.get("improvement_suggestions", []),
            missing_areas=response.get("missing_areas", []),
            raw_llm_response=json.dumps(response, default=str),
        )

    async def should_re_analyze(
        self,
        critique_result: CritiqueResult,
        confidence_threshold: float = 0.6,
    ) -> bool:
        """Determine if re-analysis is needed based on critique score."""
        if critique_result.score < confidence_threshold:
            return True
        critical_issues = [
            i for i in critique_result.issues_found
            if any(kw in i.lower() for kw in ["contradict", "incorrect", "wrong", "error", "invalid"])
        ]
        if critical_issues:
            return True
        return False

    async def generate_next_steps(
        self,
        agent_type: str,
        analysis_result: Dict[str, Any],
        critique_result: CritiqueResult,
    ) -> List[str]:
        """Generate concrete next investigation steps based on critique."""
        llm = self._get_llm_client()

        prompt = f"""Based on this {agent_type} analysis and its critique, generate 3-5 concrete next steps.

Analysis summary: {json.dumps(analysis_result, default=str)[:2000]}
Critique score: {critique_result.score:.2f}
Issues found: {', '.join(critique_result.issues_found[:5])}
Missing areas: {', '.join(critique_result.missing_areas[:5])}

Return JSON: {{"next_steps": ["step1", "step2", ...]}}"""

        messages = [
            {"role": "system", "content": "You are an expert reverse engineer. Provide actionable next steps."},
            {"role": "user", "content": prompt},
        ]

        try:
            response = await llm.chat_completion_json(messages, temperature=0.5)
            return response.get("next_steps", [])
        except Exception as e:
            logger.warning(f"Failed to generate next steps: {e}")
            return critique_result.improvement_suggestions[:5]

    @staticmethod
    def _avg_score(response: Dict[str, Any]) -> float:
        """Compute average of the three sub-scores."""
        scores = []
        for key in ("completeness_score", "accuracy_score", "consistency_score"):
            try:
                scores.append(float(response.get(key, 0.5)))
            except (ValueError, TypeError):
                scores.append(0.5)
        return round(sum(scores) / len(scores), 3) if scores else 0.5

    @staticmethod
    def _heuristic_fallback(
        tool_output_summary: str,
        analysis_result: Dict[str, Any],
    ) -> CritiqueResult:
        """Heuristic fallback when LLM is unavailable."""
        completeness = 0.5
        accuracy = 0.5
        consistency = 0.5
        issues = []
        suggestions = []
        missing = []

        # Check if analysis has meaningful content
        result_str = json.dumps(analysis_result, default=str)
        if len(result_str) < 100:
            completeness = 0.2
            issues.append("Analysis result is very sparse")
            suggestions.append("Run more detailed analysis with additional tools")

        if "error" in analysis_result:
            accuracy = 0.3
            issues.append(f"Analysis contains error: {analysis_result['error']}")

        if "summary" not in analysis_result and "basic_info" not in analysis_result:
            completeness = 0.4
            missing.append("Summary section")
            suggestions.append("Add summary of key findings")

        has_tools = bool(tool_output_summary and len(tool_output_summary) > 50)
        if not has_tools:
            accuracy = 0.3
            issues.append("No significant tool output to validate analysis")

        avg = round((completeness + accuracy + consistency) / 3, 3)
        return CritiqueResult(
            score=avg,
            completeness_score=completeness,
            accuracy_score=accuracy,
            consistency_score=consistency,
            issues_found=issues,
            improvement_suggestions=suggestions,
            missing_areas=missing,
        )
