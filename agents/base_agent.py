"""
Base Agent Class for the Reverse Engineering Lab
Provides common functionality for all specialized agents
"""

import abc
import logging
from typing import Dict, Any, List, Optional, TYPE_CHECKING
from datetime import datetime
from enum import IntEnum
from dataclasses import dataclass, field
import json
import uuid

if TYPE_CHECKING:
    from llm_client import LLMClient
    from rag_pipeline import RAGPipeline
    from self_critique import CritiqueResult
    from knowledge_extraction import ExtractionResult
    from token_budget import TokenBudgetManager


class AgentStatus(IntEnum):
    """Agent lifecycle states"""
    IDLE = 0
    BUSY = 1
    PROCESSING = 2
    ERROR = 3
    SHUTDOWN = 4


class AgentPriority(IntEnum):
    """Task priority levels for agent scheduling"""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4


@dataclass
class Task:
    """A unit of work assigned to an agent"""
    task_id: str
    description: str
    agent_type: str
    priority: Any = AgentPriority.MEDIUM
    parameters: Optional[Dict[str, Any]] = None
    status: str = "pending"
    result: Optional[Any] = None
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    started_at: Optional[str] = None
    completed_at: Optional[str] = None


@dataclass
class AgentResult:
    """Result returned after an agent completes a task"""
    task_id: str
    agent_id: str
    status: str
    result: Any = None
    error: Optional[str] = None
    confidence: float = 0.0
    reasoning_trace: List[Dict[str, Any]] = field(default_factory=list)
    tools_used: List[str] = field(default_factory=list)
    llm_analysis: Optional[Dict[str, Any]] = None
    critique: Optional[Dict[str, Any]] = None
    knowledge_extraction: Optional[Dict[str, Any]] = None
    confidence_score: float = 0.0  # computed composite confidence
    debate_result: Optional[Dict[str, Any]] = None
    reanalysis_count: int = 0
    completed_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def add_reasoning_step(self, step: str, detail: Any = None, tool: Optional[str] = None):
        """Append a step to the reasoning trace."""
        entry: Dict[str, Any] = {"step": step, "timestamp": datetime.now().isoformat()}
        if detail is not None:
            entry["detail"] = detail
        if tool:
            entry["tool"] = tool
            if tool not in self.tools_used:
                self.tools_used.append(tool)
        self.reasoning_trace.append(entry)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a plain dict."""
        return {
            "task_id": self.task_id,
            "agent_id": self.agent_id,
            "status": self.status,
            "result": self.result,
            "error": self.error,
            "confidence": self.confidence,
            "reasoning_trace": self.reasoning_trace,
            "tools_used": self.tools_used,
            "llm_analysis": self.llm_analysis,
            "critique": self.critique,
            "knowledge_extraction": self.knowledge_extraction,
            "confidence_score": self.confidence_score,
            "debate_result": self.debate_result,
            "reanalysis_count": self.reanalysis_count,
            "completed_at": self.completed_at,
        }

    def compute_confidence(
        self,
        tool_weight: float = 0.3,
        llm_weight: float = 0.4,
        critique_weight: float = 0.3,
    ) -> float:
        """Compute composite confidence score from tool output, LLM analysis, and critique.

        Returns a value between 0.0 and 1.0.
        """
        scores: List[float] = []
        weights: List[float] = []

        # Tool-based confidence: at least 0.5 if tools were used, else 0.2
        if self.tools_used:
            tool_confidence = min(1.0, 0.5 + 0.1 * len(self.tools_used))
        else:
            tool_confidence = 0.2
        scores.append(tool_confidence)
        weights.append(tool_weight)

        # LLM-based confidence
        if self.llm_analysis and "confidence" in self.llm_analysis:
            try:
                llm_confidence = float(self.llm_analysis["confidence"])
                llm_confidence = max(0.0, min(1.0, llm_confidence))
            except (ValueError, TypeError):
                llm_confidence = 0.5
        else:
            llm_confidence = 0.5
        scores.append(llm_confidence)
        weights.append(llm_weight)

        # Critique-based confidence
        if self.critique and "score" in self.critique:
            try:
                critique_confidence = float(self.critique["score"])
                critique_confidence = max(0.0, min(1.0, critique_confidence))
            except (ValueError, TypeError):
                critique_confidence = 0.5
        else:
            critique_confidence = 0.5
        scores.append(critique_confidence)
        weights.append(critique_weight)

        # Weighted average
        total_weight = sum(weights)
        if total_weight == 0:
            self.confidence_score = 0.5
        else:
            self.confidence_score = round(
                sum(s * w for s, w in zip(scores, weights)) / total_weight, 4
            )

        self.confidence = self.confidence_score
        return self.confidence_score


class BaseAgent(abc.ABC):
    """Base class for all agents in the reverse engineering lab"""

    def __init__(self, agent_id: str, name: str, description: str):
        self.agent_id = agent_id or str(uuid.uuid4())
        self.name = name
        self.description = description
        self.logger = logging.getLogger(f"agent.{name}")
        self.memory = {}  # Simple in-memory knowledge base
        self.tools = {}   # Available tools/MCP connections
        self.is_active = False
        self.status = AgentStatus.IDLE
        self.current_task: Optional[Task] = None
        self.created_at = datetime.now()
        self.last_active = datetime.now()

    @abc.abstractmethod
    async def initialize(self) -> bool:
        """Initialize the agent and its resources"""
        pass

    @abc.abstractmethod
    async def execute_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a assigned task"""
        pass

    @abc.abstractmethod
    async def cleanup(self) -> bool:
        """Clean up resources"""
        pass

    def activate(self):
        """Activate the agent"""
        self.is_active = True
        self.last_active = datetime.now()
        self.logger.info(f"Agent {self.name} activated")

    def deactivate(self):
        """Deactivate the agent"""
        self.is_active = False
        self.last_active = datetime.now()
        self.logger.info(f"Agent {self.name} deactivated")

    def add_to_memory(self, key: str, value: Any, category: str = "general"):
        """Add information to agent's memory"""
        if category not in self.memory:
            self.memory[category] = {}
        self.memory[category][key] = {
            "value": value,
            "timestamp": datetime.now().isoformat()
        }
        self.logger.debug(f"Added to memory [{category}]: {key}")

    def get_from_memory(self, key: str, category: str = "general") -> Any:
        """Retrieve information from agent's memory"""
        if category in self.memory and key in self.memory[category]:
            return self.memory[category][key]["value"]
        return None

    def register_tool(self, tool_name: str, tool_instance: Any):
        """Register a tool/MCP connection with the agent"""
        self.tools[tool_name] = tool_instance
        self.logger.debug(f"Registered tool: {tool_name}")

    def get_tool(self, tool_name: str) -> Any:
        """Get a registered tool"""
        return self.tools.get(tool_name)

    def get_status(self) -> Dict[str, Any]:
        """Get current agent status"""
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "description": self.description,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat(),
            "last_active": self.last_active.isoformat(),
            "memory_categories": list(self.memory.keys()),
            "registered_tools": list(self.tools.keys())
        }

    def is_available(self) -> bool:
        """Check if the agent is available for new work"""
        return self.status == AgentStatus.IDLE and self.is_active

    async def start_task(self, task: Task):
        """Mark agent as working on a task"""
        self.current_task = task
        self.status = AgentStatus.PROCESSING
        self.last_active = datetime.now()
        self.logger.info(f"Starting task {task.task_id}: {task.description}")

    async def complete_current_task(self):
        """Mark current task as done and return to idle"""
        if self.current_task:
            self.current_task.completed_at = datetime.now().isoformat()
            self.logger.info(f"Completed task {self.current_task.task_id}")
        self.current_task = None
        self.status = AgentStatus.IDLE

    async def shutdown(self):
        """Gracefully shut down the agent"""
        self.logger.info(f"Shutting down agent {self.name}")
        await self.cleanup()
        self.status = AgentStatus.SHUTDOWN
        self.is_active = False


class AnalysisAgent(BaseAgent):
    """Base class for analysis-oriented agents"""

    def __init__(self, agent_id: str, name: str, description: str):
        super().__init__(agent_id, name, description)
        self.analysis_results = {}
        self.tool_outputs: List[Dict[str, Any]] = []
        self._llm_client: Optional[Any] = None
        self._rag_pipeline: Optional[Any] = None
        self._knowledge_extractor: Optional[Any] = None
        self._self_critique: Optional[Any] = None
        self._token_budget_manager: Optional[Any] = None
        self._mission_id: Optional[str] = None
        self._llm_initialized = False

    def store_analysis_result(self, key: str, result: Any, confidence: float = 1.0):
        """Store an analysis result with confidence score"""
        self.analysis_results[key] = {
            "result": result,
            "confidence": confidence,
            "timestamp": datetime.now().isoformat()
        }
        self.add_to_memory(key, result, "analysis")

    def get_analysis_result(self, key: str) -> Any:
        """Retrieve an analysis result"""
        if key in self.analysis_results:
            return self.analysis_results[key]["result"]
        return None

    def record_tool_output(self, tool_name: str, command: str, stdout: str,
                           stderr: str = "", returncode: int = 0):
        """Record raw tool output for inclusion in reasoning traces."""
        entry = {
            "tool": tool_name,
            "command": command,
            "stdout": stdout[:5000],
            "stderr": stderr[:2000],
            "returncode": returncode,
            "timestamp": datetime.now().isoformat(),
        }
        self.tool_outputs.append(entry)
        return entry

    async def _init_llm_and_rag(self):
        """Initialize LLM client, RAG pipeline, and related components.

        Called lazily on first use. Raises LLMClientNotConfiguredError if no API key.
        """
        if self._llm_initialized:
            return

        try:
            from llm_client import get_llm_client
            self._llm_client = get_llm_client()
        except Exception as e:
            self.logger.warning(f"LLM client not available: {e}")
            self._llm_client = None

        try:
            from rag_pipeline import RAGPipeline
            self._rag_pipeline = RAGPipeline()
        except Exception as e:
            self.logger.warning(f"RAG pipeline not available: {e}")
            self._rag_pipeline = None

        try:
            from knowledge_extraction import KnowledgeExtractor
            self._knowledge_extractor = KnowledgeExtractor(llm_client=self._llm_client)
        except Exception as e:
            self.logger.warning(f"Knowledge extractor not available: {e}")
            self._knowledge_extractor = None

        try:
            from self_critique import SelfCritique
            self._self_critique = SelfCritique(llm_client=self._llm_client)
        except Exception as e:
            self.logger.warning(f"Self-critique not available: {e}")
            self._self_critique = None

        self._llm_initialized = True

    def _build_tool_summary(self) -> str:
        """Build a text summary of collected tool outputs for LLM consumption."""
        if not self.tool_outputs:
            return "No tool outputs collected."
        parts = []
        for entry in self.tool_outputs[-10:]:  # last 10 outputs
            tool = entry.get("tool", "unknown")
            stdout = entry.get("stdout", "")[:500]
            parts.append(f"[{tool}]\n{stdout}")
        return "\n\n".join(parts)

    async def _run_llm_analysis(
        self,
        tool_results: Dict[str, Any],
        prompt_override: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Run LLM-powered analysis on tool results.

        Returns parsed JSON analysis or None if LLM is unavailable.
        """
        if not self._llm_client:
            try:
                await self._init_llm_and_rag()
            except Exception:
                return None

        if not self._llm_client:
            return None

        tool_summary = self._build_tool_summary()
        result_str = json.dumps(tool_results, default=str)[:3000]

        if prompt_override:
            user_prompt = prompt_override
        else:
            user_prompt = self._build_analysis_prompt(tool_summary, result_str)

        messages = [
            {"role": "system", "content": self._build_system_prompt()},
            {"role": "user", "content": user_prompt},
        ]

        try:
            response = await self._llm_client.chat_completion_json(messages)
            return response
        except Exception as e:
            self.logger.error(f"LLM analysis failed: {e}")
            return None

    def _build_system_prompt(self) -> str:
        """Build the system prompt for this agent type. Override in subclasses."""
        return (
            f"You are a reverse engineering expert specializing in {self.agent_type} analysis. "
            "Analyze the provided tool outputs and extract key findings, security concerns, "
            "and actionable insights. Always respond with valid JSON."
        )

    def _build_analysis_prompt(self, tool_summary: str, result_str: str) -> str:
        """Build the analysis prompt. Override in subclasses for specialization."""
        return (
            f"Analyze the following {self.agent_type} tool outputs and results.\n\n"
            f"Tool outputs:\n{tool_summary}\n\n"
            f"Parsed results:\n{result_str}\n\n"
            "Extract key findings, security concerns, and insights.\n"
            "Return JSON with: key_findings (list), security_concerns (list), "
            "confidence (0.0-1.0), next_steps (list of strings)."
        )

    async def _run_self_critique(
        self,
        tool_output_summary: str,
        analysis_result: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Run self-critique on the analysis result."""
        if not self._self_critique:
            return None
        try:
            from config.settings import CRITIQUE_ENABLED, CRITIQUE_CONFIDENCE_THRESHOLD
            if not CRITIQUE_ENABLED:
                return None
            critique = await self._self_critique.evaluate_analysis(
                self.agent_type, tool_output_summary, analysis_result,
            )
            return critique.to_dict()
        except Exception as e:
            self.logger.warning(f"Self-critique failed: {e}")
            return None

    async def _run_knowledge_extraction(
        self,
        tool_results: Dict[str, Any],
        llm_analysis: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Extract and store knowledge from analysis results."""
        if not self._knowledge_extractor:
            return None
        try:
            from config.settings import KNOWLEDGE_EXTRACTION_ENABLED
            if not KNOWLEDGE_EXTRACTION_ENABLED:
                return None
            extraction = await self._knowledge_extractor.extract_findings(
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                tool_results=tool_results,
                llm_analysis=llm_analysis,
            )
            return extraction.to_dict()
        except Exception as e:
            self.logger.warning(f"Knowledge extraction failed: {e}")
            return None

    async def _store_with_rag(
        self,
        result_dict: Dict[str, Any],
        tags: Optional[List[str]] = None,
    ) -> Optional[str]:
        """Store analysis result in RAG pipeline for future retrieval."""
        if not self._rag_pipeline:
            return None
        try:
            return await self._rag_pipeline.store_analysis_result(
                agent_id=self.agent_id,
                analysis_type=self.agent_type,
                result_dict=result_dict,
                tags=tags,
            )
        except Exception as e:
            self.logger.warning(f"RAG storage failed: {e}")
            return None

    async def _init_token_budget(self, mission_id: Optional[str] = None):
        """Initialize token budget manager if not already set."""
        if self._token_budget_manager is not None:
            return
        try:
            from token_budget import TokenBudgetManager
            from config.settings import (
                TOKEN_BUDGET_ENABLED, TOKEN_GLOBAL_LIMIT, TOKEN_AGENT_LIMIT,
                TOKEN_MISSION_LIMIT, TOKEN_GLOBAL_RPM, TOKEN_AGENT_RPM,
                TOKEN_WARNING_THRESHOLD,
            )
            if not TOKEN_BUDGET_ENABLED:
                return
            from token_budget import BudgetConfig
            config = BudgetConfig(
                global_token_limit=TOKEN_GLOBAL_LIMIT,
                agent_token_limit=TOKEN_AGENT_LIMIT,
                mission_token_limit=TOKEN_MISSION_LIMIT,
                global_calls_per_minute=TOKEN_GLOBAL_RPM,
                agent_calls_per_minute=TOKEN_AGENT_RPM,
                warning_threshold=TOKEN_WARNING_THRESHOLD,
            )
            self._token_budget_manager = TokenBudgetManager(config)
        except Exception as e:
            self.logger.warning(f"Token budget manager not available: {e}")

    async def _check_budget(self, estimated_tokens: int = 1000) -> bool:
        """Check if we're within token budget. Returns True if call is allowed."""
        if not self._token_budget_manager:
            return True
        result = self._token_budget_manager.can_make_call(
            agent_id=self.agent_id,
            mission_id=self._mission_id,
            estimated_tokens=estimated_tokens,
        )
        for warning in result.get("warnings", []):
            self.logger.warning(f"Budget warning: {warning}")
        if not result["allowed"]:
            self.logger.error(f"Budget exceeded: {result['reason']}")
        return result["allowed"]

    def _record_token_usage(
        self, prompt_tokens: int, completion_tokens: int, success: bool = True
    ):
        """Record token usage with the budget manager."""
        if self._token_budget_manager:
            self._token_budget_manager.record_usage(
                agent_id=self.agent_id,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                mission_id=self._mission_id,
                success=success,
            )

    def _compute_confidence(self, result: AgentResult) -> float:
        """Compute composite confidence score from settings weights."""
        try:
            from config.settings import (
                CONFIDENCE_TOOL_WEIGHT, CONFIDENCE_LLM_WEIGHT,
                CONFIDENCE_CRITIQUE_WEIGHT,
            )
            return result.compute_confidence(
                tool_weight=CONFIDENCE_TOOL_WEIGHT,
                llm_weight=CONFIDENCE_LLM_WEIGHT,
                critique_weight=CONFIDENCE_CRITIQUE_WEIGHT,
            )
        except Exception:
            return result.compute_confidence()


class ExperimentAgent(BaseAgent):
    """Base class for experiment-focused agents"""

    def __init__(self, agent_id: str, name: str, description: str):
        super().__init__(agent_id, name, description)
        self.experiments = []
        self.hypotheses = []

    def add_hypothesis(self, hypothesis: str, basis: str, testable: bool = True):
        """Add a hypothesis to test"""
        self.hypotheses.append({
            "id": str(uuid.uuid4()),
            "statement": hypothesis,
            "basis": basis,
            "testable": testable,
            "created": datetime.now().isoformat(),
            "status": "proposed"
        })

    def add_experiment(self, hypothesis_id: str, design: str, procedure: str):
        """Add an experiment to test a hypothesis"""
        self.experiments.append({
            "id": str(uuid.uuid4()),
            "hypothesis_id": hypothesis_id,
            "design": design,
            "procedure": procedure,
            "status": "designed",
            "created": datetime.now().isoformat(),
            "results": None,
            "conclusion": None
        })


if __name__ == "__main__":
    # Example usage
    import asyncio

    class TestAgent(AnalysisAgent):
        async def initialize(self) -> bool:
            self.logger.info("Test agent initialized")
            return True

        async def execute_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
            self.logger.info(f"Executing task: {task.get('description', 'Unknown')}")
            return {"status": "completed", "result": "Test completed"}

        async def cleanup(self) -> bool:
            self.logger.info("Test agent cleaned up")
            return True

    async def main():
        agent = TestAgent("test-001", "Test Agent", "A test agent for demonstration")
        await agent.initialize()
        agent.activate()

        result = await agent.execute_task({
            "description": "Test task",
            "data": {"key": "value"}
        })

        print(f"Agent status: {agent.get_status()}")
        print(f"Task result: {result}")

        await agent.cleanup()

    asyncio.run(main())