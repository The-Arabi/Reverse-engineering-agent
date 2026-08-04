"""
Token Budget and Rate Limiting for the Reverse Engineering Lab.
Tracks LLM token consumption per agent, per mission, and globally.
Enforces configurable budgets and rate limits to prevent runaway costs.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("token_budget")


@dataclass
class BudgetConfig:
    """Configuration for token budgets and rate limits."""
    # Global limits
    global_token_limit: int = 1_000_000  # max tokens across all agents
    global_calls_per_minute: int = 60
    global_calls_per_hour: int = 1000

    # Per-agent limits
    agent_token_limit: int = 100_000  # max tokens per agent per mission
    agent_calls_per_minute: int = 10

    # Per-mission limits
    mission_token_limit: int = 500_000  # max tokens per mission

    # Warning thresholds (fraction of limit)
    warning_threshold: float = 0.8  # warn at 80% usage
    hard_limit_enabled: bool = True  # enforce hard limits (vs just warn)


@dataclass
class AgentBudget:
    """Tracks token usage for a single agent."""
    agent_id: str
    total_tokens: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_calls: int = 0
    failed_calls: int = 0
    call_timestamps: List[float] = field(default_factory=list)

    def record_usage(
        self, prompt_tokens: int, completion_tokens: int, success: bool = True
    ):
        """Record token usage for a call."""
        self.total_tokens += prompt_tokens + completion_tokens
        self.prompt_tokens += prompt_tokens
        self.completion_tokens += completion_tokens
        self.total_calls += 1
        if not success:
            self.failed_calls += 1
        self.call_timestamps.append(time.monotonic())
        # Keep only last 60 minutes of timestamps
        cutoff = time.monotonic() - 3600
        self.call_timestamps = [t for t in self.call_timestamps if t > cutoff]

    def calls_in_window(self, window_seconds: int = 60) -> int:
        """Count calls in the given time window."""
        cutoff = time.monotonic() - window_seconds
        return sum(1 for t in self.call_timestamps if t > cutoff)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "total_tokens": self.total_tokens,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_calls": self.total_calls,
            "failed_calls": self.failed_calls,
            "calls_last_minute": self.calls_in_window(60),
        }


@dataclass
class MissionBudget:
    """Tracks token usage for a mission."""
    mission_id: str
    agent_budgets: Dict[str, AgentBudget] = field(default_factory=dict)
    total_tokens: int = 0
    total_calls: int = 0

    def get_agent_budget(self, agent_id: str) -> AgentBudget:
        """Get or create an AgentBudget for an agent."""
        if agent_id not in self.agent_budgets:
            self.agent_budgets[agent_id] = AgentBudget(agent_id=agent_id)
        return self.agent_budgets[agent_id]

    def record_usage(
        self, agent_id: str, prompt_tokens: int, completion_tokens: int,
        success: bool = True
    ):
        """Record token usage for an agent in this mission."""
        budget = self.get_agent_budget(agent_id)
        budget.record_usage(prompt_tokens, completion_tokens, success)
        self.total_tokens += prompt_tokens + completion_tokens
        self.total_calls += 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mission_id": self.mission_id,
            "total_tokens": self.total_tokens,
            "total_calls": self.total_calls,
            "agents": {
                aid: ab.to_dict()
                for aid, ab in self.agent_budgets.items()
            },
        }


class TokenBudgetManager:
    """Manages token budgets and rate limiting for LLM calls.

    Tracks usage at global, per-mission, and per-agent levels.
    Provides budget checking before LLM calls and enforcement of limits.
    """

    def __init__(self, config: Optional[BudgetConfig] = None):
        self.config = config or BudgetConfig()
        self.mission_budgets: Dict[str, MissionBudget] = {}
        self.global_total_tokens: int = 0
        self.global_total_calls: int = 0
        self.global_call_timestamps: List[float] = []
        self._warnings_issued: set = set()

    def start_mission(self, mission_id: str) -> MissionBudget:
        """Initialize budget tracking for a mission."""
        if mission_id not in self.mission_budgets:
            self.mission_budgets[mission_id] = MissionBudget(mission_id=mission_id)
            logger.info(f"Started budget tracking for mission {mission_id}")
        return self.mission_budgets[mission_id]

    def end_mission(self, mission_id: str) -> Optional[MissionBudget]:
        """Finalize budget tracking for a mission."""
        return self.mission_budgets.pop(mission_id, None)

    def can_make_call(
        self,
        agent_id: str,
        mission_id: Optional[str] = None,
        estimated_tokens: int = 0,
    ) -> Dict[str, Any]:
        """Check if an LLM call is within budget limits.

        Returns dict with:
            allowed (bool): whether the call is allowed
            reason (str): reason if not allowed
            warnings (list): any warnings about approaching limits
        """
        warnings: List[str] = []

        # Check global rate limit
        global_rpm = self._count_calls_in_window(60)
        if global_rpm >= self.config.global_calls_per_minute:
            return {
                "allowed": False,
                "reason": f"Global rate limit reached: {global_rpm}/{self.config.global_calls_per_minute} calls/min",
                "warnings": warnings,
            }

        # Check global token limit
        if (self.config.hard_limit_enabled and
                self.global_total_tokens + estimated_tokens > self.config.global_token_limit):
            return {
                "allowed": False,
                "reason": (
                    f"Global token limit reached: "
                    f"{self.global_total_tokens}/{self.config.global_token_limit}"
                ),
                "warnings": warnings,
            }

        # Global warning threshold
        global_usage_ratio = self.global_total_tokens / max(1, self.config.global_token_limit)
        if global_usage_ratio >= self.config.warning_threshold:
            warnings.append(
                f"Global token usage at {global_usage_ratio:.0%} "
                f"({self.global_total_tokens}/{self.config.global_token_limit})"
            )

        # Check per-mission limits
        if mission_id and mission_id in self.mission_budgets:
            mission_budget = self.mission_budgets[mission_id]
            if (self.config.hard_limit_enabled and
                    mission_budget.total_tokens + estimated_tokens > self.config.mission_token_limit):
                return {
                    "allowed": False,
                    "reason": (
                        f"Mission token limit reached for {mission_id}: "
                        f"{mission_budget.total_tokens}/{self.config.mission_token_limit}"
                    ),
                    "warnings": warnings,
                }

            mission_ratio = mission_budget.total_tokens / max(1, self.config.mission_token_limit)
            if mission_ratio >= self.config.warning_threshold:
                warnings.append(
                    f"Mission token usage at {mission_ratio:.0%} "
                    f"({mission_budget.total_tokens}/{self.config.mission_token_limit})"
                )

        # Check per-agent limits
        if mission_id and mission_id in self.mission_budgets:
            mission_budget = self.mission_budgets[mission_id]
            agent_budget = mission_budget.get_agent_budget(agent_id)

            # Agent token limit
            if (self.config.hard_limit_enabled and
                    agent_budget.total_tokens + estimated_tokens > self.config.agent_token_limit):
                return {
                    "allowed": False,
                    "reason": (
                        f"Agent token limit reached for {agent_id}: "
                        f"{agent_budget.total_tokens}/{self.config.agent_token_limit}"
                    ),
                    "warnings": warnings,
                }

            agent_ratio = agent_budget.total_tokens / max(1, self.config.agent_token_limit)
            if agent_ratio >= self.config.warning_threshold:
                warnings.append(
                    f"Agent {agent_id} token usage at {agent_ratio:.0%} "
                    f"({agent_budget.total_tokens}/{self.config.agent_token_limit})"
                )

            # Agent rate limit
            agent_rpm = agent_budget.calls_in_window(60)
            if agent_rpm >= self.config.agent_calls_per_minute:
                return {
                    "allowed": False,
                    "reason": (
                        f"Agent rate limit reached for {agent_id}: "
                        f"{agent_rpm}/{self.config.agent_calls_per_minute} calls/min"
                    ),
                    "warnings": warnings,
                }

        return {"allowed": True, "reason": "", "warnings": warnings}

    def record_usage(
        self,
        agent_id: str,
        prompt_tokens: int,
        completion_tokens: int,
        mission_id: Optional[str] = None,
        success: bool = True,
    ):
        """Record actual token usage after a call completes."""
        # Global tracking
        total = prompt_tokens + completion_tokens
        self.global_total_tokens += total
        self.global_total_calls += 1
        self.global_call_timestamps.append(time.monotonic())

        # Mission tracking
        if mission_id:
            mission_budget = self.start_mission(mission_id)
            mission_budget.record_usage(agent_id, prompt_tokens, completion_tokens, success)

        logger.debug(
            f"Token usage recorded: agent={agent_id}, "
            f"prompt={prompt_tokens}, completion={completion_tokens}, "
            f"mission={mission_id}"
        )

    def get_usage_summary(
        self, mission_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get a summary of token usage."""
        summary: Dict[str, Any] = {
            "global": {
                "total_tokens": self.global_total_tokens,
                "total_calls": self.global_total_calls,
                "calls_last_minute": self._count_calls_in_window(60),
                "token_limit": self.config.global_token_limit,
                "usage_ratio": round(
                    self.global_total_tokens / max(1, self.config.global_token_limit), 4
                ),
            },
        }

        if mission_id and mission_id in self.mission_budgets:
            mission_budget = self.mission_budgets[mission_id]
            summary["mission"] = mission_budget.to_dict()

        return summary

    def get_agent_usage(
        self, agent_id: str, mission_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get token usage for a specific agent."""
        if mission_id and mission_id in self.mission_budgets:
            mission_budget = self.mission_budgets[mission_id]
            agent_budget = mission_budget.get_agent_budget(agent_id)
            return agent_budget.to_dict()
        return {"agent_id": agent_id, "total_tokens": 0, "total_calls": 0}

    def _count_calls_in_window(self, window_seconds: int) -> int:
        """Count global calls in the given time window."""
        cutoff = time.monotonic() - window_seconds
        return sum(1 for t in self.global_call_timestamps if t > cutoff)

    def reset(self):
        """Reset all budget tracking."""
        self.mission_budgets.clear()
        self.global_total_tokens = 0
        self.global_total_calls = 0
        self.global_call_timestamps.clear()
        self._warnings_issued.clear()
        logger.info("Token budget manager reset")
