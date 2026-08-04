"""
Multi-Agent Debate for the Reverse Engineering Lab.
Facilitates structured debate between agents to challenge hypotheses,
validate findings, and reach consensus on analysis conclusions.

Protocol: Assertion -> Challenge -> Defense -> Verdict
"""

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("debate")


@dataclass
class DebateRound:
    """A single round in a multi-agent debate."""
    round_number: int
    proposer_id: str
    proposer_name: str
    assertion: str
    challenge: Optional[str] = None
    challenger_id: Optional[str] = None
    challenger_name: Optional[str] = None
    defense: Optional[str] = None
    verdict: Optional[str] = None  # "supported", "challenged", "inconclusive"
    confidence_delta: float = 0.0  # change in confidence after this round

    def to_dict(self) -> Dict[str, Any]:
        return {
            "round_number": self.round_number,
            "proposer_id": self.proposer_id,
            "proposer_name": self.proposer_name,
            "assertion": self.assertion,
            "challenge": self.challenge,
            "challenger_id": self.challenger_id,
            "challenger_name": self.challenger_name,
            "defense": self.defense,
            "verdict": self.verdict,
            "confidence_delta": self.confidence_delta,
        }


@dataclass
class DebateResult:
    """Result of a multi-agent debate session."""
    debate_id: str
    topic: str
    rounds: List[DebateRound] = field(default_factory=list)
    final_consensus: str = ""  # "consensus", "divergent", "no_consensus"
    final_confidence: float = 0.5
    participants: List[str] = field(default_factory=list)
    key_disagreements: List[str] = field(default_factory=list)
    resolution_summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "debate_id": self.debate_id,
            "topic": self.topic,
            "rounds": [r.to_dict() for r in self.rounds],
            "final_consensus": self.final_consensus,
            "final_confidence": self.final_confidence,
            "participants": self.participants,
            "key_disagreements": self.key_disagreements,
            "resolution_summary": self.resolution_summary,
        }


# Prompt templates for each phase of the debate protocol
CHALLENGE_PROMPT = """You are a critical analyst in a reverse engineering debate.
Another agent has made the following assertion based on their analysis:

Assertion: {assertion}
Proposed by: {proposer_name} ({proposer_type})

Context from their analysis:
{proposer_context}

Your role is to challenge this assertion. Identify:
1. Weaknesses or gaps in the reasoning
2. Alternative explanations that weren't considered
3. Evidence that contradicts or weakens the assertion
4. Assumptions that may not hold

Return JSON:
{{
    "challenge": "Your challenge to the assertion (2-3 sentences)",
    "alternative_explanation": "An alternative interpretation of the evidence",
    "strength_of_assertion": 0.0-1.0,
    "critical_gaps": ["gap1", "gap2"]
}}"""

DEFENSE_PROMPT = """You are a reverse engineering analyst defending your assertion in a debate.
A challenger has raised the following objections:

Original assertion: {assertion}
Challenge: {challenge}
Challenger: {challenger_name} ({challenger_type})

Your context:
{proposer_context}

Defend your assertion. Address each point in the challenge:
1. Acknowledge valid criticisms
2. Provide additional evidence or reasoning
3. Explain why your original assertion holds despite the challenge
4. If the challenge is valid, concede and revise

Return JSON:
{{
    "defense": "Your defense of the original assertion (2-3 sentences)",
    "concessions": ["any valid points you acknowledge"],
    "revised_confidence": 0.0-1.0,
    "still_holds": true/false
}}"""

VERDICT_PROMPT = """You are a judge in a reverse engineering debate.
You must evaluate the assertion, challenge, and defense to reach a verdict.

Assertion: {assertion} (by {proposer_name})
Challenge: {challenge} (by {challenger_name})
Defense: {defense}

Evaluate:
1. Did the challenge identify real weaknesses?
2. Did the defense adequately address the challenge?
3. What is the overall validity of the original assertion?

Return JSON:
{{
    "verdict": "supported" | "challenged" | "inconclusive",
    "reasoning": "Brief explanation of the verdict",
    "confidence_adjustment": -0.3 to +0.3,
    "key_takeaway": "One sentence summary of the debate outcome"
}}"""


class MultiAgentDebate:
    """Facilitates structured debate between agents.

    Protocol: Assertion -> Challenge -> Defense -> Verdict
    Each debate can have multiple rounds, with different agents
    taking turns as proposer and challenger.
    """

    def __init__(self, llm_client=None):
        self._llm_client = llm_client

    def _get_llm_client(self):
        """Get or create LLM client."""
        if self._llm_client is not None:
            return self._llm_client
        from llm_client import get_llm_client
        self._llm_client = get_llm_client()
        return self._llm_client

    async def generate_challenge(
        self,
        assertion: str,
        proposer_name: str,
        proposer_type: str,
        proposer_context: str,
    ) -> Dict[str, Any]:
        """Generate a challenge to an assertion using LLM.

        Returns dict with keys: challenge, alternative_explanation,
        strength_of_assertion, critical_gaps.
        """
        llm = self._get_llm_client()

        prompt = CHALLENGE_PROMPT.format(
            assertion=assertion,
            proposer_name=proposer_name,
            proposer_type=proposer_type,
            proposer_context=proposer_context[:2000],
        )

        messages = [
            {"role": "system", "content": "You are a critical analyst. Always respond with valid JSON only."},
            {"role": "user", "content": prompt},
        ]

        try:
            return await llm.chat_completion_json(messages, temperature=0.4)
        except Exception as e:
            logger.error(f"Challenge generation failed: {e}")
            return {
                "challenge": "Unable to generate challenge due to LLM error",
                "alternative_explanation": "",
                "strength_of_assertion": 0.5,
                "critical_gaps": [],
            }

    async def generate_defense(
        self,
        assertion: str,
        challenge: str,
        challenger_name: str,
        challenger_type: str,
        proposer_context: str,
    ) -> Dict[str, Any]:
        """Generate a defense against a challenge using LLM.

        Returns dict with keys: defense, concessions, revised_confidence, still_holds.
        """
        llm = self._get_llm_client()

        prompt = DEFENSE_PROMPT.format(
            assertion=assertion,
            challenge=challenge,
            challenger_name=challenger_name,
            challenger_type=challenger_type,
            proposer_context=proposer_context[:2000],
        )

        messages = [
            {"role": "system", "content": "You are a reverse engineering analyst. Always respond with valid JSON only."},
            {"role": "user", "content": prompt},
        ]

        try:
            return await llm.chat_completion_json(messages, temperature=0.3)
        except Exception as e:
            logger.error(f"Defense generation failed: {e}")
            return {
                "defense": "Unable to generate defense due to LLM error",
                "concessions": [],
                "revised_confidence": 0.5,
                "still_holds": True,
            }

    async def generate_verdict(
        self,
        assertion: str,
        proposer_name: str,
        challenge: str,
        challenger_name: str,
        defense: str,
    ) -> Dict[str, Any]:
        """Generate a verdict on the debate using LLM.

        Returns dict with keys: verdict, reasoning, confidence_adjustment, key_takeaway.
        """
        llm = self._get_llm_client()

        prompt = VERDICT_PROMPT.format(
            assertion=assertion,
            proposer_name=proposer_name,
            challenge=challenge,
            challenger_name=challenger_name,
            defense=defense,
        )

        messages = [
            {"role": "system", "content": "You are a debate judge. Always respond with valid JSON only."},
            {"role": "user", "content": prompt},
        ]

        try:
            return await llm.chat_completion_json(messages, temperature=0.2)
        except Exception as e:
            logger.error(f"Verdict generation failed: {e}")
            return {
                "verdict": "inconclusive",
                "reasoning": "Unable to generate verdict due to LLM error",
                "confidence_adjustment": 0.0,
                "key_takeaway": "Debate inconclusive due to technical error",
            }

    async def run_debate_round(
        self,
        round_number: int,
        assertion: str,
        proposer_id: str,
        proposer_name: str,
        proposer_type: str,
        proposer_context: str,
        challenger_id: str,
        challenger_name: str,
        challenger_type: str,
    ) -> DebateRound:
        """Run a single round of debate: challenge -> defense -> verdict.

        Returns a DebateRound with the full exchange.
        """
        # Phase 1: Challenge
        challenge_result = await self.generate_challenge(
            assertion=assertion,
            proposer_name=proposer_name,
            proposer_type=proposer_type,
            proposer_context=proposer_context,
        )
        challenge_text = challenge_result.get("challenge", "")

        # Phase 2: Defense
        defense_result = await self.generate_defense(
            assertion=assertion,
            challenge=challenge_text,
            challenger_name=challenger_name,
            challenger_type=challenger_type,
            proposer_context=proposer_context,
        )
        defense_text = defense_result.get("defense", "")

        # Phase 3: Verdict
        verdict_result = await self.generate_verdict(
            assertion=assertion,
            proposer_name=proposer_name,
            challenge=challenge_text,
            challenger_name=challenger_name,
            defense=defense_text,
        )

        return DebateRound(
            round_number=round_number,
            proposer_id=proposer_id,
            proposer_name=proposer_name,
            assertion=assertion,
            challenge=challenge_text,
            challenger_id=challenger_id,
            challenger_name=challenger_name,
            defense=defense_text,
            verdict=verdict_result.get("verdict", "inconclusive"),
            confidence_delta=verdict_result.get("confidence_adjustment", 0.0),
        )

    async def run_full_debate(
        self,
        topic: str,
        assertions: List[Dict[str, Any]],
        max_rounds: int = 3,
    ) -> DebateResult:
        """Run a complete multi-agent debate session.

        Args:
            topic: The debate topic/question
            assertions: List of dicts with keys:
                - assertion (str): the claim to debate
                - agent_id (str): proposing agent ID
                - agent_name (str): proposing agent name
                - agent_type (str): proposing agent type
                - context (str): supporting context/evidence
            max_rounds: Maximum number of debate rounds

        Returns:
            DebateResult with all rounds and final consensus
        """
        import uuid

        debate_id = str(uuid.uuid4())
        rounds: List[DebateRound] = []
        participants: List[str] = []
        disagreements: List[str] = []

        for i, assert_data in enumerate(assertions[:max_rounds]):
            proposer_id = assert_data.get("agent_id", "unknown")
            proposer_name = assert_data.get("agent_name", "Agent")
            proposer_type = assert_data.get("agent_type", "general")
            proposer_context = assert_data.get("context", "")
            assertion = assert_data.get("assertion", "")

            if not assertion:
                continue

            # Select challenger (rotate through other agents)
            challengers = [
                a for a in assertions
                if a.get("agent_id") != proposer_id
            ]
            if not challengers:
                # If no other agents, self-challenge
                challengers = [assert_data]

            challenger = challengers[i % len(challengers)]
            challenger_id = challenger.get("agent_id", "unknown")
            challenger_name = challenger.get("agent_name", "Agent")
            challenger_type = challenger.get("agent_type", "general")

            if proposer_name not in participants:
                participants.append(proposer_name)
            if challenger_name not in participants:
                participants.append(challenger_name)

            # Run the round
            debate_round = await self.run_debate_round(
                round_number=i + 1,
                assertion=assertion,
                proposer_id=proposer_id,
                proposer_name=proposer_name,
                proposer_type=proposer_type,
                proposer_context=proposer_context,
                challenger_id=challenger_id,
                challenger_name=challenger_name,
                challenger_type=challenger_type,
            )

            rounds.append(debate_round)

            if debate_round.verdict == "challenged":
                disagreements.append(
                    f"Round {i+1}: {proposer_name}'s assertion was challenged by {challenger_name}"
                )

        # Determine final consensus
        verdicts = [r.verdict for r in rounds if r.verdict]
        if not verdicts:
            final_consensus = "no_consensus"
        elif all(v == "supported" for v in verdicts):
            final_consensus = "consensus"
        elif any(v == "challenged" for v in verdicts):
            final_consensus = "divergent"
        else:
            final_consensus = "inconclusive"

        # Calculate final confidence
        deltas = [r.confidence_delta for r in rounds]
        base_confidence = 0.5
        final_confidence = max(0.0, min(1.0, base_confidence + sum(deltas)))

        return DebateResult(
            debate_id=debate_id,
            topic=topic,
            rounds=rounds,
            final_consensus=final_consensus,
            final_confidence=final_confidence,
            participants=participants,
            key_disagreements=disagreements,
            resolution_summary=f"Debate on '{topic}' reached {final_consensus} with confidence {final_confidence:.2f}",
        )

    def run_debate_offline(
        self,
        topic: str,
        assertions: List[Dict[str, Any]],
        max_rounds: int = 3,
    ) -> DebateResult:
        """Run a debate without LLM using heuristic challenge/defense.

        Used when LLM is unavailable. Each assertion is challenged
        heuristically based on confidence and evidence quality.
        """
        import uuid

        debate_id = str(uuid.uuid4())
        rounds: List[DebateRound] = []
        participants: List[str] = []
        disagreements: List[str] = []

        for i, assert_data in enumerate(assertions[:max_rounds]):
            assertion = assert_data.get("assertion", "")
            agent_id = assert_data.get("agent_id", "unknown")
            agent_name = assert_data.get("agent_name", "Agent")
            context = assert_data.get("context", "")

            if not assertion:
                continue

            if agent_name not in participants:
                participants.append(agent_name)

            # Heuristic challenge: flag if context is too short
            challenge_text = ""
            verdict = "supported"
            confidence_delta = 0.05

            if len(context) < 100:
                challenge_text = (
                    "The assertion lacks sufficient supporting evidence. "
                    "The provided context is very short and may not adequately "
                    "support the conclusion."
                )
                verdict = "challenged"
                confidence_delta = -0.15
                disagreements.append(
                    f"Round {i+1}: {agent_name}'s assertion lacks sufficient context"
                )
            elif any(kw in assertion.lower() for kw in ["always", "never", "impossible"]):
                challenge_text = (
                    "The assertion uses absolute language which may not be "
                    "justified by the available evidence."
                )
                verdict = "inconclusive"
                confidence_delta = -0.05
            else:
                challenge_text = (
                    "The assertion appears reasonable given the available context."
                )
                verdict = "supported"
                confidence_delta = 0.1

            rounds.append(DebateRound(
                round_number=i + 1,
                proposer_id=agent_id,
                proposer_name=agent_name,
                assertion=assertion,
                challenge=challenge_text,
                challenger_id="heuristic",
                challenger_name="Heuristic Critic",
                defense="Assertion stands based on available evidence.",
                verdict=verdict,
                confidence_delta=confidence_delta,
            ))

        verdicts = [r.verdict for r in rounds if r.verdict]
        if not verdicts:
            final_consensus = "no_consensus"
        elif all(v == "supported" for v in verdicts):
            final_consensus = "consensus"
        elif any(v == "challenged" for v in verdicts):
            final_consensus = "divergent"
        else:
            final_consensus = "inconclusive"

        deltas = [r.confidence_delta for r in rounds]
        final_confidence = max(0.0, min(1.0, 0.5 + sum(deltas)))

        return DebateResult(
            debate_id=debate_id,
            topic=topic,
            rounds=rounds,
            final_consensus=final_consensus,
            final_confidence=final_confidence,
            participants=participants,
            key_disagreements=disagreements,
            resolution_summary=f"Offline debate on '{topic}' reached {final_consensus}",
        )
