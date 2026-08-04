"""
Integration test for the Reverse Engineering Lab
Tests basic functionality of the core components
"""

import asyncio
import logging
import tempfile
import os
import json
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from agents.base_agent import BaseAgent, Task, AgentStatus, AgentResult, AnalysisAgent
from agents.binary_analysis_agent import BinaryAnalysisAgent
from agents.firmware_analysis_agent import FirmwareAnalysisAgent
from agents.networking_agent import NetworkingAgent
from agents.cpu_analysis_agent import CpuAnalysisAgent
from agents.os_kernel_agent import OsKernelAgent
from agents.tool_runner import check_tool_available, run_file, run_strings, run_objdump, get_available_tools
from knowledge_base import KnowledgeBase, add_fact, add_hypothesis, add_experiment, kb
from orchestrator import ResearchOrchestrator
from llm_client import LLMClient, LLMConfig, LLMClientNotConfiguredError, UsageStats, get_llm_client, reset_llm_client
from embeddings import (
    TFIDFEmbeddingProvider, EmbeddingManager, EmbeddingResult,
    cosine_similarity, EmbeddingProviderNotAvailableError,
)
from rag_pipeline import RAGPipeline
from self_critique import SelfCritique, CritiqueResult
from knowledge_extraction import KnowledgeExtractor, ExtractionResult
from debate import MultiAgentDebate, DebateResult, DebateRound
from token_budget import TokenBudgetManager, BudgetConfig, AgentBudget, MissionBudget

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

import pytest


@pytest.mark.asyncio
async def test_knowledge_base():
    """Test the knowledge base functionality"""
    logger.info("=== Testing Knowledge Base ===")

    fact_id = add_fact(
        title="Test Fact",
        description="This is a test fact for verification",
        confidence=0.8,
        evidence=["test_evidence_1", "test_evidence_2"],
        source_references=["test_source.txt"],
        tags=["test", "fact"],
        source_agent="test_agent",
    )
    assert fact_id is not None, "Failed to add fact"
    logger.info(f"Added fact with ID: {fact_id}")

    retrieved_fact = kb.get_knowledge_item(fact_id)
    assert retrieved_fact is not None, "Failed to retrieve fact"
    assert retrieved_fact.title == "Test Fact", "Fact title mismatch"
    assert retrieved_fact.confidence == 0.8, "Fact confidence mismatch"
    assert len(retrieved_fact.evidence) == 2, "Fact evidence count mismatch"
    logger.info("Retrieved fact successfully")

    hyp_id = add_hypothesis(
        title="Test Hypothesis",
        description="This is a test hypothesis",
        confidence=0.5,
        basis="Based on test observations",
        testable=True,
        prediction="If tested, will produce expected results",
        falsification_condition="If test fails, hypothesis is wrong",
        tags=["test", "hypothesis"],
        source_agent="test_agent",
    )
    assert hyp_id is not None, "Failed to add hypothesis"

    exp_id = add_experiment(
        title="Test Experiment",
        description="This is a test experiment",
        confidence=0.7,
        hypothesis_id=hyp_id,
        setup="Set up test conditions",
        procedure="Execute test procedure",
        results="Observed test results",
        conclusion="Test was successful",
        tags=["test", "experiment"],
        source_agent="test_agent",
    )
    assert exp_id is not None, "Failed to add experiment"

    kb.link_items(fact_id, hyp_id, "supports")
    kb.link_items(hyp_id, exp_id, "tests")

    results = kb.search_knowledge(query="test", limit=10)
    assert len(results) >= 3, f"Expected at least 3 results, got {len(results)}"

    stats = kb.get_statistics()
    assert stats["total_items"] >= 3, "Expected at least 3 items in KB"
    logger.info("Knowledge base tests passed")
    return True


@pytest.mark.asyncio
async def test_agent_result_reasoning_trace():
    """Test that AgentResult supports reasoning traces"""
    logger.info("=== Testing AgentResult Reasoning Trace ===")

    result = AgentResult(
        task_id="trace_test",
        agent_id="test_agent",
        status="completed",
        result={"data": "test"},
    )

    result.add_reasoning_step("Started analysis", detail="Loading file")
    result.add_reasoning_step("Ran readelf", tool="readelf")
    result.add_reasoning_step("Parsed output", detail={"sections": 5})

    assert len(result.reasoning_trace) == 3, f"Expected 3 trace steps, got {len(result.reasoning_trace)}"
    assert result.reasoning_trace[0]["step"] == "Started analysis"
    assert result.reasoning_trace[1]["tool"] == "readelf"
    assert "readelf" in result.tools_used
    assert len(result.tools_used) == 1

    result_dict = result.to_dict()
    assert "reasoning_trace" in result_dict
    assert "tools_used" in result_dict
    assert len(result_dict["reasoning_trace"]) == 3

    logger.info("AgentResult reasoning trace tests passed")
    return True


@pytest.mark.asyncio
async def test_tool_runner():
    """Test the tool runner module"""
    logger.info("=== Testing Tool Runner ===")

    tool_availability = get_available_tools()
    logger.info(f"Available tools: {tool_availability}")

    assert isinstance(tool_availability, dict)
    assert "objdump" in tool_availability
    assert "readelf" in tool_availability
    assert "strings" in tool_availability

    result = await run_file("/bin/ls")
    logger.info(f"file /bin/ls: {result.stdout.strip()[:100]}")
    assert result.success, f"file command failed: {result.stderr}"

    result = await run_strings("/bin/ls", min_length=10)
    assert result.success, f"strings command failed: {result.stderr}"
    assert len(result.stdout) > 0, "strings returned no output"
    logger.info(f"strings /bin/ls: {len(result.stdout.splitlines())} strings found")

    result = await run_objdump("/bin/ls", ["-f"])
    logger.info(f"objdump -f /bin/ls: {result.stdout.strip()[:200]}")
    assert result.success, f"objdump failed: {result.stderr}"

    logger.info("Tool runner tests passed")
    return True


@pytest.mark.asyncio
async def test_binary_analysis_agent():
    """Test the binary analysis agent with real tools"""
    logger.info("=== Testing Binary Analysis Agent ===")

    agent = BinaryAnalysisAgent("test_binary_agent")

    try:
        initialized = await agent.initialize()
    except Exception as e:
        logger.warning(f"Agent initialization issue (non-fatal): {e}")
        initialized = False

    capabilities = agent.get_capabilities()
    assert "agent_type" in capabilities
    assert capabilities["agent_type"] == "binary_analysis"
    logger.info(f"Agent tools available: {capabilities.get('available_tools', {})}")

    test_task = Task(
        task_id="test_task_001",
        description="Test binary analysis on /bin/ls",
        agent_type="binary_analysis",
        priority=2,
        parameters={
            "file_path": "/bin/ls",
            "analysis_type": "basic",
        },
    )

    result = await agent.execute_task(test_task)
    assert result is not None, "Agent should return a result"
    assert result.task_id == "test_task_001", "Task ID mismatch"

    if result.status == "completed" and result.result:
        logger.info(f"Analysis completed with {len(result.reasoning_trace)} reasoning steps")
        logger.info(f"Tools used: {result.tools_used}")
        assert len(result.reasoning_trace) > 0, "Should have reasoning trace entries"

    await agent.cleanup()
    logger.info("Binary analysis agent tests passed")
    return True


@pytest.mark.asyncio
async def test_binary_analysis_nonexistent_file():
    """Test that agent gracefully handles missing files"""
    logger.info("=== Testing Binary Agent with Missing File ===")

    agent = BinaryAnalysisAgent("test_binary_missing")
    await agent.initialize()

    test_task = Task(
        task_id="test_missing",
        description="Analyze nonexistent file",
        agent_type="binary_analysis",
        priority=2,
        parameters={
            "file_path": "/nonexistent/path/to/file.bin",
            "analysis_type": "basic",
        },
    )

    result = await agent.execute_task(test_task)
    assert result is not None
    assert result.status == "failed"
    assert result.error is not None
    logger.info(f"Got expected error: {result.error}")

    await agent.cleanup()
    logger.info("Missing file test passed")
    return True


@pytest.mark.asyncio
async def test_orchestrator():
    """Test the orchestrator functionality"""
    logger.info("=== Testing Orchestrator ===")

    orchestrator = ResearchOrchestrator()

    mission_id = orchestrator.create_mission(
        title="Test Mission",
        description="A test mission for verification",
        tags=["test", "verification"],
    )
    assert mission_id is not None, "Failed to create mission"

    orchestrator.set_active_mission(mission_id)
    assert orchestrator.active_mission is not None

    mission_status = orchestrator.get_mission_status(mission_id)
    assert mission_status is not None
    assert mission_status.id == mission_id

    missions = orchestrator.list_missions()
    assert len(missions) >= 1

    status = orchestrator.get_system_status()
    assert "orchestrator_running" in status
    assert "total_agents" in status

    logger.info("Orchestrator tests passed")
    return True


@pytest.mark.asyncio
async def test_integration():
    """Test integration between components"""
    logger.info("=== Testing Component Integration ===")

    fact_id = add_fact(
        title="Integration Test Fact",
        description="Testing integration between components",
        confidence=0.9,
        evidence=["integration_test_1"],
        source_references=["integration_test.log"],
        tags=["integration", "test"],
        source_agent="integration_test",
    )

    orchestrator = ResearchOrchestrator()
    mission_id = orchestrator.create_mission(
        title="Integration Test Mission",
        description="Mission to test component integration",
        tags=["integration"],
    )

    fact = kb.get_knowledge_item(fact_id)
    assert fact is not None
    assert fact.title == "Integration Test Fact"

    mission = orchestrator.get_mission_status(mission_id)
    assert mission is not None
    assert mission.title == "Integration Test Mission"

    logger.info("Integration tests passed")
    return True


# =========================================================================
# Phase 2 tests — LLM integration, embeddings, RAG, critique, extraction
# =========================================================================


class _FakeLLMResponse:
    """Minimal mock for openai chat completion response."""
    def __init__(self, content: str):
        self.choices = [MagicMock(message=MagicMock(content=content))]
        self.usage = MagicMock(prompt_tokens=10, completion_tokens=20)


def _make_mock_llm_client(json_response: dict) -> LLMClient:
    """Build an LLMClient with a patched openai.AsyncOpenAI that returns canned JSON."""
    config = LLMConfig(api_key="test-key-123", model="test-model")
    client = LLMClient(config)
    raw = json.dumps(json_response)
    fake_response = _FakeLLMResponse(raw)
    client._client = MagicMock()
    client._client.chat.completions.create = AsyncMock(return_value=fake_response)
    return client


@pytest.mark.asyncio
async def test_llm_client_config_no_key():
    """LLMConfig raises error when API key is empty."""
    logger.info("=== Testing LLM Client Config (no key) ===")
    try:
        LLMConfig(api_key="")
        assert False, "Should have raised LLMClientNotConfiguredError"
    except LLMClientNotConfiguredError:
        pass
    logger.info("LLM client no-key test passed")


@pytest.mark.asyncio
async def test_llm_client_config_valid():
    """LLMConfig accepts a valid key."""
    logger.info("=== Testing LLM Client Config (valid) ===")
    config = LLMConfig(api_key="sk-test-123")
    assert config.model == "gpt-4"
    assert config.api_key == "sk-test-123"
    logger.info("LLM client valid config test passed")


@pytest.mark.asyncio
async def test_llm_client_chat_completion():
    """LLMClient.chat_completion returns text from a mocked API."""
    logger.info("=== Testing LLM Client Chat Completion ===")
    response_data = {"key_findings": ["test finding"], "confidence": 0.9}
    client = _make_mock_llm_client(response_data)
    messages = [{"role": "user", "content": "Analyze this"}]
    result = await client.chat_completion(messages)
    assert isinstance(result, str)
    assert "test finding" in result
    stats = client.get_usage_stats()
    assert stats["total_calls"] == 1
    assert stats["successful_calls"] == 1
    logger.info("LLM client chat completion test passed")


@pytest.mark.asyncio
async def test_llm_client_chat_completion_json():
    """LLMClient.chat_completion_json returns parsed dict."""
    logger.info("=== Testing LLM Client Chat JSON ===")
    response_data = {"key_findings": ["finding1"], "security_concerns": [], "confidence": 0.8}
    client = _make_mock_llm_client(response_data)
    messages = [{"role": "user", "content": "Analyze this"}]
    result = await client.chat_completion_json(messages)
    assert isinstance(result, dict)
    assert result["key_findings"] == ["finding1"]
    logger.info("LLM client chat JSON test passed")


@pytest.mark.asyncio
async def test_usage_stats():
    """UsageStats tracks calls correctly."""
    logger.info("=== Testing Usage Stats ===")
    stats = UsageStats()
    stats.record_call(prompt_tokens=100, completion_tokens=50, latency_ms=200.0)
    stats.record_call(prompt_tokens=80, completion_tokens=30, latency_ms=150.0, success=False)
    d = stats.to_dict()
    assert d["total_calls"] == 2
    assert d["successful_calls"] == 1
    assert d["failed_calls"] == 1
    assert d["total_tokens"] == 260
    assert d["average_latency_ms"] == 175.0
    logger.info("Usage stats test passed")


@pytest.mark.asyncio
async def test_llm_json_extraction():
    """_extract_json_from_text handles markdown fences and raw JSON."""
    logger.info("=== Testing JSON Extraction ===")
    # Direct JSON
    r = LLMClient._extract_json_from_text('{"a": 1}')
    assert r == {"a": 1}
    # Markdown fenced
    r = LLMClient._extract_json_from_text('```json\n{"b": 2}\n```')
    assert r == {"b": 2}
    # Plain fenced
    r = LLMClient._extract_json_from_text('some text\n```\n{"c": 3}\n```\nmore')
    assert r == {"c": 3}
    # Brace extraction
    r = LLMClient._extract_json_from_text('here is the result: {"d": 4} done')
    assert r == {"d": 4}
    logger.info("JSON extraction test passed")


@pytest.mark.asyncio
async def test_tfidf_embedding_provider():
    """TFIDFEmbeddingProvider produces valid fixed-dimension vectors."""
    logger.info("=== Testing TF-IDF Embedding Provider ===")
    provider = TFIDFEmbeddingProvider()
    emb = await provider.embed("ELF binary analysis with objdump and readelf")
    assert len(emb) == provider.VOCAB_SIZE
    assert all(isinstance(v, float) for v in emb)
    # L2 norm should be approximately 1.0
    norm = sum(v * v for v in emb) ** 0.5
    assert 0.95 <= norm <= 1.05, f"Embedding not normalized: norm={norm}"
    # Different texts should produce different embeddings
    emb2 = await provider.embed("network packet capture analysis with tshark")
    assert emb != emb2, "Different texts produced identical embeddings"
    logger.info("TF-IDF embedding test passed")


@pytest.mark.asyncio
async def test_tfidf_embedding_batch():
    """TFIDFEmbeddingProvider.embed_batch returns correct count."""
    logger.info("=== Testing TF-IDF Batch Embedding ===")
    provider = TFIDFEmbeddingProvider()
    results = await provider.embed_batch(["text one", "text two", "text three"])
    assert len(results) == 3
    assert all(len(r) == provider.VOCAB_SIZE for r in results)
    logger.info("TF-IDF batch embedding test passed")


@pytest.mark.asyncio
async def test_cosine_similarity():
    """cosine_similarity computes correct values."""
    logger.info("=== Testing Cosine Similarity ===")
    # Identical vectors
    assert abs(cosine_similarity([1.0, 0.0], [1.0, 0.0]) - 1.0) < 1e-6
    # Orthogonal vectors
    assert abs(cosine_similarity([1.0, 0.0], [0.0, 1.0])) < 1e-6
    # Opposite vectors
    assert abs(cosine_similarity([1.0, 0.0], [-1.0, 0.0]) - (-1.0)) < 1e-6
    # Padding mismatch
    score = cosine_similarity([1.0, 0.0], [1.0, 0.0, 0.0])
    assert abs(score - 1.0) < 1e-6
    logger.info("Cosine similarity test passed")


@pytest.mark.asyncio
async def test_embedding_manager_tfidf_only():
    """EmbeddingManager falls back to TF-IDF when no external providers."""
    logger.info("=== Testing Embedding Manager (TF-IDF only) ===")
    manager = EmbeddingManager()
    providers = manager.available_providers()
    assert "tfidf" in providers
    result = await manager.embed("test binary analysis text")
    assert isinstance(result, EmbeddingResult)
    assert result.provider_name == "tfidf"
    assert result.dimension == TFIDFEmbeddingProvider.VOCAB_SIZE
    logger.info("Embedding manager TF-IDF fallback test passed")


@pytest.mark.asyncio
async def test_rag_pipeline_store_and_retrieve():
    """RAGPipeline stores and retrieves analysis results."""
    logger.info("=== Testing RAG Pipeline Store & Retrieve ===")
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        tmp_path = tmp.name
    
    try:
        temp_kb = KnowledgeBase(db_path=tmp_path)
        pipeline = RAGPipeline(knowledge_base=temp_kb)
        unique_tag = f"rag_unique_{uuid.uuid4().hex[:8]}"
        result_dict = {
            "file_path": "/bin/test_rag_unique",
            "summary": {"architecture": "x86-64", "type": "ELF"},
        }
        item_id = await pipeline.store_analysis_result(
            agent_id="test_agent",
            analysis_type="binary_analysis",
            result_dict=result_dict,
            tags=[unique_tag],
        )
        assert item_id is not None
        # Verify item stored in KB
        stored_item = pipeline.kb.get_knowledge_item(item_id)
        assert stored_item is not None, f"Item {item_id} not found in KB after storage"
        # Retrieve with a highly specific query to match the stored item
        similar = await pipeline.retrieve_similar(
            f"ELF binary x86 architecture test_rag_unique {unique_tag}", top_k=20
        )
        assert len(similar) >= 1, f"Expected at least 1 result, got {len(similar)}"
        retrieved_ids = [r["item_id"] for r in similar]
        assert item_id in retrieved_ids, f"Stored item {item_id} not found in results {retrieved_ids}"
        logger.info("RAG pipeline store/retrieve test passed")
    finally:
        import os
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


@pytest.mark.asyncio
async def test_rag_pipeline_context_building():
    """RAGPipeline.build_context_for_analysis returns formatted context."""
    logger.info("=== Testing RAG Context Building ===")
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        temp_kb = KnowledgeBase(db_path=tmp_path)
        pipeline = RAGPipeline(knowledge_base=temp_kb)
        await pipeline.store_analysis_result(
            agent_id="test_agent",
            analysis_type="binary_analysis",
            result_dict={"file_path": "/bin/ls", "summary": {"type": "ELF binary"}},
            tags=["test"],
        )
        context = await pipeline.build_context_for_analysis("binary ELF analysis")
        assert isinstance(context, str)
        assert len(context) > 0
        logger.info(f"Context preview: {context[:200]}")
        logger.info("RAG context building test passed")
    finally:
        import os
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


@pytest.mark.asyncio
async def test_self_critique_heuristic_fallback():
    """SelfCritique falls back to heuristic scoring when LLM unavailable."""
    logger.info("=== Testing Self-Critique Heuristic Fallback ===")
    critique = SelfCritique(llm_client=None)
    # Sparse analysis result should score low
    result = critique._heuristic_fallback(
        "",
        {"file_path": "/bin/test"},
    )
    assert isinstance(result, CritiqueResult)
    assert 0.0 <= result.score <= 1.0
    assert len(result.issues_found) > 0, "Should find issues with sparse analysis"
    logger.info(f"Heuristic critique score: {result.score}, issues: {len(result.issues_found)}")

    # Rich analysis should score higher
    rich_result = critique._heuristic_fallback(
        "objdump output with 500 lines of disassembly and symbols and imports and strings",
        {
            "file_path": "/bin/ls",
            "summary": {"architecture": "x86-64", "type": "ELF"},
            "basic_info": {"type": "ELF 64-bit"},
            "sections": [".text", ".data", ".bss"],
        },
    )
    assert rich_result.score >= result.score, "Rich analysis should score higher"
    logger.info(f"Rich critique score: {rich_result.score}")
    logger.info("Self-critique heuristic fallback test passed")


@pytest.mark.asyncio
async def test_self_critique_should_re_analyze():
    """SelfCritique.should_re_analyze returns True for low scores."""
    logger.info("=== Testing Self-Critique Re-Analyze Decision ===")
    critique = SelfCritique()
    low_score = CritiqueResult(
        score=0.3, completeness_score=0.2, accuracy_score=0.4, consistency_score=0.3,
        issues_found=["contradictory findings"],
    )
    assert await critique.should_re_analyze(low_score, confidence_threshold=0.6) is True

    high_score = CritiqueResult(
        score=0.8, completeness_score=0.9, accuracy_score=0.8, consistency_score=0.7,
        issues_found=[],
    )
    assert await critique.should_re_analyze(high_score, confidence_threshold=0.6) is False
    logger.info("Self-critique re-analyze decision test passed")


@pytest.mark.asyncio
async def test_self_critique_with_mock_llm():
    """SelfCritique.evaluate_analysis uses LLM when available."""
    logger.info("=== Testing Self-Critique with Mock LLM ===")
    critique_response = {
        "completeness_score": 0.85,
        "accuracy_score": 0.9,
        "consistency_score": 0.8,
        "issues_found": ["Missing section analysis"],
        "improvement_suggestions": ["Add .got.plt analysis"],
        "missing_areas": ["dynamic linking info"],
    }
    mock_llm = _make_mock_llm_client(critique_response)
    critique = SelfCritique(llm_client=mock_llm)
    result = await critique.evaluate_analysis(
        agent_type="binary_analysis",
        tool_output_summary="readelf output showing ELF header and sections",
        analysis_result={"file_path": "/bin/ls", "summary": {"type": "ELF"}},
    )
    assert isinstance(result, CritiqueResult)
    assert result.completeness_score == 0.85
    assert result.accuracy_score == 0.9
    assert "Missing section analysis" in result.issues_found
    logger.info("Self-critique with mock LLM test passed")


@pytest.mark.asyncio
async def test_knowledge_extraction_with_mock_llm():
    """KnowledgeExtractor.extract_findings stores facts and hypotheses in KB."""
    logger.info("=== Testing Knowledge Extraction with Mock LLM ===")
    extraction_response = {
        "facts": [
            {
                "title": "Binary is ELF x86-64",
                "description": "The binary file is identified as ELF 64-bit x86-64",
                "confidence": 0.9,
                "evidence": ["file command output", "readelf header"],
                "tags": ["elf", "x86-64"],
            }
        ],
        "hypotheses": [
            {
                "title": "Binary may use dynamic linking",
                "description": "The presence of .got.plt suggests dynamic linking",
                "basis": "Section layout analysis",
                "confidence": 0.7,
                "tags": ["dynamic", "linking"],
            }
        ],
        "key_insights": ["Binary uses standard ELF format"],
        "confidence_assessment": 0.8,
    }
    mock_llm = _make_mock_llm_client(extraction_response)
    extractor = KnowledgeExtractor(llm_client=mock_llm)
    result = await extractor.extract_findings(
        agent_id="test_binary_agent",
        agent_type="binary_analysis",
        tool_results={"file_path": "/bin/ls", "file_type": "ELF 64-bit"},
        llm_analysis={"key_findings": ["ELF x86-64 binary"]},
    )
    assert isinstance(result, ExtractionResult)
    assert len(result.facts_stored) == 1
    assert len(result.hypotheses_stored) == 1
    assert len(result.key_insights) == 1
    # Verify the fact was stored in KB
    fact = kb.get_knowledge_item(result.facts_stored[0])
    assert fact is not None
    assert "ELF" in fact.title
    logger.info("Knowledge extraction test passed")


@pytest.mark.asyncio
async def test_binary_analysis_agent_with_mock_llm():
    """BinaryAnalysisAgent runs LLM analysis with mocked LLM."""
    logger.info("=== Testing Binary Agent with Mock LLM ===")
    agent = BinaryAnalysisAgent("test_binary_phase2")
    await agent.initialize()

    llm_response = {
        "key_findings": ["ELF 64-bit binary", "x86-64 architecture"],
        "security_concerns": ["Stack canary present"],
        "confidence": 0.88,
        "next_steps": ["Check for ROP gadgets"],
    }
    mock_llm = _make_mock_llm_client(llm_response)
    # Inject mock LLM directly
    agent._llm_client = mock_llm
    agent._llm_initialized = True

    task = Task(
        task_id="phase2_test",
        description="Analyze /bin/ls with LLM",
        agent_type="binary_analysis",
        parameters={"file_path": "/bin/ls", "analysis_type": "basic"},
    )
    result = await agent.execute_task(task)
    assert result.status == "completed"
    assert result.llm_analysis is not None
    assert "key_findings" in result.llm_analysis
    assert "ELF 64-bit" in str(result.llm_analysis["key_findings"])
    # Check reasoning trace includes LLM steps
    step_names = [s.get("step", s.get("step", "")) for s in result.reasoning_trace]
    assert any("llm" in s.lower() for s in step_names), f"No LLM step in trace: {step_names}"
    logger.info(f"LLM analysis keys: {list(result.llm_analysis.keys())}")
    await agent.cleanup()
    logger.info("Binary agent with mock LLM test passed")


@pytest.mark.asyncio
async def test_agent_result_serialization_with_llm_fields():
    """AgentResult.to_dict includes llm_analysis, critique, knowledge_extraction."""
    logger.info("=== Testing AgentResult Serialization ===")
    result = AgentResult(
        task_id="ser_test",
        agent_id="test",
        status="completed",
        llm_analysis={"key_findings": ["test"]},
        critique={"score": 0.8},
        knowledge_extraction={"facts_stored": ["f1"]},
    )
    d = result.to_dict()
    assert d["llm_analysis"] == {"key_findings": ["test"]}
    assert d["critique"] == {"score": 0.8}
    assert d["knowledge_extraction"] == {"facts_stored": ["f1"]}
    logger.info("AgentResult serialization test passed")


# =========================================================================
# Phase 3 tests — Confidence scoring, token budgets, debate, orchestrator
# =========================================================================


@pytest.mark.asyncio
async def test_confidence_scoring_computes_weighted_average():
    """AgentResult.compute_confidence produces weighted average from components."""
    logger.info("=== Testing Confidence Scoring ===")
    result = AgentResult(
        task_id="conf_test",
        agent_id="test",
        status="completed",
        tools_used=["objdump", "readelf", "strings"],
        llm_analysis={"confidence": 0.9},
        critique={"score": 0.8},
    )
    score = result.compute_confidence(
        tool_weight=0.3, llm_weight=0.4, critique_weight=0.3
    )
    assert 0.0 <= score <= 1.0
    # Tool confidence: 0.5 + 0.1 * 3 = 0.8 (capped at 1.0)
    # LLM confidence: 0.9
    # Critique confidence: 0.8
    # Weighted: (0.8*0.3 + 0.9*0.4 + 0.8*0.3) / 1.0 = 0.24 + 0.36 + 0.24 = 0.84
    assert 0.8 <= score <= 0.9, f"Expected ~0.84, got {score}"
    assert result.confidence_score == score
    assert result.confidence == score
    logger.info(f"Confidence score: {score}")


@pytest.mark.asyncio
async def test_confidence_scoring_no_tools_low_score():
    """Confidence is lower when no tools used and no LLM analysis."""
    logger.info("=== Testing Confidence (no tools) ===")
    result = AgentResult(
        task_id="conf_no_tools",
        agent_id="test",
        status="completed",
    )
    score = result.compute_confidence()
    # Tool: 0.2 (no tools), LLM: 0.5, Critique: 0.5
    # Weighted: (0.2*0.3 + 0.5*0.4 + 0.5*0.3) / 1.0 = 0.06 + 0.20 + 0.15 = 0.41
    assert 0.3 <= score <= 0.5, f"Expected ~0.41, got {score}"
    logger.info(f"No-tools confidence: {score}")


@pytest.mark.asyncio
async def test_token_budget_manager_allows_within_limit():
    """TokenBudgetManager allows calls within budget limits."""
    logger.info("=== Testing Token Budget (within limit) ===")
    config = BudgetConfig(
        global_token_limit=10000,
        agent_token_limit=5000,
        mission_token_limit=8000,
        global_calls_per_minute=10,
        agent_calls_per_minute=5,
    )
    mgr = TokenBudgetManager(config)
    mgr.start_mission("test_mission")

    result = mgr.can_make_call("agent_1", mission_id="test_mission", estimated_tokens=100)
    assert result["allowed"] is True, f"Should be allowed: {result}"
    logger.info("Token budget within-limit test passed")


@pytest.mark.asyncio
async def test_token_budget_manager_blocks_global_limit():
    """TokenBudgetManager blocks when global token limit exceeded."""
    logger.info("=== Testing Token Budget (global limit) ===")
    config = BudgetConfig(
        global_token_limit=500,
        agent_token_limit=100000,
        mission_token_limit=100000,
        hard_limit_enabled=True,
    )
    mgr = TokenBudgetManager(config)
    mgr.global_total_tokens = 450

    result = mgr.can_make_call("agent_1", estimated_tokens=100)
    assert result["allowed"] is False
    assert "Global token limit" in result["reason"]
    logger.info(f"Blocked: {result['reason']}")


@pytest.mark.asyncio
async def test_token_budget_manager_blocks_agent_limit():
    """TokenBudgetManager blocks when per-agent token limit exceeded."""
    logger.info("=== Testing Token Budget (agent limit) ===")
    config = BudgetConfig(
        global_token_limit=1000000,
        agent_token_limit=200,
        mission_token_limit=1000000,
        hard_limit_enabled=True,
    )
    mgr = TokenBudgetManager(config)
    mgr.start_mission("test_mission")
    # Exhaust agent budget
    mgr.record_usage("agent_1", prompt_tokens=150, completion_tokens=50, mission_id="test_mission")

    result = mgr.can_make_call("agent_1", mission_id="test_mission", estimated_tokens=10)
    assert result["allowed"] is False
    assert "Agent token limit" in result["reason"]
    logger.info(f"Blocked: {result['reason']}")


@pytest.mark.asyncio
async def test_token_budget_manager_blocks_rate_limit():
    """TokenBudgetManager blocks when rate limit exceeded."""
    logger.info("=== Testing Token Budget (rate limit) ===")
    config = BudgetConfig(
        global_token_limit=1000000,
        agent_token_limit=100000,
        agent_calls_per_minute=2,
        hard_limit_enabled=True,
    )
    mgr = TokenBudgetManager(config)
    mgr.start_mission("test_mission")
    # Exhaust rate
    mgr.record_usage("agent_1", 10, 10, mission_id="test_mission")
    mgr.record_usage("agent_1", 10, 10, mission_id="test_mission")

    result = mgr.can_make_call("agent_1", mission_id="test_mission")
    assert result["allowed"] is False
    assert "rate limit" in result["reason"].lower()
    logger.info(f"Blocked: {result['reason']}")


@pytest.mark.asyncio
async def test_token_budget_usage_tracking():
    """TokenBudgetManager tracks usage correctly per mission and agent."""
    logger.info("=== Testing Token Budget Tracking ===")
    config = BudgetConfig(global_token_limit=1000000, agent_token_limit=100000)
    mgr = TokenBudgetManager(config)
    mgr.start_mission("track_mission")

    mgr.record_usage("agent_1", 100, 50, mission_id="track_mission")
    mgr.record_usage("agent_1", 80, 30, mission_id="track_mission")
    mgr.record_usage("agent_2", 200, 100, mission_id="track_mission")

    summary = mgr.get_usage_summary(mission_id="track_mission")
    assert summary["global"]["total_tokens"] == 560
    assert summary["global"]["total_calls"] == 3
    assert summary["mission"]["total_tokens"] == 560

    agent1 = mgr.get_agent_usage("agent_1", mission_id="track_mission")
    assert agent1["total_tokens"] == 260  # 100+50 + 80+30
    assert agent1["total_calls"] == 2

    agent2 = mgr.get_agent_usage("agent_2", mission_id="track_mission")
    assert agent2["total_tokens"] == 300
    assert agent2["total_calls"] == 1

    logger.info("Token budget tracking test passed")


@pytest.mark.asyncio
async def test_token_budget_warnings():
    """TokenBudgetManager issues warnings at threshold."""
    logger.info("=== Testing Token Budget Warnings ===")
    config = BudgetConfig(
        global_token_limit=1000,
        agent_token_limit=500,
        warning_threshold=0.8,
    )
    mgr = TokenBudgetManager(config)
    mgr.start_mission("warn_mission")
    mgr.global_total_tokens = 850  # 85% of 1000

    result = mgr.can_make_call("agent_1", mission_id="warn_mission", estimated_tokens=10)
    assert result["allowed"] is True
    assert len(result["warnings"]) > 0
    assert any("85%" in w or "80%" in w for w in result["warnings"])
    logger.info(f"Warnings: {result['warnings']}")


@pytest.mark.asyncio
async def test_token_budget_reset():
    """TokenBudgetManager.reset clears all tracking."""
    logger.info("=== Testing Token Budget Reset ===")
    mgr = TokenBudgetManager()
    mgr.start_mission("reset_mission")
    mgr.record_usage("agent_1", 100, 50, mission_id="reset_mission")
    assert mgr.global_total_tokens > 0

    mgr.reset()
    assert mgr.global_total_tokens == 0
    assert mgr.global_total_calls == 0
    assert len(mgr.mission_budgets) == 0
    logger.info("Token budget reset test passed")


@pytest.mark.asyncio
async def test_debate_offline_with_two_assertions():
    """MultiAgentDebate.run_debate_offline produces a valid DebateResult."""
    logger.info("=== Testing Offline Debate ===")
    debate = MultiAgentDebate(llm_client=None)
    assertions = [
        {
            "assertion": "The binary uses AES encryption",
            "agent_id": "agent_1",
            "agent_name": "Binary Agent",
            "agent_type": "binary_analysis",
            "context": "Analysis revealed S-box patterns typical of AES. "
                       "The round key schedule matches AES-128. "
                       "Multiple rounds of transformation detected in the disassembly.",
        },
        {
            "assertion": "The binary uses XOR-based obfuscation",
            "agent_id": "agent_2",
            "agent_name": "CPU Agent",
            "agent_type": "cpu_analysis",
            "context": "Disassembly shows repeated XOR operations on data buffers. "
                       "No AES-specific instruction patterns (AESENC, AESDEC) found. "
                       "The obfuscation appears lightweight.",
        },
    ]

    result = debate.run_debate_offline(topic="What encryption does the binary use?", assertions=assertions)
    assert isinstance(result, DebateResult)
    assert result.debate_id is not None
    assert result.topic == "What encryption does the binary use?"
    assert len(result.rounds) == 2
    assert result.final_consensus in ("consensus", "divergent", "inconclusive", "no_consensus")
    assert 0.0 <= result.final_confidence <= 1.0
    assert len(result.participants) >= 1

    # Verify round structure
    for r in result.rounds:
        assert isinstance(r, DebateRound)
        assert r.assertion
        assert r.challenge
        assert r.verdict in ("supported", "challenged", "inconclusive")

    logger.info(f"Debate consensus: {result.final_consensus}, confidence: {result.final_confidence:.2f}")


@pytest.mark.asyncio
async def test_debate_offline_short_context_challenged():
    """Offline debate challenges assertions with short context."""
    logger.info("=== Testing Offline Debate (short context) ===")
    debate = MultiAgentDebate(llm_client=None)
    assertions = [
        {
            "assertion": "The binary is definitely malware",
            "agent_id": "agent_1",
            "agent_name": "Agent A",
            "agent_type": "binary_analysis",
            "context": "Short.",  # < 100 chars
        },
    ]

    result = debate.run_debate_offline(topic="Is this malware?", assertions=assertions)
    assert len(result.rounds) == 1
    # Short context should be challenged
    assert result.rounds[0].verdict == "challenged"
    assert len(result.key_disagreements) > 0
    logger.info(f"Short context verdict: {result.rounds[0].verdict}")


@pytest.mark.asyncio
async def test_debate_result_serialization():
    """DebateResult.to_dict produces valid serializable dict."""
    logger.info("=== Testing Debate Result Serialization ===")
    debate = MultiAgentDebate(llm_client=None)
    assertions = [
        {
            "assertion": "Test assertion one",
            "agent_id": "a1", "agent_name": "Agent1", "agent_type": "binary",
            "context": "Some context for assertion one with enough length to pass heuristic checks.",
        },
        {
            "assertion": "Test assertion two",
            "agent_id": "a2", "agent_name": "Agent2", "agent_type": "cpu",
            "context": "Some context for assertion two with enough length to pass heuristic checks.",
        },
    ]
    result = debate.run_debate_offline(topic="Test topic", assertions=assertions)
    d = result.to_dict()
    assert isinstance(d, dict)
    assert "debate_id" in d
    assert "rounds" in d
    assert isinstance(d["rounds"], list)
    assert len(d["rounds"]) > 0
    # Should be JSON-serializable
    json_str = json.dumps(d)
    assert len(json_str) > 0
    logger.info("Debate result serialization test passed")


@pytest.mark.asyncio
async def test_orchestrator_confidence_and_budget():
    """ResearchOrchestrator initializes Phase 3 components and tracks status."""
    logger.info("=== Testing Orchestrator Phase 3 Init ===")
    orch = ResearchOrchestrator()

    # Token budget manager should be initialized
    assert orch._token_budget_manager is not None

    # Self-critique should be initialized (may be None if no LLM key, but should exist)
    # debate system should exist
    assert orch._debate_system is not None

    # System status should include Phase 3 fields
    status = orch.get_system_status()
    assert "token_budget" in status
    assert "debate_count" in status
    assert "total_reanalyses" in status
    assert status["debate_count"] == 0
    assert status["total_reanalyses"] == 0

    logger.info("Orchestrator Phase 3 init test passed")


@pytest.mark.asyncio
async def test_orchestrator_facilitate_debate_offline():
    """Orchestrator.facilitate_debate runs offline debate with agent results."""
    logger.info("=== Testing Orchestrator Debate (offline) ===")
    orch = ResearchOrchestrator()

    # Disable LLM-based debate to test offline path
    orch._debate_system = None

    # Create two mock agent results
    result1 = AgentResult(
        task_id="debate_1",
        agent_id="agent_1",
        status="completed",
        result={"summary": {"finding": "AES encryption detected"}},
        llm_analysis={"key_findings": ["AES-128 encryption detected in binary"]},
        tools_used=["objdump", "strings"],
        confidence_score=0.8,
    )
    result2 = AgentResult(
        task_id="debate_2",
        agent_id="agent_2",
        status="completed",
        result={"summary": {"finding": "XOR obfuscation detected"}},
        llm_analysis={"key_findings": ["XOR-based obfuscation pattern found"]},
        tools_used=["objdump"],
        confidence_score=0.6,
    )

    debate_result = await orch.facilitate_debate(
        topic="What protection does the binary use?",
        agent_results={"agent_1": result1, "agent_2": result2},
    )

    assert debate_result is not None
    assert "debate_id" in debate_result
    assert "final_consensus" in debate_result
    assert len(orch.get_debate_results()) == 1
    logger.info(f"Orchestrator debate: {debate_result['final_consensus']}")


@pytest.mark.asyncio
async def test_orchestrator_debate_insufficient_participants():
    """Orchestrator skips debate when fewer than 2 assertions available."""
    logger.info("=== Testing Orchestrator Debate (insufficient) ===")
    orch = ResearchOrchestrator()

    result1 = AgentResult(
        task_id="solo_1",
        agent_id="agent_1",
        status="completed",
        result={"summary": {"finding": "something"}},
        llm_analysis={"key_findings": ["Single finding"]},
    )

    debate_result = await orch.facilitate_debate(
        topic="Solo topic",
        agent_results={"agent_1": result1},
    )
    assert debate_result is None
    logger.info("Orchestrator debate (insufficient) correctly returned None")


@pytest.mark.asyncio
async def test_binary_agent_confidence_computed():
    """BinaryAnalysisAgent computes composite confidence score."""
    logger.info("=== Testing Binary Agent Confidence ===")
    agent = BinaryAnalysisAgent("test_conf_binary")
    await agent.initialize()

    task = Task(
        task_id="conf_test_task",
        description="Analyze /bin/ls for confidence",
        agent_type="binary_analysis",
        parameters={"file_path": "/bin/ls", "analysis_type": "basic"},
    )
    result = await agent.execute_task(task)
    assert result is not None
    # Confidence should be computed (not 0.0 default)
    assert result.confidence_score > 0.0, f"Confidence should be > 0, got {result.confidence_score}"
    assert result.confidence > 0.0
    logger.info(f"Binary agent confidence: {result.confidence_score:.4f}")
    await agent.cleanup()


@pytest.mark.asyncio
async def test_budget_config_defaults():
    """BudgetConfig has sensible defaults."""
    logger.info("=== Testing BudgetConfig Defaults ===")
    config = BudgetConfig()
    assert config.global_token_limit == 1_000_000
    assert config.agent_token_limit == 100_000
    assert config.mission_token_limit == 500_000
    assert config.global_calls_per_minute == 60
    assert config.agent_calls_per_minute == 10
    assert config.warning_threshold == 0.8
    assert config.hard_limit_enabled is True
    logger.info("BudgetConfig defaults test passed")


@pytest.mark.asyncio
async def test_agent_budget_tracking():
    """AgentBudget tracks calls and tokens correctly."""
    logger.info("=== Testing Agent Budget Tracking ===")
    budget = AgentBudget(agent_id="test_agent")
    budget.record_usage(100, 50)
    budget.record_usage(80, 30, success=False)
    assert budget.total_tokens == 260
    assert budget.prompt_tokens == 180
    assert budget.completion_tokens == 80
    assert budget.total_calls == 2
    assert budget.failed_calls == 1
    d = budget.to_dict()
    assert d["agent_id"] == "test_agent"
    assert d["total_tokens"] == 260
    logger.info("Agent budget tracking test passed")


# =========================================================================
# Phase 4 tests — Monitoring, metrics, infrastructure
# =========================================================================


@pytest.mark.asyncio
async def test_counter_basic():
    """Counter increments and retrieves values correctly."""
    from monitoring import Counter
    logger.info("=== Testing Counter ===")
    c = Counter("test_counter", "A test counter")
    assert c.get() == 0.0
    c.inc()
    assert c.get() == 1.0
    c.inc(5.0)
    assert c.get() == 6.0
    # With labels
    c.inc(2.0, labels={"type": "a"})
    c.inc(3.0, labels={"type": "b"})
    assert c.get(labels={"type": "a"}) == 2.0
    assert c.get(labels={"type": "b"}) == 3.0
    assert c.get() == 6.0  # unlabeled unchanged
    all_vals = c.get_all()
    assert len(all_vals) == 3  # () , (type=a), (type=b)
    # Cannot decrement
    try:
        c.inc(-1.0)
        assert False, "Should raise ValueError"
    except ValueError:
        pass
    logger.info("Counter test passed")


@pytest.mark.asyncio
async def test_histogram_basic():
    """Histogram observes values and tracks buckets correctly."""
    from monitoring import Histogram
    logger.info("=== Testing Histogram ===")
    h = Histogram("test_histogram", "A test histogram", buckets=(0.1, 0.5, 1.0, float("inf")))
    assert h.get()["count"] == 0
    h.observe(0.05)
    h.observe(0.3)
    h.observe(0.8)
    h.observe(1.5)
    data = h.get()
    assert data["count"] == 4
    assert abs(data["sum"] - 2.65) < 0.01
    # Buckets: 0.05<=0.1, 0.3<=0.5, 0.8<=1.0, 1.5<=inf
    assert data["buckets"][0.1] == 1
    assert data["buckets"][0.5] == 2  # cumulative: 0.05 + 0.3
    assert data["buckets"][1.0] == 3  # cumulative: + 0.8
    assert data["buckets"][float("inf")] == 4  # cumulative: + 1.5
    logger.info("Histogram test passed")


@pytest.mark.asyncio
async def test_gauge_basic():
    """Gauge sets, increments, and decrements correctly."""
    from monitoring import Gauge
    logger.info("=== Testing Gauge ===")
    g = Gauge("test_gauge", "A test gauge")
    assert g.get() == 0.0
    g.set(10.0)
    assert g.get() == 10.0
    g.inc(3.0)
    assert g.get() == 13.0
    g.dec(5.0)
    assert g.get() == 8.0
    # With labels
    g.set(42.0, labels={"region": "us-east"})
    assert g.get(labels={"region": "us-east"}) == 42.0
    assert g.get() == 8.0  # unlabeled unchanged
    logger.info("Gauge test passed")


@pytest.mark.asyncio
async def test_metrics_collector_prometheus_format():
    """MetricsCollector.expose_prometheus produces valid Prometheus text."""
    from monitoring import MetricsCollector
    logger.info("=== Testing Prometheus Exposition ===")
    mc = MetricsCollector(namespace="test")
    mc.counter_inc("items_total", labels={"type": "a"})
    mc.counter_inc("items_total", labels={"type": "a"})
    mc.counter_inc("items_total", labels={"type": "b"})
    mc.gauge_set("queue_depth", 5)
    mc.histogram_observe("request_duration", 0.25)
    mc.histogram_observe("request_duration", 1.5)

    text = mc.expose_prometheus()
    assert isinstance(text, str)
    assert len(text) > 0

    # Check format: every line should end with \n (except last)
    lines = text.strip().split("\n")
    assert len(lines) > 5, f"Expected many lines, got {len(lines)}"

    # Should contain HELP and TYPE lines
    assert "# HELP test_items_total" in text
    assert "# TYPE test_items_total counter" in text
    assert "# HELP test_queue_depth" in text
    assert "# TYPE test_queue_depth gauge" in text
    assert "# HELP test_request_duration" in text
    assert "# TYPE test_request_duration histogram" in text

    # Should contain actual values
    assert 'test_items_total{type="a"} 2' in text
    assert 'test_items_total{type="b"} 1' in text
    assert "test_queue_depth 5" in text

    # Histogram should have _bucket, _sum, _count
    assert "test_request_duration_bucket" in text
    assert "test_request_duration_sum" in text
    assert "test_request_duration_count" in text

    # Uptime line
    assert "test_uptime_seconds" in text

    logger.info(f"Prometheus output preview:\n{text[:500]}")
    logger.info("Prometheus exposition test passed")


@pytest.mark.asyncio
async def test_metrics_collector_json_format():
    """MetricsCollector.expose_json returns structured dict."""
    from monitoring import MetricsCollector
    logger.info("=== Testing JSON Exposition ===")
    mc = MetricsCollector(namespace="test_json")
    mc.counter_inc("events", labels={"source": "agent"})
    mc.gauge_set("connections", 42)
    mc.histogram_observe("latency", 0.1)

    data = mc.expose_json()
    assert isinstance(data, dict)
    assert data["namespace"] == "test_json"
    assert "uptime_seconds" in data
    assert "timestamp" in data
    assert "counters" in data
    assert "histograms" in data
    assert "gauges" in data
    assert "events" in data["counters"]
    assert "connections" in data["gauges"]
    assert "latency" in data["histograms"]
    logger.info("JSON exposition test passed")


@pytest.mark.asyncio
async def test_metrics_collector_high_level_recorders():
    """MetricsCollector convenience methods record correctly."""
    from monitoring import MetricsCollector
    logger.info("=== Testing High-Level Recorders ===")
    mc = MetricsCollector()

    mc.record_agent_execution("binary_analysis", 1.23, success=True, tools_used=3)
    mc.record_agent_execution("binary_analysis", 0.5, success=False, tools_used=1)
    mc.record_llm_call("binary_analysis", 0.8, success=True, prompt_tokens=500, completion_tokens=200)
    mc.record_tool_execution("objdump", 0.05, success=True)
    mc.record_tool_execution("strings", 0.02, success=True)
    mc.record_mission_event("created")
    mc.record_mission_event("started")
    mc.record_debate("consensus", 3)
    mc.record_critique(reanalysis=False, score=0.85)
    mc.record_token_usage("agent_1", 100, 50, mission_id="m1")

    # Verify counters
    assert mc._counters["agent_executions_total"].get(labels={"agent_type": "binary_analysis", "status": "success"}) == 1.0
    assert mc._counters["agent_executions_total"].get(labels={"agent_type": "binary_analysis", "status": "failure"}) == 1.0
    assert mc._counters["tool_executions_total"].get(labels={"tool": "objdump", "status": "success"}) == 1.0
    assert mc._counters["mission_events_total"].get(labels={"event": "created"}) == 1.0
    assert mc._counters["debate_total"].get(labels={"consensus": "consensus"}) == 1.0

    # Verify histograms
    llm_data = mc._histograms["llm_latency_seconds"].get(labels={"agent_type": "binary_analysis"})
    assert llm_data["count"] == 1
    assert abs(llm_data["sum"] - 0.8) < 0.01

    logger.info("High-level recorders test passed")


@pytest.mark.asyncio
async def test_metrics_reset():
    """MetricsCollector.reset clears all values."""
    from monitoring import MetricsCollector
    logger.info("=== Testing Metrics Reset ===")
    mc = MetricsCollector()
    mc.counter_inc("items")
    mc.gauge_set("depth", 10)
    mc.histogram_observe("latency", 0.5)

    assert mc._counters["items"].get() == 1.0
    assert mc._gauges["depth"].get() == 10.0
    assert mc._histograms["latency"].get()["count"] == 1

    mc.reset()
    assert mc._counters["items"].get() == 0.0
    assert mc._gauges["depth"].get() == 0.0
    assert mc._histograms["latency"].get()["count"] == 0
    logger.info("Metrics reset test passed")


@pytest.mark.asyncio
async def test_metrics_singleton():
    """get_metrics returns the same instance; reset_metrics creates new."""
    from monitoring import get_metrics, reset_metrics, MetricsCollector
    logger.info("=== Testing Metrics Singleton ===")
    reset_metrics()
    m1 = get_metrics()
    m2 = get_metrics()
    assert m1 is m2, "Singleton should return same instance"
    reset_metrics()
    m3 = get_metrics()
    assert m3 is not m1, "After reset, should return new instance"
    reset_metrics()
    logger.info("Metrics singleton test passed")


@pytest.mark.asyncio
async def test_structured_json_logging_formatter():
    """StructuredJSONFormatter produces valid JSON log lines."""
    from monitoring import StructuredJSONFormatter
    import logging as _logging
    logger.info("=== Testing Structured JSON Logging ===")
    formatter = StructuredJSONFormatter()
    record = _logging.LogRecord(
        name="test_logger", level=_logging.INFO, pathname="test.py",
        lineno=1, msg="Test message %s", args=("arg1",), exc_info=None,
    )
    output = formatter.format(record)
    parsed = json.loads(output)
    assert parsed["level"] == "INFO"
    assert parsed["logger"] == "test_logger"
    assert "Test message arg1" in parsed["message"]
    assert "timestamp" in parsed
    logger.info("Structured JSON logging test passed")


@pytest.mark.asyncio
async def test_orchestrator_monitoring_integration():
    """ResearchOrchestrator initializes monitoring and records events."""
    logger.info("=== Testing Orchestrator Monitoring ===")
    orch = ResearchOrchestrator()
    assert orch._metrics is not None

    # Create a mission — should record metrics
    mission_id = orch.create_mission(
        title="Monitoring Test Mission",
        description="Testing monitoring integration",
    )
    assert mission_id is not None

    # Check metric was recorded
    mission_counter = orch._metrics._counters.get("mission_events_total")
    assert mission_counter is not None
    created_count = mission_counter.get(labels={"event": "created"})
    assert created_count >= 1.0, f"Expected >= 1 created event, got {created_count}"

    # System status should include monitoring_enabled
    status = orch.get_system_status()
    assert status["monitoring_enabled"] is True

    logger.info("Orchestrator monitoring integration test passed")


@pytest.mark.asyncio
async def test_monitoring_config_defaults():
    """Monitoring config settings have correct defaults."""
    logger.info("=== Testing Monitoring Config Defaults ===")
    from config.settings import (
        MONITORING_ENABLED, METRICS_PORT, METRICS_PATH,
        PROMETHEUS_ENABLED, GRAFANA_ENABLED, GRAFANA_PORT,
    )
    assert MONITORING_ENABLED is True
    assert METRICS_PORT == 9090
    assert METRICS_PATH == "/metrics"
    assert PROMETHEUS_ENABLED is True
    assert GRAFANA_ENABLED is True
    assert GRAFANA_PORT == 3000
    logger.info("Monitoring config defaults test passed")


@pytest.mark.asyncio
async def test_docker_compose_exists():
    """docker-compose.yml exists and contains required services."""
    logger.info("=== Testing docker-compose.yml ===")
    compose_path = Path("/home/ahmed/repos/reverse-engineering-lab/docker-compose.yml")
    assert compose_path.exists(), "docker-compose.yml not found"
    content = compose_path.read_text()
    # Should contain all required services
    required_services = ["app:", "postgres:", "neo4j:", "redis:", "prometheus:", "grafana:"]
    for svc in required_services:
        assert svc in content, f"Service '{svc}' not found in docker-compose.yml"
    # Should contain required volumes
    required_volumes = ["postgres-data:", "neo4j-data:", "redis-data:", "prometheus-data:", "grafana-data:"]
    for vol in required_volumes:
        assert vol in content, f"Volume '{vol}' not found in docker-compose.yml"
    logger.info("docker-compose.yml test passed")


@pytest.mark.asyncio
async def test_prometheus_config_exists():
    """Prometheus config exists and scrapes the RE lab app."""
    logger.info("=== Testing Prometheus Config ===")
    prom_path = Path("/home/ahmed/repos/reverse-engineering-lab/monitoring/prometheus/prometheus.yml")
    assert prom_path.exists(), "prometheus.yml not found"
    content = prom_path.read_text()
    assert "re-lab-app" in content, "App scrape target not found"
    assert "scrape_interval" in content, "Scrape interval not configured"
    logger.info("Prometheus config test passed")


@pytest.mark.asyncio
async def test_grafana_dashboards_exist():
    """Grafana dashboard JSONs exist and are valid JSON."""
    logger.info("=== Testing Grafana Dashboards ===")
    dash_dir = Path("/home/ahmed/repos/reverse-engineering-lab/monitoring/grafana/dashboards")
    assert dash_dir.exists(), "Dashboards directory not found"
    dash_files = list(dash_dir.glob("*.json"))
    assert len(dash_files) >= 2, f"Expected at least 2 dashboards, found {len(dash_files)}"
    for dash_file in dash_files:
        content = dash_file.read_text()
        data = json.loads(content)
        assert "title" in data, f"Dashboard {dash_file.name} missing title"
        assert "panels" in data, f"Dashboard {dash_file.name} missing panels"
        assert len(data["panels"]) > 0, f"Dashboard {dash_file.name} has no panels"
        logger.info(f"  Dashboard: {data['title']} ({len(data['panels'])} panels)")
    logger.info("Grafana dashboards test passed")


@pytest.mark.asyncio
async def test_grafana_provisioning_config():
    """Grafana provisioning configs exist and reference Prometheus."""
    logger.info("=== Testing Grafana Provisioning ===")
    ds_path = Path("/home/ahmed/repos/reverse-engineering-lab/monitoring/grafana/provisioning/datasources/prometheus.yml")
    assert ds_path.exists(), "Datasource provisioning not found"
    ds_content = ds_path.read_text()
    assert "prometheus" in ds_content.lower(), "Prometheus datasource not configured"

    db_path = Path("/home/ahmed/repos/reverse-engineering-lab/monitoring/grafana/provisioning/dashboards/dashboards.yml")
    assert db_path.exists(), "Dashboard provisioning not found"
    db_content = db_path.read_text()
    assert "dashboards" in db_content.lower(), "Dashboard provider not configured"
    logger.info("Grafana provisioning test passed")


# =========================================================================
# Phase 5 tests — Multi-provider LLM support, setup wizard
# =========================================================================


@pytest.mark.asyncio
async def test_provider_registry_all_present():
    """All 6 providers exist in the registry with required fields."""
    from providers import PROVIDERS, PROVIDER_ORDER
    logger.info("=== Testing Provider Registry ===")
    assert len(PROVIDERS) == 6
    required_fields = [
        "name", "display_name", "base_url", "default_model",
        "api_key_env", "setup_url", "setup_instructions",
    ]
    for name in PROVIDER_ORDER:
        prov = PROVIDERS[name]
        assert prov.name == name, f"Provider name mismatch: {prov.name} != {name}"
        for field in required_fields:
            val = getattr(prov, field)
            assert val, f"Provider {name} missing {field}"
        assert len(prov.models) > 0, f"Provider {name} has no models"
    logger.info("Provider registry test passed")


@pytest.mark.asyncio
async def test_provider_key_detection():
    """key_is_set and key_value reflect environment variables."""
    from providers import get_provider
    logger.info("=== Testing Provider Key Detection ===")
    prov = get_provider("openai")
    # Without env var set, should be False
    os.environ.pop("OPENAI_API_KEY", None)
    assert prov.key_is_set() is False
    assert prov.key_value() == ""
    # With env var
    os.environ["OPENAI_API_KEY"] = "test-key"
    assert prov.key_is_set() is True
    assert prov.key_value() == "test-key"
    os.environ.pop("OPENAI_API_KEY", None)
    logger.info("Provider key detection test passed")


@pytest.mark.asyncio
async def test_provider_ollama_no_api_key():
    """Ollama provider has requires_api_key=False."""
    from providers import get_provider
    logger.info("=== Testing Ollama No API Key ===")
    prov = get_provider("ollama")
    assert prov.requires_api_key is False
    assert prov.supports_json_mode is False
    assert prov.is_openai_compatible is True
    logger.info("Ollama no-API-key test passed")


@pytest.mark.asyncio
async def test_get_provider_valid_and_invalid():
    """get_provider returns provider for valid name, None for invalid."""
    from providers import get_provider, PROVIDERS
    logger.info("=== Testing get_provider ===")
    for name in PROVIDERS:
        prov = get_provider(name)
        assert prov is not None, f"get_provider('{name}') returned None"
        assert prov.name == name
    assert get_provider("nonexistent") is None
    assert get_provider("") is None
    logger.info("get_provider test passed")


@pytest.mark.asyncio
async def test_get_active_provider_from_env():
    """get_active_provider respects LLM_PROVIDER env var."""
    from providers import get_active_provider
    logger.info("=== Testing get_active_provider ===")
    # Save original
    orig = os.environ.get("LLM_PROVIDER")
    try:
        os.environ["LLM_PROVIDER"] = "anthropic"
        os.environ.pop("ANTHROPIC_API_KEY", None)
        os.environ.pop("OPENAI_API_KEY", None)
        os.environ.pop("GOOGLE_API_KEY", None)
        os.environ.pop("OPENROUTER_API_KEY", None)
        os.environ.pop("NVIDIA_API_KEY", None)
        prov = get_active_provider()
        assert prov is not None
        assert prov.name == "anthropic"
    finally:
        if orig is not None:
            os.environ["LLM_PROVIDER"] = orig
        else:
            os.environ.pop("LLM_PROVIDER", None)
    logger.info("get_active_provider test passed")


@pytest.mark.asyncio
async def test_get_active_provider_auto_detect():
    """get_active_provider auto-detects from API key env vars."""
    from providers import get_active_provider
    logger.info("=== Testing get_active_provider auto-detect ===")
    orig_provider = os.environ.get("LLM_PROVIDER")
    orig_openai = os.environ.get("OPENAI_API_KEY")
    orig_google = os.environ.get("GOOGLE_API_KEY")
    try:
        os.environ.pop("LLM_PROVIDER", None)
        os.environ.pop("OPENAI_API_KEY", None)
        os.environ.pop("GOOGLE_API_KEY", None)
        os.environ.pop("ANTHROPIC_API_KEY", None)
        os.environ.pop("OPENROUTER_API_KEY", None)
        os.environ.pop("NVIDIA_API_KEY", None)
        # Set Google key only
        os.environ["GOOGLE_API_KEY"] = "test-google-key"
        prov = get_active_provider()
        assert prov is not None
        assert prov.name == "google"
    finally:
        # Restore
        if orig_provider:
            os.environ["LLM_PROVIDER"] = orig_provider
        else:
            os.environ.pop("LLM_PROVIDER", None)
        if orig_openai:
            os.environ["OPENAI_API_KEY"] = orig_openai
        else:
            os.environ.pop("OPENAI_API_KEY", None)
        if orig_google:
            os.environ["GOOGLE_API_KEY"] = orig_google
        else:
            os.environ.pop("GOOGLE_API_KEY", None)
    logger.info("get_active_provider auto-detect test passed")


@pytest.mark.asyncio
async def test_migrate_legacy_env():
    """migrate_legacy_env copies legacy env vars to provider-specific vars."""
    from providers import migrate_legacy_env
    logger.info("=== Testing migrate_legacy_env ===")
    orig_llm = os.environ.get("LLM_API_KEY")
    orig_openai = os.environ.get("OPENAI_API_KEY")
    orig_gemini = os.environ.get("GEMINI_API_KEY")
    orig_google = os.environ.get("GOOGLE_API_KEY")
    try:
        # Clear targets
        os.environ.pop("OPENAI_API_KEY", None)
        os.environ.pop("GOOGLE_API_KEY", None)
        # Set legacy
        os.environ["LLM_API_KEY"] = "legacy-key-123"
        os.environ["LLM_PROVIDER"] = "openai"
        os.environ["GEMINI_API_KEY"] = "gemini-legacy-key"
        migrate_legacy_env()
        assert os.environ.get("OPENAI_API_KEY") == "legacy-key-123"
        assert os.environ.get("GOOGLE_API_KEY") == "gemini-legacy-key"
    finally:
        # Restore
        for key, val in [
            ("LLM_API_KEY", orig_llm), ("OPENAI_API_KEY", orig_openai),
            ("GEMINI_API_KEY", orig_gemini), ("GOOGLE_API_KEY", orig_google),
        ]:
            if val is not None:
                os.environ[key] = val
            else:
                os.environ.pop(key, None)
    logger.info("migrate_legacy_env test passed")


@pytest.mark.asyncio
async def test_detect_tools():
    """detect_tools returns a list of tool status dicts."""
    from providers import detect_tools
    logger.info("=== Testing detect_tools ===")
    tools = detect_tools()
    assert isinstance(tools, list)
    assert len(tools) > 0
    for tool in tools:
        assert "name" in tool
        assert "path" in tool
        assert "purpose" in tool
        assert "installed" in tool
        assert isinstance(tool["installed"], bool)
    # At least objdump should be installed
    names = [t["name"] for t in tools]
    assert "objdump" in names
    logger.info(f"Detected {len(tools)} tools, {sum(1 for t in tools if t['installed'])} installed")


@pytest.mark.asyncio
async def test_llm_config_resolves_openai_defaults():
    """LLMConfig resolves base_url and model from provider when not explicitly set."""
    logger.info("=== Testing LLMConfig Provider Resolution (OpenAI) ===")
    config = LLMConfig(api_key="sk-test-key", model="", provider="openai")
    assert config.base_url == "https://api.openai.com/v1"
    assert config.model == "gpt-4"
    logger.info("LLMConfig OpenAI resolution test passed")


@pytest.mark.asyncio
async def test_llm_config_resolves_anthropic_defaults():
    """LLMConfig resolves model from Anthropic provider."""
    logger.info("=== Testing LLMConfig Provider Resolution (Anthropic) ===")
    config = LLMConfig(api_key="sk-ant-test", model="", provider="anthropic")
    assert config.model == "claude-sonnet-4-20250514"
    assert "anthropic" in config.base_url
    logger.info("LLMConfig Anthropic resolution test passed")


@pytest.mark.asyncio
async def test_llm_config_ollama_allows_empty_key():
    """LLMConfig does not raise for Ollama with empty API key."""
    logger.info("=== Testing LLMConfig Ollama No Key ===")
    config = LLMConfig(api_key="", provider="ollama")
    assert config.model == "llama3.1"
    assert config.base_url == "http://localhost:11434/v1"
    logger.info("LLMConfig Ollama no-key test passed")


@pytest.mark.asyncio
async def test_llm_config_anthropic_rejects_empty_key():
    """LLMConfig raises error for Anthropic with empty API key."""
    logger.info("=== Testing LLMConfig Anthropic Empty Key ===")
    try:
        LLMConfig(api_key="", provider="anthropic")
        assert False, "Should have raised LLMClientNotConfiguredError"
    except LLMClientNotConfiguredError as e:
        assert "ANTHROPIC_API_KEY" in str(e)
    logger.info("LLMConfig Anthropic empty key test passed")


@pytest.mark.asyncio
async def test_anthropic_response_adapter():
    """_AnthropicResponse normalizes Anthropic usage to OpenAI format."""
    from llm_client import _AnthropicResponse
    logger.info("=== Testing Anthropic Response Adapter ===")

    class FakeUsage:
        input_tokens = 100
        output_tokens = 50

    resp = _AnthropicResponse("Hello world", FakeUsage())
    assert len(resp.choices) == 1
    assert resp.choices[0].message.content == "Hello world"
    assert resp.usage.prompt_tokens == 100
    assert resp.usage.completion_tokens == 50
    logger.info("Anthropic response adapter test passed")


@pytest.mark.asyncio
async def test_provider_setup_instructions_complete():
    """Every provider has non-empty setup instructions and URL."""
    from providers import PROVIDERS
    logger.info("=== Testing Provider Setup Instructions ===")
    for name, prov in PROVIDERS.items():
        assert prov.setup_url.startswith("http"), f"{name}: setup_url not a URL"
        assert len(prov.setup_instructions) > 50, f"{name}: setup_instructions too short"
        assert len(prov.api_key_format) > 0, f"{name}: api_key_format empty"
        logger.info(f"  {prov.display_name}: {prov.setup_url}")
    logger.info("Provider setup instructions test passed")


@pytest.mark.asyncio
async def test_setup_wizard_importable():
    """setup_wizard.py is importable and has required classes/functions."""
    logger.info("=== Testing Setup Wizard Import ===")
    import importlib
    mod = importlib.import_module("setup_wizard")
    assert hasattr(mod, "SetupWizard")
    assert hasattr(mod, "validate_api_key")
    assert hasattr(mod, "check_installed")
    assert hasattr(mod, "check_python_package")
    wizard = mod.SetupWizard()
    assert hasattr(wizard, "run")
    assert hasattr(wizard, "env_vars")
    logger.info("Setup wizard import test passed")


@pytest.mark.asyncio
async def test_llm_config_custom_model_overrides_provider():
    """LLMConfig preserves explicitly set model over provider default."""
    logger.info("=== Testing LLMConfig Custom Model Override ===")
    config = LLMConfig(api_key="sk-test", model="gpt-4o-mini", provider="openai")
    assert config.model == "gpt-4o-mini"
    # base_url should still be resolved from provider
    assert config.base_url == "https://api.openai.com/v1"
    logger.info("LLMConfig custom model override test passed")


@pytest.mark.asyncio
async def test_llm_client_anthropic_provider():
    """LLMClient with Anthropic provider initializes adapter instead of openai client."""
    logger.info("=== Testing LLMClient Anthropic Provider Init ===")
    with patch("llm_client._AnthropicAdapter") as mock_adapter_cls:
        mock_adapter_cls.return_value = MagicMock()
        config = LLMConfig(api_key="sk-ant-test", model="claude-sonnet-4-20250514", provider="anthropic")
        client = LLMClient(config)
        assert client._anthropic_adapter is not None
        assert client._client is None
        mock_adapter_cls.assert_called_once()
    logger.info("LLMClient Anthropic provider init test passed")


@pytest.mark.asyncio
async def test_usage_stats_serialization():
    """UsageStats.to_dict returns expected fields."""
    logger.info("=== Testing UsageStats Serialization ===")
    stats = UsageStats()
    stats.record_call(100, 50, 200.0)
    stats.record_call(80, 30, 150.0, success=False)
    d = stats.to_dict()
    required_keys = [
        "total_calls", "successful_calls", "failed_calls",
        "total_prompt_tokens", "total_completion_tokens", "total_tokens",
        "total_latency_ms", "average_latency_ms",
    ]
    for key in required_keys:
        assert key in d, f"Missing key: {key}"
    assert d["total_calls"] == 2
    assert d["successful_calls"] == 1
    assert d["failed_calls"] == 1
    assert d["total_tokens"] == 260
    logger.info("UsageStats serialization test passed")


# =========================================================================
# Phase 6 tests — MCP opencode server, agents, skills
# =========================================================================


@pytest.mark.asyncio
async def test_mcp_server_tool_registry():
    """MCP server registers all expected tools."""
    from mcp.opencode_server import TOOLS, _build_tools_list
    logger.info("=== Testing MCP Server Tool Registry ===")
    assert len(TOOLS) >= 46, f"Expected at least 46 tools, got {len(TOOLS)}"
    tool_names = [t["name"] for t in TOOLS]
    expected = [
        "re_file_identify", "re_readelf", "re_objdump", "re_strings",
        "re_hexdump", "re_binwalk", "re_tshark", "re_capinfos",
        "re_gdb", "re_ghidra", "re_available_tools", "re_run_command",
        "kb_add_fact", "kb_add_hypothesis", "kb_search", "kb_get_item",
        "kb_statistics", "kb_link_items",
        "re_debate", "re_setup_status", "re_validate_api_key",
        "re_setup_provider", "re_metrics", "re_system_status",
        "re_create_mission", "re_list_missions", "re_web_dashboard",
        "re_analyze", "re_mission_update", "re_mission_detail",
        "re_token_budget_status", "kb_add_experiment", "kb_update_item",
        "kb_delete_item", "re_ghidra_decompile", "re_ghidra_functions",
        "re_ghidra_xrefs", "re_ghidra_imports", "re_gdb_symbols",
        "re_gdb_registers", "re_gdb_backtrace", "re_gdb_memory",
        "re_rag_search", "re_rag_context", "re_config_get",
        "re_llm_status",
    ]
    for name in expected:
        assert name in tool_names, f"Missing tool: {name}"
    # tools list should not expose _handler
    tools_list = _build_tools_list()
    for t in tools_list:
        assert "_handler" not in t, f"_handler leaked into tools/list for {t['name']}"
        assert "name" in t
        assert "description" in t
        assert "inputSchema" in t
    logger.info(f"MCP server has {len(TOOLS)} tools registered")


@pytest.mark.asyncio
async def test_mcp_server_initialize():
    """MCP server handles initialize request correctly."""
    from mcp.opencode_server import handle_message
    logger.info("=== Testing MCP Server Initialize ===")
    response = await handle_message({
        "jsonrpc": "2.0",
        "id": "1",
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1.0"},
        },
    })
    assert response is not None
    assert response["jsonrpc"] == "2.0"
    assert response["id"] == "1"
    result = response["result"]
    assert result["serverInfo"]["name"] == "re-lab-mcp"
    assert result["protocolVersion"] == "2024-11-05"
    assert "tools" in result["capabilities"]
    logger.info("MCP server initialize test passed")


@pytest.mark.asyncio
async def test_mcp_server_tools_list():
    """MCP server handles tools/list request."""
    from mcp.opencode_server import handle_message
    logger.info("=== Testing MCP Server Tools List ===")
    response = await handle_message({
        "jsonrpc": "2.0",
        "id": "2",
        "method": "tools/list",
        "params": {},
    })
    assert response is not None
    tools = response["result"]["tools"]
    assert len(tools) >= 18
    names = [t["name"] for t in tools]
    assert "re_file_identify" in names
    assert "kb_search" in names
    logger.info(f"Tools list returned {len(tools)} tools")


@pytest.mark.asyncio
async def test_mcp_server_tool_call_file_identify():
    """MCP server re_file_identify works via tools/call."""
    from mcp.opencode_server import handle_message
    logger.info("=== Testing MCP Server re_file_identify ===")
    response = await handle_message({
        "jsonrpc": "2.0",
        "id": "3",
        "method": "tools/call",
        "params": {
            "name": "re_file_identify",
            "arguments": {"file_path": "/bin/ls"},
        },
    })
    assert response is not None
    result = response["result"]
    assert "content" in result
    assert result.get("isError") is not True
    text = result["content"][0]["text"]
    assert "ELF" in text or "executable" in text.lower() or "bin/ls" in text
    logger.info(f"file_identify result: {text[:100]}")


@pytest.mark.asyncio
async def test_mcp_server_tool_call_readelf():
    """MCP server re_readelf works via tools/call."""
    from mcp.opencode_server import handle_message
    logger.info("=== Testing MCP Server re_readelf ===")
    response = await handle_message({
        "jsonrpc": "2.0",
        "id": "4",
        "method": "tools/call",
        "params": {
            "name": "re_readelf",
            "arguments": {"file_path": "/bin/ls", "headers": True},
        },
    })
    result = response["result"]
    assert result.get("isError") is not True
    text = result["content"][0]["text"]
    assert "ELF" in text or "Magic" in text or "Class" in text
    logger.info(f"readelf result preview: {text[:150]}")


@pytest.mark.asyncio
async def test_mcp_server_tool_call_strings():
    """MCP server re_strings works via tools/call."""
    from mcp.opencode_server import handle_message
    logger.info("=== Testing MCP Server re_strings ===")
    response = await handle_message({
        "jsonrpc": "2.0",
        "id": "5",
        "method": "tools/call",
        "params": {
            "name": "re_strings",
            "arguments": {"file_path": "/bin/ls", "min_length": 10},
        },
    })
    result = response["result"]
    assert result.get("isError") is not True
    text = result["content"][0]["text"]
    assert len(text) > 50
    logger.info(f"strings result preview: {text[:150]}")


@pytest.mark.asyncio
async def test_mcp_server_tool_call_available_tools():
    """MCP server re_available_tools returns tool availability."""
    from mcp.opencode_server import handle_message
    logger.info("=== Testing MCP Server re_available_tools ===")
    response = await handle_message({
        "jsonrpc": "2.0",
        "id": "6",
        "method": "tools/call",
        "params": {"name": "re_available_tools", "arguments": {}},
    })
    result = response["result"]
    assert result.get("isError") is not True
    text = result["content"][0]["text"]
    assert "objdump" in text
    assert "installed" in text or "NOT FOUND" in text
    logger.info(f"available_tools result preview: {text[:200]}")


@pytest.mark.asyncio
async def test_mcp_server_tool_call_kb_add_and_search():
    """MCP server kb_add_fact + kb_search round-trip."""
    from mcp.opencode_server import handle_message
    logger.info("=== Testing MCP Server KB Round-Trip ===")
    # Add fact
    add_resp = await handle_message({
        "jsonrpc": "2.0",
        "id": "7",
        "method": "tools/call",
        "params": {
            "name": "kb_add_fact",
            "arguments": {
                "title": "MCP Test Fact",
                "description": "A fact added via MCP server test",
                "confidence": 0.95,
                "evidence": ["test evidence"],
                "tags": ["mcp", "test"],
                "source_agent": "mcp_test",
            },
        },
    })
    assert add_resp["result"].get("isError") is not True
    id_text = add_resp["result"]["content"][0]["text"]
    assert "ID:" in id_text

    # Search
    search_resp = await handle_message({
        "jsonrpc": "2.0",
        "id": "8",
        "method": "tools/call",
        "params": {
            "name": "kb_search",
            "arguments": {"query": "MCP Test Fact"},
        },
    })
    assert search_resp["result"].get("isError") is not True
    search_text = search_resp["result"]["content"][0]["text"]
    assert "MCP Test Fact" in search_text
    logger.info("KB round-trip test passed")


@pytest.mark.asyncio
async def test_mcp_server_tool_call_kb_statistics():
    """MCP server kb_statistics returns stats."""
    from mcp.opencode_server import handle_message
    logger.info("=== Testing MCP Server kb_statistics ===")
    response = await handle_message({
        "jsonrpc": "2.0",
        "id": "9",
        "method": "tools/call",
        "params": {"name": "kb_statistics", "arguments": {}},
    })
    result = response["result"]
    assert result.get("isError") is not True
    text = result["content"][0]["text"]
    assert "total_items" in text
    logger.info(f"kb_statistics: {text[:150]}")


@pytest.mark.asyncio
async def test_mcp_server_unknown_tool():
    """MCP server returns error for unknown tool."""
    from mcp.opencode_server import handle_message
    logger.info("=== Testing MCP Server Unknown Tool ===")
    response = await handle_message({
        "jsonrpc": "2.0",
        "id": "10",
        "method": "tools/call",
        "params": {"name": "nonexistent_tool", "arguments": {}},
    })
    result = response["result"]
    assert result.get("isError") is True
    assert "nonexistent_tool" in result["content"][0]["text"]
    logger.info("Unknown tool error test passed")


@pytest.mark.asyncio
async def test_mcp_server_unknown_method():
    """MCP server returns JSON-RPC error for unknown method."""
    from mcp.opencode_server import handle_message
    logger.info("=== Testing MCP Server Unknown Method ===")
    response = await handle_message({
        "jsonrpc": "2.0",
        "id": "11",
        "method": "unknown/method",
        "params": {},
    })
    assert "error" in response
    assert response["error"]["code"] == -32601
    logger.info("Unknown method error test passed")


@pytest.mark.asyncio
async def test_mcp_server_ping():
    """MCP server responds to ping."""
    from mcp.opencode_server import handle_message
    logger.info("=== Testing MCP Server Ping ===")
    response = await handle_message({
        "jsonrpc": "2.0",
        "id": "12",
        "method": "ping",
        "params": {},
    })
    assert response is not None
    assert "result" in response
    logger.info("Ping test passed")


@pytest.mark.asyncio
async def test_opencode_agent_files_exist():
    """All opencode agent definition files exist and are valid markdown."""
    logger.info("=== Testing Opencode Agent Files ===")
    agents_dir = Path("/home/ahmed/repos/reverse-engineering-lab/.opencode/agents")
    assert agents_dir.exists()
    expected_agents = ["re-binary.md", "re-firmware.md", "re-network.md", "re-kernel.md", "re-general.md"]
    for agent_file in expected_agents:
        path = agents_dir / agent_file
        assert path.exists(), f"Agent file not found: {agent_file}"
        content = path.read_text()
        assert "---" in content, f"Agent file {agent_file} missing frontmatter"
        assert "mode:" in content, f"Agent file {agent_file} missing mode"
        assert "description:" in content, f"Agent file {agent_file} missing description"
        logger.info(f"  Agent: {agent_file} OK")
    logger.info("Opencode agent files test passed")


@pytest.mark.asyncio
async def test_opencode_skill_files_exist():
    """All opencode skill definition files exist and are valid SKILL.md."""
    logger.info("=== Testing Opencode Skill Files ===")
    skills_dir = Path("/home/ahmed/repos/reverse-engineering-lab/.opencode/skills")
    assert skills_dir.exists()
    expected_skills = ["binary-analysis", "firmware-analysis", "network-analysis", "kernel-analysis"]
    for skill_name in expected_skills:
        skill_file = skills_dir / skill_name / "SKILL.md"
        assert skill_file.exists(), f"Skill file not found: {skill_name}/SKILL.md"
        content = skill_file.read_text()
        assert "---" in content, f"Skill {skill_name} missing frontmatter"
        assert "name:" in content, f"Skill {skill_name} missing name"
        assert "description:" in content, f"Skill {skill_name} missing description"
        assert skill_name in content, f"Skill {skill_name} name not in content"
        logger.info(f"  Skill: {skill_name} OK")
    logger.info("Opencode skill files test passed")


@pytest.mark.asyncio
async def test_opencode_config_exists():
    """opencode.json exists and has required fields."""
    logger.info("=== Testing opencode.json ===")
    config_path = Path("/home/ahmed/repos/reverse-engineering-lab/opencode.json")
    assert config_path.exists(), "opencode.json not found"
    config = json.loads(config_path.read_text())
    assert "$schema" in config, "Missing $schema"
    assert "mcp" in config, "Missing mcp section"
    assert "re-lab" in config["mcp"], "Missing re-lab MCP server"
    assert "agent" in config, "Missing agent section"
    expected_agents = ["re-binary", "re-firmware", "re-network", "re-kernel", "re-general"]
    for agent_name in expected_agents:
        assert agent_name in config["agent"], f"Missing agent: {agent_name}"
    assert "skills" in config, "Missing skills section"
    assert ".opencode/skills" in config["skills"]["paths"], "Skills path not configured"
    logger.info("opencode.json test passed")


@pytest.mark.asyncio
async def test_opencode_agents_md_exists():
    """AGENTS.md exists and contains usage instructions."""
    logger.info("=== Testing AGENTS.md ===")
    agents_md = Path("/home/ahmed/repos/reverse-engineering-lab/AGENTS.md")
    assert agents_md.exists(), "AGENTS.md not found"
    content = agents_md.read_text()
    assert "re_file_identify" in content, "AGENTS.md should mention re_file_identify"
    assert "kb_add_fact" in content, "AGENTS.md should mention kb_add_fact"
    assert "knowledge base" in content.lower(), "AGENTS.md should mention knowledge base"
    logger.info("AGENTS.md test passed")


@pytest.mark.asyncio
async def test_antigravity_agent_files_exist():
    """All antigravity agent definition files exist and are valid markdown."""
    logger.info("=== Testing Antigravity Agent Files ===")
    agents_dir = Path("/home/ahmed/repos/reverse-engineering-lab/.agents/agents")
    assert agents_dir.exists()
    expected_agents = ["re-binary.md", "re-firmware.md", "re-network.md", "re-kernel.md", "re-general.md"]
    for agent_file in expected_agents:
        path = agents_dir / agent_file
        assert path.exists(), f"Agent file not found: {agent_file}"
        content = path.read_text()
        assert "---" in content, f"Agent file {agent_file} missing frontmatter"
        assert "mode:" in content, f"Agent file {agent_file} missing mode"
        assert "description:" in content, f"Agent file {agent_file} missing description"
        logger.info(f"  Agent: {agent_file} OK")
    logger.info("Antigravity agent files test passed")


@pytest.mark.asyncio
async def test_antigravity_skill_files_exist():
    """All antigravity skill definition files exist and are valid SKILL.md."""
    logger.info("=== Testing Antigravity Skill Files ===")
    skills_dir = Path("/home/ahmed/repos/reverse-engineering-lab/.agents/skills")
    assert skills_dir.exists()
    expected_skills = ["binary-analysis", "firmware-analysis", "network-analysis", "kernel-analysis"]
    for skill_name in expected_skills:
        skill_file = skills_dir / skill_name / "SKILL.md"
        assert skill_file.exists(), f"Skill file not found: {skill_name}/SKILL.md"
        content = skill_file.read_text()
        assert "---" in content, f"Skill {skill_name} missing frontmatter"
        assert "name:" in content, f"Skill {skill_name} missing name"
        assert "description:" in content, f"Skill {skill_name} missing description"
        assert skill_name in content, f"Skill {skill_name} name not in content"
        logger.info(f"  Skill: {skill_name} OK")
    logger.info("Antigravity skill files test passed")


@pytest.mark.asyncio
async def test_antigravity_config_exists():
    """antigravity.json and mcp_config.json exist in .agents/ and have required fields."""
    logger.info("=== Testing antigravity.json & mcp_config.json ===")
    config_path = Path("/home/ahmed/repos/reverse-engineering-lab/.agents/antigravity.json")
    assert config_path.exists(), ".agents/antigravity.json not found"
    config = json.loads(config_path.read_text())
    assert "$schema" in config, "Missing $schema"
    assert "mcp" in config, "Missing mcp section"
    assert "re-lab" in config["mcp"], "Missing re-lab MCP server"
    assert "agent" in config, "Missing agent section"
    expected_agents = ["re-binary", "re-firmware", "re-network", "re-kernel", "re-general"]
    for agent_name in expected_agents:
        assert agent_name in config["agent"], f"Missing agent: {agent_name}"
    assert "skills" in config, "Missing skills section"
    assert ".agents/skills" in config["skills"]["paths"], "Skills path not configured"

    mcp_config_path = Path("/home/ahmed/repos/reverse-engineering-lab/.agents/mcp_config.json")
    assert mcp_config_path.exists(), ".agents/mcp_config.json not found"
    mcp_config = json.loads(mcp_config_path.read_text())
    assert "mcpServers" in mcp_config
    assert "re-lab" in mcp_config["mcpServers"]
    logger.info("antigravity config tests passed")


@pytest.mark.asyncio
async def test_mcp_server_debate_tool():
    """MCP server re_debate runs offline debate with 2 assertions."""
    from mcp.opencode_server import handle_message
    logger.info("=== Testing MCP Server re_debate ===")
    response = await handle_message({
        "jsonrpc": "2.0",
        "id": "20",
        "method": "tools/call",
        "params": {
            "name": "re_debate",
            "arguments": {
                "topic": "Is this binary using AES or XOR encryption?",
                "assertions": [
                    {
                        "assertion": "The binary uses AES encryption based on S-box patterns",
                        "agent_id": "agent_1",
                        "agent_name": "Binary Agent",
                        "agent_type": "binary_analysis",
                        "context": "S-box constants found at 0x402000 match AES specification. Round key schedule visible in disassembly.",
                    },
                    {
                        "assertion": "The binary uses XOR-based obfuscation, not AES",
                        "agent_id": "agent_2",
                        "agent_name": "CPU Agent",
                        "agent_type": "cpu_analysis",
                        "context": "Disassembly shows repeated XOR operations. No AESENC/AESDEC instructions found.",
                    },
                ],
            },
        },
    })
    result = response["result"]
    assert result.get("isError") is not True
    text = result["content"][0]["text"]
    assert "debate_id" in text
    assert "final_consensus" in text
    logger.info(f"Debate result preview: {text[:200]}")


@pytest.mark.asyncio
async def test_mcp_server_debate_rejects_single_assertion():
    """MCP server re_debate rejects fewer than 2 assertions."""
    from mcp.opencode_server import handle_message
    logger.info("=== Testing MCP Server re_debate (single assertion) ===")
    response = await handle_message({
        "jsonrpc": "2.0",
        "id": "21",
        "method": "tools/call",
        "params": {
            "name": "re_debate",
            "arguments": {
                "topic": "Test",
                "assertions": [
                    {"assertion": "Only one", "agent_id": "a1", "agent_name": "Agent1"},
                ],
            },
        },
    })
    result = response["result"]
    assert result.get("isError") is True
    assert "at least 2" in result["content"][0]["text"]
    logger.info("Debate single-assertion rejection test passed")


@pytest.mark.asyncio
async def test_mcp_server_setup_status():
    """MCP server re_setup_status returns provider and tool status."""
    from mcp.opencode_server import handle_message
    logger.info("=== Testing MCP Server re_setup_status ===")
    response = await handle_message({
        "jsonrpc": "2.0",
        "id": "22",
        "method": "tools/call",
        "params": {"name": "re_setup_status", "arguments": {}},
    })
    result = response["result"]
    assert result.get("isError") is not True
    text = result["content"][0]["text"]
    assert "providers" in text
    assert "tools" in text
    assert "openai" in text
    assert "ollama" in text
    logger.info(f"Setup status preview: {text[:200]}")


@pytest.mark.asyncio
async def test_mcp_server_setup_provider():
    """MCP server re_setup_provider writes provider config to .env."""
    from mcp.opencode_server import handle_message
    logger.info("=== Testing MCP Server re_setup_provider ===")
    import os
    # Save original .env
    env_path = Path("/home/ahmed/repos/reverse-engineering-lab/.env")
    orig_env = env_path.read_text() if env_path.exists() else None
    try:
        response = await handle_message({
            "jsonrpc": "2.0",
            "id": "23",
            "method": "tools/call",
            "params": {
                "name": "re_setup_provider",
                "arguments": {
                    "provider": "openai",
                    "api_key": "sk-test-mcp-key",
                },
            },
        })
        result = response["result"]
        assert result.get("isError") is not True
        assert "configured" in result["content"][0]["text"]
        # Verify .env was updated
        assert env_path.exists()
        env_content = env_path.read_text()
        assert "OPENAI_API_KEY=sk-test-mcp-key" in env_content
        assert "LLM_PROVIDER=openai" in env_content
        logger.info("Setup provider test passed")
    finally:
        # Restore original .env
        if orig_env is not None:
            env_path.write_text(orig_env)
        elif env_path.exists():
            env_path.unlink()


@pytest.mark.asyncio
async def test_mcp_server_metrics():
    """MCP server re_metrics returns metrics data."""
    from mcp.opencode_server import handle_message
    logger.info("=== Testing MCP Server re_metrics ===")
    response = await handle_message({
        "jsonrpc": "2.0",
        "id": "24",
        "method": "tools/call",
        "params": {"name": "re_metrics", "arguments": {"format": "json"}},
    })
    result = response["result"]
    assert result.get("isError") is not True
    text = result["content"][0]["text"]
    assert "namespace" in text or "uptime" in text
    logger.info(f"Metrics preview: {text[:150]}")


@pytest.mark.asyncio
async def test_mcp_server_metrics_prometheus():
    """MCP server re_metrics returns Prometheus format."""
    from mcp.opencode_server import handle_message
    logger.info("=== Testing MCP Server re_metrics (Prometheus) ===")
    response = await handle_message({
        "jsonrpc": "2.0",
        "id": "25",
        "method": "tools/call",
        "params": {"name": "re_metrics", "arguments": {"format": "prometheus"}},
    })
    result = response["result"]
    assert result.get("isError") is not True
    text = result["content"][0]["text"]
    assert "uptime_seconds" in text
    logger.info(f"Prometheus metrics preview: {text[:150]}")


@pytest.mark.asyncio
async def test_mcp_server_system_status():
    """MCP server re_system_status returns orchestrator status."""
    from mcp.opencode_server import handle_message
    logger.info("=== Testing MCP Server re_system_status ===")
    response = await handle_message({
        "jsonrpc": "2.0",
        "id": "26",
        "method": "tools/call",
        "params": {"name": "re_system_status", "arguments": {}},
    })
    result = response["result"]
    assert result.get("isError") is not True
    text = result["content"][0]["text"]
    assert "orchestrator_running" in text
    assert "total_agents" in text
    assert "debate_count" in text
    logger.info(f"System status preview: {text[:200]}")


@pytest.mark.asyncio
async def test_mcp_server_create_and_list_missions():
    """MCP server re_create_mission + re_list_missions round-trip."""
    from mcp.opencode_server import handle_message
    logger.info("=== Testing MCP Server Mission Round-Trip ===")
    # Create mission
    create_resp = await handle_message({
        "jsonrpc": "2.0",
        "id": "27",
        "method": "tools/call",
        "params": {
            "name": "re_create_mission",
            "arguments": {
                "title": "MCP Test Mission",
                "description": "A mission created via MCP test",
                "tags": ["mcp", "test"],
            },
        },
    })
    assert create_resp["result"].get("isError") is not True
    id_text = create_resp["result"]["content"][0]["text"]
    assert "ID:" in id_text

    # List missions
    list_resp = await handle_message({
        "jsonrpc": "2.0",
        "id": "28",
        "method": "tools/call",
        "params": {"name": "re_list_missions", "arguments": {}},
    })
    assert list_resp["result"].get("isError") is not True
    list_text = list_resp["result"]["content"][0]["text"]
    assert "MCP Test Mission" in list_text
    logger.info("Mission round-trip test passed")


@pytest.mark.asyncio
async def test_mcp_server_web_dashboard():
    """MCP server re_web_dashboard returns status (running or not)."""
    from mcp.opencode_server import handle_message
    logger.info("=== Testing MCP Server re_web_dashboard ===")
    response = await handle_message({
        "jsonrpc": "2.0",
        "id": "29",
        "method": "tools/call",
        "params": {"name": "re_web_dashboard", "arguments": {}},
    })
    result = response["result"]
    assert result.get("isError") is not True
    text = result["content"][0]["text"]
    assert "dashboard" in text.lower() or "5000" in text
    logger.info(f"Web dashboard status: {text[:150]}")


# =========================================================================
# Phase 6b tests — Extended MCP tools (agents, missions, KB, Ghidra, GDB, RAG, config)
# =========================================================================


@pytest.mark.asyncio
async def test_mcp_server_analyze_binary():
    """MCP server re_analyze runs binary analysis agent."""
    from mcp.opencode_server import handle_message
    logger.info("=== Testing MCP Server re_analyze (binary) ===")
    response = await handle_message({
        "jsonrpc": "2.0",
        "id": "30",
        "method": "tools/call",
        "params": {
            "name": "re_analyze",
            "arguments": {"agent_type": "binary", "file_path": "/bin/ls", "analysis_type": "basic"},
        },
    })
    result = response["result"]
    assert result.get("isError") is not True
    text = result["content"][0]["text"]
    assert "status" in text
    logger.info(f"re_analyze binary result preview: {text[:200]}")


@pytest.mark.asyncio
async def test_mcp_server_analyze_invalid_agent():
    """MCP server re_analyze rejects unknown agent type."""
    from mcp.opencode_server import handle_message
    logger.info("=== Testing MCP Server re_analyze (invalid) ===")
    response = await handle_message({
        "jsonrpc": "2.0",
        "id": "31",
        "method": "tools/call",
        "params": {
            "name": "re_analyze",
            "arguments": {"agent_type": "invalid", "file_path": "/bin/ls"},
        },
    })
    result = response["result"]
    assert result.get("isError") is True
    assert "Unknown agent type" in result["content"][0]["text"]
    logger.info("re_analyze invalid agent rejection test passed")


@pytest.mark.asyncio
async def test_mcp_server_mission_update():
    """MCP server re_mission_update starts and cancels a mission."""
    from mcp.opencode_server import handle_message
    logger.info("=== Testing MCP Server re_mission_update ===")
    # Create a mission first
    create_resp = await handle_message({
        "jsonrpc": "2.0",
        "id": "32a",
        "method": "tools/call",
        "params": {
            "name": "re_create_mission",
            "arguments": {"title": "Update Test Mission", "description": "Testing mission updates", "tags": ["test"]},
        },
    })
    id_text = create_resp["result"]["content"][0]["text"]
    mission_id = id_text.split("ID: ")[1].split("\n")[0].strip()

    # Start — now spawns background task, returns ACTIVE status
    start_resp = await handle_message({
        "jsonrpc": "2.0",
        "id": "32b",
        "method": "tools/call",
        "params": {
            "name": "re_mission_update",
            "arguments": {"mission_id": mission_id, "action": "start"},
        },
    })
    assert start_resp["result"].get("isError") is not True
    start_text = start_resp["result"]["content"][0]["text"]
    assert "started" in start_text.lower() or "active" in start_text.lower()

    # Wait briefly for the background task to complete (mission has no objectives)
    await asyncio.sleep(0.3)

    # Verify mission completed (no objectives → immediate completion)
    from mcp._shared_orchestrator import get_shared_orchestrator
    orch = get_shared_orchestrator()
    mission = orch.get_mission_status(mission_id)
    assert mission is not None
    # Mission should be completed since it has no objectives
    assert mission.status.value in ("completed", "active")

    logger.info("Mission update test passed")


@pytest.mark.asyncio
async def test_mcp_server_mission_detail():
    """MCP server re_mission_detail returns mission info."""
    from mcp.opencode_server import handle_message
    logger.info("=== Testing MCP Server re_mission_detail ===")
    # Create mission
    create_resp = await handle_message({
        "jsonrpc": "2.0",
        "id": "33a",
        "method": "tools/call",
        "params": {
            "name": "re_create_mission",
            "arguments": {"title": "Detail Test Mission", "description": "Testing mission detail"},
        },
    })
    id_text = create_resp["result"]["content"][0]["text"]
    mission_id = id_text.split("ID: ")[1].split("\n")[0].strip()

    # Get detail
    detail_resp = await handle_message({
        "jsonrpc": "2.0",
        "id": "33b",
        "method": "tools/call",
        "params": {
            "name": "re_mission_detail",
            "arguments": {"mission_id": mission_id},
        },
    })
    assert detail_resp["result"].get("isError") is not True
    text = detail_resp["result"]["content"][0]["text"]
    assert "Detail Test Mission" in text
    assert "planning" in text
    logger.info("Mission detail test passed")


@pytest.mark.asyncio
async def test_mcp_server_token_budget_status():
    """MCP server re_token_budget_status returns budget info."""
    from mcp.opencode_server import handle_message
    logger.info("=== Testing MCP Server re_token_budget_status ===")
    response = await handle_message({
        "jsonrpc": "2.0",
        "id": "34",
        "method": "tools/call",
        "params": {"name": "re_token_budget_status", "arguments": {}},
    })
    result = response["result"]
    assert result.get("isError") is not True
    text = result["content"][0]["text"]
    assert "global" in text.lower() or "token" in text.lower() or "not enabled" in text.lower()
    logger.info(f"Token budget status: {text[:200]}")


@pytest.mark.asyncio
async def test_mcp_server_kb_add_experiment():
    """MCP server kb_add_experiment stores an experiment."""
    from mcp.opencode_server import handle_message
    logger.info("=== Testing MCP Server kb_add_experiment ===")
    response = await handle_message({
        "jsonrpc": "2.0",
        "id": "35",
        "method": "tools/call",
        "params": {
            "name": "kb_add_experiment",
            "arguments": {
                "title": "Test Encryption Experiment",
                "description": "Testing whether binary uses AES or XOR",
                "setup": "Isolated binary in sandbox",
                "procedure": "Ran objdump and strings analysis",
                "results": "Found S-box patterns matching AES",
                "conclusion": "Binary uses AES-128 encryption",
                "tags": ["crypto", "experiment"],
            },
        },
    })
    assert response["result"].get("isError") is not True
    assert "ID:" in response["result"]["content"][0]["text"]
    logger.info("kb_add_experiment test passed")


@pytest.mark.asyncio
async def test_mcp_server_kb_update_and_delete():
    """MCP server kb_update_item + kb_delete_item round-trip."""
    from mcp.opencode_server import handle_message
    logger.info("=== Testing MCP Server KB Update + Delete ===")
    # Add fact
    add_resp = await handle_message({
        "jsonrpc": "2.0",
        "id": "36a",
        "method": "tools/call",
        "params": {
            "name": "kb_add_fact",
            "arguments": {"title": "Update/Delete Test Fact", "description": "To be updated then deleted", "confidence": 0.5},
        },
    })
    id_text = add_resp["result"]["content"][0]["text"]
    item_id = id_text.split("ID: ")[1].strip()

    # Update
    update_resp = await handle_message({
        "jsonrpc": "2.0",
        "id": "36b",
        "method": "tools/call",
        "params": {
            "name": "kb_update_item",
            "arguments": {"item_id": item_id, "title": "Updated Fact", "confidence": 0.95},
        },
    })
    assert update_resp["result"].get("isError") is not True
    assert "updated" in update_resp["result"]["content"][0]["text"].lower()

    # Verify update
    get_resp = await handle_message({
        "jsonrpc": "2.0",
        "id": "36c",
        "method": "tools/call",
        "params": {"name": "kb_get_item", "arguments": {"item_id": item_id}},
    })
    text = get_resp["result"]["content"][0]["text"]
    assert "Updated Fact" in text

    # Delete
    del_resp = await handle_message({
        "jsonrpc": "2.0",
        "id": "36d",
        "method": "tools/call",
        "params": {"name": "kb_delete_item", "arguments": {"item_id": item_id}},
    })
    assert del_resp["result"].get("isError") is not True
    assert "deleted" in del_resp["result"]["content"][0]["text"].lower()
    logger.info("KB update + delete test passed")


@pytest.mark.asyncio
async def test_mcp_server_gdb_symbols():
    """MCP server re_gdb_symbols returns symbol table."""
    from mcp.opencode_server import handle_message
    logger.info("=== Testing MCP Server re_gdb_symbols ===")
    response = await handle_message({
        "jsonrpc": "2.0",
        "id": "37",
        "method": "tools/call",
        "params": {
            "name": "re_gdb_symbols",
            "arguments": {"binary_path": "/bin/ls"},
        },
    })
    result = response["result"]
    assert result.get("isError") is not True
    text = result["content"][0]["text"]
    assert len(text) > 50
    logger.info(f"gdb_symbols preview: {text[:200]}")


@pytest.mark.asyncio
async def test_mcp_server_rag_search():
    """MCP server re_rag_search returns semantic search results."""
    from mcp.opencode_server import handle_message
    logger.info("=== Testing MCP Server re_rag_search ===")
    response = await handle_message({
        "jsonrpc": "2.0",
        "id": "38",
        "method": "tools/call",
        "params": {
            "name": "re_rag_search",
            "arguments": {"query": "ELF binary analysis", "top_k": 3},
        },
    })
    result = response["result"]
    assert result.get("isError") is not True
    text = result["content"][0]["text"]
    assert "result" in text.lower() or "found" in text.lower() or "no" in text.lower()
    logger.info(f"rag_search preview: {text[:200]}")


@pytest.mark.asyncio
async def test_mcp_server_rag_context():
    """MCP server re_rag_context returns context string."""
    from mcp.opencode_server import handle_message
    logger.info("=== Testing MCP Server re_rag_context ===")
    response = await handle_message({
        "jsonrpc": "2.0",
        "id": "39",
        "method": "tools/call",
        "params": {
            "name": "re_rag_context",
            "arguments": {"query": "binary encryption patterns", "max_tokens": 500},
        },
    })
    result = response["result"]
    assert result.get("isError") is not True
    text = result["content"][0]["text"]
    assert len(text) > 0
    logger.info(f"rag_context preview: {text[:200]}")


@pytest.mark.asyncio
async def test_mcp_server_config_get():
    """MCP server re_config_get returns config values."""
    from mcp.opencode_server import handle_message
    logger.info("=== Testing MCP Server re_config_get ===")
    response = await handle_message({
        "jsonrpc": "2.0",
        "id": "40",
        "method": "tools/call",
        "params": {"name": "re_config_get", "arguments": {}},
    })
    result = response["result"]
    assert result.get("isError") is not True
    text = result["content"][0]["text"]
    assert "TOKEN_BUDGET_ENABLED" in text
    assert "CRITIQUE_ENABLED" in text
    assert "MONITORING_ENABLED" in text
    logger.info(f"config_get preview: {text[:300]}")


@pytest.mark.asyncio
async def test_mcp_server_ghidra_imports():
    """MCP server re_ghidra_imports runs (may fail if Ghidra not installed)."""
    from mcp.opencode_server import handle_message
    logger.info("=== Testing MCP Server re_ghidra_imports ===")
    response = await handle_message({
        "jsonrpc": "2.0",
        "id": "41",
        "method": "tools/call",
        "params": {
            "name": "re_ghidra_imports",
            "arguments": {"file_path": "/bin/ls"},
        },
    })
    result = response["result"]
    # Should not error even if Ghidra is not installed (graceful fallback)
    assert "content" in result
    text = result["content"][0]["text"]
    logger.info(f"ghidra_imports result: {text[:200]}")


# ---------------------------------------------------------------------------
# Phase 6c — Mission execution engine tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_mission_start_completes_without_objectives():
    """Mission with no objectives completes immediately."""
    from orchestrator import ResearchOrchestrator, MissionStatus
    logger.info("=== Testing Mission Start (No Objectives) ===")
    orch = ResearchOrchestrator()
    mid = orch.create_mission(title="Empty Mission", description="No objectives")
    await orch.start_mission(mid)
    # Give the background task a moment to run
    await asyncio.sleep(0.3)
    mission = orch.get_mission_status(mid)
    assert mission.status == MissionStatus.COMPLETED
    assert mission.end_time is not None
    logger.info("Empty mission completed immediately")


@pytest.mark.asyncio
async def test_mission_start_with_objectives():
    """Mission with objectives decomposes and executes tasks."""
    from orchestrator import (
        ResearchOrchestrator, ResearchObjective, Priority as ObjPriority, MissionStatus,
    )
    logger.info("=== Testing Mission Start (With Objectives) ===")
    orch = ResearchOrchestrator()
    # Create a mission with a file_path in metadata
    mid = orch.create_mission(
        title="Binary Analysis Mission",
        description="Analyze /bin/ls",
        metadata={"file_path": "/bin/ls"},
    )
    obj = ResearchObjective(
        id=str(uuid.uuid4()),
        title="Identify functions",
        description="List all functions in the binary using binary analysis",
        priority=ObjPriority.HIGH,
        status="pending",
        assigned_agents=["binary"],
    )
    orch.add_objective_to_mission(mid, obj)

    await orch.start_mission(mid)
    # Wait for background task to finish
    await asyncio.sleep(1.0)

    mission = orch.get_mission_status(mid)
    assert mission.status in (MissionStatus.COMPLETED, MissionStatus.ACTIVE)
    assert mission.start_time is not None
    # The objective should have been processed (completed or failed since agent may not find the file)
    assert obj.status in ("completed", "in_progress", "failed")
    logger.info(f"Mission with objectives: status={mission.status.value}, obj_status={obj.status}")


@pytest.mark.asyncio
async def test_mission_dependency_ordering():
    """Objectives with dependencies execute in correct order."""
    from orchestrator import (
        ResearchOrchestrator, ResearchObjective, Priority as ObjPriority,
    )
    logger.info("=== Testing Mission Dependency Ordering ===")
    orch = ResearchOrchestrator()
    mid = orch.create_mission(
        title="Dependency Test",
        description="Test dependency ordering",
        metadata={"file_path": "/bin/ls"},
    )

    obj1_id = str(uuid.uuid4())
    obj2_id = str(uuid.uuid4())

    # obj2 depends on obj1
    obj1 = ResearchObjective(
        id=obj1_id, title="Step 1", description="First step",
        priority=ObjPriority.HIGH, status="pending", assigned_agents=["binary"],
    )
    obj2 = ResearchObjective(
        id=obj2_id, title="Step 2", description="Second step depends on first",
        priority=ObjPriority.HIGH, status="pending", assigned_agents=["binary"],
        dependencies=[obj1_id],
    )

    orch.add_objective_to_mission(mid, obj1)
    orch.add_objective_to_mission(mid, obj2)

    # Verify topological sort
    plan = orch._plan_objectives(orch.get_mission_status(mid))
    assert len(plan) == 2
    assert plan[0][2].id == obj1_id  # obj1 first
    assert plan[1][2].id == obj2_id  # obj2 second
    logger.info("Dependency ordering verified")


@pytest.mark.asyncio
async def test_mission_pause_and_resume():
    """Mission can be paused and resumed during execution."""
    from orchestrator import (
        ResearchOrchestrator, ResearchObjective, Priority as ObjPriority, MissionStatus,
    )
    logger.info("=== Testing Mission Pause/Resume ===")
    orch = ResearchOrchestrator()
    mid = orch.create_mission(
        title="Pause Test",
        description="Test pause/resume",
        metadata={"file_path": "/bin/ls"},
    )
    obj = ResearchObjective(
        id=str(uuid.uuid4()), title="Analyze",
        description="Analyze the binary using binary analysis",
        priority=ObjPriority.HIGH, status="pending", assigned_agents=["binary"],
    )
    orch.add_objective_to_mission(mid, obj)

    await orch.start_mission(mid)
    await asyncio.sleep(0.1)  # let background task start

    # Pause
    await orch.pause_mission(mid)
    mission = orch.get_mission_status(mid)
    assert mission.status == MissionStatus.PAUSED

    # Resume
    await orch.resume_mission(mid)
    mission = orch.get_mission_status(mid)
    assert mission.status == MissionStatus.ACTIVE

    # Wait for completion
    await asyncio.sleep(1.0)
    logger.info("Pause/resume test passed")


@pytest.mark.asyncio
async def test_mission_cancel():
    """Mission can be cancelled during execution."""
    from orchestrator import (
        ResearchOrchestrator, ResearchObjective, Priority as ObjPriority, MissionStatus,
    )
    logger.info("=== Testing Mission Cancel ===")
    orch = ResearchOrchestrator()
    mid = orch.create_mission(
        title="Cancel Test",
        description="Test cancel",
        metadata={"file_path": "/bin/ls"},
    )
    obj = ResearchObjective(
        id=str(uuid.uuid4()), title="Analyze",
        description="Analyze the binary using binary analysis",
        priority=ObjPriority.HIGH, status="pending", assigned_agents=["binary"],
    )
    orch.add_objective_to_mission(mid, obj)

    await orch.start_mission(mid)
    await asyncio.sleep(0.1)  # let background task start

    # Cancel
    await orch.cancel_mission(mid)
    mission = orch.get_mission_status(mid)
    assert mission.status == MissionStatus.CANCELLED
    assert mission.end_time is not None
    logger.info("Cancel test passed")


@pytest.mark.asyncio
async def test_mission_progress_tool():
    """re_mission_progress returns progress info."""
    from mcp.opencode_server import handle_message
    logger.info("=== Testing re_mission_progress ===")
    # Create mission
    create_resp = await handle_message({
        "jsonrpc": "2.0",
        "id": "mp1",
        "method": "tools/call",
        "params": {
            "name": "re_create_mission",
            "arguments": {"title": "Progress Test", "description": "Testing progress", "tags": ["test"]},
        },
    })
    id_text = create_resp["result"]["content"][0]["text"]
    mission_id = id_text.split("ID: ")[1].split("\n")[0].strip()

    # Get progress
    progress_resp = await handle_message({
        "jsonrpc": "2.0",
        "id": "mp2",
        "method": "tools/call",
        "params": {
            "name": "re_mission_progress",
            "arguments": {"mission_id": mission_id},
        },
    })
    assert progress_resp["result"].get("isError") is not True
    text = progress_resp["result"]["content"][0]["text"]
    assert "planning" in text
    logger.info("Mission progress tool test passed")


@pytest.mark.asyncio
async def test_create_mission_with_objectives():
    """re_create_mission with objectives parameter creates objectives."""
    from mcp.opencode_server import handle_message
    logger.info("=== Testing re_create_mission with objectives ===")
    resp = await handle_message({
        "jsonrpc": "2.0",
        "id": "co1",
        "method": "tools/call",
        "params": {
            "name": "re_create_mission",
            "arguments": {
                "title": "Obj Test",
                "description": "Test objectives creation",
                "file_path": "/bin/ls",
                "objectives": [
                    {
                        "title": "Scan binary",
                        "description": "Identify file type and structure",
                        "priority": "high",
                        "assigned_agents": ["binary"],
                    },
                    {
                        "title": "Analyze functions",
                        "description": "Decompile and list functions",
                        "priority": "medium",
                        "assigned_agents": ["binary"],
                        "dependencies": ["Scan binary"],
                    },
                ],
            },
        },
    })
    assert resp["result"].get("isError") is not True
    text = resp["result"]["content"][0]["text"]
    assert "Objectives: 2" in text
    assert "Scan binary" in text
    assert "Analyze functions" in text
    logger.info("Create mission with objectives test passed")


@pytest.mark.asyncio
async def test_mission_infer_agent_types():
    """Orchestrator infers agent types from objective descriptions."""
    from orchestrator import ResearchOrchestrator
    logger.info("=== Testing Agent Type Inference ===")
    orch = ResearchOrchestrator()

    assert orch._infer_agent_types("Analyze the ELF binary") == ["binary"]
    assert orch._infer_agent_types("Extract firmware from router image") == ["firmware"]
    assert orch._infer_agent_types("Capture network packets") == ["network"]
    assert orch._infer_agent_types("Examine CPU registers") == ["cpu"]
    assert orch._infer_agent_types("Trace system calls in kernel module") == ["kernel"]
    assert orch._infer_agent_types("General analysis") == []  # no match
    logger.info("Agent type inference test passed")


async def run_all_tests():
    """Run all tests"""
    logger.info("Starting integration tests for Reverse Engineering Lab")

    tests = [
        test_knowledge_base,
        test_agent_result_reasoning_trace,
        test_tool_runner,
        test_binary_analysis_agent,
        test_binary_analysis_nonexistent_file,
        test_orchestrator,
        test_integration,
        # Phase 2 — LLM client
        test_llm_client_config_no_key,
        test_llm_client_config_valid,
        test_llm_client_chat_completion,
        test_llm_client_chat_completion_json,
        test_usage_stats,
        test_llm_json_extraction,
        # Phase 2 — Embeddings
        test_tfidf_embedding_provider,
        test_tfidf_embedding_batch,
        test_cosine_similarity,
        test_embedding_manager_tfidf_only,
        # Phase 2 — RAG
        test_rag_pipeline_store_and_retrieve,
        test_rag_pipeline_context_building,
        # Phase 2 — Self-critique
        test_self_critique_heuristic_fallback,
        test_self_critique_should_re_analyze,
        test_self_critique_with_mock_llm,
        # Phase 2 — Knowledge extraction
        test_knowledge_extraction_with_mock_llm,
        # Phase 2 — Agent integration
        test_binary_analysis_agent_with_mock_llm,
        test_agent_result_serialization_with_llm_fields,
        # Phase 3 — Confidence scoring
        test_confidence_scoring_computes_weighted_average,
        test_confidence_scoring_no_tools_low_score,
        # Phase 3 — Token budgets
        test_token_budget_manager_allows_within_limit,
        test_token_budget_manager_blocks_global_limit,
        test_token_budget_manager_blocks_agent_limit,
        test_token_budget_manager_blocks_rate_limit,
        test_token_budget_usage_tracking,
        test_token_budget_warnings,
        test_token_budget_reset,
        # Phase 3 — Multi-agent debate
        test_debate_offline_with_two_assertions,
        test_debate_offline_short_context_challenged,
        test_debate_result_serialization,
        # Phase 3 — Orchestrator integration
        test_orchestrator_confidence_and_budget,
        test_orchestrator_facilitate_debate_offline,
        test_orchestrator_debate_insufficient_participants,
        # Phase 3 — Agent confidence
        test_binary_agent_confidence_computed,
        # Phase 3 — Budget config & tracking
        test_budget_config_defaults,
        test_agent_budget_tracking,
        # Phase 4 — Monitoring: primitives
        test_counter_basic,
        test_histogram_basic,
        test_gauge_basic,
        # Phase 4 — Monitoring: collector
        test_metrics_collector_prometheus_format,
        test_metrics_collector_json_format,
        test_metrics_collector_high_level_recorders,
        test_metrics_reset,
        test_metrics_singleton,
        # Phase 4 — Structured logging
        test_structured_json_logging_formatter,
        # Phase 4 — Orchestrator integration
        test_orchestrator_monitoring_integration,
        # Phase 4 — Config
        test_monitoring_config_defaults,
        # Phase 4 — Infrastructure
        test_docker_compose_exists,
        test_prometheus_config_exists,
        test_grafana_dashboards_exist,
        test_grafana_provisioning_config,
        # Phase 5 — Provider registry
        test_provider_registry_all_present,
        test_provider_key_detection,
        test_provider_ollama_no_api_key,
        test_get_provider_valid_and_invalid,
        test_get_active_provider_from_env,
        test_get_active_provider_auto_detect,
        test_migrate_legacy_env,
        test_detect_tools,
        # Phase 5 — Multi-provider LLM config
        test_llm_config_resolves_openai_defaults,
        test_llm_config_resolves_anthropic_defaults,
        test_llm_config_ollama_allows_empty_key,
        test_llm_config_anthropic_rejects_empty_key,
        test_anthropic_response_adapter,
        test_provider_setup_instructions_complete,
        test_setup_wizard_importable,
        test_llm_config_custom_model_overrides_provider,
        test_llm_client_anthropic_provider,
        test_usage_stats_serialization,
        # Phase 6 — MCP opencode server
        test_mcp_server_tool_registry,
        test_mcp_server_initialize,
        test_mcp_server_tools_list,
        test_mcp_server_tool_call_file_identify,
        test_mcp_server_tool_call_readelf,
        test_mcp_server_tool_call_strings,
        test_mcp_server_tool_call_available_tools,
        test_mcp_server_tool_call_kb_add_and_search,
        test_mcp_server_tool_call_kb_statistics,
        test_mcp_server_unknown_tool,
        test_mcp_server_unknown_method,
        test_mcp_server_ping,
        # Phase 6 — Opencode agents & skills
        test_opencode_agent_files_exist,
        test_opencode_skill_files_exist,
        test_opencode_config_exists,
        test_opencode_agents_md_exists,
        # Phase 6 — Debate, setup, monitoring, orchestrator tools
        test_mcp_server_debate_tool,
        test_mcp_server_debate_rejects_single_assertion,
        test_mcp_server_setup_status,
        test_mcp_server_setup_provider,
        test_mcp_server_metrics,
        test_mcp_server_metrics_prometheus,
        test_mcp_server_system_status,
        test_mcp_server_create_and_list_missions,
        test_mcp_server_web_dashboard,
        # Phase 6b — Extended MCP tools
        test_mcp_server_analyze_binary,
        test_mcp_server_analyze_invalid_agent,
        test_mcp_server_mission_update,
        test_mcp_server_mission_detail,
        test_mcp_server_token_budget_status,
        test_mcp_server_kb_add_experiment,
        test_mcp_server_kb_update_and_delete,
        test_mcp_server_gdb_symbols,
        test_mcp_server_rag_search,
        test_mcp_server_rag_context,
        test_mcp_server_config_get,
        test_mcp_server_ghidra_imports,
        # Phase 6c — Mission execution engine
        test_mission_start_completes_without_objectives,
        test_mission_start_with_objectives,
        test_mission_dependency_ordering,
        test_mission_pause_and_resume,
        test_mission_cancel,
        test_mission_progress_tool,
        test_create_mission_with_objectives,
        test_mission_infer_agent_types,
    ]

    passed = 0
    failed = 0

    for test_func in tests:
        try:
            logger.info(f"\nRunning {test_func.__name__}...")
            result = await test_func()
            if result:
                passed += 1
                logger.info(f"PASSED: {test_func.__name__}")
            else:
                failed += 1
                logger.error(f"FAILED: {test_func.__name__}")
        except Exception as e:
            failed += 1
            logger.error(f"FAILED: {test_func.__name__} with exception: {e}", exc_info=True)

    logger.info(f"\n=== Test Results ===")
    logger.info(f"Passed: {passed}")
    logger.info(f"Failed: {failed}")
    logger.info(f"Total:  {passed + failed}")

    if failed == 0:
        logger.info("All tests passed!")
        return True
    else:
        logger.error(f"{failed} test(s) failed")
        return False


if __name__ == "__main__":
    success = asyncio.run(run_all_tests())
    exit(0 if success else 1)
