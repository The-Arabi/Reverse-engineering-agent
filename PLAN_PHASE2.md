# Phase 2: LLM Integration & Knowledge Extraction — Implementation Plan

**Goal:** Add the intelligent reasoning layer — LLM client, embedding providers, RAG pipeline,
self-critique, hypothesis tracking, and wire LLM-powered analysis into all agents.

**User decisions:**
- LLM client: hard-fail without API key (agents fail with clear error)
- Embeddings: dual Gemini + Jina + TF-IDF fallback
- Self-critique: LLM-powered

---

## Files to Create (7 new files)

### 1. `llm_client.py` — Shared LLM Client Wrapper
Async wrapper around `openai` library for any OpenAI-compatible API.

**Class: `LLMClient`**
- `__init__(api_key, model, base_url, temperature, max_tokens)`
- `async chat_completion(messages, temperature, max_tokens, response_format) -> str`
- `async chat_completion_json(messages, schema) -> dict` — forces JSON output
- `_count_tokens(text) -> int` — rough tiktoken-based count
- `get_usage_stats() -> dict` — total tokens used, calls made, cost estimate

**Class: `LLMConfig`**
- Dataclass with: provider, api_key, model, base_url, temperature, max_tokens, timeout
- Loaded from `config/settings.py` LLM_* env vars
- Validates api_key is non-empty at construction time (raises ValueError if missing)

**Error handling:**
- `LLMClientNotConfiguredError` raised if api_key is empty
- Retry with exponential backoff (3 attempts) on transient errors (429, 500-503)
- Timeout after 60s default
- `LLMError` for all other failures

**Singleton:** Module-level `get_llm_client() -> LLMClient` that initializes once from settings.

### 2. `embeddings.py` — Dual Embedding Provider
Unified embedding interface with Gemini, Jina, and local TF-IDF fallback.

**Abstract: `EmbeddingProvider`**
- `async embed(text: str) -> List[float]`
- `async embed_batch(texts: List[str]) -> List[List[float]]`
- `dimension() -> int`

**`GeminiEmbeddingProvider(EmbeddingProvider)`**
- Uses `google-generativeai` SDK
- Model: `text-embedding-004` (768 dimensions)
- Handles batching (max 100 texts per request)
- Rate limiting: 1500 req/day free tier

**`JinaEmbeddingProvider(EmbeddingProvider)`**
- Uses `requests` (REST API)
- Model: `jina-embeddings-v3`
- 32k context window — ideal for long documents
- Rate limiting: 1M tokens/month free tier

**`TFIDFEmbeddingProvider(EmbeddingProvider)`**
- Local fallback using `scikit-learn` TfidfVectorizer
- Always available, no API key needed
- Lower quality but functional

**`EmbeddingManager`**
- Provider fallback chain: configured provider -> secondary provider -> TF-IDF
- `async embed_with_fallback(text) -> (List[float], str_provider_name)`
- Stores provider metadata with each embedding

### 3. `rag_pipeline.py` — RAG Retrieval Pipeline
Retrieval-Augmented Generation for knowledge-enhanced analysis.

**`RAGPipeline`**
- `__init__(knowledge_base, embedding_manager, llm_client)`
- `async store_analysis_result(agent_id, analysis_type, result_dict, tags) -> str`
  - Stores result in KB as Finding
  - Generates embedding of key summary
  - Stores embedding in SQLite `embeddings` table
- `async retrieve_similar(query, top_k=5, min_confidence=0.3) -> List[dict]`
  - Embed query text
  - Cosine similarity search against stored embeddings
  - Return top_k results with scores
- `async build_context_for_analysis(query, max_tokens=3000) -> str`
  - Retrieve similar items
  - Format as structured context block for LLM prompt
- `async store_hypothesis_from_analysis(agent_id, title, description, basis, confidence) -> str`
  - Auto-generate hypothesis from LLM analysis results
  - Store in KB with proper linking

**SQLite `embeddings` table:**
```sql
CREATE TABLE IF NOT EXISTS embeddings (
    id TEXT PRIMARY KEY,
    item_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    embedding BLOB NOT NULL,  -- JSON-serialized float array
    created_at TEXT,
    FOREIGN KEY (item_id) REFERENCES knowledge_items (id)
)
```

### 4. `self_critique.py` — LLM-Powered Self-Critique
Post-analysis quality evaluation and improvement suggestions.

**`SelfCritique`**
- `__init__(llm_client)`
- `async evaluate_analysis(agent_type, tool_output_summary, analysis_result) -> CritiqueResult`
  - LLM prompt: "Evaluate this analysis for completeness, accuracy, and logical consistency"
  - Returns: score (0-1), issues_found, improvement_suggestions, missing_areas
- `async should_re_analyze(critique_result, confidence_threshold=0.6) -> bool`
  - Returns True if score < threshold or critical issues found
- `async generate_next_steps(agent_type, analysis_result, critique_result) -> List[str]`
  - LLM generates 3-5 concrete next investigation steps

**`CritiqueResult` dataclass:**
- score: float (0.0-1.0)
- completeness_score: float
- accuracy_score: float
- consistency_score: float
- issues_found: List[str]
- improvement_suggestions: List[str]
- missing_areas: List[str]
- raw_llm_response: str

### 5. `knowledge_extraction.py` — Structured Knowledge Extraction from LLM
Extract facts, hypotheses, and correlations from LLM analysis responses.

**`KnowledgeExtractor`**
- `__init__(llm_client, rag_pipeline)`
- `async extract_findings(agent_id, analysis_type, tool_results, llm_analysis) -> ExtractionResult`
  - LLM prompt with structured JSON schema for extracting findings
  - Auto-stores extracted facts/hypotheses in KB
- `async extract_hypotheses(agent_id, context, tool_results) -> List[Hypothesis]`
  - LLM generates testable hypotheses from analysis context
  - Stores in KB with proper metadata
- `async extract_correlations(agent_id, item_ids) -> List[Correlation]`
  - LLM identifies relationships between knowledge items
  - Creates correlation entries in KB

**`ExtractionResult` dataclass:**
- facts_stored: List[str] — fact IDs
- hypotheses_stored: List[str] — hypothesis IDs
- correlations_found: List[str] — correlation IDs
- key_insights: List[str]
- confidence_assessment: float

### 6. Update `.env.template` — Add All New Variables

```bash
# LLM Configuration (REQUIRED - agents will fail without this)
LLM_PROVIDER=openai
LLM_API_KEY=sk-your-api-key-here
LLM_MODEL=gpt-4
LLM_TEMPERATURE=0.7
LLM_MAX_TOKENS=4096
# LLM_BASE_URL=  # Uncomment for Ollama, LM Studio, etc.

# Embedding Configuration
EMBEDDING_PROVIDER=gemini
GEMINI_API_KEY=your-gemini-api-key-here
GEMINI_MODEL=text-embedding-004
JINA_API_KEY=your-jina-api-key-here
JINA_MODEL=jina-embeddings-v3

# Self-Critique
CRITIQUE_ENABLED=true
CRITIQUE_CONFIDENCE_THRESHOLD=0.6

# Knowledge Extraction
KNOWLEDGE_EXTRACTION_ENABLED=true
```

### 7. Update `config/settings.py` — Add Embedding + Critique Config

Add to settings.py:
```python
# Embedding configuration
EMBEDDING_PROVIDER = os.getenv("EMBEDDING_PROVIDER", "gemini")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "text-embedding-004")
JINA_API_KEY = os.getenv("JINA_API_KEY", "")
JINA_MODEL = os.getenv("JINA_MODEL", "jina-embeddings-v3")

# Self-critique configuration
CRITIQUE_ENABLED = os.getenv("CRITIQUE_ENABLED", "true").lower() == "true"
CRITIQUE_CONFIDENCE_THRESHOLD = float(os.getenv("CRITIQUE_CONFIDENCE_THRESHOLD", "0.6"))

# Knowledge extraction
KNOWLEDGE_EXTRACTION_ENABLED = os.getenv("KNOWLEDGE_EXTRACTION_ENABLED", "true").lower() == "true"
```

---

## Files to Modify (7 existing files)

### 8. `agents/base_agent.py` — Add LLM + RAG integration points

Changes:
- Add `llm_client` and `rag_pipeline` optional attributes to `AnalysisAgent.__init__`
- Add `async _init_llm_and_rag()` method that initializes LLM client and RAG pipeline
- Add `_llm_analysis_prompt(tool_results_summary) -> str` template method
- Add `async _run_llm_analysis(tool_results, prompt_override=None) -> dict` that calls LLM
- Add `_self_critique(result)` integration point
- Add `_store_with_embeddings(result, tags)` that uses RAG pipeline
- AgentResult gets optional `llm_analysis: Optional[Dict]` and `critique: Optional[Dict]` fields

### 9. `agents/binary_analysis_agent.py` — Add LLM interpretation step

After tool output collection, add:
- `_llm_interpret_binary(tool_output_summary) -> dict` method
  - Sends tool output summary to LLM with analysis prompt
  - Returns structured interpretation: vulnerabilities, functions of interest, crypto detection
- Call `_run_llm_analysis()` in `execute_task()` after tool execution
- Store extracted knowledge via `knowledge_extraction.py`
- Add self-critique evaluation

### 10. `agents/firmware_analysis_agent.py` — Add LLM interpretation

Same pattern as binary agent. After binwalk/strings extraction:
- LLM interprets firmware structure, identifies suspicious components
- Extracts security findings as KB facts
- Generates hypotheses about firmware purpose and vulnerabilities

### 11. `agents/networking_agent.py` — Add LLM interpretation

After tshark/capinfos analysis:
- LLM interprets network patterns, identifies C2 traffic, data exfiltration
- Generates hypotheses about network behavior
- Extracts security findings

### 12. `agents/cpu_analysis_agent.py` — Add LLM interpretation

After objdump disassembly:
- LLM interprets instruction patterns, identifies algorithm implementations
- Detects crypto, compression, encoding algorithms
- Generates hypotheses about code purpose

### 13. `agents/os_kernel_agent.py` — Add LLM interpretation

After strings/readelf/objdump analysis:
- LLM interprets kernel version, config, syscall patterns
- Identifies kernel exploits, privilege escalation vectors
- Generates hypotheses about kernel modifications

### 14. `tests/integration_test.py` — Add Phase 2 tests

New test functions:
- `test_llm_client_initialization()` — tests config validation, error on missing key
- `test_llm_client_mock_chat()` — tests with mock API response
- `test_embedding_providers()` — tests TF-IDF fallback (no API needed)
- `test_rag_pipeline()` — tests store + retrieve with TF-IDF embeddings
- `test_self_critique()` — tests critique evaluation
- `test_knowledge_extraction()` — tests extraction from analysis
- `test_agent_llm_integration()` — tests full agent pipeline with mock LLM

---

## Implementation Order

1. **`llm_client.py`** — foundation, everything depends on this
2. **`embeddings.py`** — embedding providers (TF-IDF for testing, Gemini/Jina for production)
3. **`config/settings.py` + `.env.template`** — configuration for new modules
4. **`rag_pipeline.py`** — RAG retrieval, depends on embeddings
5. **`self_critique.py`** — depends on LLM client
6. **`knowledge_extraction.py`** — depends on LLM + RAG
7. **`agents/base_agent.py`** — add LLM/RAG integration points
8. **Update 5 agents** — wire LLM analysis into each
9. **`tests/integration_test.py`** — comprehensive testing
10. **Syntax verification** — `py_compile` all files

---

## Key Design Decisions

- **No external API calls in tests**: Tests mock the LLM client and use TF-IDF embeddings only
- **Graceful degradation**: If LLM call fails mid-analysis, agent still returns tool output results
- **Token budget**: Default 4000 tokens per analysis call, configurable
- **Embedding storage**: SQLite `embeddings` table with JSON-serialized float arrays (simple, no pgvector dependency for MVP)
- **Cosine similarity**: Pure Python implementation for vector search (sufficient for <100k items)

---

## Verification Plan

1. `py_compile` all new and modified files
2. Run full test suite: `python -m pytest tests/ -v`
3. Verify all 7 original tests still pass
4. Verify all new Phase 2 tests pass
5. Verify imports work cleanly (no circular dependencies)
