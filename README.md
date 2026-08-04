# Reverse Engineering Lab

An **autonomous, multi-agent reverse engineering research platform**. It combines 5+ specialized AI analysis agents, a persistent knowledge base, structured multi-agent debate, LLM self-critique, RAG semantic search, and real tool integration (objdump, readelf, gdb, Ghidra, binwalk, tshark, radare2, …).

Everything is driven by agents that plan, run real RE tools, store findings as **facts / hypotheses / experiments**, and argue out disagreements — so conclusions come with evidence and confidence scores, not just vibes.

---

## Highlights

- **Specialized analysis agents** — binary, firmware, network, CPU, and kernel analysis pipelines
- **Knowledge base (SQLite)** — every finding is a fact, hypothesis, or experiment with confidence, evidence, and tags
- **Multi-agent debate** — conflicting findings are resolved through a structured debate protocol
- **Self-critique** — each agent's output is LLM-reviewed before it becomes a finding
- **RAG semantic search** — find related past analyses across all stored results
- **Mission management** — create research missions with objectives, assign agents, track progress
- **Token budgets** — per-agent and per-mission rate limiting so runaway LLM calls can't happen
- **Monitoring** — Prometheus metrics + Grafana dashboards (via docker-compose)
- **Real tool integration** — 46 MCP tools wrapping standard RE tooling

---

## Quick Start

Requires **Python 3.10+** and optionally an **LLM API key** (the agents run on an LLM; a local [Ollama](https://ollama.com) install also works).

### 1. Install dependencies

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure the project (run the setup wizard)

The interactive wizard detects installed RE tools, walks you through choosing an LLM provider (OpenAI / Anthropic / Google / OpenRouter / NVIDIA NIM / Ollama), validates the API key, and writes your `.env`:

```bash
python setup_wizard.py
```

Prefer to do it by hand?

```bash
cp .env.template .env
# edit .env: set LLM_PROVIDER and the matching *_API_KEY
```

### 3. Verify the install

```bash
python -m pytest tests/ -v          # run the test suite
```

---

## Usage

### Terminal AI interface (recommended)

The platform is exposed as an **MCP server** (`re-lab`, 46 tools) and is pre-configured for [opencode](https://opencode.ai). Launch the terminal TUI and drive the whole lab in natural language:

```bash
opencode
```

From there you get the `re-binary`, `re-firmware`, `re-network`, `re-kernel`, and `re-general` agents plus all `re_*` and `kb_*` tools (analyze binaries, run missions, run debates, query the knowledge base).

### Web dashboard

Flask web UI for browsing knowledge items, adding facts/hypotheses/experiments, searching, and viewing system stats:

```bash
python web_dashboard.py
# → http://localhost:5000
```

### Example script

See a full agent-driven workflow end to end:

```bash
python example_usage.py
```

### Working with the knowledge base in code

```python
from knowledge_base import add_fact, add_hypothesis, add_experiment, kb

fact_id = add_fact(
    title="Stack buffer overflow in HTTP parser",
    description="Found exploitable buffer overflow when parsing the User-Agent header",
    confidence=0.9,
    evidence=["crash_dump_001", "poc_exploit.py"],
    tags=["vulnerability", "buffer-overflow"],
    source_agent="networking_agent",
)

print(kb.search_knowledge(query="buffer overflow", limit=5))
```

---

## For AI Agents (LLMs, Copilots, CI Bots)

**If you are an AI agent working in this repository, read [`AGENTS.md`](AGENTS.md) first.** It is the canonical context file: it lists all 46 MCP tools, the agent architecture, and the recommended analysis workflows.

Minimal setup summary for agents:

```bash
# 1. Create venv + install deps
python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt

# 2. Configure an LLM provider (interactive, or answer prompts)
python setup_wizard.py

# 3. Verify from the MCP layer
#    re_setup_status()   → providers, RE tools, .env status
#    re_llm_status()     → active provider + model
#    re_available_tools()→ which RE tools are installed
```

If no provider is configured, agents fail fast — set one up with `python setup_wizard.py` or `re_setup_provider(provider, api_key, model)`.

> **Note:** `opencode.json` and `antigravity.json` register the `re-lab` MCP server using the repo-local `venv/bin/python`. Regenerate/repoint those if you create your venv elsewhere.

---

## Repository Layout

```
agents/            Specialized analysis agents (binary, firmware, cpu, kernel, network, …)
mcp/               MCP servers + Ghidra scripts (opencode_server, debugger_server, …)
config/            Settings with .env overrides
monitoring/        Prometheus + Grafana configuration
knowledge_base*.py SQLite-backed knowledge store (facts/hypotheses/experiments)
debate.py          Multi-agent debate protocol
self_critique.py   LLM self-review of agent output
rag_pipeline.py    Semantic search over analysis results
embeddings.py      Embedding providers (gemini / jina / local tfidf)
token_budget.py    Token budget + rate limiting
orchestrator.py    Agent lifecycle, missions, task scheduling
web_dashboard.py   Flask dashboard
setup_wizard.py    Interactive setup (tools + LLM provider + .env)
setup_workflow.py  Tool detection / requirements generation
startup.py         Minimal async demo of the orchestrator
tests/             Test suite
data/              Runtime data (knowledge DB, Ghidra projects) — gitignored
logs/              Log output — gitignored
```

## Configuration

All knobs live in `.env` (see [`.env.template`](.env.template) for the full annotated list):

- **LLM** — `LLM_PROVIDER`, provider-specific `*_API_KEY`, `LLM_MODEL`, `LLM_BASE_URL`
- **Embeddings** — `EMBEDDING_PROVIDER` (`gemini` / `jina` / `tfidf`)
- **Debate** — `DEBATE_ENABLED`, `DEBATE_MAX_ROUNDS`, thresholds
- **Budgets** — `TOKEN_GLOBAL_LIMIT`, `TOKEN_AGENT_LIMIT`, rate limits
- **Dashboard** — `DASHBOARD_HOST`, `DASHBOARD_PORT`
- **Monitoring** — `METRICS_PORT`, Prometheus/Grafana toggles
- **Environment** — `REVERSE_ENGINEERING_ENV` (`development` / `testing` / `production`)

## Docker

Containerized build with Ghidra, GDB, QEMU, radare2, tshark, and the app:

```bash
docker compose up --build          # app + optional PG/Neo4j/Redis/Prometheus/Grafana
docker build -t reverse-engineering-lab:latest .
```

- Dashboard → `http://localhost:5000`
- Metrics → `http://localhost:9090/metrics`
- Grafana → `http://localhost:3000` (admin/admin)

## License

MIT — see [LICENSE](LICENSE).
