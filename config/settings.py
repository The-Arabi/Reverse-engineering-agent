"""
Configuration file for the Reverse Engineering Lab
Supports .env file overrides via python-dotenv
"""

import os
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent.parent / ".env")
except ImportError:
    pass

# Base directories
BASE_DIR = Path(__file__).parent.absolute().parent
DATA_DIR = BASE_DIR / "data"
LOGS_DIR = BASE_DIR / "logs"
CONFIG_DIR = BASE_DIR / "config"
MODULES_DIR = BASE_DIR / "modules"
GHIDRA_PROJECTS_DIR = DATA_DIR / "ghidra_projects"

# Ensure directories exist
for directory in [DATA_DIR, LOGS_DIR, CONFIG_DIR, MODULES_DIR, GHIDRA_PROJECTS_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# Knowledge base configuration
KNOWLEDGE_DB_PATH = DATA_DIR / "knowledge_base.db"

# LLM configuration — multi-provider support
# Provider: "openai", "google", "anthropic", "openrouter", "nvidia_nim", "ollama"
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "openai")
LLM_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0.7"))
LLM_MAX_TOKENS = int(os.getenv("LLM_MAX_TOKENS", "4096"))
LLM_BASE_URL = os.getenv("LLM_BASE_URL", None)

# Resolve API key and model from provider-specific env vars
_PROVIDER_KEY_MAP = {
    "openai": "OPENAI_API_KEY",
    "google": "GOOGLE_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "nvidia_nim": "NVIDIA_API_KEY",
    "ollama": "OLLAMA_API_KEY",
}
_PROVIDER_MODEL_MAP = {
    "openai": "gpt-4",
    "google": "gemini-2.0-flash",
    "anthropic": "claude-sonnet-4-20250514",
    "openrouter": "anthropic/claude-sonnet-4-20250514",
    "nvidia_nim": "nvidia/llama-3.1-8b-instruct",
    "ollama": "llama3.1",
}

_llm_key_env = _PROVIDER_KEY_MAP.get(LLM_PROVIDER, "OPENAI_API_KEY")
LLM_API_KEY = os.getenv(_llm_key_env, "") or os.getenv("LLM_API_KEY", "")
LLM_MODEL = os.getenv("LLM_MODEL", _PROVIDER_MODEL_MAP.get(LLM_PROVIDER, "gpt-4"))

# MCP Server configurations
MCP_SERVERS = {
    "binary_analysis": {
        "host": os.getenv("MCP_BINARY_HOST", "localhost"),
        "port": int(os.getenv("MCP_BINARY_PORT", "8001")),
        "enabled": os.getenv("MCP_BINARY_ENABLED", "true").lower() == "true",
    },
    "debugger": {
        "host": os.getenv("MCP_DEBUGGER_HOST", "localhost"),
        "port": int(os.getenv("MCP_DEBUGGER_PORT", "8002")),
        "enabled": os.getenv("MCP_DEBUGGER_ENABLED", "true").lower() == "true",
    },
    "hardware_communication": {
        "host": os.getenv("MCP_HARDWARE_HOST", "localhost"),
        "port": int(os.getenv("MCP_HARDWARE_PORT", "8003")),
        "enabled": os.getenv("MCP_HARDWARE_ENABLED", "false").lower() == "true",
    },
    "network": {
        "host": os.getenv("MCP_NETWORK_HOST", "localhost"),
        "port": int(os.getenv("MCP_NETWORK_PORT", "8004")),
        "enabled": os.getenv("MCP_NETWORK_ENABLED", "true").lower() == "true",
    },
}

# Agent configurations
AGENT_CONFIGS = {
    "binary_analysis": {
        "class": "agents.binary_analysis_agent.BinaryAnalysisAgent",
        "count": 2,
        "enabled": True,
    },
    "firmware_analysis": {
        "class": "agents.firmware_analysis_agent.FirmwareAnalysisAgent",
        "count": 1,
        "enabled": True,
    },
    "cpu_analysis": {
        "class": "agents.cpu_analysis_agent.CpuAnalysisAgent",
        "count": 1,
        "enabled": True,
    },
    "os_kernel": {
        "class": "agents.os_kernel_agent.OsKernelAgent",
        "count": 1,
        "enabled": True,
    },
    "networking": {
        "class": "agents.networking_agent.NetworkingAgent",
        "count": 1,
        "enabled": True,
    },
    "hardware_behavior": {
        "class": "agents.hardware_behavior_agent.HardwareBehaviorAgent",
        "count": 1,
        "enabled": True,
    },
    "gpu_reverse_engineering": {
        "class": "agents.gpu_reverse_engineering_agent.GpuReverseEngineeringAgent",
        "count": 1,
        "enabled": True,
    },
    "experiment_design": {
        "class": "agents.experiment_design_agent.ExperimentDesignAgent",
        "count": 1,
        "enabled": True,
    },
    "emulator_development": {
        "class": "agents.emulator_development_agent.EmulatorDevelopmentAgent",
        "count": 1,
        "enabled": True,
    },
}

# Logging configuration
LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {
            "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        },
        "detailed": {
            "format": "%(asctime)s [%(levelname)s] %(name)s:%(lineno)d: %(message)s"
        },
        "json": {
            "format": "%(message)s",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "level": os.getenv("LOG_LEVEL", "INFO"),
            "formatter": "standard",
            "stream": "ext://sys.stdout",
        },
        "file": {
            "class": "logging.FileHandler",
            "level": "DEBUG",
            "formatter": "detailed",
            "filename": str(LOGS_DIR / "reverse_engineering_lab.log"),
            "mode": "a",
        },
    },
    "loggers": {
        "": {
            "handlers": ["console", "file"],
            "level": os.getenv("LOG_LEVEL", "INFO"),
            "propagate": False,
        }
    },
}

# Orchestrator configuration
ORCHESTRATOR_CONFIG = {
    "max_concurrent_tasks": int(os.getenv("ORCH_MAX_CONCURRENT", "10")),
    "task_timeout_seconds": int(os.getenv("ORCH_TASK_TIMEOUT", "300")),
    "agent_heartbeat_interval": 30,
    "enable_metrics_collection": True,
    "metrics_retention_days": 30,
}

# External tool paths (overridable via env)
TOOL_PATHS = {
    "ghidra": os.getenv("GHIDRA_PATH", "/opt/ghidra/support/analyzeHeadless"),
    "ida": os.getenv("IDA_PATH", "/opt/ida/idat64"),
    "binary_ninja": os.getenv("BINJA_PATH", "/usr/local/bin/binaryninja"),
    "radare2": os.getenv("RADARE2_PATH", "/usr/bin/radare2"),
    "objdump": "/usr/bin/objdump",
    "readelf": "/usr/bin/readelf",
    "strings": "/usr/bin/strings",
    "strace": "/usr/bin/strace",
    "ltrace": "/usr/bin/ltrace",
    "gdb": os.getenv("GDB_PATH", "/usr/bin/gdb"),
    "qemu": os.getenv("QEMU_PATH", "/usr/bin/qemu-system-x86_64"),
}

# Embedding configuration
EMBEDDING_PROVIDER = os.getenv("EMBEDDING_PROVIDER", "tfidf")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "text-embedding-004")
JINA_API_KEY = os.getenv("JINA_API_KEY", "")
JINA_MODEL = os.getenv("JINA_MODEL", "jina-embeddings-v3")

# Self-critique configuration
CRITIQUE_ENABLED = os.getenv("CRITIQUE_ENABLED", "true").lower() == "true"
CRITIQUE_CONFIDENCE_THRESHOLD = float(os.getenv("CRITIQUE_CONFIDENCE_THRESHOLD", "0.6"))

# Knowledge extraction configuration
KNOWLEDGE_EXTRACTION_ENABLED = os.getenv("KNOWLEDGE_EXTRACTION_ENABLED", "true").lower() == "true"

# Debate configuration
DEBATE_ENABLED = os.getenv("DEBATE_ENABLED", "true").lower() == "true"
DEBATE_MAX_ROUNDS = int(os.getenv("DEBATE_MAX_ROUNDS", "3"))
DEBATE_CONFIDENCE_THRESHOLD = float(os.getenv("DEBATE_CONFIDENCE_THRESHOLD", "0.5"))
DEBATE_MIN_PARTICIPANTS = int(os.getenv("DEBATE_MIN_PARTICIPANTS", "2"))

# Token budget configuration
TOKEN_BUDGET_ENABLED = os.getenv("TOKEN_BUDGET_ENABLED", "true").lower() == "true"
TOKEN_GLOBAL_LIMIT = int(os.getenv("TOKEN_GLOBAL_LIMIT", "1000000"))
TOKEN_AGENT_LIMIT = int(os.getenv("TOKEN_AGENT_LIMIT", "100000"))
TOKEN_MISSION_LIMIT = int(os.getenv("TOKEN_MISSION_LIMIT", "500000"))
TOKEN_GLOBAL_RPM = int(os.getenv("TOKEN_GLOBAL_RPM", "60"))
TOKEN_AGENT_RPM = int(os.getenv("TOKEN_AGENT_RPM", "10"))
TOKEN_WARNING_THRESHOLD = float(os.getenv("TOKEN_WARNING_THRESHOLD", "0.8"))

# Confidence scoring configuration
CONFIDENCE_TOOL_WEIGHT = float(os.getenv("CONFIDENCE_TOOL_WEIGHT", "0.3"))
CONFIDENCE_LLM_WEIGHT = float(os.getenv("CONFIDENCE_LLM_WEIGHT", "0.4"))
CONFIDENCE_CRITIQUE_WEIGHT = float(os.getenv("CONFIDENCE_CRITIQUE_WEIGHT", "0.3"))
CONFIDENCE_MIN_THRESHOLD = float(os.getenv("CONFIDENCE_MIN_THRESHOLD", "0.3"))
REANALYZE_ENABLED = os.getenv("REANALYZE_ENABLED", "true").lower() == "true"
REANALYZE_MAX_ATTEMPTS = int(os.getenv("REANALYZE_MAX_ATTEMPTS", "2"))

# Feature flags
FEATURES = {
    "enable_experiment_tracking": True,
    "enable_knowledge_graph": True,
    "enable_auto_reporting": True,
    "enable_collaborative_reasoning": True,
    "enable_real_time_dashboard": os.getenv("ENABLE_REALTIME_DASHBOARD", "false").lower() == "true",
}

# Dashboard
WEB_HOST = os.getenv("DASHBOARD_HOST", "0.0.0.0")
WEB_PORT = int(os.getenv("DASHBOARD_PORT", "5000"))
WEB_DEBUG = os.getenv("DASHBOARD_DEBUG", "false").lower() == "true"

# Monitoring & Observability
MONITORING_ENABLED = os.getenv("MONITORING_ENABLED", "true").lower() == "true"
METRICS_PORT = int(os.getenv("METRICS_PORT", "9090"))
METRICS_PATH = os.getenv("METRICS_PATH", "/metrics")
STRUCTURED_LOGGING = os.getenv("STRUCTURED_LOGGING", "false").lower() == "true"

# Prometheus
PROMETHEUS_ENABLED = os.getenv("PROMETHEUS_ENABLED", "true").lower() == "true"
PROMETHEUS_SCRAPE_INTERVAL = os.getenv("PROMETHEUS_SCRAPE_INTERVAL", "15s")

# Grafana
GRAFANA_ENABLED = os.getenv("GRAFANA_ENABLED", "true").lower() == "true"
GRAFANA_PORT = int(os.getenv("GRAFANA_PORT", "3000"))
GRAFANA_ADMIN_USER = os.getenv("GRAFANA_ADMIN_USER", "admin")
GRAFANA_ADMIN_PASSWORD = os.getenv("GRAFANA_ADMIN_PASSWORD", "admin")

# Environment
ENVIRONMENT = os.getenv("REVERSE_ENGINEERING_ENV", "development")

if ENVIRONMENT == "production":
    LOGGING_CONFIG["handlers"]["console"]["level"] = "WARNING"
    ORCHESTRATOR_CONFIG["max_concurrent_tasks"] = 20
elif ENVIRONMENT == "testing":
    LOGGING_CONFIG["handlers"]["console"]["level"] = "DEBUG"
    KNOWLEDGE_DB_PATH = DATA_DIR / "test_knowledge_base.db"
