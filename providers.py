"""
LLM Provider Registry for the Reverse Engineering Lab.
Defines supported providers with metadata, defaults, setup instructions, and validation.

Supported providers:
- openai        — OpenAI (GPT-4, GPT-4o, etc.)
- google        — Google AI Studio (Gemini)
- anthropic     — Anthropic Claude
- openrouter    — OpenRouter (multi-model gateway)
- nvidia_nim    — NVIDIA NIM (inference microservices)
- ollama        — Ollama (local, no API key)
"""

import os
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class LLMProvider:
    """Metadata for a supported LLM provider."""
    name: str
    display_name: str
    base_url: str
    default_model: str
    api_key_env: str
    api_key_format: str  # hint for the key format
    setup_url: str       # where to get the key
    setup_instructions: str  # step-by-step instructions
    requires_api_key: bool = True
    is_openai_compatible: bool = True  # can use openai SDK
    supports_json_mode: bool = True    # supports response_format json_object
    models: List[str] = field(default_factory=list)  # popular models

    def key_is_set(self) -> bool:
        """Check if the API key env var is set and non-empty."""
        return bool(os.getenv(self.api_key_env, "").strip())

    def key_value(self) -> str:
        """Return the current API key value."""
        return os.getenv(self.api_key_env, "").strip()

    def tool_is_installed(self) -> Optional[bool]:
        """For Ollama: check if the binary is installed. Others: None."""
        if self.name != "ollama":
            return None
        try:
            result = subprocess.run(
                ["which", "ollama"], capture_output=True, timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False

    def ollama_is_running(self) -> bool:
        """Check if Ollama server is reachable."""
        if self.name != "ollama":
            return False
        try:
            import urllib.request
            req = urllib.request.Request(
                "http://localhost:11434/api/tags",
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                return resp.status == 200
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Provider registry
# ---------------------------------------------------------------------------

PROVIDERS: Dict[str, LLMProvider] = {
    "openai": LLMProvider(
        name="openai",
        display_name="OpenAI",
        base_url="https://api.openai.com/v1",
        default_model="gpt-4",
        api_key_env="OPENAI_API_KEY",
        api_key_format="sk-...",
        setup_url="https://platform.openai.com/api-keys",
        setup_instructions=(
            "1. Go to https://platform.openai.com/api-keys\n"
            "2. Sign in or create an OpenAI account\n"
            "3. Click 'Create new secret key'\n"
            "4. Copy the key (it starts with 'sk-')\n"
            "5. You'll need billing set up for GPT-4 access"
        ),
        models=["gpt-4", "gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo"],
    ),
    "google": LLMProvider(
        name="google",
        display_name="Google AI Studio (Gemini)",
        base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
        default_model="gemini-2.0-flash",
        api_key_env="GOOGLE_API_KEY",
        api_key_format="AIza...",
        setup_url="https://aistudio.google.com/apikey",
        setup_instructions=(
            "1. Go to https://aistudio.google.com/apikey\n"
            "2. Sign in with your Google account\n"
            "3. Click 'Create API key'\n"
            "4. Copy the key (it starts with 'AIza')\n"
            "5. Free tier includes generous rate limits"
        ),
        models=["gemini-2.0-flash", "gemini-2.0-flash-lite", "gemini-1.5-pro", "gemini-1.5-flash"],
    ),
    "anthropic": LLMProvider(
        name="anthropic",
        display_name="Anthropic Claude",
        base_url="https://api.anthropic.com/v1",
        default_model="claude-sonnet-4-20250514",
        api_key_env="ANTHROPIC_API_KEY",
        api_key_format="sk-ant-...",
        setup_url="https://console.anthropic.com/settings/keys",
        setup_instructions=(
            "1. Go to https://console.anthropic.com/settings/keys\n"
            "2. Sign in or create an Anthropic account\n"
            "3. Click 'Create Key'\n"
            "4. Copy the key (it starts with 'sk-ant-')\n"
            "5. Add billing for API access"
        ),
        is_openai_compatible=False,
        models=["claude-sonnet-4-20250514", "claude-3-5-sonnet-20241022", "claude-3-5-haiku-20241022", "claude-3-opus-20240229"],
    ),
    "openrouter": LLMProvider(
        name="openrouter",
        display_name="OpenRouter",
        base_url="https://openrouter.ai/api/v1",
        default_model="anthropic/claude-sonnet-4-20250514",
        api_key_env="OPENROUTER_API_KEY",
        api_key_format="sk-or-...",
        setup_url="https://openrouter.ai/keys",
        setup_instructions=(
            "1. Go to https://openrouter.ai/keys\n"
            "2. Sign in (Google/GitHub)\n"
            "3. Click 'Create Key'\n"
            "4. Copy the key (it starts with 'sk-or-')\n"
            "5. Add credits — access 100+ models including GPT-4, Claude, Gemini, Llama"
        ),
        models=[
            "anthropic/claude-sonnet-4-20250514",
            "openai/gpt-4o",
            "google/gemini-2.0-flash-001",
            "meta-llama/llama-3.1-405b-instruct",
            "mistralai/mixtral-8x22b-instruct",
        ],
    ),
    "nvidia_nim": LLMProvider(
        name="nvidia_nim",
        display_name="NVIDIA NIM",
        base_url="https://integrate.api.nvidia.com/v1",
        default_model="nvidia/llama-3.1-8b-instruct",
        api_key_env="NVIDIA_API_KEY",
        api_key_format="nvapi-...",
        setup_url="https://build.nvidia.com/",
        setup_instructions=(
            "1. Go to https://build.nvidia.com/\n"
            "2. Sign in with an NVIDIA account\n"
            "3. Pick any model and click 'Get API Key'\n"
            "4. Copy the key (it starts with 'nvapi-')\n"
            "5. Free tier available with generous credits"
        ),
        models=[
            "nvidia/llama-3.1-8b-instruct",
            "nvidia/llama-3.1-70b-instruct",
            "nvidia/llama-3.1-405b-instruct",
            "nvidia/mixtral-8x7b-instruct-v0.1",
        ],
    ),
    "ollama": LLMProvider(
        name="ollama",
        display_name="Ollama (Local)",
        base_url="http://localhost:11434/v1",
        default_model="llama3.1",
        api_key_env="OLLAMA_API_KEY",
        api_key_format="ollama (no key needed)",
        setup_url="https://ollama.com/download",
        setup_instructions=(
            "1. Go to https://ollama.com/download\n"
            "2. Download and install Ollama for your OS\n"
            "3. Run: ollama pull llama3.1\n"
            "4. Run: ollama serve (starts on port 11434)\n"
            "5. No API key required — runs entirely locally"
        ),
        requires_api_key=False,
        supports_json_mode=False,
        models=["llama3.1", "llama3.1:70b", "codellama", "mistral", "mixtral", "phi3", "gemma2"],
    ),
}

# Preferred provider order for the setup wizard
PROVIDER_ORDER = ["openai", "google", "anthropic", "openrouter", "nvidia_nim", "ollama"]

# Legacy env var mapping (for backward compatibility)
LEGACY_ENV_MAP = {
    "LLM_API_KEY": {
        "openai": "OPENAI_API_KEY",
        "google": "GOOGLE_API_KEY",
        "anthropic": "ANTHROPIC_API_KEY",
        "openrouter": "OPENROUTER_API_KEY",
        "nvidia_nim": "NVIDIA_API_KEY",
    },
    "GEMINI_API_KEY": "GOOGLE_API_KEY",
    "JINA_API_KEY": "JINA_API_KEY",
}


def get_provider(name: str) -> Optional[LLMProvider]:
    """Get a provider by name."""
    return PROVIDERS.get(name)


def get_active_provider() -> Optional[LLMProvider]:
    """Determine the active provider from environment variables.

    Checks LLM_PROVIDER first, then falls back to detecting which
    API key is set.
    """
    provider_name = os.getenv("LLM_PROVIDER", "").strip().lower()
    if provider_name and provider_name in PROVIDERS:
        return PROVIDERS[provider_name]

    # Auto-detect from env vars
    for name, provider in PROVIDERS.items():
        if provider.requires_api_key and provider.key_is_set():
            return provider

    # Check Ollama (no key needed)
    ollama = PROVIDERS.get("ollama")
    if ollama and ollama.tool_is_installed():
        return ollama

    return None


def migrate_legacy_env():
    """Migrate legacy LLM_API_KEY to provider-specific env vars.

    If LLM_API_KEY is set but the provider-specific var is not,
    copy the value over for backward compatibility.
    """
    legacy_key = os.getenv("LLM_API_KEY", "").strip()
    provider_name = os.getenv("LLM_PROVIDER", "").strip().lower()

    if legacy_key and provider_name in LEGACY_ENV_MAP.get("LLM_API_KEY", {}):
        target_env = LEGACY_ENV_MAP["LLM_API_KEY"][provider_name]
        if not os.getenv(target_env, "").strip():
            os.environ[target_env] = legacy_key

    # Migrate GEMINI_API_KEY -> GOOGLE_API_KEY
    gemini_key = os.getenv("GEMINI_API_KEY", "").strip()
    if gemini_key and not os.getenv("GOOGLE_API_KEY", "").strip():
        os.environ["GOOGLE_API_KEY"] = gemini_key


def detect_tools() -> List[Dict[str, any]]:
    """Detect installed RE tools and return status list."""
    tools = [
        {"name": "objdump", "path": "/usr/bin/objdump", "purpose": "Disassemble binaries, inspect ELF headers"},
        {"name": "readelf", "path": "/usr/bin/readelf", "purpose": "Display ELF file structure and sections"},
        {"name": "strings", "path": "/usr/bin/strings", "purpose": "Extract printable strings from binaries"},
        {"name": "file", "path": "/usr/bin/file", "purpose": "Identify file type and architecture"},
        {"name": "gdb", "path": "/usr/bin/gdb", "purpose": "GNU Debugger for runtime analysis"},
        {"name": "binwalk", "path": "/usr/bin/binwalk", "purpose": "Analyze and extract firmware images"},
        {"name": "tshark", "path": "/usr/bin/tshark", "purpose": "Capture and analyze network traffic"},
        {"name": "ghidra", "path": "/opt/ghidra/support/analyzeHeadless", "purpose": "NSA reverse engineering suite (decompiler, disassembler)"},
        {"name": "radare2", "path": "/usr/bin/radare2", "purpose": "Reverse engineering framework (disassembler, debugger)"},
        {"name": "qemu", "path": "/usr/bin/qemu-system-x86_64", "purpose": "CPU emulation for firmware analysis"},
        {"name": "strace", "path": "/usr/bin/strace", "purpose": "Trace system calls"},
    ]
    for tool in tools:
        tool["installed"] = os.path.isfile(tool["path"])
    return tools
