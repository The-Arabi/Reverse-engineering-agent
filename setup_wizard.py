#!/usr/bin/env python3
"""
Interactive Terminal Setup Wizard for the Reverse Engineering Lab.

Guides new users through:
1. Detecting installed RE tools (with purpose of each)
2. Detecting programs that could be installed (with purpose)
3. Multi-provider LLM setup with validation
4. Generating a .env file

Usage:
    python setup_wizard.py
"""

import os
import sys
import subprocess
import urllib.request
import json
from pathlib import Path

# Add project root to path so we can import providers
sys.path.insert(0, str(Path(__file__).parent))

from providers import (
    PROVIDERS, PROVIDER_ORDER, detect_tools, get_provider,
)

# ---------------------------------------------------------------------------
# Terminal colors
# ---------------------------------------------------------------------------

class C:
    """ANSI color codes for terminal output."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    GREEN   = "\033[32m"
    YELLOW  = "\033[33m"
    RED     = "\033[31m"
    CYAN    = "\033[36m"
    BLUE    = "\033[34m"
    MAGENTA = "\033[35m"

    @staticmethod
    def disable():
        for attr in ("RESET", "BOLD", "DIM", "GREEN", "YELLOW", "RED",
                      "CYAN", "BLUE", "MAGENTA"):
            setattr(C, attr, "")


def ok(msg: str) -> str:
    return f"{C.GREEN}  [OK]{C.RESET} {msg}"

def warn(msg: str) -> str:
    return f"{C.YELLOW}  [!!]{C.RESET} {msg}"

def fail(msg: str) -> str:
    return f"{C.RED}  [--]{C.RESET} {msg}"

def info(msg: str) -> str:
    return f"{C.CYAN}  [>>]{C.RESET} {msg}"

def header(msg: str) -> str:
    return f"\n{C.BOLD}{C.CYAN}{'=' * 60}\n  {msg}\n{'=' * 60}{C.RESET}"


# ---------------------------------------------------------------------------
# Dependency detection
# ---------------------------------------------------------------------------

# Core RE tools (used by tool_runner.py)
RE_TOOLS = [
    ("objdump",   "/usr/bin/objdump",   "Disassemble binaries, inspect ELF headers"),
    ("readelf",   "/usr/bin/readelf",   "Display ELF file structure and sections"),
    ("strings",   "/usr/bin/strings",   "Extract printable strings from binaries"),
    ("file",      "/usr/bin/file",      "Identify file type and architecture"),
    ("gdb",       "/usr/bin/gdb",       "GNU Debugger for runtime analysis"),
    ("binwalk",   "/usr/bin/binwalk",   "Analyze and extract firmware images"),
    ("tshark",    "/usr/bin/tshark",    "Capture and analyze network traffic"),
    ("ghidra",    "/opt/ghidra/support/analyzeHeadless", "NSA reverse engineering suite (decompiler, disassembler)"),
    ("radare2",   "/usr/bin/radare2",   "Reverse engineering framework (disassembler, debugger)"),
    ("qemu",      "/usr/bin/qemu-system-x86_64", "CPU emulation for firmware analysis"),
    ("strace",    "/usr/bin/strace",    "Trace system calls"),
    ("capinfos",  "/usr/bin/capinfos",  "Display capture file information (pcap)"),
]

# Optional companion tools
COMPANION_TOOLS = [
    ("ghidra",       "AnalyzeHeadless",  "Install Ghidra from https://ghidra-sre.org/ and add to PATH"),
    ("gdb",          "gdb-multiarch",    "apt install gdb-multiarch or brew install gdb"),
    ("binwalk",      "binwalk",          "pip install binwalk or apt install binwalk"),
    ("radare2",      "r2",               "apt install radare2 or brew install radare2"),
    ("qemu",         "qemu-system-*",    "apt install qemu-system or brew install qemu"),
    ("strace",       "strace",           "apt install strace"),
    ("tshark",       "tshark",           "apt install tshark or brew install wireshark"),
    ("capinfos",     "capinfos",         "apt install tshark or brew install wireshark"),
    ("node",         "node",             "Required for Ghidra MCP server. Install from https://nodejs.org/"),
    ("pip",          "pip",              "Python package manager (should already be installed)"),
]

# Python packages
PYTHON_DEPS = [
    ("openai",   "OpenAI / OpenAI-compatible API clients"),
    ("anthropic","Anthropic Claude API client"),
    ("httpx",    "Async HTTP client (used by embeddings)"),
    ("aiohttp",  "Async HTTP client"),
    ("flask",    "Web dashboard"),
    ("pydantic", "Data validation"),
]


def check_installed(name: str, path: str) -> bool:
    if os.path.isfile(path):
        return True
    try:
        result = subprocess.run(
            ["which", name], capture_output=True, timeout=5
        )
        return result.returncode == 0
    except Exception:
        return False


def check_python_package(name: str) -> bool:
    try:
        __import__(name)
        return True
    except ImportError:
        return False


# ---------------------------------------------------------------------------
# API key validation
# ---------------------------------------------------------------------------

def validate_api_key(provider_name: str, api_key: str) -> tuple[bool, str]:
    """Validate an API key by making a lightweight request.

    Returns (success: bool, message: str).
    """
    provider = get_provider(provider_name)
    if not provider:
        return False, f"Unknown provider: {provider_name}"

    # Ollama — check if server is reachable
    if provider_name == "ollama":
        try:
            req = urllib.request.Request(
                "http://localhost:11434/api/tags", method="GET"
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status == 200:
                    return True, "Ollama server is reachable"
                return False, f"Ollama responded with status {resp.status}"
        except Exception as e:
            return False, f"Cannot reach Ollama: {e}"

    # Anthropic — use anthropic SDK if available, else skip
    if provider_name == "anthropic":
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=api_key, timeout=10)
            # Minimal request: just list models
            client.models.list()
            return True, "Anthropic API key is valid"
        except ImportError:
            return True, "Key format looks correct (anthropic package not installed for live validation)"
        except anthropic.AuthenticationError:
            return False, "Invalid Anthropic API key"
        except anthropic.PermissionDeniedError:
            return False, "API key lacks permission"
        except Exception as e:
            # Other errors (network, rate limit) — key format likely OK
            return True, f"Cannot validate live (network error), but key format looks correct"

    # OpenAI-compatible providers — use openai SDK
    try:
        import openai
        client = openai.OpenAI(
            api_key=api_key,
            base_url=provider.base_url,
            timeout=10,
        )
        # Minimal request: list models (or just try a tiny chat)
        client.models.list()
        return True, f"{provider.display_name} API key is valid"
    except ImportError:
        return True, "Key format looks correct (openai package not installed for live validation)"
    except openai.AuthenticationError:
        return False, f"Invalid {provider.display_name} API key"
    except openai.PermissionDeniedError:
        return False, f"API key lacks permission for {provider.display_name}"
    except Exception as e:
        return True, f"Cannot validate live (network error), but key format looks correct"


# ---------------------------------------------------------------------------
# Setup wizard
# ---------------------------------------------------------------------------

class SetupWizard:
    def __init__(self):
        self.env_vars: dict[str, str] = {}
        self.warnings: list[str] = []
        self.errors: list[str] = []

    def run(self):
        self._print_banner()
        self._detect_system()
        self._setup_llm_provider()
        self._setup_embeddings()
        self._setup_other_config()
        self._print_summary()
        self._write_env_file()

    # ----- Banner -----

    def _print_banner(self):
        print(f"""
{C.BOLD}{C.CYAN}╔══════════════════════════════════════════════════════════╗
║         Reverse Engineering Lab — Setup Wizard           ║
╚══════════════════════════════════════════════════════════╝{C.RESET}

{C.DIM}This wizard will guide you through setting up the platform.
It detects installed tools and helps configure your LLM provider.{C.RESET}
""")

    # ----- System detection -----

    def _detect_system(self):
        print(header("Step 1: Detecting Installed Tools"))
        print()

        installed = 0
        missing = 0

        for name, path, purpose in RE_TOOLS:
            if check_installed(name, path):
                print(ok(f"{C.GREEN}{name}{C.RESET} — {C.DIM}{purpose}{C.RESET}"))
                installed += 1
            else:
                print(fail(f"{C.RED}{name}{C.RESET} — {C.DIM}{purpose}{C.RESET}"))
                missing += 1

        print(f"\n{C.DIM}Found {installed}/{installed + missing} core tools{C.RESET}")

        if missing > 0:
            print(f"\n{C.YELLOW}Optional companion tools (not required, but useful):{C.RESET}")
            for tool_name, alt_name, install_hint in COMPANION_TOOLS:
                if not check_installed(tool_name, COMPANION_TOOLS[0][1]):
                    print(info(f"{alt_name}: {C.DIM}{install_hint}{C.RESET}"))

        # Python packages
        print(f"\n{C.DIM}Python packages:{C.RESET}")
        for pkg, desc in PYTHON_DEPS:
            if check_python_package(pkg):
                print(ok(f"{pkg} — {C.DIM}{desc}{C.RESET}"))
            else:
                print(warn(f"{pkg} — {C.DIM}{desc}{C.RESET}"))

        print()

    # ----- LLM provider setup -----

    def _setup_llm_provider(self):
        print(header("Step 2: LLM Provider Setup"))
        print()
        print("Choose an LLM provider. This powers the AI analysis agents.")
        print("All providers except Ollama require an API key.\n")

        # Show provider menu
        for i, name in enumerate(PROVIDER_ORDER, 1):
            prov = PROVIDERS[name]
            status = ""
            if name == "ollama":
                if check_installed("ollama", "/usr/bin/ollama"):
                    status = f" {C.GREEN}(installed){C.RESET}"
                else:
                    status = f" {C.DIM}(not installed){C.RESET}"
            elif prov.key_is_set():
                status = f" {C.GREEN}(key set){C.RESET}"
            print(f"  {C.CYAN}{i}.{C.RESET} {prov.display_name}{status}")

        print()

        while True:
            choice = input(f"  {C.BOLD}Select provider [1-{len(PROVIDER_ORDER)}]:{C.RESET} ").strip()
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(PROVIDER_ORDER):
                    provider_name = PROVIDER_ORDER[idx]
                    break
            except ValueError:
                pass
            print(f"  {C.RED}Please enter a number between 1 and {len(PROVIDER_ORDER)}{C.RESET}")

        provider = PROVIDERS[provider_name]
        print(f"\n  {C.BOLD}Selected: {provider.display_name}{C.RESET}")

        # Set LLM_PROVIDER
        self.env_vars["LLM_PROVIDER"] = provider_name

        # Model selection
        print(f"\n  {C.DIM}Available models:{C.RESET}")
        for i, model in enumerate(provider.models, 1):
            marker = f" {C.GREEN}(default){C.RESET}" if model == provider.default_model else ""
            print(f"    {C.CYAN}{i}.{C.RESET} {model}{marker}")

        print()
        model_choice = input(f"  {C.BOLD}Select model [Enter for default '{provider.default_model}']:{C.RESET} ").strip()
        if model_choice:
            try:
                idx = int(model_choice) - 1
                if 0 <= idx < len(provider.models):
                    self.env_vars["LLM_MODEL"] = provider.models[idx]
            except ValueError:
                self.env_vars["LLM_MODEL"] = model_choice

        # API key setup
        if provider.requires_api_key:
            print(f"\n  {C.BOLD}API Key Setup{C.RESET}")
            print(f"  To get your API key:")
            for line in provider.setup_instructions.split("\n"):
                print(f"    {C.DIM}{line}{C.RESET}")
            print(f"  {C.CYAN}Key format: {provider.api_key_format}{C.RESET}")
            print(f"  {C.CYAN}Get key at: {provider.setup_url}{C.RESET}\n")

            existing = os.getenv(provider.api_key_env, "").strip()
            if existing:
                use_existing = input(
                    f"  {C.YELLOW}Existing key found for {provider.api_key_env}. "
                    f"Keep it? [Y/n]:{C.RESET} "
                ).strip().lower()
                if use_existing != "n":
                    self.env_vars[provider.api_key_env] = existing
                    print(ok("Using existing key"))
                    return

            while True:
                key = input(f"  {C.BOLD}Enter {provider.api_key_env}:{C.RESET} ").strip()
                if not key:
                    print(f"  {C.DIM}You can skip this and set it later in .env{C.RESET}")
                    break

                # Validate
                print(f"  {C.DIM}Validating...{C.RESET}")
                success, msg = validate_api_key(provider_name, key)
                if success:
                    print(ok(msg))
                    self.env_vars[provider.api_key_env] = key
                    break
                else:
                    print(fail(msg))
                    retry = input(f"  {C.YELLOW}Try again? [y/N]:{C.RESET} ").strip().lower()
                    if retry != "y":
                        break
        else:
            # Ollama
            print()
            if check_installed("ollama", "/usr/bin/ollama"):
                print(ok("Ollama is installed"))
                # Check if running
                ollama_prov = get_provider("ollama")
                if ollama_prov and ollama_prov.ollama_is_running():
                    print(ok("Ollama server is running"))
                else:
                    print(warn("Ollama server is not running"))
                    print(info("Start it with: ollama serve"))
                    print(info("Then pull a model: ollama pull llama3.1"))
            else:
                print(fail("Ollama is not installed"))
                print(info(f"Download from: {provider.setup_url}"))
                print(info("After install, run: ollama pull llama3.1"))

            # Base URL for Ollama
            base_url = input(
                f"  {C.BOLD}Ollama base URL [default: http://localhost:11434/v1]:{C.RESET} "
            ).strip()
            if base_url:
                self.env_vars["LLM_BASE_URL"] = base_url

    # ----- Embeddings setup -----

    def _setup_embeddings(self):
        print(header("Step 3: Embedding Provider Setup"))
        print()
        print("Embeddings power semantic search in the knowledge base.")
        print(f"  {C.CYAN}1.{C.RESET} TF-IDF (local, fast, no API key)")
        print(f"  {C.CYAN}2.{C.RESET} Google Gemini (cloud, free tier)")
        print(f"  {C.CYAN}3.{C.RESET} Jina (cloud, free tier)")
        print()

        choice = input(f"  {C.BOLD}Select embedding provider [1 for TF-IDF]:{C.RESET} ").strip()
        if choice == "2":
            self.env_vars["EMBEDDING_PROVIDER"] = "gemini"
            key = input(f"  {C.BOLD}Gemini API key (get at aistudio.google.com/apikey):{C.RESET} ").strip()
            if key:
                self.env_vars["GEMINI_API_KEY"] = key
        elif choice == "3":
            self.env_vars["EMBEDDING_PROVIDER"] = "jina"
            key = input(f"  {C.BOLD}Jina API key (get at jina.ai):{C.RESET} ").strip()
            if key:
                self.env_vars["JINA_API_KEY"] = key
        else:
            self.env_vars["EMBEDDING_PROVIDER"] = "tfidf"
            print(ok("TF-IDF selected (local, no API key needed)"))

        print()

    # ----- Other config -----

    def _setup_other_config(self):
        print(header("Step 4: Default Configuration"))
        print()
        print("The following sensible defaults will be written to .env:")
        defaults = {
            "LLM_TEMPERATURE": "0.7",
            "LLM_MAX_TOKENS": "4096",
            "CRITIQUE_ENABLED": "true",
            "CRITIQUE_CONFIDENCE_THRESHOLD": "0.6",
            "KNOWLEDGE_EXTRACTION_ENABLED": "true",
            "DEBATE_ENABLED": "true",
            "DEBATE_MAX_ROUNDS": "3",
            "TOKEN_BUDGET_ENABLED": "true",
            "TOKEN_GLOBAL_LIMIT": "1000000",
            "MONITORING_ENABLED": "true",
            "LOG_LEVEL": "INFO",
        }
        for key, val in defaults.items():
            if key not in self.env_vars:
                self.env_vars[key] = val
            print(f"  {C.DIM}{key}={self.env_vars[key]}{C.RESET}")

        print()

    # ----- Summary -----

    def _print_summary(self):
        print(header("Setup Summary"))
        print()

        provider_name = self.env_vars.get("LLM_PROVIDER", "unknown")
        provider = get_provider(provider_name)
        if provider:
            has_key = (
                provider.key_is_set()
                or provider.api_key_env in self.env_vars
            )
            if provider.requires_api_key and has_key:
                print(ok(f"LLM: {provider.display_name} — key configured"))
            elif not provider.requires_api_key:
                print(ok(f"LLM: {provider.display_name} — local (no key needed)"))
            else:
                print(warn(f"LLM: {provider.display_name} — NO key configured"))
                print(info("Set it later in .env or re-run this wizard"))

        emb = self.env_vars.get("EMBEDDING_PROVIDER", "tfidf")
        print(ok(f"Embeddings: {emb}"))

        print()
        print(f"{C.DIM}Configuration will be written to: .env{C.RESET}")

    # ----- Write .env -----

    def _write_env_file(self):
        env_path = Path(__file__).parent / ".env"

        if env_path.exists():
            overwrite = input(
                f"\n  {C.YELLOW}.env already exists. Overwrite? [y/N]:{C.RESET} "
            ).strip().lower()
            if overwrite != "y":
                print(f"  {C.DIM}Skipping .env write. Update it manually.{C.RESET}")
                return

        # Build .env content
        lines = [
            "# Generated by Reverse Engineering Lab Setup Wizard",
            "#",
            f"# Provider: {self.env_vars.get('LLM_PROVIDER', 'openai')}",
            "",
        ]

        # LLM section
        lines.append("# === LLM Provider ===")
        for key in ("LLM_PROVIDER", "LLM_MODEL", "LLM_BASE_URL",
                     "LLM_TEMPERATURE", "LLM_MAX_TOKENS"):
            if key in self.env_vars:
                lines.append(f"{key}={self.env_vars[key]}")

        # Provider-specific keys
        lines.append("")
        lines.append("# === API Keys ===")
        for prov_name in PROVIDER_ORDER:
            prov = PROVIDERS[prov_name]
            if prov.api_key_env in self.env_vars:
                lines.append(f"{prov.api_key_env}={self.env_vars[prov.api_key_env]}")
            elif prov.key_is_set():
                lines.append(f"{prov.api_key_env}={prov.key_value()}")
            else:
                lines.append(f"# {prov.api_key_env}=  # {prov.display_name}")

        # Embeddings
        lines.append("")
        lines.append("# === Embeddings ===")
        for key in ("EMBEDDING_PROVIDER", "GEMINI_API_KEY", "JINA_API_KEY"):
            if key in self.env_vars:
                lines.append(f"{key}={self.env_vars[key]}")

        # Other defaults
        lines.append("")
        lines.append("# === Other Defaults ===")
        for key, val in sorted(self.env_vars.items()):
            if key.startswith("LLM_") or key.endswith("_API_KEY"):
                continue
            if key == "EMBEDDING_PROVIDER":
                continue
            lines.append(f"{key}={val}")

        # Database / Dashboard / Monitoring defaults (commented out)
        lines.extend([
            "",
            "# === Database (defaults for docker-compose) ===",
            "POSTGRES_HOST=localhost",
            "POSTGRES_PORT=5432",
            "POSTGRES_DB=knowledge_base",
            "POSTGRES_USER=postgres",
            "POSTGRES_PASSWORD=postgres",
            "NEO4J_URI=bolt://localhost:7687",
            "NEO4J_USER=neo4j",
            "NEO4J_PASSWORD=neo4j",
            "REDIS_HOST=localhost",
            "REDIS_PORT=6379",
            "",
            "# === Dashboard ===",
            "DASHBOARD_HOST=0.0.0.0",
            "DASHBOARD_PORT=5000",
            "DASHBOARD_DEBUG=False",
            "",
            "# === Monitoring ===",
            "MONITORING_ENABLED=true",
            "METRICS_PORT=9090",
            "STRUCTURED_LOGGING=false",
            "PROMETHEUS_ENABLED=true",
            "GRAFANA_ENABLED=true",
            "GRAFANA_PORT=3000",
        ])

        env_path.write_text("\n".join(lines) + "\n")
        print(f"\n  {C.GREEN}{C.BOLD}.env written to {env_path}{C.RESET}")
        print(f"  {C.DIM}You can edit it anytime to adjust settings.{C.RESET}\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    # Detect if running in a terminal; disable colors if piped
    if not sys.stdout.isatty():
        C.disable()

    try:
        wizard = SetupWizard()
        wizard.run()
    except KeyboardInterrupt:
        print(f"\n\n{C.YELLOW}Setup cancelled.{C.RESET}\n")
        sys.exit(1)
    except EOFError:
        print(f"\n\n{C.DIM}Setup ended (no input).{C.RESET}\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
