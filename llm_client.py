"""
Shared LLM Client for the Reverse Engineering Lab.
Supports multiple providers: OpenAI, Google AI Studio, Anthropic Claude,
OpenRouter, NVIDIA NIM, and Ollama (local).
Hard-fails if no API key is configured (except Ollama).
"""

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("llm_client")


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class LLMClientNotConfiguredError(Exception):
    """Raised when the LLM client is used without a valid API key."""


class LLMError(Exception):
    """General LLM call failure after retries."""


class LLMRateLimitError(LLMError):
    """Rate-limited by the LLM provider."""


class LLMTimeoutError(LLMError):
    """LLM call timed out."""


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class LLMConfig:
    """Configuration for the LLM client.

    If provider is given, base_url and model defaults are auto-resolved
    from the provider registry unless explicitly overridden.
    """
    api_key: str
    model: str = ""
    base_url: Optional[str] = None
    provider: str = "openai"
    temperature: float = 0.7
    max_tokens: int = 4096
    timeout: int = 60
    max_retries: int = 3
    retry_base_delay: float = 1.0

    def __post_init__(self):
        # Resolve defaults from provider registry
        from providers import get_provider
        prov = get_provider(self.provider)
        if prov:
            if not self.base_url:
                self.base_url = prov.base_url
            if not self.model:
                self.model = prov.default_model
            # Ollama doesn't require an API key
            if prov.requires_api_key and not self.api_key:
                raise LLMClientNotConfiguredError(
                    f"{prov.display_name} API key is required. "
                    f"Set {prov.api_key_env} environment variable."
                )
        else:
            # Unknown provider — need base_url and model
            if not self.model:
                self.model = "gpt-4"
            if not self.api_key:
                raise LLMClientNotConfiguredError(
                    "LLM API key is required. Set the provider-specific API key "
                    "environment variable (e.g., OPENAI_API_KEY, ANTHROPIC_API_KEY)."
                )


# ---------------------------------------------------------------------------
# Token counting (rough estimate)
# ---------------------------------------------------------------------------

def _estimate_tokens(text: str) -> int:
    """Rough token count: ~4 chars per token for English text."""
    if not text:
        return 0
    return max(1, len(text) // 4)


# ---------------------------------------------------------------------------
# Usage tracker
# ---------------------------------------------------------------------------

@dataclass
class UsageStats:
    """Tracks LLM usage statistics."""
    total_calls: int = 0
    successful_calls: int = 0
    failed_calls: int = 0
    total_prompt_tokens: int = 0
    total_completion_tokens: int = 0
    total_tokens: int = 0
    total_latency_ms: float = 0.0

    def record_call(self, prompt_tokens: int, completion_tokens: int,
                    latency_ms: float, success: bool = True):
        self.total_calls += 1
        if success:
            self.successful_calls += 1
        else:
            self.failed_calls += 1
        self.total_prompt_tokens += prompt_tokens
        self.total_completion_tokens += completion_tokens
        self.total_tokens += prompt_tokens + completion_tokens
        self.total_latency_ms += latency_ms

    def to_dict(self) -> Dict[str, Any]:
        avg_latency = (
            round(self.total_latency_ms / self.total_calls, 1)
            if self.total_calls > 0 else 0.0
        )
        return {
            "total_calls": self.total_calls,
            "successful_calls": self.successful_calls,
            "failed_calls": self.failed_calls,
            "total_prompt_tokens": self.total_prompt_tokens,
            "total_completion_tokens": self.total_completion_tokens,
            "total_tokens": self.total_tokens,
            "total_latency_ms": round(self.total_latency_ms, 1),
            "average_latency_ms": avg_latency,
        }


# ---------------------------------------------------------------------------
# Anthropic adapter (wraps anthropic SDK to match openai interface)
# ---------------------------------------------------------------------------

class _AnthropicAdapter:
    """Wraps the anthropic SDK to provide a chat.completions.create()-like interface.

    This allows LLMClient to use the same calling pattern for Anthropic
    as it does for OpenAI-compatible providers.
    """

    def __init__(self, api_key: str, model: str, timeout: int = 60):
        try:
            import anthropic
        except ImportError:
            raise LLMClientNotConfiguredError(
                "anthropic package not installed. Run: pip install anthropic"
            )
        self._client = anthropic.AsyncAnthropic(
            api_key=api_key,
            timeout=timeout,
        )
        self._model = model

    async def create(self, messages: List[Dict[str, str]], temperature: float,
                     max_tokens: int, **kwargs) -> Any:
        """Create a chat completion using the Anthropic Messages API.

        Returns an object with .choices[0].message.content and .usage
        matching the OpenAI response interface.
        """
        # Separate system message (Anthropic takes it as a top-level param)
        system_text = ""
        user_messages = []
        for msg in messages:
            if msg["role"] == "system":
                system_text = msg["content"]
            else:
                user_messages.append(msg)

        if not user_messages:
            user_messages = [{"role": "user", "content": "Hello"}]

        request_kwargs: Dict[str, Any] = {
            "model": self._model,
            "messages": user_messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if system_text:
            request_kwargs["system"] = system_text

        response = await self._client.messages.create(**request_kwargs)

        # Normalize to OpenAI-like response
        content = ""
        for block in response.content:
            if hasattr(block, "text"):
                content += block.text

        return _AnthropicResponse(content, response.usage)


class _AnthropicResponse:
    """Mimics the OpenAI chat completion response for Anthropic output."""

    def __init__(self, content: str, usage: Any):
        self.choices = [_AnthropicChoice(content)]
        self.usage = _AnthropicUsage(usage)


class _AnthropicChoice:
    def __init__(self, content: str):
        self.message = _AnthropicMessage(content)


class _AnthropicMessage:
    def __init__(self, content: str):
        self.content = content


class _AnthropicUsage:
    def __init__(self, usage: Any):
        self.prompt_tokens = getattr(usage, "input_tokens", 0) or 0
        self.completion_tokens = getattr(usage, "output_tokens", 0) or 0


# ---------------------------------------------------------------------------
# LLM Client
# ---------------------------------------------------------------------------

class LLMClient:
    """Async LLM client supporting multiple providers.

    For OpenAI-compatible providers (openai, google, openrouter, nvidia_nim,
    ollama): uses the openai package directly.
    For Anthropic: uses the anthropic package via _AnthropicAdapter.

    Raises LLMClientNotConfiguredError at construction if api_key is empty
    (except for Ollama).
    """

    def __init__(self, config: LLMConfig):
        self.config = config
        self.stats = UsageStats()
        self._client = None
        self._anthropic_adapter = None
        self._init_client()

    def _init_client(self):
        """Initialize the appropriate client for the provider."""
        self.logger = logging.getLogger("llm_client")

        if self.config.provider == "anthropic":
            # Use Anthropic SDK directly
            self._anthropic_adapter = _AnthropicAdapter(
                api_key=self.config.api_key,
                model=self.config.model,
                timeout=self.config.timeout,
            )
            self.logger.info(
                f"LLM client initialized (Anthropic): model={self.config.model}"
            )
            return

        # All other providers: use openai SDK (OpenAI-compatible)
        try:
            import openai
        except ImportError:
            raise LLMClientNotConfiguredError(
                "openai package not installed. Run: pip install openai"
            )

        kwargs: Dict[str, Any] = {
            "api_key": self.config.api_key or "ollama",
            "timeout": self.config.timeout,
            "max_retries": 0,  # We handle retries ourselves
        }
        if self.config.base_url:
            kwargs["base_url"] = self.config.base_url

        self._client = openai.AsyncOpenAI(**kwargs)
        self.logger.info(
            f"LLM client initialized: model={self.config.model}, "
            f"provider={self.config.provider}, "
            f"base_url={self.config.base_url}"
        )

    async def chat_completion(
        self,
        messages: List[Dict[str, str]],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        response_format: Optional[Dict[str, str]] = None,
    ) -> str:
        """Send a chat completion request and return the response text.

        Retries on transient errors (429, 500-503) with exponential backoff.
        """
        if temperature is None:
            temperature = self.config.temperature
        if max_tokens is None:
            max_tokens = self.config.max_tokens

        last_error: Optional[Exception] = None
        for attempt in range(self.config.max_retries):
            t0 = time.monotonic()
            try:
                # Anthropic path
                if self._anthropic_adapter:
                    response = await self._anthropic_adapter.create(
                        messages=messages,
                        temperature=temperature,
                        max_tokens=max_tokens,
                    )
                else:
                    # OpenAI-compatible path
                    kwargs: Dict[str, Any] = {
                        "model": self.config.model,
                        "messages": messages,
                        "temperature": temperature,
                        "max_tokens": max_tokens,
                    }
                    if response_format:
                        # Ollama doesn't support json_mode — skip it
                        from providers import get_provider
                        prov = get_provider(self.config.provider)
                        if prov and prov.supports_json_mode:
                            kwargs["response_format"] = response_format
                    response = await self._client.chat.completions.create(**kwargs)

                elapsed_ms = (time.monotonic() - t0) * 1000
                choice = response.choices[0]
                content = choice.message.content or ""
                prompt_tokens = getattr(response.usage, "prompt_tokens", 0) or 0
                completion_tokens = getattr(response.usage, "completion_tokens", 0) or 0

                self.stats.record_call(prompt_tokens, completion_tokens, elapsed_ms)
                self.logger.debug(
                    f"LLM call OK ({self.config.provider}): "
                    f"{prompt_tokens}+{completion_tokens} tokens, "
                    f"{elapsed_ms:.0f}ms"
                )
                return content

            except Exception as e:
                elapsed_ms = (time.monotonic() - t0) * 1000
                last_error = e
                error_str = str(e).lower()

                # Rate limit — retry after delay
                if "rate" in error_str or "429" in error_str or "overloaded" in error_str:
                    delay = self.config.retry_base_delay * (2 ** attempt)
                    self.logger.warning(
                        f"Rate limited, retrying in {delay:.1f}s "
                        f"(attempt {attempt + 1}/{self.config.max_retries})"
                    )
                    self.stats.record_call(0, 0, elapsed_ms, success=False)
                    await asyncio.sleep(delay)
                    continue

                # Transient server errors — retry
                if any(code in error_str for code in ("500", "502", "503", "504")):
                    delay = self.config.retry_base_delay * (2 ** attempt)
                    self.logger.warning(
                        f"Server error, retrying in {delay:.1f}s "
                        f"(attempt {attempt + 1}/{self.config.max_retries})"
                    )
                    self.stats.record_call(0, 0, elapsed_ms, success=False)
                    await asyncio.sleep(delay)
                    continue

                # Timeout
                if "timeout" in error_str or "timed out" in error_str:
                    self.stats.record_call(0, 0, elapsed_ms, success=False)
                    raise LLMTimeoutError(f"LLM call timed out: {e}") from e

                # Non-retryable error
                break

        self.stats.record_call(0, 0, 0, success=False)
        raise LLMError(
            f"LLM call failed after {self.config.max_retries} attempts: {last_error}"
        ) from last_error

    async def chat_completion_json(
        self,
        messages: List[Dict[str, str]],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Chat completion that returns parsed JSON.

        Adds response_format={"type": "json_object"} and parses the result.
        Falls back to manual JSON extraction if response_format is not supported.
        """
        from providers import get_provider
        prov = get_provider(self.config.provider)
        supports_json = prov.supports_json_mode if prov else True

        if supports_json:
            try:
                raw = await self.chat_completion(
                    messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    response_format={"type": "json_object"},
                )
                return json.loads(raw)
            except (json.JSONDecodeError, Exception):
                pass

        # Fallback: request JSON in the prompt and parse manually
        raw = await self.chat_completion(
            messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        return self._extract_json_from_text(raw)

    @staticmethod
    def _extract_json_from_text(text: str) -> Dict[str, Any]:
        """Best-effort JSON extraction from text that may contain markdown fences."""
        text = text.strip()
        # Try direct parse
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        # Try extracting from ```json ... ``` fences
        if "```json" in text:
            start = text.index("```json") + 7
            end = text.index("```", start)
            return json.loads(text[start:end].strip())
        if "```" in text:
            start = text.index("```") + 3
            end = text.index("```", start)
            return json.loads(text[start:end].strip())
        # Try finding first { ... } block
        brace_start = text.find("{")
        brace_end = text.rfind("}")
        if brace_start != -1 and brace_end > brace_start:
            return json.loads(text[brace_start:brace_end + 1])
        raise LLMError(f"Could not extract JSON from LLM response: {text[:200]}")

    def get_usage_stats(self) -> Dict[str, Any]:
        """Return usage statistics."""
        return self.stats.to_dict()


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_llm_client_instance: Optional[LLMClient] = None


def get_llm_client() -> LLMClient:
    """Get or create the global LLM client from settings.

    Auto-detects the active provider from environment variables.
    Raises LLMClientNotConfiguredError if no valid key is found.
    """
    global _llm_client_instance
    if _llm_client_instance is not None:
        return _llm_client_instance

    from providers import get_active_provider, migrate_legacy_env
    migrate_legacy_env()

    # Determine provider and key
    provider = get_active_provider()
    if provider is None:
        raise LLMClientNotConfiguredError(
            "No LLM provider configured. Set LLM_PROVIDER and the "
            "corresponding API key environment variable."
        )

    # Get API key (Ollama doesn't need one)
    api_key = provider.key_value() if provider.requires_api_key else "ollama"

    # Read model/base_url from settings, falling back to provider defaults
    try:
        from config.settings import (
            LLM_MODEL, LLM_BASE_URL, LLM_TEMPERATURE, LLM_MAX_TOKENS,
        )
    except ImportError:
        LLM_MODEL = provider.default_model
        LLM_BASE_URL = provider.base_url
        LLM_TEMPERATURE = 0.7
        LLM_MAX_TOKENS = 4096

    # If settings model is the generic default ("gpt-4") and provider isn't openai,
    # use the provider's default model instead
    model = LLM_MODEL
    if model == "gpt-4" and provider.name != "openai":
        model = provider.default_model

    config = LLMConfig(
        api_key=api_key,
        model=model,
        base_url=LLM_BASE_URL or provider.base_url,
        provider=provider.name,
        temperature=LLM_TEMPERATURE,
        max_tokens=LLM_MAX_TOKENS,
    )
    _llm_client_instance = LLMClient(config)
    return _llm_client_instance


def reset_llm_client():
    """Reset the singleton (for testing)."""
    global _llm_client_instance
    _llm_client_instance = None
