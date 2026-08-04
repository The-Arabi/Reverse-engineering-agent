"""
Embedding providers for the Reverse Engineering Lab.
Supports Google Gemini text-embedding-004, Jina AI jina-embeddings-v3,
and local TF-IDF fallback. Provides unified EmbeddingManager with fallback chain.
"""

import json
import logging
import math
import os
import re
from abc import ABC, abstractmethod
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("embeddings")


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class EmbeddingError(Exception):
    """Base embedding error."""


class EmbeddingProviderNotAvailableError(EmbeddingError):
    """Requested embedding provider is not configured or available."""


# ---------------------------------------------------------------------------
# Abstract provider
# ---------------------------------------------------------------------------

class EmbeddingProvider(ABC):
    """Abstract base for embedding providers."""

    @abstractmethod
    async def embed(self, text: str) -> List[float]:
        """Generate embedding for a single text."""

    @abstractmethod
    async def embed_batch(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings for a list of texts."""

    @abstractmethod
    def dimension(self) -> int:
        """Return the embedding dimension."""

    @abstractmethod
    def provider_name(self) -> str:
        """Return the provider name string."""


# ---------------------------------------------------------------------------
# TF-IDF local provider (always available, no API key needed)
# ---------------------------------------------------------------------------

class TFIDFEmbeddingProvider(EmbeddingProvider):
    """Local TF-IDF vectorizer. No external API needed.

    Uses a fixed vocabulary of common RE/binary analysis terms plus
    character n-grams for general text coverage.
    """

    VOCAB_SIZE = 2048
    NGRAM_RANGE = (2, 4)

    def __init__(self):
        self._vocab: Dict[str, int] = {}
        self._idf: Dict[str, float] = {}
        self._fitted = False
        self._doc_count = 0
        self._build_initial_vocab()

    def _build_initial_vocab(self):
        """Build initial vocabulary from domain-specific terms."""
        re_terms = [
            "elf", "binary", "firmware", "kernel", "module", "symbol",
            "function", "instruction", "opcode", "register", "memory",
            "stack", "heap", "buffer", "overflow", "vulnerability",
            "exploit", "shellcode", "payload", "callback", "shell",
            "network", "packet", "protocol", "tcp", "udp", "http",
            "dns", "tls", "ssl", "certificate", "encryption", "aes",
            "rsa", "sha", "md5", "hash", "key", "secret", "password",
            "credential", "token", "auth", "login", "privilege",
            "escalation", "root", "admin", "system", "process", "thread",
            "syscall", "interrupt", "driver", "device", "pci", "usb",
            "gpio", "spi", "i2c", "uart", "jtag", "debug", "trace",
            "breakpoint", "emulator", "qemu", "unicorn", "hypervisor",
            "virtualization", "container", "docker", "sandbox",
            "obfuscation", "packer", "upx", "cryptor", "anti-debug",
            "anti-tampering", "integrity", "checksum", "crc", "section",
            "header", "segment", "relocation", "import", "export",
            "dynamic", "static", "disassembly", "decompilation",
            "ghidra", "ida", "radare2", "objdump", "readelf", "strings",
            "hexdump", "binwalk", "gdb", "ltrace", "strace",
            "gpu", "shader", "vertex", "fragment", "texture", "render",
            "framebuffer", "pipeline", "draw", "call", "dispatch",
            "arm", "x86", "mips", "riscv", "powerpc", "sparc",
            "endian", "little", "big", "32bit", "64bit", "16bit",
            "little-endian", "big-endian", "android", "linux", "windows",
            "rtos", "bare-metal", "bootloader", "uboot", "bios", "uefi",
        ]
        for i, term in enumerate(re_terms):
            self._vocab[term] = i
        # Also add character n-gram indices
        for i in range(self.VOCAB_SIZE - len(re_terms)):
            self._vocab[f"_ng{i}"] = len(re_terms) + i
        self._fitted = False

    def _tokenize(self, text: str) -> List[str]:
        """Tokenize text into words + character n-grams."""
        text = text.lower()
        words = re.findall(r"[a-z0-9_]{2,}", text)
        tokens = list(words)
        # Character n-grams
        clean = re.sub(r"[^a-z0-9]", "", text)
        for n in range(self.NGRAM_RANGE[0], self.NGRAM_RANGE[1] + 1):
            for i in range(len(clean) - n + 1):
                tokens.append(clean[i:i + n])
        return tokens

    def _vectorize(self, tokens: List[str]) -> List[float]:
        """Convert tokens to a fixed-dim TF-IDF-like vector."""
        counter = Counter(tokens)
        total = len(tokens) if tokens else 1
        vec = [0.0] * self.VOCAB_SIZE
        for token, count in counter.items():
            if token in self._vocab:
                idx = self._vocab[token] % self.VOCAB_SIZE
                tf = count / total
                idf = self._idf.get(token, 1.0)
                vec[idx] += tf * idf
        # L2 normalize
        norm = math.sqrt(sum(v * v for v in vec)) or 1.0
        return [v / norm for v in vec]

    async def embed(self, text: str) -> List[float]:
        tokens = self._tokenize(text)
        return self._vectorize(tokens)

    async def embed_batch(self, texts: List[str]) -> List[List[float]]:
        return [await self.embed(t) for t in texts]

    def dimension(self) -> int:
        return self.VOCAB_SIZE

    def provider_name(self) -> str:
        return "tfidf"


# ---------------------------------------------------------------------------
# Gemini embedding provider
# ---------------------------------------------------------------------------

class GeminiEmbeddingProvider(EmbeddingProvider):
    """Google Gemini text-embedding-004 provider. 768 dimensions."""

    MODEL_DIMENSION = 768

    def __init__(self, api_key: Optional[str] = None, model: str = "text-embedding-004"):
        self._api_key = api_key or os.getenv("GEMINI_API_KEY", "")
        self._model = model
        if not self._api_key:
            raise EmbeddingProviderNotAvailableError(
                "Gemini API key not configured. Set GEMINI_API_KEY."
            )

    async def embed(self, text: str) -> List[float]:
        results = await self.embed_batch([text])
        return results[0]

    async def embed_batch(self, texts: List[str]) -> List[List[float]]:
        if not texts:
            return []
        try:
            import google.generativeai as genai
        except ImportError:
            raise EmbeddingProviderNotAvailableError(
                "google-generativeai not installed. Run: pip install google-generativeai"
            )

        genai.configure(api_key=self._api_key)
        # Batch max 100 texts per request
        all_embeddings: List[List[float]] = []
        batch_size = 100
        for i in range(0, len(texts), batch_size):
            batch = texts[i:i + batch_size]
            result = await genai.embed_content_async(
                model=self._model,
                content=batch,
                task_type="RETRIEVAL_DOCUMENT",
            )
            all_embeddings.extend(result["embedding"])

        return all_embeddings

    def dimension(self) -> int:
        return self.MODEL_DIMENSION

    def provider_name(self) -> str:
        return "gemini"


# ---------------------------------------------------------------------------
# Jina embedding provider
# ---------------------------------------------------------------------------

class JinaEmbeddingProvider(EmbeddingProvider):
    """Jina AI jina-embeddings-v3 provider. Supports long documents (32k context)."""

    MODEL_DIMENSION = 1024

    def __init__(self, api_key: Optional[str] = None, model: str = "jina-embeddings-v3"):
        self._api_key = api_key or os.getenv("JINA_API_KEY", "")
        self._model = model
        self._api_url = "https://api.jina.ai/v1/embeddings"
        if not self._api_key:
            raise EmbeddingProviderNotAvailableError(
                "Jina API key not configured. Set JINA_API_KEY."
            )

    async def embed(self, text: str) -> List[float]:
        results = await self.embed_batch([text])
        return results[0]

    async def embed_batch(self, texts: List[str]) -> List[List[float]]:
        if not texts:
            return []
        try:
            import aiohttp
        except ImportError:
            raise EmbeddingProviderNotAvailableError(
                "aiohttp not installed. Run: pip install aiohttp"
            )

        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self._model,
            "input": texts,
        }

        all_embeddings: List[List[float]] = []
        batch_size = 32  # Jina recommended batch size
        for i in range(0, len(texts), batch_size):
            batch = texts[i:i + batch_size]
            payload["input"] = batch
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self._api_url, json=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=30)
                ) as resp:
                    if resp.status != 200:
                        body = await resp.text()
                        raise EmbeddingError(
                            f"Jina API error {resp.status}: {body[:200]}"
                        )
                    data = await resp.json()
                    for item in data.get("data", []):
                        all_embeddings.append(item["embedding"])

        return all_embeddings

    def dimension(self) -> int:
        return self.MODEL_DIMENSION

    def provider_name(self) -> str:
        return "jina"


# ---------------------------------------------------------------------------
# Cosine similarity (pure Python)
# ---------------------------------------------------------------------------

def cosine_similarity(a: List[float], b: List[float]) -> float:
    """Compute cosine similarity between two vectors."""
    if len(a) != len(b):
        # Pad shorter vector with zeros
        max_len = max(len(a), len(b))
        a = a + [0.0] * (max_len - len(a))
        b = b + [0.0] * (max_len - len(b))
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a)) or 1.0
    norm_b = math.sqrt(sum(x * x for x in b)) or 1.0
    return dot / (norm_a * norm_b)


# ---------------------------------------------------------------------------
# Embedding Manager
# ---------------------------------------------------------------------------

@dataclass
class EmbeddingResult:
    """Result of an embedding operation."""
    embedding: List[float]
    provider_name: str
    dimension: int


class EmbeddingManager:
    """Manages embedding providers with fallback chain.

    Usage:
        manager = EmbeddingManager()
        result = await manager.embed("some text")
    """

    def __init__(
        self,
        primary_provider: Optional[EmbeddingProvider] = None,
        fallback_provider: Optional[EmbeddingProvider] = None,
    ):
        self._providers: List[EmbeddingProvider] = []
        self._init_providers(primary_provider, fallback_provider)

    def _init_providers(
        self,
        primary: Optional[EmbeddingProvider],
        fallback: Optional[EmbeddingProvider],
    ):
        """Initialize provider chain: primary -> fallback -> TF-IDF (always last)."""
        if primary:
            self._providers.append(primary)
        if fallback and fallback.provider_name() != getattr(primary, "provider_name", lambda: "")():
            self._providers.append(fallback)
        # Always add TF-IDF as final fallback
        self._providers.append(TFIDFEmbeddingProvider())

    @classmethod
    def from_settings(cls) -> "EmbeddingManager":
        """Create manager from config/settings.py env vars."""
        from config.settings import (
            EMBEDDING_PROVIDER, GEMINI_API_KEY, GEMINI_MODEL,
            JINA_API_KEY, JINA_MODEL,
        )

        primary: Optional[EmbeddingProvider] = None
        fallback: Optional[EmbeddingProvider] = None

        # Determine primary provider
        if EMBEDDING_PROVIDER == "gemini" and GEMINI_API_KEY:
            try:
                primary = GeminiEmbeddingProvider(
                    api_key=GEMINI_API_KEY, model=GEMINI_MODEL
                )
            except EmbeddingProviderNotAvailableError as e:
                logger.warning(f"Gemini provider unavailable: {e}")
        elif EMBEDDING_PROVIDER == "jina" and JINA_API_KEY:
            try:
                primary = JinaEmbeddingProvider(
                    api_key=JINA_API_KEY, model=JINA_MODEL
                )
            except EmbeddingProviderNotAvailableError as e:
                logger.warning(f"Jina provider unavailable: {e}")

        # Set up fallback
        if primary and primary.provider_name() != "jina" and JINA_API_KEY:
            try:
                fallback = JinaEmbeddingProvider(
                    api_key=JINA_API_KEY, model=JINA_MODEL
                )
            except EmbeddingProviderNotAvailableError:
                pass
        elif primary and primary.provider_name() != "gemini" and GEMINI_API_KEY:
            try:
                fallback = GeminiEmbeddingProvider(
                    api_key=GEMINI_API_KEY, model=GEMINI_MODEL
                )
            except EmbeddingProviderNotAvailableError:
                pass

        manager = cls(primary_provider=primary, fallback_provider=fallback)
        provider_names = [p.provider_name() for p in manager._providers]
        logger.info(f"Embedding manager initialized with chain: {provider_names}")
        return manager

    async def embed(self, text: str) -> EmbeddingResult:
        """Generate embedding, falling back through providers on failure."""
        last_error: Optional[Exception] = None
        for provider in self._providers:
            try:
                embedding = await provider.embed(text)
                return EmbeddingResult(
                    embedding=embedding,
                    provider_name=provider.provider_name(),
                    dimension=provider.dimension(),
                )
            except Exception as e:
                last_error = e
                logger.warning(
                    f"Embedding failed with {provider.provider_name()}: {e}"
                )
                continue

        raise EmbeddingError(
            f"All embedding providers failed. Last error: {last_error}"
        )

    async def embed_batch(self, texts: List[str]) -> List[EmbeddingResult]:
        """Generate embeddings for multiple texts."""
        return [await self.embed(t) for t in texts]

    def available_providers(self) -> List[str]:
        """Return list of available provider names."""
        return [p.provider_name() for p in self._providers]
