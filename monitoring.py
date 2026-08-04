"""
Monitoring & Observability for the Reverse Engineering Lab.
Provides metrics collection with Prometheus exposition format and structured logging.

Metric types:
- Counter: monotonically increasing values (e.g. total executions)
- Histogram: distribution of values with configurable buckets (e.g. duration)
- Gauge: value that can go up or down (e.g. active agents)

Usage:
    from monitoring import get_metrics
    metrics = get_metrics()
    metrics.counter_inc("agent_executions_total", labels={"agent_type": "binary"})
    metrics.histogram_observe("agent_duration_seconds", 1.23, labels={"agent_type": "binary"})
    metrics.gauge_set("active_agents", 3)
    print(metrics.expose_prometheus())
"""

import time
import json
import threading
import logging
import math
from typing import Dict, List, Optional, Any
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger("monitoring")


# ---------------------------------------------------------------------------
# Metric value containers
# ---------------------------------------------------------------------------

class Counter:
    """Monotonically increasing counter."""

    def __init__(self, name: str, help_text: str):
        self.name = name
        self.help_text = help_text
        self._values: Dict[tuple, float] = defaultdict(float)
        self._lock = threading.Lock()

    def inc(self, value: float = 1.0, labels: Optional[Dict[str, str]] = None):
        if value < 0:
            raise ValueError("Counter value must be non-negative")
        key = self._label_key(labels)
        with self._lock:
            self._values[key] += value

    def get(self, labels: Optional[Dict[str, str]] = None) -> float:
        key = self._label_key(labels)
        with self._lock:
            return self._values.get(key, 0.0)

    def get_all(self) -> Dict[tuple, float]:
        with self._lock:
            return dict(self._values)

    @staticmethod
    def _label_key(labels: Optional[Dict[str, str]]) -> tuple:
        if not labels:
            return ()
        return tuple(sorted(labels.items()))


class Histogram:
    """Histogram with configurable buckets for measuring distributions."""

    DEFAULT_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, float("inf"))

    def __init__(self, name: str, help_text: str, buckets: Optional[tuple] = None):
        self.name = name
        self.help_text = help_text
        self.buckets = buckets or self.DEFAULT_BUCKETS
        self._sums: Dict[tuple, float] = defaultdict(float)
        self._counts: Dict[tuple, int] = defaultdict(int)
        self._bucket_counts: Dict[tuple, Dict[float, int]] = defaultdict(lambda: defaultdict(int))
        self._lock = threading.Lock()

    def observe(self, value: float, labels: Optional[Dict[str, str]] = None):
        key = self._label_key(labels)
        with self._lock:
            self._sums[key] += value
            self._counts[key] += 1
            for bucket in self.buckets:
                if value <= bucket:
                    self._bucket_counts[key][bucket] += 1

    def get(self, labels: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        key = self._label_key(labels)
        with self._lock:
            return {
                "sum": self._sums.get(key, 0.0),
                "count": self._counts.get(key, 0),
                "buckets": dict(self._bucket_counts.get(key, {})),
            }

    def get_all(self) -> Dict[tuple, Dict[str, Any]]:
        with self._lock:
            result = {}
            all_keys = set(list(self._sums.keys()) + list(self._counts.keys()))
            for key in all_keys:
                result[key] = {
                    "sum": self._sums.get(key, 0.0),
                    "count": self._counts.get(key, 0),
                    "buckets": dict(self._bucket_counts.get(key, {})),
                }
            return result

    @staticmethod
    def _label_key(labels: Optional[Dict[str, str]]) -> tuple:
        if not labels:
            return ()
        return tuple(sorted(labels.items()))


class Gauge:
    """Gauge that can go up or down."""

    def __init__(self, name: str, help_text: str):
        self.name = name
        self.help_text = help_text
        self._values: Dict[tuple, float] = defaultdict(float)
        self._lock = threading.Lock()

    def set(self, value: float, labels: Optional[Dict[str, str]] = None):
        key = self._label_key(labels)
        with self._lock:
            self._values[key] = value

    def inc(self, value: float = 1.0, labels: Optional[Dict[str, str]] = None):
        key = self._label_key(labels)
        with self._lock:
            self._values[key] += value

    def dec(self, value: float = 1.0, labels: Optional[Dict[str, str]] = None):
        key = self._label_key(labels)
        with self._lock:
            self._values[key] -= value

    def get(self, labels: Optional[Dict[str, str]] = None) -> float:
        key = self._label_key(labels)
        with self._lock:
            return self._values.get(key, 0.0)

    def get_all(self) -> Dict[tuple, float]:
        with self._lock:
            return dict(self._values)

    @staticmethod
    def _label_key(labels: Optional[Dict[str, str]]) -> tuple:
        if not labels:
            return ()
        return tuple(sorted(labels.items()))


# ---------------------------------------------------------------------------
# MetricsCollector
# ---------------------------------------------------------------------------

class MetricsCollector:
    """Central metrics collector with Prometheus exposition support.

    Creates pre-defined metrics for the RE lab system and provides
    convenience methods for recording agent, LLM, tool, mission,
    debate, and token-budget events.
    """

    def __init__(self, namespace: str = "re_lab"):
        self.namespace = namespace
        self._counters: Dict[str, Counter] = {}
        self._histograms: Dict[str, Histogram] = {}
        self._gauges: Dict[str, Gauge] = {}
        self._created_at = time.monotonic()
        self._info: Dict[str, str] = {}
        self._register_default_metrics()

    # -- Registration --------------------------------------------------------

    def counter(self, name: str, help_text: str) -> Counter:
        if name not in self._counters:
            self._counters[name] = Counter(name, help_text)
        return self._counters[name]

    def histogram(self, name: str, help_text: str, buckets: Optional[tuple] = None) -> Histogram:
        if name not in self._histograms:
            self._histograms[name] = Histogram(name, help_text, buckets)
        return self._histograms[name]

    def gauge(self, name: str, help_text: str) -> Gauge:
        if name not in self._gauges:
            self._gauges[name] = Gauge(name, help_text)
        return self._gauges[name]

    def set_info(self, key: str, value: str):
        self._info[key] = value

    # -- Convenience wrappers ------------------------------------------------

    def counter_inc(self, name: str, value: float = 1.0, labels: Optional[Dict[str, str]] = None):
        c = self._counters.get(name)
        if c is None:
            c = self.counter(name, "")
        c.inc(value, labels)

    def histogram_observe(self, name: str, value: float, labels: Optional[Dict[str, str]] = None):
        h = self._histograms.get(name)
        if h is None:
            h = self.histogram(name, "")
        h.observe(value, labels)

    def gauge_set(self, name: str, value: float, labels: Optional[Dict[str, str]] = None):
        g = self._gauges.get(name)
        if g is None:
            g = self.gauge(name, "")
        g.set(value, labels)

    def gauge_inc(self, name: str, value: float = 1.0, labels: Optional[Dict[str, str]] = None):
        g = self._gauges.get(name)
        if g is None:
            g = self.gauge(name, "")
        g.inc(value, labels)

    def gauge_dec(self, name: str, value: float = 1.0, labels: Optional[Dict[str, str]] = None):
        g = self._gauges.get(name)
        if g is None:
            g = self.gauge(name, "")
        g.dec(value, labels)

    # -- High-level event recorders ------------------------------------------

    def record_agent_execution(self, agent_type: str, duration_seconds: float, success: bool, tools_used: int = 0):
        """Record an agent execution event."""
        status = "success" if success else "failure"
        labels = {"agent_type": agent_type, "status": status}
        self.counter_inc("agent_executions_total", labels=labels)
        self.histogram_observe("agent_duration_seconds", duration_seconds, labels={"agent_type": agent_type})
        if tools_used > 0:
            self.counter_inc("agent_tool_calls_total", value=tools_used, labels={"agent_type": agent_type})

    def record_llm_call(self, agent_type: str, duration_seconds: float, success: bool,
                        prompt_tokens: int = 0, completion_tokens: int = 0):
        """Record an LLM call event."""
        status = "success" if success else "failure"
        labels = {"agent_type": agent_type, "status": status}
        self.counter_inc("llm_calls_total", labels=labels)
        self.histogram_observe("llm_latency_seconds", duration_seconds, labels={"agent_type": agent_type})
        if prompt_tokens > 0:
            self.counter_inc("llm_tokens_total", value=prompt_tokens, labels={"agent_type": agent_type, "token_type": "prompt"})
        if completion_tokens > 0:
            self.counter_inc("llm_tokens_total", value=completion_tokens, labels={"agent_type": agent_type, "token_type": "completion"})

    def record_tool_execution(self, tool_name: str, duration_seconds: float, success: bool):
        """Record a tool execution event."""
        status = "success" if success else "failure"
        labels = {"tool": tool_name, "status": status}
        self.counter_inc("tool_executions_total", labels=labels)
        self.histogram_observe("tool_duration_seconds", duration_seconds, labels={"tool": tool_name})

    def record_mission_event(self, event: str):
        """Record a mission lifecycle event (created, started, completed, failed)."""
        self.counter_inc("mission_events_total", labels={"event": event})

    def record_debate(self, consensus: str, rounds: int):
        """Record a debate completion event."""
        self.counter_inc("debate_total", labels={"consensus": consensus})
        self.histogram_observe("debate_rounds", float(rounds))

    def record_critique(self, reanalysis: bool, score: float):
        """Record a critique event."""
        status = "reanalyzed" if reanalysis else "accepted"
        self.counter_inc("critique_events_total", labels={"outcome": status})
        self.histogram_observe("critique_scores", score)

    def record_token_usage(self, agent_id: str, prompt_tokens: int, completion_tokens: int, mission_id: Optional[str] = None):
        """Record token usage."""
        total = prompt_tokens + completion_tokens
        self.counter_inc("token_usage_total", value=total, labels={"agent_id": agent_id})
        self.counter_inc("token_usage_prompt_total", value=prompt_tokens, labels={"agent_id": agent_id})
        self.counter_inc("token_usage_completion_total", value=completion_tokens, labels={"agent_id": agent_id})

    # -- Pre-defined metrics -------------------------------------------------

    def _register_default_metrics(self):
        """Register all standard metrics for the RE lab."""
        # Agent metrics
        self.counter("agent_executions_total", "Total number of agent executions")
        self.histogram("agent_duration_seconds", "Agent execution duration in seconds")
        self.counter("agent_tool_calls_total", "Total tool calls made by agents")
        self.gauge("active_agents", "Number of currently active agents")

        # LLM metrics
        self.counter("llm_calls_total", "Total number of LLM API calls")
        self.histogram("llm_latency_seconds", "LLM API call latency in seconds")
        self.counter("llm_tokens_total", "Total tokens consumed by LLM calls")
        self.gauge("llm_tokens_inflight", "Tokens currently being processed")

        # Tool metrics
        self.counter("tool_executions_total", "Total tool executions")
        self.histogram("tool_duration_seconds", "Tool execution duration in seconds")

        # Mission metrics
        self.counter("mission_events_total", "Mission lifecycle events")
        self.gauge("active_missions", "Number of active missions")
        self.gauge("total_missions_created", "Total missions created")

        # Debate metrics
        self.counter("debate_total", "Total debates completed")
        self.histogram("debate_rounds", "Number of debate rounds")

        # Critique metrics
        self.counter("critique_events_total", "Total critique events")
        self.histogram("critique_scores", "Critique quality scores")

        # Token budget metrics
        self.counter("token_usage_total", "Total tokens consumed")
        self.counter("token_usage_prompt_total", "Total prompt tokens consumed")
        self.counter("token_usage_completion_total", "Total completion tokens consumed")
        self.counter("token_budget_blocks_total", "Total budget block events")

        # System metrics
        self.gauge("uptime_seconds", "Process uptime in seconds")
        self.counter("errors_total", "Total errors by category")

    # -- Prometheus exposition -----------------------------------------------

    def expose_prometheus(self) -> str:
        """Render all metrics in Prometheus text exposition format (OpenMetrics-compatible)."""
        lines: List[str] = []
        timestamp_ms = int(time.time() * 1000)

        # Info metric
        if self._info:
            info_parts = ", ".join(f'{k}="{self._escape_label_value(v)}"' for k, v in self._info.items())
            lines.append(f'# HELP {self.namespace}_info Information about the RE lab system.')
            lines.append(f'# TYPE {self.namespace}_info gauge')
            lines.append(f'{self.namespace}_info{{{info_parts}}} 1')

        # Uptime
        uptime = time.monotonic() - self._created_at
        lines.append(f'# HELP {self.namespace}_uptime_seconds Process uptime in seconds.')
        lines.append(f'# TYPE {self.namespace}_uptime_seconds gauge')
        lines.append(f'{self.namespace}_uptime_seconds {uptime:.3f}')

        # Counters
        for name, counter in self._counters.items():
            full_name = f"{self.namespace}_{name}"
            lines.append(f'# HELP {full_name} {counter.help_text}')
            lines.append(f'# TYPE {full_name} counter')
            for label_tuple, value in counter.get_all().items():
                label_str = self._format_labels(label_tuple)
                lines.append(f'{full_name}{label_str} {value:.0f}')

        # Histograms
        for name, histogram in self._histograms.items():
            full_name = f"{self.namespace}_{name}"
            lines.append(f'# HELP {full_name} {histogram.help_text}')
            lines.append(f'# TYPE {full_name} histogram')
            for label_tuple, data in histogram.get_all().items():
                label_str = self._format_labels(label_tuple)
                base_labels = dict(label_tuple) if label_tuple else {}
                cumulative = 0
                for bucket in histogram.buckets:
                    bucket_count = data["buckets"].get(bucket, 0)
                    cumulative += bucket_count
                    bucket_labels = {**base_labels, "le": self._format_bucket(bucket)}
                    bucket_label_str = self._format_labels(tuple(sorted(bucket_labels.items())))
                    lines.append(f'{full_name}_bucket{bucket_label_str} {cumulative}')
                # +Inf bucket
                inf_labels = {**base_labels, "le": "+Inf"}
                inf_label_str = self._format_labels(tuple(sorted(inf_labels.items())))
                lines.append(f'{full_name}_bucket{inf_label_str} {data["count"]}')
                lines.append(f'{full_name}_sum{label_str} {data["sum"]:.6f}')
                lines.append(f'{full_name}_count{label_str} {data["count"]}')

        # Gauges
        for name, gauge in self._gauges.items():
            full_name = f"{self.namespace}_{name}"
            lines.append(f'# HELP {full_name} {gauge.help_text}')
            lines.append(f'# TYPE {full_name} gauge')
            for label_tuple, value in gauge.get_all().items():
                label_str = self._format_labels(label_tuple)
                lines.append(f'{full_name}{label_str} {value:.4f}')

        return "\n".join(lines) + "\n"

    # -- JSON summary --------------------------------------------------------

    def expose_json(self) -> Dict[str, Any]:
        """Return all metrics as a structured dict (for API consumption)."""
        result: Dict[str, Any] = {
            "namespace": self.namespace,
            "uptime_seconds": round(time.monotonic() - self._created_at, 3),
            "timestamp": datetime.now().isoformat(),
            "counters": {},
            "histograms": {},
            "gauges": {},
        }

        for name, counter in self._counters.items():
            all_vals = counter.get_all()
            if all_vals:
                result["counters"][name] = {
                    self._format_label_key(k): v for k, v in all_vals.items()
                }

        for name, histogram in self._histograms.items():
            all_vals = histogram.get_all()
            if all_vals:
                result["histograms"][name] = {
                    self._format_label_key(k): {
                        "sum": v["sum"],
                        "count": v["count"],
                    } for k, v in all_vals.items()
                }

        for name, gauge in self._gauges.items():
            all_vals = gauge.get_all()
            if all_vals:
                result["gauges"][name] = {
                    self._format_label_key(k): v for k, v in all_vals.items()
                }

        return result

    # -- Reset ---------------------------------------------------------------

    def reset(self):
        """Reset all metrics to zero."""
        for counter in self._counters.values():
            with counter._lock:
                counter._values.clear()
        for histogram in self._histograms.values():
            with histogram._lock:
                histogram._sums.clear()
                histogram._counts.clear()
                histogram._bucket_counts.clear()
        for gauge in self._gauges.values():
            with gauge._lock:
                gauge._values.clear()

    # -- Helpers -------------------------------------------------------------

    @staticmethod
    def _format_labels(label_tuple: tuple) -> str:
        if not label_tuple:
            return ""
        parts = [f'{k}="{MetricsCollector._escape_label_value(v)}"' for k, v in label_tuple]
        return "{" + ", ".join(parts) + "}"

    @staticmethod
    def _format_label_key(label_tuple: tuple) -> str:
        if not label_tuple:
            return "{}"
        return json.dumps(dict(label_tuple))

    @staticmethod
    def _escape_label_value(value: str) -> str:
        return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")

    @staticmethod
    def _format_bucket(bucket: float) -> str:
        if bucket == float("inf"):
            return "+Inf"
        if bucket == int(bucket):
            return str(int(bucket))
        return str(bucket)


# ---------------------------------------------------------------------------
# Structured JSON logging
# ---------------------------------------------------------------------------

class StructuredJSONFormatter(logging.Formatter):
    """JSON log formatter for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[0]:
            log_entry["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
            }
        # Include any extra fields passed via logging calls
        for key in ("agent_type", "agent_id", "task_id", "mission_id", "tool", "duration", "status"):
            val = getattr(record, key, None)
            if val is not None:
                log_entry[key] = val
        return json.dumps(log_entry, default=str)


def setup_structured_logging(level: str = "INFO", json_format: bool = False):
    """Configure structured logging for the application.

    Args:
        level: Logging level string (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        json_format: If True, use JSON formatter; otherwise use standard formatter.
    """
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Remove existing handlers
    for handler in root.handlers[:]:
        root.removeHandler(handler)

    handler = logging.StreamHandler()
    if json_format:
        handler.setFormatter(StructuredJSONFormatter())
    else:
        handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        ))
    root.addHandler(handler)


# ---------------------------------------------------------------------------
# Module singleton
# ---------------------------------------------------------------------------

_collector: Optional[MetricsCollector] = None


def get_metrics() -> MetricsCollector:
    """Get or create the global MetricsCollector singleton."""
    global _collector
    if _collector is None:
        _collector = MetricsCollector()
    return _collector


def reset_metrics():
    """Reset the global MetricsCollector (for testing)."""
    global _collector
    if _collector is not None:
        _collector.reset()
    _collector = None
