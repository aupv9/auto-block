from __future__ import annotations
from dataclasses import dataclass, field
from typing import Literal

PenaltyState = Literal["CLEAN", "WARN", "SLOW", "BLOCK", "BLACKLIST"]
Algorithm = Literal["sliding_window", "token_bucket", "hybrid"]
Dimension = Literal["ip", "user_id", "endpoint"]


@dataclass(frozen=True)
class PenaltyThresholds:
    warn: int = 3
    slow: int = 6
    block: int = 10
    blacklist: int = 15


@dataclass(frozen=True)
class LimitsConfig:
    requests: int
    window_seconds: int
    burst: int = 0


@dataclass(frozen=True)
class PenaltyStepConfig:
    score_threshold: int
    delay_ms: int = 0
    duration_seconds: int = 300
    notify: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class PenaltyConfig:
    warn: PenaltyStepConfig | None = None
    slow: PenaltyStepConfig | None = None
    block: PenaltyStepConfig | None = None
    blacklist: PenaltyStepConfig | None = None
    thresholds: PenaltyThresholds = field(default_factory=PenaltyThresholds)
    ttl_seconds: int = 86400


@dataclass(frozen=True)
class RuleConfig:
    id: str
    endpoint_pattern: str
    dimensions: list[Dimension]
    limits: LimitsConfig
    penalties: PenaltyConfig
    enabled: bool = True
    algorithm: Algorithm = "hybrid"
    methods: list[str] = field(default_factory=list)
    description: str = ""


@dataclass(frozen=True)
class MiddlewareConfig:
    fail_open: bool = True
    skip_paths: list[str] = field(default_factory=lambda: ["/health", "/ready", "/favicon.ico"])
    trust_proxy: bool = True
    trusted_proxy_depth: int = 1
    ip_header: str = "x-forwarded-for"
    user_id_extractor: Literal["jwt_sub", "header", "none"] = "none"
    user_id_header: str = ""


@dataclass(frozen=True)
class AutoBlockConfig:
    tenant: str
    rules: list[RuleConfig]
    middleware: MiddlewareConfig = field(default_factory=MiddlewareConfig)


@dataclass
class RequestContext:
    ip: str
    endpoint: str
    method: str
    user_id: str | None = None
    timestamp: int | None = None


@dataclass
class RateLimitDecision:
    allowed: bool
    state: PenaltyState
    score: int
    limit: float
    remaining: float
    retry_after_seconds: int | None = None
    delay_ms: int | None = None
    status_code: int | None = None
