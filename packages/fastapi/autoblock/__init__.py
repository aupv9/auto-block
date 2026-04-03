"""AutoBlock — adaptive rate limiting & auto-remediation for FastAPI / Starlette."""

from .decay_worker import DecayWorker
from .middleware import AutoBlockMiddleware
from .rate_limiter import RateLimiter
from .rules_watcher import RulesWatcher
from .types import (
    AutoBlockConfig,
    LimitsConfig,
    MiddlewareConfig,
    PenaltyConfig,
    PenaltyStepConfig,
    PenaltyThresholds,
    RateLimitDecision,
    RequestContext,
    RuleConfig,
)

__all__ = [
    "DecayWorker",
    "AutoBlockMiddleware",
    "RateLimiter",
    "RulesWatcher",
    "AutoBlockConfig",
    "RuleConfig",
    "LimitsConfig",
    "PenaltyConfig",
    "PenaltyStepConfig",
    "PenaltyThresholds",
    "MiddlewareConfig",
    "RateLimitDecision",
    "RequestContext",
]
