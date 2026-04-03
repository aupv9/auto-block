import hashlib


class KeyBuilder:
    """Mirrors the TypeScript KeyBuilder — same key schema across all SDKs."""

    def __init__(self, tenant: str, prefix: str = "ab") -> None:
        self._tenant = tenant
        self._prefix = prefix

    def _base(self, *parts: str) -> str:
        return ":".join([self._prefix, self._tenant, *parts])

    def endpoint_hash(self, path: str) -> str:
        return hashlib.sha256(path.encode()).hexdigest()[:8]

    # Rate limit counters
    def sliding_window(self, dimension: str, value: str, ep_hash: str = "") -> str:
        if ep_hash:
            return self._base("sw", dimension, value, ep_hash)
        return self._base("sw", dimension, value)

    def token_bucket(self, dimension: str, value: str, ep_hash: str = "") -> str:
        if ep_hash:
            return self._base("tb", dimension, value, ep_hash)
        return self._base("tb", dimension, value)

    # Penalty tracking
    def penalty_score(self, dimension: str, value: str) -> str:
        return self._base("penalty", "score", dimension, value)

    def penalty_state(self, dimension: str, value: str) -> str:
        return self._base("penalty", "state", dimension, value)

    def penalty_history(self, dimension: str, value: str) -> str:
        return self._base("penalty", "history", dimension, value)

    def penalty_decay_ts(self, dimension: str, value: str) -> str:
        return self._base("penalty", "decay", dimension, value)

    def penalty_score_pattern(self, dimension: str) -> str:
        return self._base("penalty", "score", dimension, "*")

    # Allow/deny lists
    def blacklist(self, typ: str) -> str:
        return self._base("blacklist", typ)

    def blacklist_cidr(self) -> str:
        return self._base("blacklist", "cidr")

    def whitelist(self, typ: str) -> str:
        return self._base("whitelist", typ)

    def whitelist_cidr(self) -> str:
        return self._base("whitelist", "cidr")

    # Dynamic rules hash (managed by engine API, hot-reloaded by SDKs)
    def rules(self) -> str:
        return self._base("rules", "endpoint")

    def rules_changed(self) -> str:
        return self._base("rules", "changed")

    # Audit stream
    def audit_stream(self) -> str:
        return self._base("audit", "stream")
