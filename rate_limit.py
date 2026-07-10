from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass
from typing import Any

try:
    import redis
except ImportError:  # pragma: no cover
    redis = None


@dataclass(frozen=True)
class ApiIdentity:
    subject: str
    plan: str
    monthly_limit: int | None
    authenticated: bool


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    limit: int
    remaining: int
    reset_epoch: int
    scope: str
    plan: str


class ApiKeyRegistry:
    """Loads API keys from environment without exposing raw keys in logs or storage.

    Supported forms:
      TA14_API_KEY=<legacy single key>
      TA14_API_KEYS_JSON='[{"key":"...","name":"Partner","plan":"partner","monthly_limit":5000}]'
    """

    def __init__(self) -> None:
        self._entries: dict[str, dict[str, Any]] = {}
        self.reload()

    @staticmethod
    def _fingerprint(raw_key: str) -> str:
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    def reload(self) -> None:
        entries: dict[str, dict[str, Any]] = {}

        legacy = os.getenv("TA14_API_KEY", "").strip()
        if legacy:
            entries[self._fingerprint(legacy)] = {
                "name": "legacy",
                "plan": os.getenv("TA14_LEGACY_KEY_PLAN", "partner"),
                "monthly_limit": _optional_int(os.getenv("TA14_LEGACY_KEY_MONTHLY_LIMIT", "5000")),
                "active": True,
            }

        raw_json = os.getenv("TA14_API_KEYS_JSON", "").strip()
        if raw_json:
            parsed = json.loads(raw_json)
            if not isinstance(parsed, list):
                raise ValueError("TA14_API_KEYS_JSON must be a JSON array.")
            for item in parsed:
                if not isinstance(item, dict) or not item.get("key"):
                    raise ValueError("Each TA14_API_KEYS_JSON item must contain a key.")
                fingerprint = self._fingerprint(str(item["key"]))
                entries[fingerprint] = {
                    "name": str(item.get("name") or "api-client"),
                    "plan": str(item.get("plan") or "developer_free"),
                    "monthly_limit": _optional_int(item.get("monthly_limit", 100)),
                    "active": bool(item.get("active", True)),
                }

        self._entries = entries

    def resolve(self, raw_key: str | None) -> ApiIdentity | None:
        if not raw_key:
            return None
        fingerprint = self._fingerprint(raw_key.strip())
        entry = self._entries.get(fingerprint)
        if not entry or not entry.get("active"):
            return None
        name = str(entry["name"])
        return ApiIdentity(
            subject=f"key:{fingerprint[:24]}:{name}",
            plan=str(entry["plan"]),
            monthly_limit=entry["monthly_limit"],
            authenticated=True,
        )

    @property
    def has_keys(self) -> bool:
        return bool(self._entries)


class UsageStore:
    def increment(self, key: str, ttl_seconds: int) -> int:
        raise NotImplementedError


class MemoryUsageStore(UsageStore):
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._values: dict[str, tuple[int, float]] = {}

    def increment(self, key: str, ttl_seconds: int) -> int:
        now = time.time()
        with self._lock:
            count, expires_at = self._values.get(key, (0, now + ttl_seconds))
            if expires_at <= now:
                count, expires_at = 0, now + ttl_seconds
            count += 1
            self._values[key] = (count, expires_at)
            if len(self._values) > 10000:
                self._values = {
                    k: v for k, v in self._values.items() if v[1] > now
                }
            return count


class RedisUsageStore(UsageStore):
    def __init__(self, url: str) -> None:
        if redis is None:
            raise RuntimeError("redis package is not installed")
        self._client = redis.Redis.from_url(url, decode_responses=True)
        self._client.ping()

    def increment(self, key: str, ttl_seconds: int) -> int:
        pipe = self._client.pipeline()
        pipe.incr(key)
        pipe.expire(key, ttl_seconds, nx=True)
        count, _ = pipe.execute()
        return int(count)


def make_usage_store() -> UsageStore:
    url = (os.getenv("TA14_REDIS_URL") or os.getenv("REDIS_URL") or "").strip()
    if url:
        try:
            return RedisUsageStore(url)
        except Exception:
            # The API remains available, but production should configure a working Redis URL.
            pass
    return MemoryUsageStore()


class SandboxRateLimiter:
    def __init__(self, store: UsageStore) -> None:
        self.store = store
        self.anonymous_hourly = int(os.getenv("TA14_ANON_HOURLY_LIMIT", "5"))
        self.anonymous_daily = int(os.getenv("TA14_ANON_DAILY_LIMIT", "20"))
        self.default_key_monthly = int(os.getenv("TA14_KEY_MONTHLY_LIMIT", "100"))

    def check(self, identity: ApiIdentity, now: int | None = None) -> RateLimitResult:
        now = int(now or time.time())
        if identity.authenticated:
            limit = identity.monthly_limit
            if limit is None or limit <= 0:
                return RateLimitResult(True, 0, 0, _next_month_epoch(now), "month", identity.plan)
            return self._consume(
                identity=identity,
                bucket="month",
                bucket_id=time.strftime("%Y-%m", time.gmtime(now)),
                ttl_seconds=max(60, _next_month_epoch(now) - now),
                limit=limit or self.default_key_monthly,
                reset_epoch=_next_month_epoch(now),
            )

        hourly = self._consume(
            identity=identity,
            bucket="hour",
            bucket_id=time.strftime("%Y-%m-%dT%H", time.gmtime(now)),
            ttl_seconds=max(60, _next_hour_epoch(now) - now),
            limit=self.anonymous_hourly,
            reset_epoch=_next_hour_epoch(now),
        )
        if not hourly.allowed:
            return hourly

        daily = self._consume(
            identity=identity,
            bucket="day",
            bucket_id=time.strftime("%Y-%m-%d", time.gmtime(now)),
            ttl_seconds=max(60, _next_day_epoch(now) - now),
            limit=self.anonymous_daily,
            reset_epoch=_next_day_epoch(now),
        )
        if not daily.allowed:
            return daily

        # Return the tighter remaining allowance to the caller.
        if hourly.remaining <= daily.remaining:
            return hourly
        return daily

    def _consume(
        self,
        identity: ApiIdentity,
        bucket: str,
        bucket_id: str,
        ttl_seconds: int,
        limit: int,
        reset_epoch: int,
    ) -> RateLimitResult:
        key = f"ta14:usage:{identity.subject}:{bucket}:{bucket_id}"
        count = self.store.increment(key, ttl_seconds)
        remaining = max(0, limit - count)
        return RateLimitResult(
            allowed=count <= limit,
            limit=limit,
            remaining=remaining,
            reset_epoch=reset_epoch,
            scope=bucket,
            plan=identity.plan,
        )


def _optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    parsed = int(value)
    return None if parsed <= 0 else parsed


def _next_hour_epoch(now: int) -> int:
    return now - (now % 3600) + 3600


def _next_day_epoch(now: int) -> int:
    return now - (now % 86400) + 86400


def _next_month_epoch(now: int) -> int:
    current = time.gmtime(now)
    if current.tm_mon == 12:
        year, month = current.tm_year + 1, 1
    else:
        year, month = current.tm_year, current.tm_mon + 1
    return int(time.mktime((year, month, 1, 0, 0, 0, 0, 0, 0)) - time.timezone)
