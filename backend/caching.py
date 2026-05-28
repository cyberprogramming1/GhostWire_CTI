"""
backend/caching.py
------------------
"""

from __future__ import annotations

import functools
import hashlib
import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

_DEFAULT_CACHE_DIR = Path.home() / ".ghostwire" / "cache"
_DEFAULT_TTL_HOURS = 24
_MAX_VALUE_BYTES   = 5_000_000   # 5MB per cache entry — prevents runaway storage

# Engine-specific TTL overrides (hours)
# Rationale: threat intel changes at different rates
_ENGINE_TTL: dict[str, int] = {
    "virustotal":     24,   # VT updates daily
    "urlhaus":        12,   # abuse.ch updates more frequently
    "abuseipdb":      24,
    "greynoise":       6,   # GreyNoise scanner data changes hourly
    "otx":            24,
    "shodan":         48,   # Shodan banners change slowly
    "whois":          72,   # WHOIS rarely changes
    "passive_dns":    24,
    "hybrid_analysis": 48,
    "ssl":            12,   # Certs can change
}

# ── Thread safety ─────────────────────────────────────────────────────────────
# One lock per cache file path — prevents concurrent writes to same file.
# Dict itself is protected by a module-level lock.

_file_locks: dict[str, threading.Lock] = {}
_locks_lock  = threading.Lock()


def _get_file_lock(path: str) -> threading.Lock:
    """Return (creating if needed) a Lock for the given cache file path."""
    with _locks_lock:
        if path not in _file_locks:
            _file_locks[path] = threading.Lock()
        return _file_locks[path]


# ── Key generation ─────────────────────────────────────────────────────────────

def _make_cache_key(engine: str, target: str) -> str:
    
    normalized = target.strip().lower().rstrip("/")
    raw = f"{engine}:{normalized}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _defang(target: str) -> str:
   
    try:
        # uses canonical defang_url
        from config import defang_url as _dfu
        return _dfu(str(target))
    except Exception:
        # Fallback if circular import (shouldn't happen, config has no backend deps)
        t = str(target).strip()
        t = t.replace("https://", "hxxps://").replace("http://", "hxxp://").replace("ftp://", "fxp://")
        return t


# ── Cache directory ────────────────────────────────────────────────────────────

def _get_cache_dir() -> Path:
  
    log_path_env = os.environ.get("GHOSTWIRE_LOG_PATH", "")
    if log_path_env:
        # Put cache next to log file: /custom/path/audit.jsonl → /custom/path/cache/
        return Path(log_path_env).parent / "cache"
    return _DEFAULT_CACHE_DIR


def _engine_cache_dir(engine: str) -> Path:
    """Per-engine subdirectory: ~/.ghostwire/cache/virustotal/"""
    d = _get_cache_dir() / engine
    d.mkdir(parents=True, exist_ok=True)
    return d


# ── Audit log integration ──────────────────────────────────────────────────────

def _audit_cache_event(
    engine: str,
    target: str,
    source: str,   # "cache" or "api"
    hit:    bool,
    ttl_remaining_hours: Optional[float] = None,
) -> None:
    
    try:
        log_path_env = os.environ.get("GHOSTWIRE_LOG_PATH", "")
        if log_path_env:
            log_path = Path(log_path_env)
        else:
            log_path = Path.home() / ".ghostwire" / "audit.jsonl"

        log_path.parent.mkdir(parents=True, exist_ok=True)

        entry = {
            "ts":         datetime.now(tz=timezone.utc).isoformat(),
            "event":      "cache_hit" if hit else "cache_miss",
            "engine":     engine,
            "target":     _defang(target)[:80],
            "source":     source,           # "cache" | "api"
            "ttl_left_h": round(ttl_remaining_hours, 1) if ttl_remaining_hours else None,
        }
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass   # Never crash on audit failure


# ── Core CacheManager ─────────────────────────────────────────────────────────

class CacheManager:
   

    def __init__(self, engine: str, ttl_hours: Optional[int] = None):
        self.engine    = engine.lower().replace(" ", "_")
        self.ttl_hours = ttl_hours or _ENGINE_TTL.get(self.engine, _DEFAULT_TTL_HOURS)
        self._dir      = _engine_cache_dir(self.engine)

    def _cache_path(self, target: str) -> Path:
        key = _make_cache_key(self.engine, target)
        return self._dir / f"{key}.json"

    def get(self, target: str) -> Optional[Any]:
       
        path = self._cache_path(target)
        lock = _get_file_lock(str(path))

        with lock:
            if not path.exists():
                _audit_cache_event(self.engine, target, "api", hit=False)
                return None

            try:
                raw = path.read_text(encoding="utf-8")
                envelope = json.loads(raw)
            except Exception as e:
                logger.warning("Cache read error [%s] %s: %s", self.engine, path.name[:16], e)
                _audit_cache_event(self.engine, target, "api", hit=False)
                return None

            # TTL check
            cached_at = envelope.get("cached_at_unix", 0)
            ttl_secs  = envelope.get("ttl_secs", self.ttl_hours * 3600)
            age_secs  = time.time() - cached_at
            remaining = ttl_secs - age_secs

            if remaining <= 0:
                logger.debug("Cache EXPIRED [%s] age=%.1fh", self.engine, age_secs / 3600)
                try:
                    path.unlink(missing_ok=True)
                except Exception:
                    pass
                _audit_cache_event(self.engine, target, "api", hit=False)
                return None

            logger.debug("Cache HIT [%s] ttl_left=%.1fh", self.engine, remaining / 3600)
            _audit_cache_event(self.engine, target, "cache", hit=True,
                               ttl_remaining_hours=remaining / 3600)
            return envelope.get("data")

    def set(self, target: str, data: Any) -> bool:
       
        path = self._cache_path(target)
        lock = _get_file_lock(str(path))

        envelope = {
            "engine":          self.engine,
            "target_defanged": _defang(target),    # No live URLs in cache metadata
            "cached_at_unix":  time.time(),
            "cached_at_iso":   datetime.now(tz=timezone.utc).isoformat(),
            "ttl_secs":        self.ttl_hours * 3600,
            "ttl_hours":       self.ttl_hours,
            "data":            data,
        }

        try:
            serialized = json.dumps(envelope, default=str, ensure_ascii=False)
        except Exception as e:
            logger.warning("Cache serialize error [%s]: %s", self.engine, e)
            return False

        if len(serialized.encode("utf-8")) > _MAX_VALUE_BYTES:
            logger.warning("Cache entry too large [%s] %d bytes — skipping",
                           self.engine, len(serialized))
            return False

        with lock:
            try:
                path.write_text(serialized, encoding="utf-8")
                logger.debug("Cache SET [%s] ttl=%dh", self.engine, self.ttl_hours)
                return True
            except Exception as e:
                logger.warning("Cache write error [%s]: %s", self.engine, e)
                return False

    def invalidate(self, target: str) -> bool:
        """Force-expire a specific cache entry."""
        path = self._cache_path(target)
        lock = _get_file_lock(str(path))
        with lock:
            try:
                path.unlink(missing_ok=True)
                return True
            except Exception:
                return False

    def clear_all(self) -> int:
        """Delete all cache entries for this engine. Returns count deleted."""
        deleted = 0
        try:
            for f in self._dir.glob("*.json"):
                try:
                    f.unlink()
                    deleted += 1
                except Exception:
                    pass
        except Exception:
            pass
        logger.info("Cache cleared [%s]: %d entries removed", self.engine, deleted)
        return deleted

    def stats(self) -> dict:
        """Return cache statistics for this engine."""
        total = expired = size_bytes = 0
        now = time.time()
        try:
            for f in self._dir.glob("*.json"):
                total += 1
                size_bytes += f.stat().st_size
                try:
                    env = json.loads(f.read_text(encoding="utf-8"))
                    age = now - env.get("cached_at_unix", 0)
                    if age > env.get("ttl_secs", _DEFAULT_TTL_HOURS * 3600):
                        expired += 1
                except Exception:
                    expired += 1
        except Exception:
            pass
        return {
            "engine":       self.engine,
            "total":        total,
            "expired":      expired,
            "active":       total - expired,
            "size_mb":      round(size_bytes / 1_000_000, 2),
            "ttl_hours":    self.ttl_hours,
            "cache_dir":    str(self._dir),
        }


# ── @cache_result decorator ────────────────────────────────────────────────────

def cache_result(
    engine:    str,
    ttl_hours: Optional[int] = None,
    key_arg:   int           = 0,     # positional arg index to use as cache key
    key_kwarg: Optional[str] = None,  # OR kwarg name to use as cache key
) -> Callable:
   
    cm = CacheManager(engine, ttl_hours=ttl_hours)

    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # ── Extract cache key from args/kwargs ────────────────────
            try:
                if key_kwarg and key_kwarg in kwargs:
                    cache_target = str(kwargs[key_kwarg])
                elif args and key_arg < len(args):
                    cache_target = str(args[key_arg])
                else:
                    # Cannot determine key → skip cache, call directly
                    logger.debug("cache_result: cannot extract key for %s — bypassing", fn.__name__)
                    return fn(*args, **kwargs)
            except Exception:
                return fn(*args, **kwargs)

            # ── Try cache ─────────────────────────────────────────────
            cached = cm.get(cache_target)
            if cached is not None:
                return cached

            # ── Cache miss → call real function ───────────────────────
            result = fn(*args, **kwargs)

            # ── Store result ──────────────────────────────────────────
            # Only cache non-error results to avoid cementing failures
            if result is not None:
                _should_cache = True
                # Don't cache dicts with top-level "error" key
                if isinstance(result, dict) and "error" in result:
                    _should_cache = False
                    logger.debug("cache_result: skipping cache for error result [%s]", engine)

                if _should_cache:
                    # Dataclass → dict conversion
                    data_to_store = result
                    if hasattr(result, "__dataclass_fields__"):
                        import dataclasses
                        data_to_store = dataclasses.asdict(result)
                    cm.set(cache_target, data_to_store)

            return result

        # Attach cache manager for manual control: fn.cache.invalidate(target)
        wrapper.cache = cm   # type: ignore[attr-defined]
        return wrapper

    return decorator


# ── Global cache utilities ────────────────────────────────────────────────────

def clear_all_caches() -> dict[str, int]:
    
    results: dict[str, int] = {}
    cache_root = _get_cache_dir()
    if not cache_root.exists():
        return results
    for engine_dir in cache_root.iterdir():
        if engine_dir.is_dir():
            cm = CacheManager(engine_dir.name)
            results[engine_dir.name] = cm.clear_all()
    return results


def get_all_cache_stats() -> list[dict]:
   
    stats: list[dict] = []
    cache_root = _get_cache_dir()
    if not cache_root.exists():
        return stats
    for engine_dir in sorted(cache_root.iterdir()):
        if engine_dir.is_dir():
            cm = CacheManager(engine_dir.name)
            stats.append(cm.stats())
    return stats


def expire_old_entries() -> int:
   
    total = 0
    cache_root = _get_cache_dir()
    if not cache_root.exists():
        return 0
    now = time.time()
    for f in cache_root.rglob("*.json"):
        try:
            env = json.loads(f.read_text(encoding="utf-8"))
            age = now - env.get("cached_at_unix", 0)
            ttl = env.get("ttl_secs", _DEFAULT_TTL_HOURS * 3600)
            if age > ttl:
                f.unlink(missing_ok=True)
                total += 1
        except Exception:
            # Corrupted file → delete it
            try:
                f.unlink(missing_ok=True)
                total += 1
            except Exception:
                pass
    if total:
        logger.info("Cache cleanup: %d expired entries removed", total)
    return total
