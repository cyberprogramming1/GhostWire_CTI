"""
tests/test_caching.py
---------------------
"""
import json
import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
sys.path.insert(0, str(Path(__file__).parent.parent))

import backend.caching as caching


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def tmp_cache(tmp_path, monkeypatch):
    """Redirect all cache I/O to a temp directory for isolation."""
    monkeypatch.setattr(caching, "_get_cache_dir", lambda: tmp_path / "cache")
    monkeypatch.setattr(caching, "_engine_cache_dir", lambda e: (
        tmp_path / "cache" / e
    ).mkdir(parents=True, exist_ok=True) or (tmp_path / "cache" / e))
    yield tmp_path


# ── CacheManager tests ────────────────────────────────────────────────────────

class TestCacheManager:

    def test_miss_returns_none(self, tmp_cache):
        cm = caching.CacheManager("test_engine", ttl_hours=1)
        assert cm.get("http://example.com") is None

    def test_set_and_get(self, tmp_cache):
        cm = caching.CacheManager("test_engine", ttl_hours=1)
        data = {"score": 42, "flags": ["test_flag"]}
        cm.set("http://example.com", data)
        result = cm.get("http://example.com")
        assert result == data

    def test_different_targets_different_keys(self, tmp_cache):
        cm = caching.CacheManager("test_engine", ttl_hours=1)
        cm.set("http://evil.com", {"score": 90})
        cm.set("http://clean.com", {"score": 5})
        assert cm.get("http://evil.com")["score"] == 90
        assert cm.get("http://clean.com")["score"] == 5

    def test_ttl_expiry(self, tmp_cache):
        cm = caching.CacheManager("test_engine", ttl_hours=1)
        cm.set("http://example.com", {"score": 50})

        # Manually expire by writing old timestamp
        key = caching._make_cache_key("test_engine", "http://example.com")
        cache_dir = caching._get_cache_dir() / "test_engine"
        cache_file = cache_dir / f"{key}.json"

        envelope = json.loads(cache_file.read_text())
        envelope["cached_at_unix"] = time.time() - 7200  # 2 hours ago
        cache_file.write_text(json.dumps(envelope))

        # Should return None — expired
        assert cm.get("http://example.com") is None
        # File should be deleted
        assert not cache_file.exists()

    def test_corrupted_file_returns_none(self, tmp_cache):
        cm = caching.CacheManager("test_engine", ttl_hours=1)
        cache_dir = caching._get_cache_dir() / "test_engine"
        cache_dir.mkdir(parents=True, exist_ok=True)

        key = caching._make_cache_key("test_engine", "http://evil.com")
        bad_file = cache_dir / f"{key}.json"
        bad_file.write_text("not valid json {{{{")

        assert cm.get("http://evil.com") is None

    def test_invalidate(self, tmp_cache):
        cm = caching.CacheManager("test_engine", ttl_hours=1)
        cm.set("http://example.com", {"score": 70})
        assert cm.get("http://example.com") is not None
        cm.invalidate("http://example.com")
        assert cm.get("http://example.com") is None

    def test_clear_all(self, tmp_cache):
        cm = caching.CacheManager("test_engine", ttl_hours=1)
        for i in range(5):
            cm.set(f"http://target{i}.com", {"score": i})
        deleted = cm.clear_all()
        assert deleted == 5
        for i in range(5):
            assert cm.get(f"http://target{i}.com") is None

    def test_stats(self, tmp_cache):
        cm = caching.CacheManager("test_engine", ttl_hours=24)
        cm.set("http://a.com", {"data": "x"})
        cm.set("http://b.com", {"data": "y"})
        s = cm.stats()
        assert s["total"] == 2
        assert s["active"] == 2
        assert s["expired"] == 0
        assert s["engine"] == "test_engine"

    def test_oversized_entry_not_cached(self, tmp_cache, monkeypatch):
        monkeypatch.setattr(caching, "_MAX_VALUE_BYTES", 10)
        cm = caching.CacheManager("test_engine", ttl_hours=1)
        result = cm.set("http://example.com", {"large": "x" * 1000})
        assert result is False
        assert cm.get("http://example.com") is None


# ── Key generation tests ──────────────────────────────────────────────────────

class TestKeyGeneration:

    def test_same_target_same_key(self):
        k1 = caching._make_cache_key("vt", "http://evil.com")
        k2 = caching._make_cache_key("vt", "http://evil.com")
        assert k1 == k2

    def test_different_engines_different_keys(self):
        k1 = caching._make_cache_key("virustotal", "http://evil.com")
        k2 = caching._make_cache_key("urlhaus",    "http://evil.com")
        assert k1 != k2

    def test_key_is_hex_64_chars(self):
        k = caching._make_cache_key("vt", "http://evil.com")
        assert len(k) == 64
        assert all(c in "0123456789abcdef" for c in k)

    def test_normalisation_strips_trailing_slash(self):
        k1 = caching._make_cache_key("vt", "http://evil.com/")
        k2 = caching._make_cache_key("vt", "http://evil.com")
        assert k1 == k2

    def test_normalisation_lowercases(self):
        k1 = caching._make_cache_key("vt", "HTTP://EVIL.COM")
        k2 = caching._make_cache_key("vt", "http://evil.com")
        assert k1 == k2


# ── Defang tests ──────────────────────────────────────────────────────────────

class TestDefang:

    def test_http_defanged(self):
        assert "hxxp://" in caching._defang("http://evil.com")

    def test_https_defanged(self):
        assert "hxxps://" in caching._defang("https://evil.com")

    def test_no_live_urls_in_metadata(self, tmp_cache):
        cm = caching.CacheManager("test_engine", ttl_hours=1)
        cm.set("http://evil.com/payload.exe", {"score": 90})
        key = caching._make_cache_key("test_engine", "http://evil.com/payload.exe")
        cache_file = (caching._get_cache_dir() / "test_engine" / f"{key}.json")
        content = cache_file.read_text()
        # Live URL must NOT appear in cache file
        assert "http://evil.com" not in content
        # Defanged version should be there
        assert "hxxp://" in content


# ── Decorator tests ───────────────────────────────────────────────────────────

class TestCacheResultDecorator:

    def test_decorator_caches_result(self, tmp_cache):
        call_count = 0

        @caching.cache_result(engine="test_dec", ttl_hours=1)
        def fake_api(url: str) -> dict:
            nonlocal call_count
            call_count += 1
            return {"data": "from_api", "url": url}

        r1 = fake_api("http://example.com")
        r2 = fake_api("http://example.com")

        assert call_count == 1          # API called only once
        assert r1["data"] == "from_api"
        assert r2["data"] == "from_api"

    def test_decorator_does_not_cache_errors(self, tmp_cache):
        call_count = 0

        @caching.cache_result(engine="test_err", ttl_hours=1)
        def failing_api(url: str) -> dict:
            nonlocal call_count
            call_count += 1
            return {"error": "API timeout"}

        failing_api("http://example.com")
        failing_api("http://example.com")
        assert call_count == 2   # Error result → always re-tries API

    def test_decorator_different_targets_called_separately(self, tmp_cache):
        call_count = 0

        @caching.cache_result(engine="test_multi", ttl_hours=1)
        def api(url: str) -> dict:
            nonlocal call_count
            call_count += 1
            return {"url": url}

        api("http://a.com")
        api("http://b.com")
        api("http://a.com")  # cache hit

        assert call_count == 2

    def test_decorator_exposes_cache_manager(self, tmp_cache):
        @caching.cache_result(engine="test_attr", ttl_hours=1)
        def api(url: str) -> dict:
            return {"score": 1}

        # Should have .cache attribute for manual control
        assert hasattr(api, "cache")
        assert isinstance(api.cache, caching.CacheManager)

    def test_decorator_key_kwarg(self, tmp_cache):
        call_count = 0

        @caching.cache_result(engine="test_kwarg", key_kwarg="ip")
        def lookup(*, ip: str, api_key: str) -> dict:
            nonlocal call_count
            call_count += 1
            return {"ip": ip}

        lookup(ip="1.2.3.4", api_key="secret")
        lookup(ip="1.2.3.4", api_key="secret")
        assert call_count == 1


# ── Thread safety tests ───────────────────────────────────────────────────────

class TestThreadSafety:

    def test_concurrent_writes_no_corruption(self, tmp_cache):
        """Multiple threads writing to same key should not corrupt data."""
        cm = caching.CacheManager("thread_test", ttl_hours=1)
        errors = []

        def write_and_read(i):
            try:
                cm.set("http://shared.com", {"thread": i, "data": "x" * 100})
                result = cm.get("http://shared.com")
                assert result is not None
                assert "thread" in result
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=write_and_read, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0, f"Thread errors: {errors}"

    def test_concurrent_reads_consistent(self, tmp_cache):
        """Multiple threads reading same cached value get consistent results."""
        cm = caching.CacheManager("thread_read", ttl_hours=1)
        cm.set("http://read.com", {"value": 42})

        results = []

        def read():
            r = cm.get("http://read.com")
            if r:
                results.append(r["value"])

        threads = [threading.Thread(target=read) for _ in range(30)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert all(v == 42 for v in results)
        assert len(results) == 30


# ── Global utility tests ──────────────────────────────────────────────────────

class TestGlobalUtils:

    def test_expire_old_entries(self, tmp_cache):
        cm = caching.CacheManager("expire_test", ttl_hours=1)
        cm.set("http://old.com", {"score": 1})
        cm.set("http://new.com", {"score": 2})

        # Age one entry manually
        key_old = caching._make_cache_key("expire_test", "http://old.com")
        old_file = caching._get_cache_dir() / "expire_test" / f"{key_old}.json"
        env = json.loads(old_file.read_text())
        env["cached_at_unix"] = time.time() - 7200
        old_file.write_text(json.dumps(env))

        removed = caching.expire_old_entries()
        assert removed >= 1
        assert cm.get("http://old.com") is None
        assert cm.get("http://new.com") is not None

    def test_get_all_cache_stats_empty(self, tmp_cache):
        stats = caching.get_all_cache_stats()
        assert isinstance(stats, list)

    def test_clear_all_caches(self, tmp_cache):
        for engine in ["vt", "urlhaus", "otx"]:
            cm = caching.CacheManager(engine, ttl_hours=1)
            cm.set("http://test.com", {"data": engine})

        results = caching.clear_all_caches()
        assert sum(results.values()) == 3
