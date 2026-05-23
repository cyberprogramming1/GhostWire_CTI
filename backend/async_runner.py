"""
backend/async_runner.py
------------------------
GhostWire CTI v6 — Parallel engine runner.

v6.1 additions:
  - urlhaus_engine integrated for URL, Hash, and IP pipelines
  - URLhausResult added to run_engines_parallel return dict (key: "urlhaus")
  - run_hash_engines_parallel: parallel runner for pipeline_hash
  - run_ip_engines_parallel  : parallel runner for pipeline_ip

Graceful degradation:
  URLHAUS_API_KEY is optional. If absent or if abuse.ch is unreachable,
  the urlhaus engine returns an empty URLhausResult and logs a warning.
  The pipeline continues with all other engines — analysis never stops.
"""

from __future__ import annotations

import concurrent.futures
import logging
from typing import Callable, Any

logger = logging.getLogger(__name__)


# ── URL / Domain Pipeline Runner ──────────────────────────────────────────────

def run_engines_parallel(
    target:        str,
    *,
    vt_key:        str  = "",
    abuse_key:     str  = "",
    shodan_key:    str  = "",
    ollama_model:  str  = "phi3:mini",
    run_ai:        bool = True,
    run_sandbox:   bool = True,
    run_ssl:       bool = True,
    run_pdns:      bool = True,
    run_shodan:    bool = True,
    run_greynoise: bool = True,
    run_urlhaus:   bool = True,   # NEW — URLhaus URL + host lookup
    run_otx:       bool = True,   # v7  — AlienVault OTX threat intel
    ip_address:    str | None = None,
) -> dict[str, Any]:
    """
    Run all CTI engines concurrently on `target` (URL / domain / IP).

    Returns a dict with keys:
      heuristics, whois, ai, reputation, deception,
      sandbox, ssl, pdns, shodan, greynoise, urlhaus (NEW)

    Each value is the engine's result dataclass or a typed error stub.
    This function never raises — all failures are caught per-engine.
    """
    from backend.heuristics      import analyze_url,           HeuristicsResult
    from backend.whois_check     import analyze_domain,        WhoisResult
    from backend.ai_analyzer     import analyze_text,          AIAnalysisResult
    from backend.reputation      import analyze_reputation,    ReputationResult
    from backend.deception       import analyze_deception,     DeceptionResult
    from backend.sandbox         import analyze_sandbox,       SandboxResult
    from backend.ssl_engine      import analyze_ssl,           SSLResult
    from backend.passive_dns     import analyze_passive_dns,   PassiveDNSResult
    from backend.external_intel  import analyze_shodan,        ShodanResult
    from backend.external_intel  import analyze_greynoise,     GreyNoiseResult
    from backend.urlhaus_engine  import query_url_host,        URLhausResult  # NEW
    from backend.otx_engine       import query_domain, query_url, OTXResult      # v7 OTX

    # ── Typed error stub factories ────────────────────────────────────
    def _err_ai(msg: str) -> AIAnalysisResult:
        r = AIAnalysisResult(); r.flags.append(msg); return r

    def _err_sandbox(msg: str) -> SandboxResult:
        r = SandboxResult(); r.errors.append(msg); return r

    def _err_ssl(msg: str) -> SSLResult:
        r = SSLResult(); r.errors.append(msg); return r

    def _err_pdns(msg: str) -> PassiveDNSResult:
        r = PassiveDNSResult(); r.errors.append(msg); return r

    def _err_shodan(msg: str) -> ShodanResult:
        r = ShodanResult(); r.errors.append(msg); r.available = False; return r

    def _err_greynoise(msg: str) -> GreyNoiseResult:
        r = GreyNoiseResult(); r.errors.append(msg); r.available = False; return r

    def _err_urlhaus(msg: str) -> URLhausResult:
        # Graceful degradation — engine skip, analysis continues
        r = URLhausResult(); r.errors.append(msg); return r

    def _err_otx(msg: str) -> OTXResult:
        r = OTXResult(); r.errors.append(msg); return r

    # ── Safe wrapper — catches all exceptions, never crashes pipeline ──
    def _safe(fn: Callable, err_factory: Callable, *args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except Exception as exc:
            msg = f"{fn.__name__} error: {str(exc)[:120]}"
            logger.warning("Engine failure: %s", msg)
            return err_factory(msg)

    # ── Group A: fast local engines (no network) — run sequentially ───
    h_res   = _safe(analyze_url,       lambda m: HeuristicsResult(), target)
    w_res   = _safe(analyze_domain,    lambda m: WhoisResult(),      target)
    dec_res = _safe(analyze_deception, lambda m: DeceptionResult(),  target)

    # ── Group B: network-bound engines — run in parallel ──────────────
    tasks: list[tuple[str, Callable, tuple, dict, Callable]] = []

    if run_ai:
        tasks.append(("ai", analyze_text, (target,), {"model": ollama_model}, _err_ai))
    else:
        logger.debug("AI NLP disabled — skipping")

    tasks.append((
        "reputation", analyze_reputation, (target,),
        {"vt_api_key": vt_key, "abuse_api_key": abuse_key},
        lambda m: ReputationResult(),
    ))

    if run_sandbox:
        tasks.append(("sandbox", analyze_sandbox, (target,), {}, _err_sandbox))
    else:
        logger.debug("Sandbox disabled — skipping")

    _da = getattr(w_res, "domain_age_days", None)
    if run_ssl:
        tasks.append(("ssl", analyze_ssl, (target,), {"domain_age_days": _da}, _err_ssl))
    else:
        logger.debug("SSL check disabled — skipping")

    if run_pdns:
        tasks.append(("pdns", analyze_passive_dns, (target,), {}, _err_pdns))
    else:
        logger.debug("Passive DNS disabled — skipping")

    if run_shodan:
        _st = ip_address or target
        tasks.append(("shodan", analyze_shodan, (_st,), {"api_key": shodan_key}, _err_shodan))
    else:
        logger.debug("Shodan disabled — skipping")

    if run_greynoise and ip_address:
        tasks.append(("greynoise", analyze_greynoise, (ip_address,), {}, _err_greynoise))
    else:
        logger.debug("GreyNoise disabled or no IP — skipping")

    # NEW: URLhaus — URL + host parallel lookup
    if run_urlhaus:
        tasks.append(("urlhaus", query_url_host, (target,), {}, _err_urlhaus))
    else:
        logger.debug("URLhaus disabled — skipping (set run_urlhaus=True to enable)")

    # v7: OTX — domain + URL parallel lookup
    # vt_malicious passed at task-level; we use 0 here and re-score in pipeline
    # after reputation engine completes. OTX is context engine — gracefully skipped if no key.
    if run_otx:
        tasks.append(("otx", query_domain, (target,), {}, _err_otx))
    else:
        logger.debug("OTX disabled — skipping")

    # ── Execute parallel group ─────────────────────────────────────────
    network_results: dict[str, Any] = {}

    if tasks:
        logger.info("Launching %d engines in parallel for target: %s", len(tasks), target[:60])
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(len(tasks), 8),
            thread_name_prefix="ghostwire_engine",
        ) as pool:
            futures = {
                name: pool.submit(_safe, fn, err_factory, *args, **kwargs)
                for name, fn, args, kwargs, err_factory in tasks
            }
            for name, future in futures.items():
                try:
                    network_results[name] = future.result(timeout=90)
                    logger.debug("Engine '%s' completed", name)
                except concurrent.futures.TimeoutError:
                    err_map: dict[str, Callable] = {
                        "ai":         _err_ai,
                        "reputation": lambda m: ReputationResult(),
                        "sandbox":    _err_sandbox,
                        "ssl":        _err_ssl,
                        "pdns":       _err_pdns,
                        "shodan":     _err_shodan,
                        "greynoise":  _err_greynoise,
                        "urlhaus":    _err_urlhaus,   # NEW
                        "otx":        _err_otx,       # v7
                    }
                    ef = err_map.get(name, lambda m: None)
                    timeout_msg = f"{name} timed out after 90s"
                    logger.error("Engine timeout: %s", timeout_msg)
                    network_results[name] = ef(timeout_msg)

    # ── Collect all results ────────────────────────────────────────────
    return {
        "heuristics":  h_res,
        "whois":       w_res,
        "deception":   dec_res,
        "ai":          network_results.get("ai",         _err_ai("AI disabled")),
        "reputation":  network_results.get("reputation", ReputationResult()),
        "sandbox":     network_results.get("sandbox",    _err_sandbox("Sandbox disabled")),
        "ssl":         network_results.get("ssl",        _err_ssl("SSL disabled")),
        "pdns":        network_results.get("pdns",       _err_pdns("Passive DNS disabled")),
        "shodan":      network_results.get("shodan",     _err_shodan("Shodan disabled")),
        "greynoise":   network_results.get("greynoise",  _err_greynoise("GreyNoise disabled")),
        "urlhaus":     network_results.get("urlhaus",    _err_urlhaus("URLhaus disabled")),  # NEW
        "otx":         network_results.get("otx",       _err_otx("OTX disabled")),         # v7
    }


# ── Hash Pipeline Runner ───────────────────────────────────────────────────────

def run_hash_engines_parallel(
    hash_str: str,
    *,
    vt_key:      str  = "",
    run_urlhaus: bool = True,
) -> dict[str, Any]:
    """
    Run parallel engines for pipeline_hash (File / Hash analysis).

    Engines run in parallel:
      - URLhaus hash lookup (query_hash) — checks if hash is a known malware payload

    hash_engine itself (VirusTotal) runs in pipeline_hash.py sequentially
    because it needs the file bytes — we add URLhaus alongside it.

    Returns dict with key: urlhaus
    """
    from backend.urlhaus_engine import query_hash, URLhausResult

    def _err_urlhaus(msg: str) -> URLhausResult:
        r = URLhausResult(); r.errors.append(msg); return r

    def _safe(fn: Callable, err_factory: Callable, *args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except Exception as exc:
            msg = f"{fn.__name__} error: {str(exc)[:120]}"
            logger.warning("Hash engine failure: %s", msg)
            return err_factory(msg)

    results: dict[str, Any] = {}

    tasks = []
    if run_urlhaus and hash_str:
        tasks.append(("urlhaus", query_hash, (hash_str,), {}, _err_urlhaus))

    if tasks:
        logger.info("Launching %d hash engines in parallel", len(tasks))
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=len(tasks),
            thread_name_prefix="ghostwire_hash",
        ) as pool:
            futures = {
                name: pool.submit(_safe, fn, err_factory, *args, **kwargs)
                for name, fn, args, kwargs, err_factory in tasks
            }
            for name, future in futures.items():
                try:
                    results[name] = future.result(timeout=30)
                except concurrent.futures.TimeoutError:
                    results[name] = _err_urlhaus(f"{name} timed out after 30s")

    return {
        "urlhaus": results.get("urlhaus", _err_urlhaus("URLhaus disabled")),
    }


# ── IP Pipeline Runner ─────────────────────────────────────────────────────────

def run_ip_urlhaus_parallel(
    ip_or_host: str,
    *,
    run_urlhaus: bool = True,
) -> dict[str, Any]:
    """
    Run URLhaus host lookup in parallel alongside pipeline_ip engines.

    pipeline_ip.py calls analyze_ip() sequentially (already fast).
    This function runs URLhaus query_host() concurrently so it
    doesn't add to the wall-clock time.

    Returns dict with key: urlhaus
    """
    from backend.urlhaus_engine import query_host, URLhausResult

    def _err_urlhaus(msg: str) -> URLhausResult:
        r = URLhausResult(); r.errors.append(msg); return r

    def _safe(fn: Callable, err_factory: Callable, *args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except Exception as exc:
            msg = f"{fn.__name__} error: {str(exc)[:120]}"
            logger.warning("IP engine failure: %s", msg)
            return err_factory(msg)

    results: dict[str, Any] = {}

    if run_urlhaus and ip_or_host:
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix="ghostwire_ip",
        ) as pool:
            future = pool.submit(_safe, query_host, _err_urlhaus, ip_or_host)
            try:
                results["urlhaus"] = future.result(timeout=30)
            except concurrent.futures.TimeoutError:
                results["urlhaus"] = _err_urlhaus("URLhaus host lookup timed out after 30s")

    return {
        "urlhaus": results.get("urlhaus", _err_urlhaus("URLhaus disabled")),
    }
