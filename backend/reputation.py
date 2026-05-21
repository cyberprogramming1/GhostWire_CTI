"""
utils/reputation.py
-------------------
Infrastructure Reputation Engine — GhostWire CTI v6.

Integrates:
  • VirusTotal v3  — URL & domain malicious engine detections
  • AbuseIPDB v2   — IP abuse confidence score & Tor detection
  • DNS Inspector  — A/MX/NS/TXT records, SPF, DMARC validation
"""

import os
import socket
import ipaddress
from dataclasses import dataclass, field
from typing import Optional

import requests
import tldextract

import logging
logger = logging.getLogger(__name__)


@dataclass
class ReputationResult:
    score: int = 0

    # ── VirusTotal engine scan ─────────────────────────────────────────
    vt_malicious: int = 0
    vt_suspicious: int = 0
    vt_harmless: int = 0
    vt_total_engines: int = 0
    vt_categories: list[str] = field(default_factory=list)
    vt_url_final: Optional[str] = None

    # ── VT Community (votes + comments) ──────────────────────────────
    vt_community_malicious_votes: int = 0
    vt_community_harmless_votes:  int = 0
    vt_community_comment_score:   int = 0   # score contribution from comments
    vt_community_malicious_comments: int = 0
    vt_community_comment_texts: list[str] = field(default_factory=list)  # raw comment texts for NLP

    # ── VT Relations ──────────────────────────────────────────────────
    vt_relation_score: int = 0              # score contribution from relations
    vt_malicious_files_related: int = 0     # total malicious related files

    # ── VT Domain ─────────────────────────────────────────────────────
    vt_popularity_rank: Optional[int] = None
    vt_registrar: Optional[str] = None

    # ── AbuseIPDB ─────────────────────────────────────────────────────
    ip_address: Optional[str] = None
    abuse_confidence: int = 0
    abuse_reports: int = 0
    abuse_country: Optional[str] = None
    abuse_isp: Optional[str] = None
    is_tor: bool = False

    # ── DNS ───────────────────────────────────────────────────────────
    a_records: list[str] = field(default_factory=list)
    mx_records: list[str] = field(default_factory=list)
    ns_records: list[str] = field(default_factory=list)
    txt_records: list[str] = field(default_factory=list)
    spf_valid: Optional[bool] = None
    dmarc_found: bool = False

    # ── Output ────────────────────────────────────────────────────────
    flags: list[str] = field(default_factory=list)
    iocs: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


TIMEOUT = 8
ABUSE_NS = ["namecheap", "dynadot", "freenom", "njal.la", "reg.ru"]


def _extract_domain(url: str) -> str:
    ext = tldextract.extract(url)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return url.split("//")[-1].split("/")[0].split("?")[0]


def _resolve_ip(domain: str) -> Optional[str]:
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


def _is_private(ip: str) -> bool:
    """
    Returns True if the IP should NOT be submitted to external APIs.
    Covers: private, loopback, link-local, multicast, reserved, unspecified.
    Multicast (224.x.x.x) and unspecified (0.0.0.0) are NOT caught by
    is_private alone — they must be checked explicitly.
    """
    try:
        addr = ipaddress.ip_address(ip)
        return (
            addr.is_private or
            addr.is_loopback or
            addr.is_link_local or
            addr.is_reserved or
            addr.is_multicast or
            addr.is_unspecified
        )
    except Exception:
        return True  # treat invalid IPs as unsafe


def _vt_headers(key: str) -> dict:
    return {"x-apikey": key, "Accept": "application/json"}


# ── VirusTotal — API queries ─────────────────────────────────────────────────

def _query_vt_url(url: str, key: str) -> dict:
    """Query VT URL endpoint. Returns full JSON including votes/comments."""
    import base64
    uid = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{uid}",
            headers=_vt_headers(key), timeout=TIMEOUT
        )
        if r.status_code == 404:
            s = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=_vt_headers(key), data={"url": url}, timeout=TIMEOUT
            )
            return {"queued": True} if s.status_code == 200 else {"error": "VT submit failed"}
        return r.json() if r.status_code == 200 else {"error": f"VT HTTP {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def _query_vt_domain(domain: str, key: str) -> dict:
    """Query VT domain endpoint — includes votes, categories, resolutions."""
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers=_vt_headers(key), timeout=TIMEOUT
        )
        return r.json() if r.status_code == 200 else {"error": f"VT HTTP {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def _query_vt_comments(resource_id: str, key: str, resource_type: str = "urls") -> list[dict]:
    """
    Fetch community comments for a URL or domain.
    resource_type: "urls" | "domains" | "ip_addresses"
    Returns list of comment dicts (up to 10 most recent).
    """
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/{resource_type}/{resource_id}/comments",
            headers=_vt_headers(key),
            params={"limit": 10},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            return r.json().get("data", [])
    except Exception:
        pass
    return []


def _query_vt_votes(resource_id: str, key: str, resource_type: str = "urls") -> dict:
    """
    Fetch community votes (malicious / harmless) for a URL or domain.
    Returns {"malicious": N, "harmless": N}
    """
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/{resource_type}/{resource_id}/votes",
            headers=_vt_headers(key),
            params={"limit": 40},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            votes = r.json().get("data", [])
            malicious = sum(1 for v in votes if v.get("attributes", {}).get("verdict") == "malicious")
            harmless  = sum(1 for v in votes if v.get("attributes", {}).get("verdict") == "harmless")
            return {"malicious": malicious, "harmless": harmless, "total": len(votes)}
    except Exception:
        pass
    return {"malicious": 0, "harmless": 0, "total": 0}


def _query_vt_relations(resource_id: str, key: str, resource_type: str = "urls") -> dict:
    """
    Fetch VT relationship data for a URL or domain.
    Checks: communicating_files, downloaded_files, referrer_files, contacted_domains, contacted_ips.
    Returns dict with counts and malicious flags.
    """
    relations: dict = {}
    relation_endpoints = {
        "communicating_files": "files that communicate with this target",
        "downloaded_files":    "files downloaded from this target",
        "referrer_files":      "files that reference this URL",
    }
    if resource_type == "domains":
        relation_endpoints["resolutions"] = "historical IP resolutions"
        relation_endpoints["contacted_ips"] = "IPs contacted by this domain"

    for rel_name, rel_desc in relation_endpoints.items():
        try:
            r = requests.get(
                f"https://www.virustotal.com/api/v3/{resource_type}/{resource_id}/{rel_name}",
                headers=_vt_headers(key),
                params={"limit": 10},
                timeout=TIMEOUT,
            )
            if r.status_code == 200:
                items = r.json().get("data", [])
                mal_count = 0
                for item in items:
                    stats = item.get("attributes", {}).get("last_analysis_stats", {})
                    if stats.get("malicious", 0) >= 3:
                        mal_count += 1
                if items:
                    relations[rel_name] = {
                        "total":     len(items),
                        "malicious": mal_count,
                        "desc":      rel_desc,
                    }
        except Exception:
            pass
    return relations


# ── VirusTotal — Score Parser ────────────────────────────────────────────────

# Keywords that indicate malicious intent in community comments
_MALICIOUS_COMMENT_KEYWORDS = [
    "phishing", "malware", "scam", "spam", "malicious", "threat", "hack",
    "ransomware", "trojan", "virus", "suspicious", "fake", "fraud",
    "credential", "steal", "c2", "c&c", "botnet", "exploit", "payload",
    "dropper", "loader", "redirects", "impersonat", "typosquat",
]
_BENIGN_COMMENT_KEYWORDS = [
    "legitimate", "safe", "trusted", "false positive", "fp", "whitelist",
    "official", "verified", "clean", "harmless",
]


def _score_comments(comments: list[dict]) -> tuple[int, list[str]]:
    """
    Analyse community comments for malicious signals.
    Returns (score_to_add, flags).

    Scoring logic:
      Each comment with 3+ malicious keywords → +8 pts (max +25)
      Each comment with 1-2 malicious keywords → +4 pts
      Each comment with only benign keywords  → -2 pts (max -10 offset)
      Net score capped at +25
    """
    if not comments:
        return 0, []

    flags: list[str] = []
    score = 0
    malicious_comments: list[str] = []
    benign_comments:    list[str] = []

    for c in comments:
        text  = c.get("attributes", {}).get("text", "").lower()
        votes = c.get("attributes", {}).get("votes", {})
        # Comments that got upvoted are more reliable
        upvotes = votes.get("positive", 0)

        mal_hits = [kw for kw in _MALICIOUS_COMMENT_KEYWORDS if kw in text]
        ben_hits = [kw for kw in _BENIGN_COMMENT_KEYWORDS    if kw in text]

        if len(mal_hits) >= 3:
            pts = 8 + min(upvotes * 2, 6)   # upvoted malicious comments score higher
            score += pts
            snippet = text[:120].replace("\n", " ").strip()
            malicious_comments.append(f'"{snippet}…"')
        elif len(mal_hits) >= 1 and len(ben_hits) == 0:
            score += 4
            snippet = text[:80].replace("\n", " ").strip()
            malicious_comments.append(f'"{snippet}…"')
        elif ben_hits and not mal_hits:
            score = max(score - 2, 0)
            benign_comments.append(text[:60])

    if malicious_comments:
        flags.append(
            f"💬 VT COMMUNITY: {len(malicious_comments)} comment(s) flag this as malicious"
        )
        for i, snippet in enumerate(malicious_comments[:3]):
            flags.append(f"   Comment {i+1}: {snippet}")

    if benign_comments:
        flags.append(
            f"💬 VT COMMUNITY: {len(benign_comments)} comment(s) suggest legitimate"
        )

    return min(score, 25), flags


def _score_votes(votes: dict) -> tuple[int, list[str]]:
    """
    Score community votes.
    Scoring:
      malicious votes >> harmless → malicious signal
      harmless votes >> malicious → slightly reduces score
      Even split → neutral
    """
    mal  = votes.get("malicious", 0)
    harm = votes.get("harmless",  0)
    total = votes.get("total",    0)

    if total == 0:
        return 0, []

    flags: list[str] = []
    score = 0

    if mal >= 5:
        score += min(mal * 3, 20)
        flags.append(
            f"👎 VT COMMUNITY VOTES: {mal} malicious vs {harm} harmless "
            f"— community consensus: MALICIOUS"
        )
    elif mal >= 2:
        score += mal * 3
        flags.append(f"👎 VT COMMUNITY VOTES: {mal} users voted malicious, {harm} harmless")
    elif harm >= 3 and mal == 0:
        flags.append(
            f"👍 VT COMMUNITY VOTES: {harm} users voted harmless — community consensus: SAFE"
        )

    return min(score, 20), flags


def _score_relations(relations: dict) -> tuple[int, list[str]]:
    """
    Score VT relation data.

    Key insight: a domain/URL with 0 engine detections can still have
    malicious *communicating files* or *downloaded files* — this is the
    most important FP-prevention signal for new/fresh domains.

    Scoring:
      Malicious communicating files → +15 each (max +30)
      Malicious downloaded files    → +20 each (max +30)
      Malicious referrer files      → +10 each (max +20)
      Total relations capped at +40
    """
    if not relations:
        return 0, []

    flags: list[str] = []
    score = 0

    weights = {
        "downloaded_files":    (20, "files downloaded FROM this target"),
        "communicating_files": (15, "files communicating WITH this target"),
        "referrer_files":      (10, "files referencing this URL"),
    }

    for rel_name, (pts_each, desc) in weights.items():
        rel = relations.get(rel_name)
        if not rel:
            continue
        total = rel["total"]
        mal   = rel["malicious"]

        if mal > 0:
            pts = min(mal * pts_each, 30)
            score += pts
            flags.append(
                f"🔗 VT RELATIONS [{rel_name}]: {mal}/{total} {desc} "
                f"are MALICIOUS → +{pts} pts"
            )
            if rel_name == "downloaded_files":
                flags.append(
                    "   ⚠ Malware is being served from this URL — critical indicator"
                )
        elif total > 0:
            flags.append(
                f"🔗 VT RELATIONS [{rel_name}]: {total} related files, none malicious"
            )

    # Resolution history for domains
    if "resolutions" in relations:
        res = relations["resolutions"]
        if res["total"] > 0:
            flags.append(
                f"🌐 VT RESOLUTIONS: {res['total']} historical IPs for this domain"
            )

    return min(score, 40), flags


def _parse_vt(data: dict, result: ReputationResult) -> None:
    """Parse URL-level VT response: engines + categories."""
    if "error" in data or "queued" in data:
        result.errors.append(f"VirusTotal: {data.get('error', 'URL queued — retry in 30s')}")
        return

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    result.vt_malicious     = stats.get("malicious", 0)
    result.vt_suspicious    = stats.get("suspicious", 0)
    result.vt_harmless      = stats.get("harmless", 0)
    result.vt_total_engines = sum(stats.values()) if stats else 0
    result.vt_categories    = list(set(attrs.get("categories", {}).values()))[:6]
    result.vt_url_final     = attrs.get("last_final_url")

    # ── Engine detections ─────────────────────────────────────────────
    if result.vt_malicious >= 10:
        result.score += 25
        result.flags.append(
            f"🔴 VirusTotal: {result.vt_malicious}/{result.vt_total_engines} engines MALICIOUS"
        )
        result.iocs.append(f"VT_MALICIOUS:{result.vt_malicious}_ENGINES")
    elif result.vt_malicious >= 3:
        result.score += 15
        result.flags.append(
            f"🟠 VirusTotal: {result.vt_malicious} malicious detections"
        )
        result.iocs.append(f"VT_MALICIOUS:{result.vt_malicious}_ENGINES")
    elif result.vt_malicious >= 1:
        result.score += 8
        result.flags.append(
            f"🟡 VirusTotal: {result.vt_malicious} engine(s) flagged — low confidence"
        )
    elif result.vt_suspicious >= 2:
        result.score += 6
        result.flags.append(
            f"🟡 VirusTotal: {result.vt_suspicious} suspicious detections"
        )
    else:
        result.flags.append(
            f"✅ VirusTotal: {result.vt_harmless}/{result.vt_total_engines} engines clean"
        )

    # ── Category tags ─────────────────────────────────────────────────
    danger_cats = [
        c for c in result.vt_categories
        if c.lower() in {"phishing", "malware", "spam", "malicious", "ransomware",
                         "trojan", "exploit", "command-and-control"}
    ]
    if danger_cats:
        result.score += 8
        result.flags.append(
            f"🏷 VirusTotal categories: {', '.join(danger_cats)}"
        )
        result.iocs.append(f"VT_CATEGORY:{','.join(danger_cats)}")


def _parse_vt_domain_extra(data: dict, result: ReputationResult) -> None:
    """
    Parse domain-level VT response.
    Extracts: engine detections, popularity rank, last DNS records,
    registrar info, community score from attributes.
    """
    if "error" in data:
        return

    attrs = data.get("data", {}).get("attributes", {})
    dom_id = data.get("data", {}).get("id", "")

    stats = attrs.get("last_analysis_stats", {})
    dom_mal = stats.get("malicious", 0)
    dom_sus = stats.get("suspicious", 0)

    if dom_mal > result.vt_malicious:
        result.score += min((dom_mal - result.vt_malicious) * 3, 12)
        result.flags.append(
            f"🔴 VT Domain-level: {dom_mal} malicious detections "
            f"(higher than URL scan)"
        )
        result.iocs.append(f"VT_DOMAIN_MALICIOUS:{dom_mal}")

    # Popularity rank — very popular domains are less likely phishing
    popularity = attrs.get("popularity_ranks", {})
    if popularity:
        ranks = [v.get("rank", 999999) for v in popularity.values()]
        min_rank = min(ranks)
        if min_rank <= 10000:
            # Very popular domain — reduce score (major brand)
            result.flags.append(
                f"📊 VT Popularity rank: #{min_rank} — high-traffic legitimate domain"
            )
            result.score = max(result.score - 10, 0)
        elif min_rank <= 100000:
            result.flags.append(f"📊 VT Popularity rank: #{min_rank}")
    else:
        result.flags.append(
            "📊 VT Popularity: domain not ranked — unknown/new/low-traffic"
        )

    # Registrar from VT
    registrar = attrs.get("registrar")
    if registrar:
        result.flags.append(f"📋 Registrar (VT): {registrar}")

    # Community score from domain attributes (total_votes)
    total_votes = attrs.get("total_votes", {})
    if total_votes:
        vt_mal_votes  = total_votes.get("malicious", 0)
        vt_harm_votes = total_votes.get("harmless", 0)
        if vt_mal_votes > 0:
            pts = min(vt_mal_votes * 4, 15)
            result.score += pts
            result.flags.append(
                f"👎 VT Community (domain): {vt_mal_votes} malicious votes, "
                f"{vt_harm_votes} harmless → +{pts} pts"
            )
            result.iocs.append(f"VT_COMMUNITY_MALICIOUS_VOTES:{vt_mal_votes}")


# ── AbuseIPDB ───────────────────────────────────────────────────────────────

def _query_abuse(ip: str, key: str) -> dict:
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=TIMEOUT,
        )
        return r.json() if r.status_code == 200 else {"error": f"AbuseIPDB HTTP {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def _parse_abuse(data: dict, result: ReputationResult) -> None:
    if "error" in data:
        result.errors.append(f"AbuseIPDB: {data['error']}")
        return
    d = data.get("data", {})
    result.abuse_confidence = d.get("abuseConfidenceScore", 0)
    result.abuse_reports    = d.get("totalReports", 0)
    result.abuse_country    = d.get("countryCode")
    result.abuse_isp        = d.get("isp")
    result.is_tor           = bool(d.get("isTor", False))

    if result.abuse_confidence >= 80:
        result.score += 20
        result.flags.append(
            f"AbuseIPDB: CRITICAL — {result.abuse_confidence}% confidence, {result.abuse_reports} reports"
        )
        result.iocs.append(f"ABUSIVE_IP:{result.ip_address}")
    elif result.abuse_confidence >= 40:
        result.score += 10
        result.flags.append(f"AbuseIPDB: {result.abuse_confidence}% abuse confidence score")
    elif result.abuse_reports > 0:
        result.score += 4
        result.flags.append(f"AbuseIPDB: {result.abuse_reports} historical abuse reports")
    else:
        result.flags.append(f"AbuseIPDB: No abuse reports for {result.ip_address}")

    if result.is_tor:
        result.score += 8
        result.flags.append("IP is a confirmed Tor exit node 🧅")
        result.iocs.append(f"TOR_EXIT_NODE:{result.ip_address}")


# ── DNS Inspector ────────────────────────────────────────────────────────────

def _dns_inspect(domain: str, result: ReputationResult) -> None:
    try:
        import dns.resolver
    except ImportError:
        result.errors.append("dnspython not installed — DNS inspection skipped")
        return

    res = dns.resolver.Resolver()
    res.timeout = res.lifetime = 5

    for rtype, store in [("A", "a_records"), ("MX", "mx_records"), ("NS", "ns_records")]:
        try:
            ans = res.resolve(domain, rtype)
            if rtype == "A":
                records = [r.address for r in ans]
                result.ip_address = records[0] if records else None
            elif rtype == "MX":
                records = [str(r.exchange).rstrip(".") for r in ans]
            else:
                records = [str(r.target).rstrip(".") for r in ans]
            setattr(result, store, records)
        except Exception:
            pass

    # TXT — SPF & DMARC
    try:
        ans = res.resolve(domain, "TXT")
        txts = [b"".join(r.strings).decode("utf-8", errors="ignore") for r in ans]
        result.txt_records = txts[:6]
        spf = [t for t in txts if t.startswith("v=spf1")]
        result.spf_valid = bool(spf)
        if not result.spf_valid:
            result.flags.append("No SPF record — domain spoofing is trivial")
    except Exception:
        result.spf_valid = False

    try:
        ans = res.resolve(f"_dmarc.{domain}", "TXT")
        dmarc = [b"".join(r.strings).decode("utf-8", errors="ignore") for r in ans]
        result.dmarc_found = any("v=DMARC1" in t for t in dmarc)
    except Exception:
        result.dmarc_found = False

    if not result.dmarc_found:
        result.flags.append("No DMARC record — phishing emails bypass email authentication")

    for ns in result.ns_records:
        for bad in ABUSE_NS:
            if bad in ns.lower():
                result.score += 5
                result.flags.append(f"Nameserver '{ns}' linked to high-abuse registrar")
                result.iocs.append(f"SUSPICIOUS_NS:{ns}")
                break


# ── Main ────────────────────────────────────────────────────────────────────

def analyze_reputation(
    url: str,
    vt_api_key: Optional[str] = None,
    abuse_api_key: Optional[str] = None,
) -> ReputationResult:
    """
    Full infrastructure reputation analysis.

    Pipeline:
      1. DNS inspection (A/MX/NS/SPF/DMARC)
      2. VirusTotal URL scan  → engine detections + categories
      3. VirusTotal Domain    → domain-level detections + popularity rank
      4. VT Community Votes   → user-voted malicious/harmless
      5. VT Community Comments→ NLP on text signals ("phishing", "scam"…)
      6. VT Relations         → communicating/downloaded/referrer files
      7. AbuseIPDB            → IP abuse confidence + report count
    """
    result = ReputationResult()
    domain = _extract_domain(url)

    # ── DNS ───────────────────────────────────────────────────────────
    _dns_inspect(domain, result)
    if not result.ip_address:
        result.ip_address = _resolve_ip(domain)
    if result.ip_address:
        result.iocs.append(f"IP:{result.ip_address}")

    if vt_api_key:
        import base64

        # ── Engine scan (URL level) ───────────────────────────────────
        url_data = _query_vt_url(url, vt_api_key)
        _parse_vt(url_data, result)

        # Get URL resource ID for community queries
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

        # ── Domain level ──────────────────────────────────────────────
        dom_data = _query_vt_domain(domain, vt_api_key)
        _parse_vt_domain_extra(dom_data, result)

        # ── Community Votes (URL + Domain) ──────────────────────────
        url_votes = _query_vt_votes(url_id, vt_api_key, "urls")
        vote_score, vote_flags = _score_votes(url_votes)
        result.score += vote_score
        result.flags.extend(vote_flags)
        result.vt_community_malicious_votes += url_votes.get("malicious", 0)
        result.vt_community_harmless_votes  += url_votes.get("harmless",  0)

        dom_votes = _query_vt_votes(domain, vt_api_key, "domains")
        if dom_votes["malicious"] > url_votes.get("malicious", 0):
            d_vote_score, d_vote_flags = _score_votes(dom_votes)
            result.score += d_vote_score
            result.flags.extend(d_vote_flags)
            result.vt_community_malicious_votes = max(
                result.vt_community_malicious_votes, dom_votes["malicious"]
            )
            result.vt_community_harmless_votes = max(
                result.vt_community_harmless_votes, dom_votes["harmless"]
            )

        # ── Community Comments (URL + Domain) ───────────────────────
        url_comments = _query_vt_comments(url_id, vt_api_key, "urls")
        dom_comments = _query_vt_comments(domain,  vt_api_key, "domains")
        all_comments = url_comments + dom_comments

        if all_comments:
            comment_score, comment_flags = _score_comments(all_comments)
            result.score += comment_score
            result.vt_community_comment_score = comment_score
            # Store raw comment texts for scoring.py NLP (_has_suspicious_community_comment)
            result.vt_community_comment_texts = [
                c.get("attributes", {}).get("text", "")
                for c in all_comments
                if c.get("attributes", {}).get("text")
            ]
            # Count how many comments were malicious-tagged
            result.vt_community_malicious_comments = sum(
                1 for c in all_comments
                if any(kw in c.get("attributes", {}).get("text", "").lower()
                       for kw in _MALICIOUS_COMMENT_KEYWORDS[:6])
            )
            result.flags.extend(comment_flags)
            if comment_score > 0:
                result.iocs.append("VT_COMMUNITY_COMMENTS_MALICIOUS")
        else:
            result.flags.append("💬 VT Community: No comments yet for this target")

        # ── Relations (URL + Domain) ─────────────────────────────────
        url_relations = _query_vt_relations(url_id, vt_api_key, "urls")
        dom_relations = _query_vt_relations(domain,  vt_api_key, "domains")
        all_relations = {**dom_relations, **url_relations}

        if all_relations:
            rel_score, rel_flags = _score_relations(all_relations)
            result.vt_relation_score = rel_score
            result.vt_malicious_files_related = sum(
                r["malicious"] for r in all_relations.values()
                if isinstance(r, dict) and "malicious" in r
            )
            result.flags.extend(rel_flags)

            # ── Static Whitelist Gate (Early — prevents rep.score inflation) ──
            # Import here to avoid circular dependency; scoring.py already has this.
            # ── AZ TLD + whitelist relations gate (reputation layer) ────────────
            # Suppression tiers at source — before rep.score accumulates:
            #   AZ_LEGIT (explicit)  → suppress
            #   AZ TLD / AZ_SAFE     → suppress (VT=0, no community)
            #   AZ TLD / AZ_REVIEW   → suppress (relations only, no votes)
            #   AZ TLD / AZ_SUSPECT  → do NOT suppress (community flagged it)
            #   INFRA domains        → suppress
            #   Global unknown       → do NOT suppress
            try:
                from backend.scoring import _check_infra_domain, _classify_az_domain
                _infra_hit, _infra_org = _check_infra_domain(domain)

                # AZ TLD tier — regex-based classifier
                _az_tier = "NOT_AZ"
                if not _infra_hit:
                    _az_tier, _ = _classify_az_domain(domain, result)
            except Exception:
                _infra_hit = False
                _infra_org = ""
                _az_tier   = "NOT_AZ"

            # Decide suppression
            _suppress_rel = (
                _infra_hit                               # global infra (163.com…)
                or _az_tier in ("AZ_SAFE", "AZ_REVIEW") # clean/review .az TLD
            )

            if _az_tier == "AZ_SAFE":
                _suppress_label = "AZ TLD SAFE [VT=0, Abuse=0, no community]"
            elif _az_tier == "AZ_REVIEW":
                _suppress_label = "AZ TLD REVIEW [relations only, no votes/comments]"
            elif _infra_hit:
                _suppress_label = f"INFRA DOMAIN: {_infra_org}"
            else:
                _suppress_label = ""

            if _suppress_rel and rel_score > 0:
                result.flags.append(
                    f"✅ {_suppress_label} [reputation]: '{domain}' — "
                    f"VT relations score suppressed at source (+{rel_score} pts blocked). "
                    f"Related files are user-uploaded samples, not domain-served malware."
                )
                result.vt_relation_score = 0
                # vt_malicious_files_related kept intact for UI display
            else:
                result.score += rel_score
                if rel_score >= 15:
                    result.iocs.append("VT_RELATIONS_MALICIOUS_FILES")
        else:
            result.flags.append("🔗 VT Relations: No related files found")

    else:
        result.errors.append("VirusTotal API key not set — configure in .env")

    # ── AbuseIPDB ─────────────────────────────────────────────────────
    if abuse_api_key and result.ip_address and not _is_private(result.ip_address):
        _parse_abuse(_query_abuse(result.ip_address, abuse_api_key), result)
    elif not abuse_api_key:
        result.errors.append("AbuseIPDB API key not set — configure in .env")

    # Cap at 40 (scoring.py normalizes the total)
    result.score = min(result.score, 40)
    return result
