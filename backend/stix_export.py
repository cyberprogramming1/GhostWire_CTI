"""
backend/stix_export.py
-----------------------
GhostWire CTI v7 — STIX 2.1 / TAXII-compatible IOC Export Engine.

Generates STIX 2.1 Bundle JSON without external dependencies (stix2 lib optional).
Falls back to pure-JSON STIX structure if stix2 library is not installed.

What is exported:
  - Indicators (URL, domain, IP, hash) with pattern expressions
  - Threat actor (if OTX attributed)
  - Malware object (if signature detected)
  - Relationship objects linking indicators to threats
  - Report object tying everything together

Output formats:
  export_stix_bundle(result_dict) → str (STIX 2.1 JSON bundle)
  export_csv_iocs(result_dict)    → str (simple IOC CSV)

TAXII compatibility:
  The bundle JSON can be POSTed directly to a TAXII 2.1 Collections endpoint:
    POST /taxii2/api_root/collections/{collection_id}/objects/
    Content-Type: application/taxii+json;version=2.1
    Body: export_stix_bundle(...)

Docs:
  STIX 2.1: https://docs.oasis-open.org/cti/stix/v2.1/
  TAXII 2.1: https://docs.oasis-open.org/cti/taxii/v2.1/
"""

from __future__ import annotations

import json
import uuid
import hashlib
from datetime import datetime, timezone
from typing import Optional


# ── STIX 2.1 Object Builders (pure Python — no stix2 dep required) ───────────

def _now_stix() -> str:
    """Return current UTC timestamp in STIX 2.1 format."""
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _stix_id(obj_type: str, seed: str = "") -> str:
    """Generate deterministic STIX ID from seed (reproducible for same IOC)."""
    if seed:
        ns = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")  # GhostWire namespace
        uid = str(uuid.uuid5(ns, f"{obj_type}:{seed}"))
    else:
        uid = str(uuid.uuid4())
    return f"{obj_type}--{uid}"


def _make_identity() -> dict:
    """GhostWire tool identity object."""
    return {
        "type": "identity",
        "spec_version": "2.1",
        "id": _stix_id("identity", "ghostwire-cti-v7"),
        "created": "2026-01-01T00:00:00.000Z",
        "modified": "2026-01-01T00:00:00.000Z",
        "name": "GhostWire CTI v7",
        "identity_class": "system",
        "description": "GhostWire Cyber Threat Intelligence Platform — automated IOC analysis",
    }


def _make_indicator(
    name: str,
    pattern: str,
    pattern_type: str,
    indicator_types: list[str],
    description: str,
    confidence: int = 50,
    labels: Optional[list[str]] = None,
    created_by: str = "",
) -> dict:
    """Build STIX 2.1 Indicator object."""
    now = _now_stix()
    obj: dict = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": _stix_id("indicator", pattern),
        "created": now,
        "modified": now,
        "name": name,
        "description": description,
        "indicator_types": indicator_types,
        "pattern": pattern,
        "pattern_type": pattern_type,
        "valid_from": now,
        "confidence": max(0, min(100, confidence)),
    }
    if labels:
        obj["labels"] = labels
    if created_by:
        obj["created_by_ref"] = created_by
    return obj


def _make_malware(name: str, malware_types: list[str], created_by: str = "") -> dict:
    """Build STIX 2.1 Malware object."""
    now = _now_stix()
    obj = {
        "type": "malware",
        "spec_version": "2.1",
        "id": _stix_id("malware", name.lower()),
        "created": now,
        "modified": now,
        "name": name,
        "malware_types": malware_types,
        "is_family": True,
    }
    if created_by:
        obj["created_by_ref"] = created_by
    return obj


def _make_threat_actor(name: str, created_by: str = "") -> dict:
    """Build STIX 2.1 ThreatActor object."""
    now = _now_stix()
    obj = {
        "type": "threat-actor",
        "spec_version": "2.1",
        "id": _stix_id("threat-actor", name.lower()),
        "created": now,
        "modified": now,
        "name": name,
        "threat_actor_types": ["criminal", "spy"],
    }
    if created_by:
        obj["created_by_ref"] = created_by
    return obj


def _make_relationship(
    rel_type: str,
    source_id: str,
    target_id: str,
    created_by: str = "",
) -> dict:
    """Build STIX 2.1 Relationship object."""
    now = _now_stix()
    obj = {
        "type": "relationship",
        "spec_version": "2.1",
        "id": _stix_id("relationship", f"{source_id}:{rel_type}:{target_id}"),
        "created": now,
        "modified": now,
        "relationship_type": rel_type,
        "source_ref": source_id,
        "target_ref": target_id,
    }
    if created_by:
        obj["created_by_ref"] = created_by
    return obj


def _make_report(
    name: str,
    description: str,
    object_ids: list[str],
    threat_level: str,
    score: int,
    created_by: str = "",
) -> dict:
    """Build STIX 2.1 Report object."""
    now = _now_stix()
    obj = {
        "type": "report",
        "spec_version": "2.1",
        "id": _stix_id("report", name + now),
        "created": now,
        "modified": now,
        "name": name,
        "description": description,
        "published": now,
        "report_types": ["threat-report"],
        "object_refs": object_ids,
        "labels": [f"threat-level:{threat_level.lower()}", f"score:{score}"],
    }
    if created_by:
        obj["created_by_ref"] = created_by
    return obj


# ── Main Export Function ──────────────────────────────────────────────────────

def export_stix_bundle(
    target_url: str,
    threat_level: str,
    score: int,
    iocs: list[str],
    flags: list[str],
    malware_family: Optional[str] = None,
    threat_actors: Optional[list[str]] = None,
    ip_address: Optional[str] = None,
    verdict_text: str = "",
    sha256_hash: Optional[str] = None,
    md5_hash: Optional[str] = None,
    mitre_ids: Optional[list[str]] = None,
) -> str:
    """
    Build a STIX 2.1 Bundle from GhostWire analysis results.

    Parameters mirror the fields available after a full pipeline run.
    Returns a JSON string ready to POST to a TAXII 2.1 endpoint.
    """
    objects: list[dict] = []
    relationships: list[dict] = []

    # Identity (GhostWire as creator)
    identity = _make_identity()
    objects.append(identity)
    creator_ref = identity["id"]

    indicator_ids: list[str] = []

    # ── URL Indicator ─────────────────────────────────────────────────
    if target_url:
        # Classify indicator type
        ind_types = _classify_indicator_types(threat_level, flags)
        confidence = _score_to_confidence(score)

        url_ind = _make_indicator(
            name=f"Malicious URL: {target_url[:80]}",
            pattern=f"[url:value = '{_escape_stix(target_url)}']",
            pattern_type="stix",
            indicator_types=ind_types,
            description=f"GhostWire analysis: score {score}/100, threat level {threat_level}. {verdict_text[:300]}",
            confidence=confidence,
            labels=["ghostwire-auto-generated"],
            created_by=creator_ref,
        )
        objects.append(url_ind)
        indicator_ids.append(url_ind["id"])

        # Domain extraction
        try:
            import urllib.parse as up
            parsed = up.urlparse(target_url if "://" in target_url else "http://" + target_url)
            domain = parsed.hostname or ""
            if domain and "." in domain:
                dom_ind = _make_indicator(
                    name=f"Malicious domain: {domain}",
                    pattern=f"[domain-name:value = '{_escape_stix(domain)}']",
                    pattern_type="stix",
                    indicator_types=ind_types,
                    description=f"Domain extracted from GhostWire target URL analysis",
                    confidence=confidence,
                    labels=["ghostwire-auto-generated"],
                    created_by=creator_ref,
                )
                objects.append(dom_ind)
                indicator_ids.append(dom_ind["id"])
        except Exception:
            pass

    # ── IP Indicator ──────────────────────────────────────────────────
    if ip_address:
        ind_types = _classify_indicator_types(threat_level, flags)
        ip_ind = _make_indicator(
            name=f"Malicious IP: {ip_address}",
            pattern=f"[ipv4-addr:value = '{_escape_stix(ip_address)}']",
            pattern_type="stix",
            indicator_types=ind_types,
            description=f"IP hosting malicious infrastructure (GhostWire score {score}/100)",
            confidence=_score_to_confidence(score),
            labels=["ghostwire-auto-generated"],
            created_by=creator_ref,
        )
        objects.append(ip_ind)
        indicator_ids.append(ip_ind["id"])

    # ── Hash Indicators ───────────────────────────────────────────────
    if sha256_hash:
        hash_ind = _make_indicator(
            name=f"Malicious file SHA256: {sha256_hash[:16]}...",
            pattern=f"[file:hashes.'SHA-256' = '{_escape_stix(sha256_hash)}']",
            pattern_type="stix",
            indicator_types=["malicious-activity"],
            description=f"Malware payload hash from GhostWire URLhaus detection",
            confidence=90,
            labels=["malware-hash"],
            created_by=creator_ref,
        )
        objects.append(hash_ind)
        indicator_ids.append(hash_ind["id"])

    if md5_hash:
        md5_ind = _make_indicator(
            name=f"Malicious file MD5: {md5_hash}",
            pattern=f"[file:hashes.MD5 = '{_escape_stix(md5_hash)}']",
            pattern_type="stix",
            indicator_types=["malicious-activity"],
            description=f"Malware payload MD5 from GhostWire URLhaus detection",
            confidence=85,
            labels=["malware-hash"],
            created_by=creator_ref,
        )
        objects.append(md5_ind)
        indicator_ids.append(md5_ind["id"])

    # ── Malware object ────────────────────────────────────────────────
    malware_obj = None
    if malware_family:
        malware_types = _classify_malware_types(malware_family)
        malware_obj = _make_malware(
            name=malware_family,
            malware_types=malware_types,
            created_by=creator_ref,
        )
        objects.append(malware_obj)

        # Relationships: indicators indicate this malware
        for ind_id in indicator_ids:
            rel = _make_relationship(
                "indicates", ind_id, malware_obj["id"], creator_ref
            )
            relationships.append(rel)

    # ── Threat Actor objects ──────────────────────────────────────────
    for actor_name in (threat_actors or [])[:3]:
        actor = _make_threat_actor(actor_name, creator_ref)
        objects.append(actor)

        if malware_obj:
            rel = _make_relationship(
                "uses", actor["id"], malware_obj["id"], creator_ref
            )
            relationships.append(rel)

        for ind_id in indicator_ids[:2]:
            rel = _make_relationship(
                "uses", actor["id"], ind_id, creator_ref
            )
            relationships.append(rel)

    objects.extend(relationships)

    # ── Report ────────────────────────────────────────────────────────
    all_ids = [o["id"] for o in objects if o.get("type") != "identity"]
    if all_ids:
        report = _make_report(
            name=f"GhostWire CTI Analysis — {target_url[:60]}",
            description=f"Automated threat intelligence report. Score: {score}/100, Level: {threat_level}. {verdict_text[:200]}",
            object_ids=all_ids,
            threat_level=threat_level,
            score=score,
            created_by=creator_ref,
        )
        objects.append(report)

    # ── Bundle ────────────────────────────────────────────────────────
    bundle = {
        "type": "bundle",
        "id": f"bundle--{str(uuid.uuid4())}",
        "spec_version": "2.1",
        "objects": objects,
    }

    return json.dumps(bundle, indent=2, ensure_ascii=False)


def export_csv_iocs(
    target_url: str,
    ip_address: Optional[str],
    iocs: list[str],
    threat_level: str,
    score: int,
    sha256_hash: Optional[str] = None,
    md5_hash: Optional[str] = None,
    malware_family: Optional[str] = None,
) -> str:
    """
    Export IOCs in simple CSV format for SIEM ingestion.
    Compatible with: Splunk, QRadar, Elastic SIEM, Microsoft Sentinel.
    """
    lines = ["type,value,threat_level,score,malware_family,source,timestamp"]
    ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    mf = malware_family or ""

    def row(ioc_type, value):
        v = value.replace(",", " ").replace('"', "'")
        return f'{ioc_type},"{v}",{threat_level},{score},"{mf}",GhostWire-CTI-v7,{ts}'

    if target_url:
        lines.append(row("url", target_url))

    if ip_address:
        lines.append(row("ip", ip_address))

    if sha256_hash:
        lines.append(row("sha256", sha256_hash))

    if md5_hash:
        lines.append(row("md5", md5_hash))

    # Structured IOCs
    for ioc in iocs:
        if ioc.startswith("IP:"):
            lines.append(row("ip", ioc[3:]))
        elif ioc.startswith("URLHAUS_MALWARE:"):
            lines.append(row("malware_family", ioc[16:]))
        elif ioc.startswith("MITRE:"):
            lines.append(row("mitre_technique", ioc[6:]))
        elif ioc.startswith("OTX_ACTOR:"):
            lines.append(row("threat_actor", ioc[10:]))

    return "\n".join(lines)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _escape_stix(value: str) -> str:
    """Escape single quotes and backslashes for STIX pattern strings."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _score_to_confidence(score: int) -> int:
    """Map GhostWire 0-100 score to STIX confidence 0-100."""
    return min(95, max(10, score))


def _classify_indicator_types(threat_level: str, flags: list[str]) -> list[str]:
    """Determine STIX indicator_types from threat context."""
    types = []
    flags_lower = " ".join(flags).lower()

    if "phishing" in flags_lower or "credential" in flags_lower:
        types.append("malicious-activity")
    if "malware" in flags_lower or "trojan" in flags_lower:
        types.append("malicious-activity")
    if "c2" in flags_lower or "botnet" in flags_lower:
        types.append("compromised")
    if threat_level in ("HIGH", "CRITICAL"):
        if not types:
            types.append("malicious-activity")
    if not types:
        types = ["anomalous-activity"]

    return list(dict.fromkeys(types))  # deduplicate


def _classify_malware_types(family: str) -> list[str]:
    """Map malware family name to STIX malware_types."""
    name = family.lower()
    if any(x in name for x in ["ransom", "locker", "crypt"]):
        return ["ransomware"]
    if any(x in name for x in ["trojan", "rat", "remote"]):
        return ["remote-access-trojan"]
    if any(x in name for x in ["bot", "emotet", "qbot", "trickbot"]):
        return ["bot"]
    if any(x in name for x in ["stealer", "infostealer", "formgrab"]):
        return ["spyware"]
    if any(x in name for x in ["dropper", "loader", "downloader"]):
        return ["dropper"]
    if any(x in name for x in ["miner", "xmrig", "monero"]):
        return ["resource-exploitation"]
    return ["malware"]
