# GhostWire CTI v7 — AlienVault OTX Integration

## Setup (1 step)

```bash
# 1. Get your free OTX API key
#    → https://otx.alienvault.com/settings  (scroll to "OTX Key")

# 2. Add to your .env
echo "OTX_API_KEY=your_key_here" >> .env

# 3. Restart Streamlit — no new pip install needed
streamlit run app.py
```

## What OTX adds to GhostWire

| Feature | Where shown |
|---|---|
| Pulse count badge | OTX panel (all pipelines) |
| MITRE ATT&CK technique IDs | OTX panel — T1566, T1059 etc. |
| Threat actor attribution | OTX panel — "Lazarus Group" etc. |
| Campaign pulse names | OTX panel — expandable list |
| Targeted countries/sectors | OTX panel — tag chips |
| Corroborated score (+6/+12 pts) | Final score (only with VT confirmation) |
| OTX IOCs in CTI report | all_iocs list |

## Scoring logic (FP-safe)

OTX score ONLY contributes when VT also flags the indicator:

| Condition | Score added |
|---|---|
| 10+ pulses AND VT malicious > 0 | +12 pts |
| 3-9 pulses AND VT malicious > 0 | +6 pts |
| Any pulses, VT clean | 0 pts (context only) |
| 0 pulses | 0 pts |

## Files changed

- `backend/otx_engine.py` — NEW: full OTX API client + scoring
- `frontend/otx_panel.py` — NEW: OTX UI panel renderer
- `backend/async_runner.py` — OTX added to parallel engine pool
- `pipelines/pipeline_url.py` — OTX integrated (domain + URL lookup)
- `pipelines/pipeline_hash.py` — OTX integrated (hash lookup)
- `pipelines/pipeline_ip.py` — OTX integrated (IP lookup)
- `config.py` — OTX_API_KEY added
- `app.py` — OTX key status + toggle added
- `env.example` — OTX_API_KEY documented
