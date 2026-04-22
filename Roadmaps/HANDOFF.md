# UNICC Pipeline — Session Handoff (April 16, 2026)

## Current State: What Works

| Component | Status |
|---|---|
| FastAPI running on port 8000 | ✅ |
| `GET /search` — hybrid CVE search | ✅ |
| `GET /cve/{id}` — full context expansion | ✅ |
| `GET /technique/{attack_id}` — technique pivot | ✅ |
| `POST /investigate` — LLM narrative via OpenRouter | ✅ |
| `index.html` — light pastel UI, vis-network graph | ✅ (serve via `python3 -m http.server 3000`) |
| Neo4j — 323k Vulnerability nodes + 174k PATTERN_OF edges + ATT&CK anchor | ✅ |
| Qdrant — 249k CVE vectors (all-mpnet-base-v2) | ✅ |

## Files (all in `~/Workspace/phase4/`)
```
api.py           — FastAPI app
search.py        — HybridSearchEngine
narrative.py     — OpenRouter (Llama 3.1 8B free tier)
index.html       — investigator UI
qdrant_loader.py — CVE embedding loader
```

## Env vars needed to start API
```bash
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=<your_password>
QDRANT_HOST=localhost
QDRANT_PORT=6333
EMBED_MODEL=sentence-transformers/all-mpnet-base-v2
OPENROUTER_API_KEY=<your_key>
OPENROUTER_MODEL=meta-llama/llama-3.1-8b-instruct
uvicorn api:app --host 0.0.0.0 --port 8000 --reload
```

## Known Bugs / Gotchas
- **Neo4j HTTP for graph UI**: must serve index.html via `python3 -m http.server 3000`, not file://. Update `NEO4J_AUTH = 'neo4j:YOUR_PASSWORD'` in index.html script block.
- **Qdrant API**: use `client.query_points()` not `client.search()` (deprecated)
- **Neo4j queries**: always use labeled MATCH e.g. `MATCH (v:Vulnerability {...})` — label-free scans time out at 323k nodes
- **Gemini free tier**: exhausted. Using OpenRouter free tier instead.
- **MPNet load warning** (`UNEXPECTED: embeddings.position_ids`): harmless, ignore it.

## What's NOT Done (priority order)

### 1. PDF chunks → Qdrant (HIGH — SOW gap)
The 8 parsed reports (AT&T v5/v6/v8, ENISA 2023/2024/2025, Microsoft DDFR 2023/2025)
are sitting as chunked JSONs on disk but are NOT in Qdrant or Neo4j.
SOW explicitly names these as data sources. UNICC can't query them right now.

**To fix:** Load PDF chunks from Docling output JSONs, embed with same model,
upsert into a new Qdrant collection `pdf_chunks`, add source filter to `/search`.

Parsed PDF JSONs location: `~/Workspace/parse/parse/` (double-nested)

### 2. Evaluation Script (MEDIUM — demo evidence)
Need 20-query test set with ground-truth answers.
Metrics: avg latency, actor recall, technique recall.
Required to demonstrate "investigative efficiency improvement" per SOW.

**Structure:**
```python
TEST_QUERIES = [
    {"query": "CVE-2021-44228", "expected_techniques": ["T1190"], "expected_groups": []},
    {"query": "ransomware targeting healthcare RDP", "expected_techniques": ["T1133","T1486"], ...},
    # ... 18 more
]
# measure latency per query, check if expected values appear in narrative/top_cves
```

### 3. README.md for GitHub (LOW)
Setup instructions, architecture diagram, sample queries, no API keys.

## SOW Compliance Summary
| Requirement | Met? |
|---|---|
| Summarize threat reports → narratives | ✅ /investigate |
| Extract key info via NLP | ✅ structural CVE extraction |
| Searchability across historical reports | ⚠️ CVEs yes, PDFs no |
| Correlate with MITRE ATT&CK TTPs | ✅ Neo4j 2-hop |
| Investigative efficiency improvement (measured) | ❌ eval script needed |

## Start Next Session With
Load `SKILL_project_context.md` + this file.
First task: PDF chunks → Qdrant ingestion, then eval script.
