# SKILL: UNICC Cybersecurity Intelligence Pipeline — Project Context

> Feed this file to any LLM at the start of a session. It gives full project awareness.

---

## 1. Project Identity

| Field | Value |
|---|---|
| **Name** | Cybersecurity Threat Intelligence Extraction & Analysis Pipeline |
| **Client** | UNICC — United Nations International Computing Centre |
| **Institution** | IIT Gandhinagar (IITGN), B.Tech Capstone |
| **Faculty Advisor** | Dr. Rajeev Shorey |
| **Formalization** | MoU + Statement of Work (SOW) signed Nov 2025 |
| **GitHub Deliverable** | August 2026 |
| **Student** | Anand |

---

## 2. SOW Requirements (verbatim intent)

The tool must:
1. **Summarize** threat landscape reports into concise, actionable narratives
2. **Extract key information** from CVE/NVD, ENISA, NIST, Microsoft, AT&T reports
3. **Enable searchability** across historical event logs and threat reports
4. **Provide enriched contextual analysis** correlating new incidents with historical TTPs from MITRE ATT&CK

**UNICC evaluation criteria (these are the success metrics):**
- Investigative efficiency improvement (time-to-answer)
- Historical reference capability via graph queries
- Precision over recall in all extractions

---

## 3. Architecture — What Has Been Built (Phase 1 ✅ COMPLETE)

### 3a. Data Ingestion
- **341,089 CVE JSON 5.x files** normalized to flat JSONL in 27s via `ProcessPoolExecutor`
- Output: `cve_normalized.jsonl` — 323,647 records (17,442 REJECTED-state skipped)
- Schema per record: `{cve_id, description, cvss_v3, cwe_ids, affected_products, published_date, state, source_file}`
- CVSS coverage: 44.5% (pre-2016 CVEs never had v3 — expected, not a data quality bug)
- CWE coverage: 43.7% (voluntary assignment — expected)
- High-confidence ground truth subset: ~144k records with both CVSS + CWE

### 3b. PDF Parsing
- **8 cybersecurity reports parsed**: AT&T, ENISA, Microsoft
- Primary parser: **Docling** (Python 3.11-slim Docker container, volume-mounted)
- Fallback: **marker-pdf** (auto-triggered per-file, logged in `_parse_summary.json`)
- Output: `.md` + `.json` per PDF with HybridChunker-preserved structure

### 3c. MITRE ATT&CK → Neo4j (THE ANCHOR GRAPH)
- Downloaded `enterprise-attack.json` (44 MB) from MITRE CTI GitHub
- Parsed via `stix2.MemoryStore` with `_attr()` helper for mixed typed/dict returns
- **Loaded into Neo4j:**
  - 1,705 nodes: Technique(691), Software(784), Group(172), Mitigation(44), Tactic(14)
  - 18,022 edges: USES(16,102), MITIGATES(1,445), SUBTECHNIQUE_OF(475), ENABLES_TACTIC(887)
  - 2,026 relationships skipped (REVOKED types)
- **Indexes created** on `attack_id` and `name` for all node types (critical for NER resolution speed)
- 7 spot-check queries verified post-load

### 3d. Files Produced
```
docker/docker-compose.yml          # Container definition
docker/Dockerfile                  # Python 3.11-slim + poppler + tesseract + docling + marker-pdf
parse/parse.py                     # Layout-aware PDF parser
parse/normalize_cves.py            # CVE JSON 5.x → flat JSONL normalizer
parse/profile_cves.py              # JSONL profiler
parse/stix_to_neo4j.py             # MITRE ATT&CK STIX → Neo4j loader
cve_normalized.jsonl               # 323,647 flat CVE records
~/data/enterprise-attack.json      # Cached MITRE STIX bundle (44 MB)
```

### 3e. Key Engineering Decisions (don't repeat these mistakes)
1. **Docker for Docling isolation** — PyTorch/transformers/RapidOCR conflict with system Python
2. **Docling-first, marker fallback per file** — automatic, logged
3. **Multiprocessing for CVE normalization** — 12,488 files/s with ProcessPoolExecutor N-1 workers
4. **Highest CVSS score wins** across CNA + ADP containers (worst-case severity for threat intel)
5. **`_attr()` helper** for stix2 mixed type returns — routes to `.get()` or `getattr()` based on isinstance
6. **Neo4j indexes on attack_id and name** created at load time, not after

---

## 4. Architecture — What Comes Next

### Phase 2: NER Extraction (PRIMARY CURRENT FOCUS)
**Goal:** Extract cyber entities from parsed text, resolve against Neo4j ATT&CK graph

**Models to use (in order of priority):**
1. **CyNER** (`xlm-roberta-large`) — primary model. Repo: `github.com/aiforsec/CyNER`
   - Handles: Malware, Threat Actor, Attack Pattern, Vulnerability, Indicator
2. **GLiNER** — zero-shot NER for entity types CyNER misses
3. **SecureBERT** — domain embeddings for entity resolution similarity

**Entity resolution strategy:**
- Fuzzy string match + embedding cosine similarity against Neo4j `attack_id` and `name` indexes
- Collapse aliases: APT29 = Cozy Bear = The Dukes → single canonical node
- Confidence scoring per extraction — threshold >0.7 for inclusion

**Paramananta (HPC) role here:**
- Batch CyNER inference on 323,647 CVE descriptions via SLURM array job
- SLURM scripts already written: `submit_ner_cves.sh`, `submit_ner_pdfs.sh`, `merge_cve_shards.sh`
- SSH: `suhani@paramananta.iitgn.ac.in -p 4422`
- Key dirs: `~/Workspace/cyner_src/`, `/scratch/suhani/cyner_project/`
- nltk fix already applied (`punkt`, `punkt_tab` corpora downloaded)

**Reference implementation to study:**
- `github.com/imouiche/Threat-Intelligence-Knowledge-Graphs` — TiKG paper (Computers & Security 2025)
  - Uses: SecureBERT + BiLSTM/BiGRU + CRF. Domain ontology for error control.
  - Datasets: DNRTI, STUCCO, CyNER. Clone and adapt NER pipeline.
- `github.com/IS5882/Open-CyKG` — OIE-based KG from APT reports
  - Uses: attention-based neural OIE + NER + KG fusion via word embeddings
  - Directly reusable: canonicalization / entity fusion logic

### Phase 3: STIX Graph Construction + Relationship Extraction
**Goal:** Convert extracted entities to STIX 2.1 objects, enrich Neo4j with document-derived edges

**Stack:**
- `stix2` Python library for object generation
- `neo4j` driver for graph ingestion
- Gemini Flash (via API) for relationship extraction between co-occurring entities
- DSPy for prompt optimization (use `dspy.ChainOfThought` + `dspy.Predict`)

**From imouiche TiKG — directly adoptable:**
- Entity-Relation triple extraction format
- Domain ontology-guided error control (filter misclassified relation triples)
- Neo4j triple storage schema

**From TRAM (`center-for-threat-informed-defense/tram`) — directly adoptable:**
- ATT&CK technique mapping logic (sentence → technique classifier)
- Training data annotation pipeline
- Model registry pattern (plug new models without refactoring)

**STIX objects to generate:**
- `ThreatActor`, `Malware`, `AttackPattern`, `Vulnerability`, `Indicator`, `Relationship`
- All anchored to ATT&CK `external_references` where resolvable

### Phase 4: Hybrid Search Layer
**Goal:** Unified query API combining vector similarity + graph traversal

- **Qdrant** for ANN vector search (embed chunks with `AI-Growth-Lab/SecBERT` or `all-mpnet-base-v2`)
- **Neo4j Cypher** for graph traversal (path queries, subgraph extraction)
- Merged ranking: `score = α * vector_score + (1-α) * graph_hop_score`
- Key query: "given new IOC/TTP, find top-k historically similar incidents"

### Phase 5: Narrative Generation & Investigator UI
**Goal:** Generate investigative narratives from graph context; minimal UI for UNICC demo

- **DSPy** pipeline: STIX bundle + query → structured narrative
- **FastAPI** backend
- **neovis.js** for graph visualization in browser
- **Evaluation against SOW**: time-to-answer on 20 test queries vs. manual baseline

---

## 5. Reference Repositories

| Repo | What to adopt |
|---|---|
| `imouiche/Threat-Intelligence-Knowledge-Graphs` | TiKG NER pipeline (SecureBERT-BiLSTM-CRF), relation extraction ontology, Neo4j triple schema |
| `IS5882/Open-CyKG` | OIE-based triple extraction, KG canonicalization / entity fusion |
| `center-for-threat-informed-defense/tram` | ATT&CK technique classifier, annotation pipeline, model registry |
| `aiforsec/CyNER` | Primary NER model — clone and run directly |
| `mitre/cti` | enterprise-attack.json STIX bundle (already downloaded) |

---

## 6. Tech Stack

```
NER:           CyNER (xlm-roberta-large), GLiNER, SecureBERT
Graph:         Neo4j (ATT&CK anchor + extracted KG)
Vector store:  Qdrant
Metadata DB:   Postgres
LLM/Rel-extr:  Gemini Flash API
Orchestration: DSPy (prompt optimization)
Standards:     STIX 2.1, MITRE ATT&CK Enterprise
HPC:           Paramananta (SLURM), CONDA
Parsing:       Docling (primary), marker-pdf (fallback)
UI:            FastAPI + neovis.js
Dev:           Cursor, Python 3.11, Docker
```

---

## 7. Principles (Non-Negotiable)

- **Precision over recall** — per SOW. Only high-confidence extractions enter the graph.
- **LLMs for relationship extraction only** — not NER. Domain NER models dominate on precision.
- **Entity resolution is mandatory** before any graph insertion. No unresolved aliases.
- **MITRE ATT&CK is the canonical anchor** — all entities resolve against it or get flagged as novel.
- **Schema validation ≠ semantic validation** — Pydantic enforces structure, not entity correctness.
- **Paramananta for scale/air-gap, not convenience** — local tooling is fine for dev; HPC for batch inference.
